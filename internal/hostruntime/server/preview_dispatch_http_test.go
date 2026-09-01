package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

type previewDispatcherFunc func(context.Context, preview.DispatchAuthorization, preview.DispatchRequest) (preview.DispatchOutcome, error)

func (f previewDispatcherFunc) Dispatch(ctx context.Context, authorization preview.DispatchAuthorization, request preview.DispatchRequest) (preview.DispatchOutcome, error) {
	return f(ctx, authorization, request)
}

func previewDispatchHTTPFixture(t *testing.T) (preview.DispatchRequest, auth.Claims, time.Time) {
	t.Helper()
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	request := preview.DispatchRequest{
		Schema: preview.PreviewTunnelSchemaV1, Kind: preview.PreviewDispatchKind,
		PreviewID: "prv_dispatch_1", OperationID: "operation_dispatch_1", AccountID: "account_1", ActorID: "actor_1",
		OwnerDeviceID: "machine_1", OwnerSessionID: "session_dispatch_1",
		Target: preview.LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public",
		Endpoint: "https://preview-dispatch.preview.example.test", LeaseDeadline: now.Add(time.Hour),
		LeaseETag: `"ptv1:preview_lease:cHJ2X2Rpc3BhdGNoXzE:1"`, ExpectedGeneration: 1,
		IdempotencyKey: "preview_dispatch_key_1", RequestID: "request_dispatch_1", CorrelationID: "correlation_dispatch_1",
		State: "allocating", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown",
		CreatedAt: now, LastRenewedAt: now,
	}
	hash, err := request.ComputeRequestHash()
	if err != nil {
		t.Fatal(err)
	}
	request.RequestHash = hash
	claims := auth.Claims{
		CredentialClass: "preview_launch", Subject: request.ActorID, UserID: request.ActorID, AccountID: request.AccountID, ActorID: request.ActorID,
		MachineID: request.OwnerDeviceID, OwnerSessionID: request.OwnerSessionID, PreviewID: request.PreviewID,
		OperationID: request.OperationID, ExpectedGeneration: request.ExpectedGeneration, RequestHash: request.RequestHash,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		TargetScheme: request.Target.Scheme, TargetAddress: request.Target.Address, AccessMode: request.AccessMode,
		Endpoint: request.Endpoint, LeaseDeadline: request.LeaseDeadline.Unix(), LeaseETag: request.LeaseETag,
		State: request.State, AllocationState: request.AllocationState, EdgeState: request.EdgeState, OriginState: request.OriginState,
		CreatedAt: request.CreatedAt.Unix(), LastRenewedAt: request.LastRenewedAt.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	return request, claims, now
}

func TestPreviewDispatchHTTPBindsVerifiedClaimsAndReturnsAccepted(t *testing.T) {
	input, claims, now := previewDispatchHTTPFixture(t)
	called := false
	handler, err := NewPreviewDispatchHandler(PreviewDispatchHandlerConfig{
		MachineID: "machine_1", Now: func() time.Time { return now },
		Authorizer: func(token string) (Authorizer, error) {
			if token != "single-operation-proof" {
				t.Fatalf("token=%q", token)
			}
			return authorizerFunc(func(_ context.Context, frame protocol.Frame) (Authorization, error) {
				if frame.Capability != "preview.launch.v1" || frame.OperationID != input.OperationID {
					t.Fatalf("frame=%+v", frame)
				}
				return Authorization{MachineID: "machine_1", Value: claims}, nil
			}), nil
		},
		Dispatcher: previewDispatcherFunc(func(_ context.Context, authorization preview.DispatchAuthorization, request preview.DispatchRequest) (preview.DispatchOutcome, error) {
			called = true
			if authorization.RequestHash != input.RequestHash || authorization.PreviewID != input.PreviewID || request != input {
				t.Fatalf("authorization=%+v request=%+v", authorization, request)
			}
			return preview.DispatchOutcome{Schema: preview.PreviewTunnelSchemaV1, Kind: preview.PreviewDispatchKind, PreviewID: input.PreviewID, OperationID: input.OperationID, State: "accepted", Generation: 1}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer single-operation-proof")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !called || strings.Contains(recorder.Body.String(), "single-operation-proof") {
		t.Fatalf("status=%d called=%v body=%s", recorder.Code, called, recorder.Body.String())
	}
}

func TestPreviewDispatchHTTPRejectsClaimMismatchAndUnknownFields(t *testing.T) {
	input, claims, now := previewDispatchHTTPFixture(t)
	claims.OwnerSessionID = "session_other"
	called := false
	handler, err := NewPreviewDispatchHandler(PreviewDispatchHandlerConfig{
		MachineID: "machine_1", Now: func() time.Time { return now },
		Authorizer: func(string) (Authorizer, error) {
			return authorizerFunc(func(context.Context, protocol.Frame) (Authorization, error) {
				return Authorization{MachineID: "machine_1", Value: claims}, nil
			}), nil
		},
		Dispatcher: previewDispatcherFunc(func(_ context.Context, authorization preview.DispatchAuthorization, request preview.DispatchRequest) (preview.DispatchOutcome, error) {
			called = true
			if _, err := request.Validate(authorization.MachineID, now); err != nil {
				return preview.DispatchOutcome{}, err
			}
			if authorization.OwnerSessionID != request.OwnerSessionID {
				return preview.DispatchOutcome{}, preview.ErrDispatchInvalid
			}
			return preview.DispatchOutcome{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer proof")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || called {
		t.Fatalf("mismatch status=%d called=%v body=%s", recorder.Code, called, recorder.Body.String())
	}

	unknown := append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"credential":"secret"}`)...)
	request = httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewReader(unknown))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer proof")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("unknown status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	duplicate := append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"operation_id":"operation_dispatch_1"}`)...)
	request = httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewReader(duplicate))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer proof")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("duplicate status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPreviewDispatchAuthorizationRejectsEveryClaimClassMismatch(t *testing.T) {
	input, claims, _ := previewDispatchHTTPFixture(t)
	cases := map[string]func(*auth.Claims){
		"actor":            func(value *auth.Claims) { value.ActorID = "actor_other" },
		"target":           func(value *auth.Claims) { value.TargetAddress = "127.0.0.1:4000" },
		"deadline":         func(value *auth.Claims) { value.LeaseDeadline++ },
		"etag":             func(value *auth.Claims) { value.LeaseETag = `"ptv1:preview_lease:cHJ2X2Rpc3BhdGNoXzE:2"` },
		"lifecycle":        func(value *auth.Claims) { value.EdgeState = "ready" },
		"generation":       func(value *auth.Claims) { value.ExpectedGeneration++ },
		"idempotency":      func(value *auth.Claims) { value.IdempotencyKey = "different-key" },
		"request trace":    func(value *auth.Claims) { value.RequestID = "request_other" },
		"correlation":      func(value *auth.Claims) { value.CorrelationID = "correlation_other" },
		"request hash":     func(value *auth.Claims) { value.RequestHash = strings.Repeat("0", 64) },
		"subject":          func(value *auth.Claims) { value.Subject = "actor_other" },
		"user":             func(value *auth.Claims) { value.UserID = "actor_other" },
		"created time":     func(value *auth.Claims) { value.CreatedAt++ },
		"renewed time":     func(value *auth.Claims) { value.LastRenewedAt++ },
		"owner session":    func(value *auth.Claims) { value.OwnerSessionID = "session_other" },
		"preview":          func(value *auth.Claims) { value.PreviewID = "prv_other" },
		"operation":        func(value *auth.Claims) { value.OperationID = "operation_other" },
		"access mode":      func(value *auth.Claims) { value.AccessMode = "private" },
		"endpoint":         func(value *auth.Claims) { value.Endpoint = "https://other.preview.example.test" },
		"allocation state": func(value *auth.Claims) { value.AllocationState = "ready" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := claims
			mutate(&candidate)
			if _, err := previewDispatchAuthorization(candidate, input); err == nil {
				t.Fatal("mismatched signed claim was accepted")
			}
		})
	}
}
