package preview

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

func TestAttachmentClientSendsExactMachineProofAndDecodesSafeAttachment(t *testing.T) {
	now := time.Now().UTC()
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_client", "operation_client_01", "route_client_01", testPreviewCarrierIdentity(1), 1)
	request, err := AttachmentRequestForLease(lease, "request_client_01", "correlation_client_01")
	if err != nil {
		t.Fatal(err)
	}
	attachment.RequestID = request.RequestID
	attachment.CorrelationID = request.CorrelationID
	attachment.RequestHash, err = request.Hash(attachment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	var proofOperation, proofMethod, proofPath string
	var proofBody []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/previews/preview_client/carrier-attachment" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer machine-token" || r.Header.Get("X-Paperboat-Machine-Identity") != "machine-proof-identity" {
			t.Fatalf("machine auth headers = %#v", r.Header)
		}
		encodedProof, decodeErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		if decodeErr != nil || string(encodedProof) != "proof-bytes" {
			t.Fatalf("machine proof = %q, err=%v", r.Header.Get("X-Paperboat-Machine-Proof"), decodeErr)
		}
		if r.Header.Get("Idempotency-Key") != request.OperationID || r.Header.Get("If-Match") != lease.ETag || r.Header.Get("Request-Id") != request.RequestID || r.Header.Get("Correlation-Id") != request.CorrelationID {
			t.Fatalf("trace headers = %#v", r.Header)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		proofOperation, proofMethod, proofPath, proofBody = request.OperationID, r.Method, r.URL.Path, append([]byte(nil), body...)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Data Attachment `json:"data"`
		}{Data: attachment}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client, err := NewAttachmentClient(AttachmentClientConfig{
		ControlURL: server.URL, AllowedHosts: []string{"127.0.0.1"},
		Tokens:     tokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil }),
		Identities: tokenSourceFunc(func(context.Context) (string, error) { return "machine-proof-identity", nil }),
		Proofs: controlProof(func(_ context.Context, operationID, method, path string, body []byte) ([]byte, error) {
			proofOperation, proofMethod, proofPath, proofBody = operationID, method, path, append([]byte(nil), body...)
			return []byte("proof-bytes"), nil
		}),
		Transport: server.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Allocate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got.Binding != attachment.Binding || got.AttachmentGeneration != attachment.AttachmentGeneration {
		t.Fatalf("attachment = %#v", got)
	}
	if proofOperation != request.OperationID || proofMethod != http.MethodPost || proofPath != "/v1/previews/preview_client/carrier-attachment" || len(proofBody) == 0 {
		t.Fatalf("proof input = op=%q method=%q path=%q body=%q", proofOperation, proofMethod, proofPath, proofBody)
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(proofBody) != string(encodedRequest) {
		t.Fatalf("proof body = %s, request body = %s", proofBody, encodedRequest)
	}
}

func TestAttachmentAdmissionAllowsDialOnlyAfterServerAdmission(t *testing.T) {
	now := time.Now().UTC()
	_, attachment := providerTestLeaseAttachment(t, now, "preview_admitted", "operation_admitted_01", "route_admitted_01", testPreviewCarrierIdentity(1), 1)
	attachment.State = "admitted"
	attachment.EdgeReady = false
	attachment.OriginReady = false
	attachment.ReadyAt = nil
	if _, err := attachment.Admission(); err != nil {
		t.Fatalf("admitted attachment was not dialable: %v", err)
	}
	attachment.State = "pending"
	if _, err := attachment.Admission(); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("pending attachment admission error = %v", err)
	}
}

func TestAttachmentClientRejectsDuplicateUnknownOversizedAndRedirectResponses(t *testing.T) {
	now := time.Now().UTC()
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_strict", "operation_strict_01", "route_strict_01", testPreviewCarrierIdentity(1), 1)
	request, err := AttachmentRequestForLease(lease, "request_strict_01", "correlation_strict_01")
	if err != nil {
		t.Fatal(err)
	}
	validBody, err := json.Marshal(struct {
		Data Attachment `json:"data"`
	}{Data: attachment})
	if err != nil {
		t.Fatal(err)
	}
	responses := []struct {
		name string
		body string
	}{
		{name: "duplicate envelope", body: `{"data":` + string(validBody[len(`{"data":`):len(validBody)-1]) + `,"data":{}}`},
		{name: "unknown envelope", body: `{"data":` + string(validBody[len(`{"data":`):len(validBody)-1]) + `,"secret":"do-not-accept"}`},
	}
	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			client := attachmentClientWithTransport(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			if _, err := client.Allocate(context.Background(), request); !errors.Is(err, ErrAttachmentClientInvalid) {
				t.Fatalf("error = %v, want invalid response", err)
			}
		})
	}
	oversized := attachmentClientWithTransport(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 257)))}, nil
	}), 256)
	if _, err := oversized.Allocate(context.Background(), request); !errors.Is(err, ErrAttachmentClientInvalid) {
		t.Fatalf("oversized response error = %v", err)
	}
	redirect := attachmentClientWithTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://other.example.test/"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}))
	if _, err := redirect.Allocate(context.Background(), request); !errors.Is(err, ErrAttachmentClientInvalid) {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestAttachmentClientRejectsUnsafeEndpointAndMissingCreateOperation(t *testing.T) {
	for _, endpoint := range []string{"http://api.example.test", "https://user:secret@api.example.test", "https://api.example.test/?query=1"} {
		if _, err := NewAttachmentClient(AttachmentClientConfig{ControlURL: endpoint, AllowedHosts: []string{"api.example.test"}, Identities: tokenSourceFunc(func(context.Context) (string, error) { return "identity", nil }), Proofs: controlProof(func(context.Context, string, string, string, []byte) ([]byte, error) { return []byte("proof"), nil })}); !errors.Is(err, ErrAttachmentClientInvalid) {
			t.Fatalf("endpoint=%s error=%v", endpoint, err)
		}
	}
	lease := Lease{ID: "preview_missing", OwnerDeviceID: "machine_01", OwnerSessionID: "owner_session_01"}
	if _, err := AttachmentRequestForLease(lease, "request_missing", "correlation_missing"); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("missing operation error = %v", err)
	}
	if _, err := AttachmentRequestForLease(Lease{ID: "preview_missing", OwnerDeviceID: "machine_01", OwnerSessionID: "owner_session_01", CreateOperationID: "operation_01", ETag: formatLeaseETag("preview_missing", 1)}, "x\ny", "correlation_missing"); !errors.Is(err, ErrAttachmentClientInvalid) {
		t.Fatalf("unsafe request ID error = %v", err)
	}
}

func TestAttachmentClientRequiresLeaseETagAndClassifiesStalePrecondition(t *testing.T) {
	now := time.Now().UTC()
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_etag", "operation_etag_01", "route_etag_01", testPreviewCarrierIdentity(1), 1)
	request, err := AttachmentRequestForLease(lease, "request_etag_01", "correlation_etag_01")
	if err != nil {
		t.Fatal(err)
	}
	request.LeaseETag = ""
	client := attachmentClientWithTransport(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport called without lease ETag")
		return nil, nil
	}))
	if _, err := client.Allocate(context.Background(), request); !errors.Is(err, api.ErrPreviewLeaseETagRequired) {
		t.Fatalf("missing ETag error = %v, want ErrPreviewLeaseETagRequired", err)
	}

	request.LeaseETag = lease.ETag
	_ = attachment
	stale := attachmentClientWithTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("If-Match") != lease.ETag {
			t.Fatalf("If-Match = %q, want %q", req.Header.Get("If-Match"), lease.ETag)
		}
		return &http.Response{StatusCode: http.StatusPreconditionFailed, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("stale")), Request: req}, nil
	}))
	if _, err := stale.Allocate(context.Background(), request); !errors.Is(err, ErrAttachmentLeaseETagStale) {
		t.Fatalf("stale ETag error = %v, want ErrAttachmentLeaseETagStale", err)
	}
}

func TestAttachmentClientWaitsForAdmissionThenEdgeReadyAndRecordsOriginReadiness(t *testing.T) {
	now := time.Now().UTC()
	lease, base := providerTestLeaseAttachment(t, now, "preview_admission", "operation_admission_01", "route_admission_01", testPreviewCarrierIdentity(1), 1)
	request, err := AttachmentRequestForLease(lease, "request_admission_01", "correlation_admission_01")
	if err != nil {
		t.Fatal(err)
	}
	pending := base
	pending.State, pending.EdgeReady, pending.OriginReady = "pending", false, false
	pending.AttachmentGeneration = 1
	pending.RequestID, pending.CorrelationID = request.RequestID, request.CorrelationID
	pending.RequestHash, err = request.Hash(pending.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	admitted := pending
	admitted.State, admitted.AttachmentGeneration = "admitted", 2
	edgeReady := admitted
	edgeReady.State, edgeReady.EdgeReady, edgeReady.OriginReady = "edge_ready", true, false
	edgeReady.AttachmentGeneration = 3
	ready := edgeReady
	ready.State, ready.OriginReady = "ready", true
	ready.AttachmentGeneration = 4
	readyAt := now
	ready.ReadyAt = &readyAt
	for name, value := range map[string]Attachment{"pending": pending, "admitted": admitted, "edge_ready": edgeReady, "ready": ready} {
		if err := value.Validate(now); err != nil {
			t.Fatalf("%s attachment invalid: %v", name, err)
		}
	}
	var calls []string
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("If-Match") != lease.ETag {
			t.Fatalf("%s If-Match = %q, want %q", req.URL.Path, req.Header.Get("If-Match"), lease.ETag)
		}
		if req.Header.Get("Idempotency-Key") != request.OperationID {
			t.Fatalf("%s idempotency key = %q", req.URL.Path, req.Header.Get("Idempotency-Key"))
		}
		calls = append(calls, req.URL.Path)
		value := admitted
		if req.URL.Path != "/v1/previews/preview_admission/carrier-attachment" {
			if req.URL.Path != "/v1/previews/preview_admission/carrier-attachment/readiness" {
				t.Fatalf("unexpected attachment path %q", req.URL.Path)
			}
			value = ready
		} else if len(calls) > 1 {
			value = edgeReady
		}
		body, err := json.Marshal(struct {
			Data Attachment `json:"data"`
		}{Data: value})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})
	client, err := NewAttachmentClient(AttachmentClientConfig{
		ControlURL: "https://api.example.test", AllowedHosts: []string{"api.example.test"}, AdmissionPollInterval: time.Millisecond,
		Tokens:     tokenSourceFunc(func(context.Context) (string, error) { return "token", nil }),
		Identities: tokenSourceFunc(func(context.Context) (string, error) { return "identity", nil }),
		Proofs:     controlProof(func(context.Context, string, string, string, []byte) ([]byte, error) { return []byte("proof"), nil }), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.WaitForAdmission(context.Background(), request, pending)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "admitted" || got.EdgeReady || got.AttachmentGeneration != admitted.AttachmentGeneration {
		t.Fatalf("admitted attachment = %#v", got)
	}
	got, err = client.WaitForEdgeReady(context.Background(), request, got)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "edge_ready" || !got.EdgeReady || got.AttachmentGeneration != edgeReady.AttachmentGeneration {
		t.Fatalf("edge-ready attachment = %#v", got)
	}
	got, err = client.ObserveOrigin(context.Background(), request, got, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "ready" || !got.EdgeReady || !got.OriginReady || got.AttachmentGeneration != ready.AttachmentGeneration {
		t.Fatalf("ready attachment = %#v", got)
	}
	if len(calls) != 3 || calls[0] != "/v1/previews/preview_admission/carrier-attachment" || calls[1] != "/v1/previews/preview_admission/carrier-attachment" || calls[2] != "/v1/previews/preview_admission/carrier-attachment/readiness" {
		t.Fatalf("attachment calls = %#v", calls)
	}
}

func TestAttachmentClientAcceptsIdempotentOriginFailure(t *testing.T) {
	now := time.Now().UTC()
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_origin_replay", "operation_origin_replay_01", "route_origin_replay_01", testPreviewCarrierIdentity(1), 1)
	request, err := AttachmentRequestForLease(lease, "request_origin_replay_01", "correlation_origin_replay_01")
	if err != nil {
		t.Fatal(err)
	}
	attachment.RequestID = request.RequestID
	attachment.CorrelationID = request.CorrelationID
	attachment.RequestHash, err = request.Hash(attachment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if attachment.State != "edge_ready" || !attachment.EdgeReady || attachment.OriginReady {
		t.Fatalf("fixture attachment = %#v, want edge_ready", attachment)
	}
	body, err := json.Marshal(struct {
		Data Attachment `json:"data"`
	}{Data: attachment})
	if err != nil {
		t.Fatal(err)
	}
	client := attachmentClientWithTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/previews/preview_origin_replay/carrier-attachment/readiness" {
			t.Fatalf("readiness path = %q", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	}))
	got, err := client.ObserveOrigin(context.Background(), request, attachment, false)
	if err != nil {
		t.Fatalf("idempotent origin failure = %v", err)
	}
	if got.Binding != attachment.Binding || got.AttachmentGeneration != attachment.AttachmentGeneration || got.State != attachment.State || got.OriginReady != attachment.OriginReady {
		t.Fatalf("idempotent attachment = %#v, want same binding/generation/state %#v", got, attachment)
	}
}

func TestAttachmentBindingAcceptsRawBase64URLEdgeProcessEpoch(t *testing.T) {
	_, attachment := providerTestLeaseAttachment(t, time.Now().UTC(), "preview_epoch", "operation_epoch", "route_epoch", testPreviewCarrierIdentity(1), 1)
	attachment.Binding.EdgeProcessEpoch = "_epoch12"
	if err := attachment.Binding.Validate(); err != nil {
		t.Fatalf("valid opaque process epoch: %v", err)
	}
	attachment.Binding.EdgeProcessEpoch = "epoch.12"
	if err := attachment.Binding.Validate(); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("invalid opaque process epoch error = %v", err)
	}
}

func attachmentClientWithTransport(t *testing.T, transport http.RoundTripper, maxResponse ...int64) *AttachmentClient {
	t.Helper()
	max := int64(64 << 10)
	if len(maxResponse) != 0 {
		max = maxResponse[0]
	}
	client, err := NewAttachmentClient(AttachmentClientConfig{
		ControlURL: "https://api.example.test", AllowedHosts: []string{"api.example.test"}, MaxResponseBytes: max,
		Tokens:     tokenSourceFunc(func(context.Context) (string, error) { return "token", nil }),
		Identities: tokenSourceFunc(func(context.Context) (string, error) { return "identity", nil }),
		Proofs:     controlProof(func(context.Context, string, string, string, []byte) ([]byte, error) { return []byte("proof"), nil }), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
