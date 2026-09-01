package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

const maxPreviewDispatchBytes = 32 << 10

// PreviewDispatcher is the canonical dashboard-to-device foreground preview
// boundary. The durable lease is created by paperboat-server before this is
// called; a dispatcher must never allocate a second lease or endpoint.
type PreviewDispatcher interface {
	Dispatch(context.Context, preview.DispatchAuthorization, preview.DispatchRequest) (preview.DispatchOutcome, error)
}

type PreviewDispatchHandlerConfig struct {
	Authorizer AuthorizerFactory
	Dispatcher PreviewDispatcher
	MachineID  string
	Now        func() time.Time
}

func NewPreviewDispatchHandler(config PreviewDispatchHandlerConfig) (http.Handler, error) {
	config.MachineID = strings.TrimSpace(config.MachineID)
	if config.Authorizer == nil || config.Dispatcher == nil || config.MachineID == "" {
		return nil, errors.New("invalid preview dispatch handler configuration")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if contentType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); contentType != "application/json" {
			writer.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(request.Body, maxPreviewDispatchBytes+1))
		if readErr != nil || len(body) > maxPreviewDispatchBytes {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var input preview.DispatchRequest
		if decodeStrict(body, &input) != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := input.Validate(config.MachineID, config.Now()); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		token, ok := bearerToken(request.Header.Values("Authorization"))
		if !ok {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorizer, err := config.Authorizer(token)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if closer, ok := authorizer.(interface{ CloseAuthorization() }); ok {
			defer closer.CloseAuthorization()
		}
		authorized, err := authorizer.Authorize(request.Context(), protocol.Frame{Type: "request", Version: protocol.ProtocolVersion, OperationID: input.OperationID, Capability: "preview.launch.v1"})
		if err != nil || authorized.MachineID != config.MachineID {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		claims, ok := authorized.Value.(auth.Claims)
		if !ok {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		dispatchAuthorization, err := previewDispatchAuthorization(claims, input)
		if err != nil {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		outcome, err := config.Dispatcher.Dispatch(request.Context(), dispatchAuthorization, input)
		if err != nil {
			writePreviewDispatchError(writer, err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		status := http.StatusAccepted
		if outcome.State == "ready" {
			status = http.StatusOK
		}
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(outcome)
	}), nil
}

func previewDispatchAuthorization(claims auth.Claims, request preview.DispatchRequest) (preview.DispatchAuthorization, error) {
	if claims.CredentialClass != "preview_launch" || claims.AccountID == "" || claims.ActorID == "" || claims.MachineID == "" || claims.OwnerSessionID == "" || claims.PreviewID == "" || claims.OperationID == "" || claims.ExpectedGeneration < 1 || claims.IdempotencyKey == "" || claims.RequestID == "" || claims.CorrelationID == "" || claims.RequestHash == "" || claims.ExpiresAt <= 0 {
		return preview.DispatchAuthorization{}, errors.New("preview dispatch authorization is incomplete")
	}
	if claims.Subject != claims.ActorID || claims.UserID != claims.ActorID ||
		claims.AccountID != request.AccountID || claims.ActorID != request.ActorID || claims.MachineID != request.OwnerDeviceID ||
		claims.OwnerSessionID != request.OwnerSessionID || claims.PreviewID != request.PreviewID || claims.OperationID != request.OperationID ||
		claims.TargetScheme != request.Target.Scheme || claims.TargetAddress != request.Target.Address || claims.AccessMode != request.AccessMode ||
		claims.Endpoint != request.Endpoint || claims.LeaseDeadline != request.LeaseDeadline.UTC().Unix() ||
		!matchingDispatchDeadline(claims.UserDeadline, request.UserDeadline) || claims.LeaseETag != request.LeaseETag ||
		claims.State != request.State || claims.AllocationState != request.AllocationState || claims.EdgeState != request.EdgeState || claims.OriginState != request.OriginState ||
		claims.CreatedAt != request.CreatedAt.UTC().Unix() || claims.LastRenewedAt != request.LastRenewedAt.UTC().Unix() ||
		claims.ExpectedGeneration != request.ExpectedGeneration || claims.IdempotencyKey != request.IdempotencyKey ||
		claims.RequestID != request.RequestID || claims.CorrelationID != request.CorrelationID || claims.RequestHash != request.RequestHash {
		return preview.DispatchAuthorization{}, errors.New("preview dispatch authorization does not match request")
	}
	return preview.DispatchAuthorization{
		AccountID: claims.AccountID, ActorID: claims.ActorID, MachineID: claims.MachineID,
		OwnerSessionID: claims.OwnerSessionID, PreviewID: claims.PreviewID, OperationID: claims.OperationID,
		ExpectedGeneration: claims.ExpectedGeneration, IdempotencyKey: claims.IdempotencyKey,
		RequestID: claims.RequestID, CorrelationID: claims.CorrelationID, RequestHash: claims.RequestHash,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

func matchingDispatchDeadline(claimed *int64, requested *time.Time) bool {
	if claimed == nil || requested == nil {
		return claimed == nil && requested == nil
	}
	return *claimed == requested.UTC().Unix()
}

func writePreviewDispatchError(writer http.ResponseWriter, err error) {
	status, code, retryable := http.StatusConflict, "preview_dispatch_rejected", false
	switch {
	case errors.Is(err, preview.ErrDispatchUnavailable):
		status, code, retryable = http.StatusServiceUnavailable, "preview_dispatch_unavailable", true
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code, retryable = http.StatusGatewayTimeout, "preview_dispatch_uncertain", true
	case errors.Is(err, preview.ErrDispatchInvalid):
		status, code = http.StatusForbidden, "preview_dispatch_binding_invalid"
	case errors.Is(err, preview.ErrDispatchConflict), errors.Is(err, preview.ErrSessionConflict):
		status, code = http.StatusConflict, "preview_dispatch_conflict"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]any{"code": code, "message": "The selected device could not accept this preview request.", "retryable": retryable}})
}
