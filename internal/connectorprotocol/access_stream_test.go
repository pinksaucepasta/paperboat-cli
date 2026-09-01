package connectorprotocol

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"
)

func privateAccessTestRequest(now time.Time) PrivateAccessRequest {
	return PrivateAccessRequest{
		AccountID: "account_1", ResourceKind: "preview", ResourceID: "preview_1", RouteID: "route_1",
		Audience: "paperboat-preview-http", DeviceID: "machine_1", SessionID: "installation_4",
		InstallationGeneration: 4, ExpiresAt: now.Add(time.Minute), Nonce: "nonce_1", OperationID: "operation_1",
		CarrierSessionID: "session_1", RouteGeneration: 1, ProcessGeneration: 2, ConfigGeneration: 3,
		SessionGeneration: 4, AssignmentGeneration: 5, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_1",
		Protocol: "http", Method: http.MethodConnect, Host: "private.preview.example.test", Path: "/",
		IdempotencyKey: "access_1", RequestID: "request_1", CorrelationID: "correlation_1",
	}
}

func TestPrivateAccessFramesAreStrictBoundedAndSecretMinimal(t *testing.T) {
	now := time.Now().UTC()
	open := PrivateAccessOpen{Schema: PrivateAccessSchema, Kind: PrivateAccessKind, Grant: "signed-grant", Request: privateAccessTestRequest(now)}
	var wire bytes.Buffer
	if err := WritePrivateAccessOpen(&wire, open); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateAccessOpen(&wire, now)
	if err != nil || decoded.Grant != open.Grant || decoded.Request != open.Request {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	result := PrivateAccessResult{Schema: PrivateAccessSchema, Kind: PrivateAccessKind, Status: http.StatusOK, ExpiresAt: now.Add(time.Minute)}
	if err := WritePrivateAccessResult(&wire, result); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivateAccessResult(&wire, now); err != nil || got != result {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestPrivateAccessFramesRejectBrowserCredentialsAndInvalidStatus(t *testing.T) {
	now := time.Now().UTC()
	request := privateAccessTestRequest(now)
	open := PrivateAccessOpen{Schema: PrivateAccessSchema, Kind: PrivateAccessKind, Grant: " signed-grant", Request: request}
	if err := open.Validate(now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("grant validation error=%v", err)
	}
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		result := PrivateAccessResult{Schema: PrivateAccessSchema, Kind: PrivateAccessKind, Status: status}
		if status == http.StatusOK {
			result.ExpiresAt = now.Add(time.Minute)
		}
		if err := result.Validate(now); err != nil {
			t.Fatalf("status %d error=%v", status, err)
		}
	}
	if err := (PrivateAccessResult{Schema: PrivateAccessSchema, Kind: PrivateAccessKind, Status: http.StatusNotFound}).Validate(now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("404 validation error=%v", err)
	}
}
