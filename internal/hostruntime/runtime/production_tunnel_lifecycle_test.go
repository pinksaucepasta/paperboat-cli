//go:build darwin || linux || windows

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
)

type runtimeEnrollmentAuth struct{}

func (runtimeEnrollmentAuth) Token(context.Context) (string, error) {
	return "runtime-machine-token", nil
}

func (runtimeEnrollmentAuth) Proof(_ context.Context, operation, method, path string, body []byte) ([]byte, error) {
	digest := sha256.Sum256(append([]byte(operation+method+path), body...))
	return digest[:], nil
}

type runtimeBlockingActivator struct {
	mu       sync.Mutex
	calls    int
	entered  chan int
	release  chan struct{}
	failure  error
	blockAll bool
}

func newRuntimeBlockingActivator() *runtimeBlockingActivator {
	return &runtimeBlockingActivator{entered: make(chan int, 8), release: make(chan struct{})}
}

func (a *runtimeBlockingActivator) Activate(ctx context.Context, request tunnelenrollment.ActivationRequest) (tunnelenrollment.Projection, error) {
	a.mu.Lock()
	a.calls++
	call := a.calls
	failure := a.failure
	block := a.blockAll
	a.mu.Unlock()
	a.entered <- call
	if failure != nil {
		return tunnelenrollment.Projection{}, failure
	}
	if block {
		select {
		case <-a.release:
		case <-ctx.Done():
			return tunnelenrollment.Projection{}, ctx.Err()
		}
	}
	readyAt := time.Now().UTC()
	return tunnelenrollment.Projection{
		Schema: tunnelenrollment.Schema, Kind: "tunnel_connector", TunnelID: request.TunnelID,
		HostID: request.HostID, ConnectorID: request.ConnectorID, OperationID: request.OperationID,
		State: "ready", CredentialReference: request.CredentialReference,
		CredentialGeneration: request.CredentialGeneration, ReadyAt: &readyAt,
	}, nil
}

func TestProductionTunnelEnrollmentStartDoesNotWaitForConnectorReadiness(t *testing.T) {
	server := newRuntimeEnrollmentServer(t)
	defer server.Close()
	activator := newRuntimeBlockingActivator()
	activator.blockAll = true
	service, err := NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		StateRoot: t.TempDir(), ControlURL: server.URL, HostID: "host_01", ControlToken: "local-token",
		Auth: runtimeEnrollmentAuth{}, Transport: server.Client().Transport, Activator: activator,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed the durable exchanged phase while keeping activation blocked. This
	// mirrors a process crash after exchange and before connector readiness.
	enrollCtx, cancelEnroll := context.WithCancel(context.Background())
	enrollDone := make(chan error, 1)
	go func() {
		_, enrollErr := service.manager.Enroll(enrollCtx, "tunnel_resume_01", "local-request-01")
		enrollDone <- enrollErr
	}()
	select {
	case call := <-activator.entered:
		if call != 1 {
			t.Fatalf("initial activation call = %d, want 1", call)
		}
	case <-time.After(time.Second):
		t.Fatal("initial activation did not start")
	}
	cancelEnroll()
	select {
	case err := <-enrollDone:
		if err == nil {
			t.Fatal("canceled initial activation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("initial activation did not cancel")
	}

	start := time.Now()
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Start waited %s for connector readiness", elapsed)
	}
	if got := service.RecoveryHealth(); got.State != "recovering" || !got.WorkerRunning {
		t.Fatalf("health immediately after Start = %#v", got)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrProductionTunnelEnrollmentStarted) {
		t.Fatalf("repeated Start error = %v", err)
	}
	select {
	case call := <-activator.entered:
		if call != 2 {
			t.Fatalf("resume activation call = %d, want 2", call)
		}
	case <-time.After(time.Second):
		t.Fatal("background recovery did not start")
	}
	close(activator.release)
	waitForProductionTunnelHealth(t, service, func(health ProductionTunnelRecoveryHealth) bool {
		return health.State == productionTunnelRecoveryReady && !health.WorkerRunning
	})
	if err := service.RecoveryError(); err != nil {
		t.Fatalf("successful recovery retained error: %v", err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := service.RecoveryHealth(); got.State != productionTunnelRecoveryStopped || got.WorkerRunning {
		t.Fatalf("health after Shutdown = %#v", got)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeated Shutdown error = %v", err)
	}
}

func TestProductionTunnelEnrollmentRecoveryFailureIsHealthOnly(t *testing.T) {
	server := newRuntimeEnrollmentServer(t)
	defer server.Close()
	activator := newRuntimeBlockingActivator()
	activator.failure = errors.New("connector readiness failed")
	service, err := NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		StateRoot: t.TempDir(), ControlURL: server.URL, HostID: "host_01", ControlToken: "local-token",
		Auth: runtimeEnrollmentAuth{}, Transport: server.Client().Transport, Activator: activator,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The first failed activation leaves the durable exchanged record for the
	// recovery worker to retry, without requiring a second server mutation.
	if _, err := service.manager.Enroll(context.Background(), "tunnel_failure_01", "local-request-02"); err == nil {
		t.Fatal("failed initial activation succeeded")
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForProductionTunnelHealth(t, service, func(health ProductionTunnelRecoveryHealth) bool {
		return health.State == productionTunnelRecoveryDegraded && !health.WorkerRunning
	})
	if err := service.RecoveryError(); err == nil || !strings.Contains(err.Error(), "connector readiness failed") {
		t.Fatalf("recovery error = %v", err)
	}
	if got := service.RecoveryHealth(); got.LastErrorCode != "activation_unavailable" || got.LastErrorKnown == false {
		t.Fatalf("failure health = %#v", got)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func waitForProductionTunnelHealth(t *testing.T, service *ProductionTunnelEnrollment, want func(ProductionTunnelRecoveryHealth) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if want(service.RecoveryHealth()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for health, got %#v", service.RecoveryHealth())
}

func newRuntimeEnrollmentServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/connectors/enrollments"):
			w.WriteHeader(http.StatusCreated)
			writeRuntimeEnvelope(t, w, map[string]any{
				"schema": api.TunnelV1Schema, "kind": "connector_enrollment", "id": "enrollment_runtime_01",
				"tunnel_id": strings.Split(r.URL.Path, "/")[3], "host_id": "host_01",
				"enrollment_token": "pbce_" + strings.Repeat("r", 48), "expires_at": time.Now().UTC().Add(time.Hour),
				"capabilities": []string{"h2c", "http", "tcp_private", "unix"},
			})
		case strings.HasSuffix(r.URL.Path, "/connectors/enrollments/exchange"):
			w.WriteHeader(http.StatusAccepted)
			parts := strings.Split(r.URL.Path, "/")
			writeRuntimeEnvelope(t, w, map[string]any{
				"schema": api.TunnelV1Schema, "kind": "connector_activation", "account_id": "account_01",
				"tunnel_id": parts[3], "connector_id": "connector_runtime_01", "host_id": "host_01",
				"stable_endpoint_id": "123e4567-e89b-12d3-a456-426614174000", "credential_generation": 3, "process_generation": 2,
				"operation": map[string]any{
					"schema": api.TunnelV1Schema, "kind": "operation", "id": "operation_runtime_01", "resource_kind": "connector", "resource_id": "connector_runtime_01",
					"phase": "connecting", "state": "running", "progress": 60, "retrying": false,
					"correlation_id": "correlation_runtime_01", "created_at": time.Now().UTC(), "updated_at": time.Now().UTC(),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func writeRuntimeEnvelope(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]any{"data": value}); err != nil {
		t.Fatal(err)
	}
}
