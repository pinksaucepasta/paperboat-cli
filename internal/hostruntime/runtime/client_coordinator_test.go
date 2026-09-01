package runtime

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

type clientServiceStub struct{}

func (clientServiceStub) Start(context.Context) error    { return nil }
func (clientServiceStub) Shutdown(context.Context) error { return nil }
func (clientServiceStub) Capabilities() []string         { return nil }

type clientLifecycleService struct {
	starts    int
	shutdowns int
}

func (s *clientLifecycleService) Start(context.Context) error { s.starts++; return nil }
func (s *clientLifecycleService) Shutdown(context.Context) error {
	s.shutdowns++
	return nil
}

func TestClientCoordinatorExposesOnlyClientRoutes(t *testing.T) {
	root := t.TempDir()
	host, err := NewClientCoordinator(context.Background(), HostConfig{
		Runtime:       runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources},
		ListenAddress: "127.0.0.1:0", WorkspaceRoot: root, InboxPath: filepath.Join(root, "Inbox"), MachineID: "machine_test",
	}, HostDependencies{
		Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Connector:  clientServiceStub{}, RuntimeObservationService: clientServiceStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Shutdown(context.Background()) })
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/v1/file-transfers", http.StatusUnauthorized},
		{http.MethodPost, "/v1/preview-launches", http.StatusNotFound},
		{http.MethodGet, "/v1/runtime", http.StatusNotFound},
		{http.MethodPost, "/v1/codex-sessions/session_1", http.StatusNotFound},
		{http.MethodGet, "/v1/codex-sessions/session_1/ws", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		host.handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want {
			t.Errorf("%s %s status=%d, want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}
	if host.sessions != nil {
		t.Fatal("client coordinator initialized terminal sessions")
	}
}

func TestClientCoordinatorSupportsStableHostLifecycle(t *testing.T) {
	root := t.TempDir()
	peer := &clientLifecycleService{}
	host, err := NewClientCoordinator(context.Background(), HostConfig{
		Runtime:       runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources},
		ListenAddress: "127.0.0.1:0", WorkspaceRoot: root, InboxPath: filepath.Join(root, "Inbox"), MachineID: "machine_test",
	}, HostDependencies{
		Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Connector:  clientServiceStub{}, RuntimeObservationService: clientServiceStub{},
		NativePeerFactory: func(func(net.Conn) error, http.Handler, http.Handler) (Service, error) { return peer, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.StartStable(t.Context()); err != nil {
		t.Fatalf("start stable Client coordinator: %v", err)
	}
	if peer.starts != 1 {
		t.Fatalf("client peer poller starts = %d, want 1", peer.starts)
	}
	if host.State() != Running {
		t.Fatalf("client coordination state = %q, want %q", host.State(), Running)
	}
	health := host.health.Snapshot()
	if capability := health.Capabilities["worker_lifecycle"]; capability.State != "ready" {
		t.Fatalf("client worker lifecycle health = %#v, want ready", capability)
	}
	status := host.WorkloadStatus()
	if status.Generation == 0 {
		t.Fatalf("workload status = %#v, want initialized generation", status)
	}
	if err := host.ShutdownStable(context.Background()); err != nil {
		t.Fatalf("shutdown stable Client coordinator: %v", err)
	}
	if peer.shutdowns != 1 {
		t.Fatalf("client peer poller shutdowns = %d, want 1", peer.shutdowns)
	}
}
