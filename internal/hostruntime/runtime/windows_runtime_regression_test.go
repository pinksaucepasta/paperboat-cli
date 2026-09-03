//go:build windows

package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

// windowsRegressionAccessSource is intentionally inert. The PAC failure is
// injected before AccessService can bind a listener, so this test exercises
// only hostd lifecycle ownership and never opens a network connection.
type windowsRegressionAccessSource struct{}

func (windowsRegressionAccessSource) Snapshot(context.Context) ([]privatepreviewproxy.AccessRoute, error) {
	return nil, nil
}

func (windowsRegressionAccessSource) Open(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("access source must not be opened during PAC startup")
}

type windowsRegressionPAC struct {
	recoverErr error
}

func (p windowsRegressionPAC) Recover(context.Context) error { return p.recoverErr }
func (windowsRegressionPAC) Install(context.Context, string) error {
	return errors.New("PAC install must not be reached after recovery failure")
}
func (windowsRegressionPAC) Remove(context.Context) error { return nil }

// TestWindowsPACFailureLeavesOwnerSessionLeasesUsable protects the failure
// boundary that was broken on Victus: an interactive-user PAC failure is
// optional in a LocalSystem hostd process and must not tear down the preview
// owner-session manager. Shutdown still closes the manager and rejects later
// acquisition.
func TestWindowsPACFailureLeavesOwnerSessionLeasesUsable(t *testing.T) {
	runtimeDone := make(chan struct{})
	owners, err := preview.NewRuntimeOwnerSessionRegistry(preview.RuntimeOwnerSessionRegistryConfig{
		MachineID: "machine_windows_regression", RuntimeDone: runtimeDone,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerLeases, err := preview.NewOwnerSessionLeaseManager(preview.OwnerSessionLeaseManagerConfig{
		MachineID: "machine_windows_regression", ControlToken: "local-control-token", Registry: owners,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateAccess, err := privatepreviewproxy.NewAccessService(privatepreviewproxy.AccessServiceConfig{
		Proxy:        privatepreviewproxy.AccessProxyConfig{Source: windowsRegressionAccessSource{}},
		Configurator: windowsRegressionPAC{recoverErr: errors.New("interactive user registry unavailable")},
	})
	if err != nil {
		t.Fatal(err)
	}
	assembly := &productionPreviewAssembly{
		privateAccess: privateAccess,
		owners:        owners,
		ownerLeases:   ownerLeases,
		runtimeDone:   runtimeDone,
	}

	if err := assembly.Start(context.Background()); err != nil {
		t.Fatalf("optional Windows PAC failure stopped preview assembly: %v", err)
	}
	lease, err := ownerLeases.Acquire(preview.OwnerSessionLeaseRequest{
		Target: preview.LeaseTarget{Scheme: "http", Address: "127.0.0.1:8080"},
	}, "preview-owner-regression-1")
	if err != nil {
		t.Fatalf("owner-session acquisition after isolated PAC failure: %v", err)
	}
	if lease.ID == "" || lease.OwnerSessionID == "" {
		t.Fatalf("incomplete owner-session lease: %#v", lease)
	}

	if err := assembly.Shutdown(context.Background()); err != nil {
		t.Fatalf("assembly shutdown: %v", err)
	}
	if _, err := ownerLeases.Acquire(preview.OwnerSessionLeaseRequest{
		Target: preview.LeaseTarget{Scheme: "http", Address: "127.0.0.1:8080"},
	}, "preview-owner-regression-2"); !errors.Is(err, preview.ErrOwnerSessionLeaseLost) {
		t.Fatalf("acquisition after assembly shutdown = %v, want owner-session lease lost", err)
	}
}

type windowsRegressionEndpoint struct {
	mu        sync.Mutex
	starts    int
	shutdowns int
	calls     int
}

func (e *windowsRegressionEndpoint) Start(context.Context) error {
	e.mu.Lock()
	e.starts++
	e.mu.Unlock()
	return nil
}

func (e *windowsRegressionEndpoint) Shutdown(context.Context) error {
	e.mu.Lock()
	e.shutdowns++
	e.mu.Unlock()
	return nil
}

func (e *windowsRegressionEndpoint) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (e *windowsRegressionEndpoint) counts() (starts, shutdowns, calls int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.starts, e.shutdowns, e.calls
}

// TestWindowsStableHostStartsTunnelEnrollmentBeforeEndpointUseAndStopsOnce
// proves the stable Host owns tunnel enrollment. Endpoint use is attempted
// only after StartStable, and repeated shutdown does not call the lifecycle a
// second time.
func TestWindowsStableHostStartsTunnelEnrollmentBeforeEndpointUseAndStopsOnce(t *testing.T) {
	endpoint := &windowsRegressionEndpoint{}
	host := newWindowsRegressionCoordinator(t, endpoint, endpoint)
	if err := host.StartStable(context.Background()); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	host.handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/tunnel-connectors/enroll", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("enrollment endpoint status=%d, want %d", response.Code, http.StatusNoContent)
	}
	if starts, shutdowns, calls := endpoint.counts(); starts != 1 || shutdowns != 0 || calls != 1 {
		t.Fatalf("after endpoint use starts=%d shutdowns=%d calls=%d, want 1/0/1", starts, shutdowns, calls)
	}

	if err := host.ShutdownStable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := host.ShutdownStable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts, shutdowns, calls := endpoint.counts(); starts != 1 || shutdowns != 1 || calls != 1 {
		t.Fatalf("after repeated shutdown starts=%d shutdowns=%d calls=%d, want 1/1/1", starts, shutdowns, calls)
	}
}

// TestWindowsStableHostDoesNotImplicitlyStartTunnelEnrollmentWithoutLifecycle
// keeps the handler-only composition explicit: a handler is not treated as a
// service, so Host must not guess how or when to start it.
func TestWindowsStableHostDoesNotImplicitlyStartTunnelEnrollmentWithoutLifecycle(t *testing.T) {
	endpoint := &windowsRegressionEndpoint{}
	host := newWindowsRegressionCoordinator(t, endpoint, nil)
	if err := host.StartStable(context.Background()); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	host.handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/tunnel-connectors/enroll", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("enrollment endpoint status=%d, want %d", response.Code, http.StatusNoContent)
	}
	if starts, shutdowns, calls := endpoint.counts(); starts != 0 || shutdowns != 0 || calls != 1 {
		t.Fatalf("handler-only composition starts=%d shutdowns=%d calls=%d, want 0/0/1", starts, shutdowns, calls)
	}
	if err := host.ShutdownStable(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newWindowsRegressionCoordinator(t *testing.T, endpoint http.Handler, lifecycle Service) *Host {
	t.Helper()
	root := t.TempDir()
	config := runtimeconfig.Config{
		Profile:   runtimeconfig.BYOD,
		StateRoot: root,
		Version:   "windows-regression-test",
		Limits:    runtimeconfig.DefaultLimits,
		Resources: runtimeconfig.DefaultResources,
	}
	host, err := NewClientCoordinator(context.Background(), HostConfig{
		Runtime:       config,
		ListenAddress: "127.0.0.1:0",
		WorkspaceRoot: root,
		InboxPath:     root,
		MachineID:     "machine_windows_regression",
	}, HostDependencies{
		Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Connector:  clientServiceStub{}, RuntimeObservationService: clientServiceStub{},
		Listener: func() (net.Listener, error) {
			return newWindowsRegressionListener(), nil
		},
		LocalControlToken:         "local-control-token",
		TunnelEnrollment:          endpoint,
		TunnelEnrollmentLifecycle: lifecycle,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Shutdown(context.Background()) })
	return host
}

type windowsRegressionListener struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newWindowsRegressionListener() *windowsRegressionListener {
	return &windowsRegressionListener{closed: make(chan struct{})}
}

func (l *windowsRegressionListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *windowsRegressionListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *windowsRegressionListener) Addr() net.Addr { return windowsRegressionAddr("runtime") }

type windowsRegressionAddr string

func (a windowsRegressionAddr) Network() string { return "pipe" }
func (a windowsRegressionAddr) String() string  { return string(a) }
