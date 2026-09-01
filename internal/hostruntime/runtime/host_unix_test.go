//go:build darwin || linux

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configapply"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/envinject"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
)

type hostAuthorizer struct{}

const runtimeTestHostRecipientKeyID = "envk_IwY-MQtEprrsxiSheZeY7fXcsuKArWSF8qsJfiPSteM"

func TestCommandManagedEnvironmentDoesNotMutatePersistedCommand(t *testing.T) {
	variables := map[string]string{"API_TOKEN": "canary-secret", "EMPTY": ""}
	path := filepath.Join(t.TempDir(), "environment-cache.json")
	managed, err := envinject.Open(context.Background(), envinject.Config{
		Path: path, HighWaterPath: filepath.Join(t.TempDir(), "environment-high-water.json"), IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true, AccountID: "acct_1", MachineID: "mach_1",
		InstallationGeneration: 1, HostKeyGeneration: 1, HostRecipientKeyID: runtimeTestHostRecipientKeyID,
		GenesisMarker: runtimeTestGenesisMarkerFor(t, path),
		Processor:     runtimeTestEnvironmentProcessor{variables: variables},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.Apply(context.Background(), envinject.Bundle{Schema: envinject.BundleSchema}); err != nil {
		t.Fatal(err)
	}
	persisted := pty.Command{Path: "/bin/sh", Env: []string{"PATH=/bin", "API_TOKEN=base"}}
	launched, err := commandWithManagedEnvironment(persisted, managed)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(persisted.Env, "\x00"); strings.Contains(got, "canary-secret") || got != "PATH=/bin\x00API_TOKEN=base" {
		t.Fatalf("persisted environment changed: %q", got)
	}
	if got := strings.Join(launched.Env, "\x00"); !strings.Contains(got, "API_TOKEN=canary-secret") || !strings.Contains(got, "EMPTY=") {
		t.Fatalf("launch environment=%q", got)
	}
}

func (hostAuthorizer) Authorize(context.Context, protocol.Frame) (server.Authorization, error) {
	return server.Authorization{JournalBinding: "test:user:client", EnvironmentID: "env_test", UserID: "user_test", ClientID: "client_test"}, nil
}

type hostProber struct{}

func (hostProber) Probe(context.Context, preview.Target) error { return nil }

type hostedLifecycleStub struct{}

func (hostedLifecycleStub) Start(context.Context) error    { return nil }
func (hostedLifecycleStub) Shutdown(context.Context) error { return nil }
func (hostedLifecycleStub) Capabilities() []string         { return []string{"hosted.lifecycle.v1"} }

type testSessionLauncher struct {
	sessions *session.Manager
	path     string
	args     []string
	env      []string
}

func (l testSessionLauncher) Launch(ctx context.Context, request process.LaunchRequest) (session.Snapshot, error) {
	return l.sessions.Create(ctx, session.CreateRequest{ID: request.ID, Name: request.Name, Command: pty.Command{Path: l.path, Args: l.args, Env: l.env, CWD: request.CWD, Dimensions: request.Dimensions}})
}

func testSessionLauncherFactory(path string, args, env []string) func(*session.Manager) (server.SessionLauncher, error) {
	return func(sessions *session.Manager) (server.SessionLauncher, error) {
		resolved, err := pty.ValidateProcessPolicy(path, args, env)
		if err != nil {
			return nil, err
		}
		return testSessionLauncher{sessions: sessions, path: resolved, args: args, env: env}, nil
	}
}

type hostListener struct {
	mu     sync.Mutex
	conn   net.Conn
	closed chan struct{}
}

func (l *hostListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.conn != nil {
		connection := l.conn
		l.conn = nil
		l.mu.Unlock()
		return connection, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *hostListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (*hostListener) Addr() net.Addr { return hostAddress("runtime") }

type hostAddress string

func (a hostAddress) Network() string { return "pipe" }
func (a hostAddress) String() string  { return string(a) }

func TestHostCompositionNegotiatesAuthenticatedHealthAndClosesDurableState(t *testing.T) {
	root := t.TempDir()
	serverSide, clientSide := net.Pipe()
	listener := &hostListener{conn: serverSide, closed: make(chan struct{})}
	config := runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources}
	previews, err := preview.New(preview.Config{Prober: hostProber{}, MaxTargets: 4, MaxConcurrentProbes: 1})
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewHost(context.Background(), HostConfig{
		Runtime: config, ListenAddress: "127.0.0.1:0", WorkspaceRoot: root,
		EnvironmentID: "env_test", MachineID: "machine_test",
	}, HostDependencies{
		Authorizer: func(token string) (server.Authorizer, error) {
			if token != "signed-operation-credential" {
				t.Fatalf("token=%q", token)
			}
			return hostAuthorizer{}, nil
		},
		Listener:    func() (net.Listener, error) { return listener, nil },
		Previews:    previews,
		ConfigApply: configapply.ConformanceHandler{}, ConfigApplyProof: true,
		SessionLauncherFactory: testSessionLauncherFactory("/bin/sh", []string{"-l"}, []string{"PATH=/usr/bin:/bin"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return clientSide, nil }}
	connection, response, err := websocket.Dial(context.Background(), "ws://runtime.test/v1/runtime", &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: transport},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer signed-operation-credential"}},
		Subprotocols: []string{server.DefaultWebSocketSubprotocol},
	})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	writeFrame := func(frame protocol.Frame) {
		t.Helper()
		encoded, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.Write(context.Background(), websocket.MessageText, encoded); err != nil {
			t.Fatal(err)
		}
	}
	readFrame := func() protocol.Frame {
		t.Helper()
		messageType, encoded, err := connection.Read(context.Background())
		if err != nil || messageType != websocket.MessageText {
			t.Fatalf("read type=%v err=%v", messageType, err)
		}
		var frame protocol.Frame
		if err := json.Unmarshal(encoded, &frame); err != nil {
			t.Fatal(err)
		}
		return frame
	}
	writeFrame(protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1","config.apply.v1"]}`)})
	if welcome := readFrame(); welcome.Type != "welcome" || bytes.Contains(welcome.Payload, []byte(`"preview.public.v1"`)) || !bytes.Contains(welcome.Payload, []byte(`"config.apply.v1"`)) {
		t.Fatalf("welcome=%#v", welcome)
	}
	writeFrame(protocol.Frame{Type: "request", RequestID: "req_health", Version: "1.0", OperationID: "op_health_0001", Capability: "health.v1", DeadlineMS: 5_000, Payload: json.RawMessage(`{}`)})
	responseFrame := readFrame()
	if responseFrame.Type != "response" || !bytes.Contains(responseFrame.Payload, []byte(`"live":true`)) {
		t.Fatalf("response=%#v", responseFrame)
	}
	_ = connection.Close(websocket.StatusNormalClosure, "done")
	transport.CloseIdleConnections()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := host.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if host.State() != Stopped {
		t.Fatalf("state=%s", host.State())
	}
	reopened, err := store.Open(context.Background(), store.Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostCompositionRejectsMissingTrustBoundaryBeforeStateCreation(t *testing.T) {
	root := t.TempDir()
	config := runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources}
	if _, err := NewHost(context.Background(), HostConfig{Runtime: config, ListenAddress: "127.0.0.1:0", WorkspaceRoot: root}, HostDependencies{}); !errors.Is(err, ErrHostInvalid) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file err=%v", err)
	}
}

func TestHostCompositionEnforcesHostedProfileBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile runtimeconfig.Profile
		hosted  HostedLifecycle
	}{
		{name: "hosted requires lifecycle", profile: runtimeconfig.Hosted},
		{name: "byod forbids lifecycle", profile: runtimeconfig.BYOD, hosted: hostedLifecycleStub{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			runtimeConfig := runtimeconfig.Config{Profile: tc.profile, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources}
			_, err := NewHost(context.Background(), HostConfig{Runtime: runtimeConfig, ListenAddress: "127.0.0.1:0", WorkspaceRoot: root}, HostDependencies{
				Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil }, HostedLifecycle: tc.hosted,
			})
			if !errors.Is(err, ErrHostInvalid) {
				t.Fatalf("error=%v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "state.db")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state file error=%v", err)
			}
		})
	}
}

func TestHostCompositionRejectsUnsafeBindBeforeStateCreation(t *testing.T) {
	root := t.TempDir()
	config := runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources}
	_, err := NewHost(context.Background(), HostConfig{Runtime: config, ListenAddress: "0.0.0.0:8080", WorkspaceRoot: root}, HostDependencies{
		Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
	})
	if !errors.Is(err, ErrHostInvalid) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file err=%v", err)
	}
}
