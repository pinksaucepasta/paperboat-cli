//go:build darwin || linux

package hostservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeApplier struct {
	mu    sync.Mutex
	modes []string
	err   error
}

func (a *fakeApplier) Apply(_ context.Context, mode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.modes = append(a.modes, mode)
	return a.err
}
func (a *fakeApplier) Close(context.Context) error { return nil }

type blockingApplier struct {
	entered chan struct{}
	release chan struct{}
}

func (a *blockingApplier) Apply(context.Context, string) error {
	close(a.entered)
	<-a.release
	return nil
}
func (a *blockingApplier) Close(context.Context) error { return nil }

func TestNewAllowsRootPeerIdentity(t *testing.T) {
	root := t.TempDir()
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"),
		StatePath:  filepath.Join(root, "policy.json"),
		UID:        0,
		GID:        0,
		Applier:    &fakeApplier{},
		Version:    "test",
	})
	if err != nil || server.config.UID != 0 || server.config.GID != 0 {
		t.Fatalf("server=%v error=%v", server, err)
	}
}

func TestNewRejectsHeartbeatIntervalWithoutCallback(t *testing.T) {
	root := t.TempDir()
	_, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: &fakeApplier{}, Version: "test", HeartbeatInterval: time.Second,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error=%v", err)
	}
}

func TestServeListenerReportsPeriodicHeartbeatsDuringRequestTraffic(t *testing.T) {
	root, err := os.MkdirTemp("", "pb-hostservice-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	ready := make(chan struct{}, 1)
	heartbeat := make(chan struct{}, 2)
	ticks := make(chan time.Time, 2)
	tickerStopped := make(chan struct{})
	applier := &blockingApplier{entered: make(chan struct{}), release: make(chan struct{})}
	var heartbeatCount atomic.Int64
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: applier, Version: "test",
		Ready:     func() error { ready <- struct{}{}; return nil },
		Heartbeat: func() error { heartbeatCount.Add(1); heartbeat <- struct{}{}; return nil }, HeartbeatInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.newHeartbeatTicker = func(interval time.Duration) (<-chan time.Time, func()) {
		if interval != time.Second {
			t.Errorf("heartbeat interval=%s", interval)
		}
		return ticks, func() { close(tickerStopped) }
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.config.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveListener(ctx, listener) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("readiness was not reported")
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: server.config.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(client).Encode(Request{Schema: ProtocolV1, Operation: "apply_availability", Mode: KeepAwake, Version: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applier.entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the blocking applier")
	}
	for index := 0; index < 2; index++ {
		ticks <- time.Time{}
		select {
		case <-heartbeat:
		case <-time.After(time.Second):
			t.Fatalf("request traffic blocked periodic heartbeat %d", index+1)
		}
	}
	if got := heartbeatCount.Load(); got != 2 {
		t.Fatalf("heartbeat count=%d", got)
	}
	close(applier.release)
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if response.Status != "applied" || response.ObservedVersion != 1 {
		t.Fatalf("response=%+v", response)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	select {
	case <-tickerStopped:
	default:
		t.Fatal("heartbeat ticker was not stopped")
	}
	completedHeartbeats := heartbeatCount.Load()
	ticks <- time.Time{}
	if heartbeatCount.Load() != completedHeartbeats {
		t.Fatal("heartbeat continued after server cancellation")
	}
}

func TestServeListenerReturnsPeriodicHeartbeatFailure(t *testing.T) {
	root, err := os.MkdirTemp("", "pb-hostservice-heartbeat-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	ticks := make(chan time.Time, 1)
	tickerStopped := make(chan struct{})
	heartbeatErr := errors.New("notify watchdog")
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: &fakeApplier{}, Version: "test",
		Heartbeat: func() error { return heartbeatErr }, HeartbeatInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.newHeartbeatTicker = func(time.Duration) (<-chan time.Time, func()) {
		return ticks, func() { close(tickerStopped) }
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.config.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.serveListener(context.Background(), listener) }()
	ticks <- time.Time{}
	select {
	case err := <-done:
		if !errors.Is(err, heartbeatErr) {
			t.Fatalf("run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure did not stop the listener")
	}
	select {
	case <-tickerStopped:
	default:
		t.Fatal("heartbeat ticker was not stopped after failure")
	}
}

func TestHostServiceSocketUsesEnrolledUserAndGroupMode(t *testing.T) {
	root, err := os.MkdirTemp("", "pb-hostservice-mode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: &fakeApplier{}, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := server.listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Lstat(server.config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode=%v", info.Mode())
	}
}

func TestProtocolAppliesMonotonicPolicyAndIsIdempotent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("peer test requires a non-root enrolled user")
	}
	applier := &fakeApplier{}
	server := testServer(t, os.Getuid(), applier)
	first := requestServer(t, server, Request{Schema: ProtocolV1, Operation: "apply_availability", Mode: KeepAwake, Version: 1})
	if first.Status != "applied" || first.ObservedMode != KeepAwake || first.ObservedVersion != 1 {
		t.Fatalf("first response=%+v", first)
	}
	second := requestServer(t, server, Request{Schema: ProtocolV1, Operation: "apply_availability", Mode: KeepAwake, Version: 1})
	if second.Status != "applied" || len(applier.modes) != 1 {
		t.Fatalf("idempotent response=%+v modes=%v", second, applier.modes)
	}
	stale := requestServer(t, server, Request{Schema: ProtocolV1, Operation: "apply_availability", Mode: AllowSleep, Version: 1})
	if stale.ErrorCode != "stale_policy" || len(applier.modes) != 1 {
		t.Fatalf("stale response=%+v modes=%v", stale, applier.modes)
	}
}

func TestProtocolRejectsUnknownFieldsAndWrongPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("peer test requires a non-root enrolled user")
	}
	server := testServer(t, os.Getuid(), &fakeApplier{})
	response := rawRequestServer(t, server, []byte(`{"schema":"paperboat.host-service/v1","operation":"apply_availability","mode":"keep_awake","version":1,"command":"sh"}`))
	if response.ErrorCode != "invalid_request" {
		t.Fatalf("response=%+v", response)
	}
	denied := testServer(t, os.Getuid()+1, &fakeApplier{})
	serverSide, clientSide := unixPair(t)
	done := make(chan error, 1)
	go func() { done <- denied.serve(serverSide); serverSide.Close() }()
	_ = json.NewEncoder(clientSide).Encode(Request{Schema: ProtocolV1, Operation: "apply_availability", Mode: KeepAwake, Version: 1})
	clientSide.Close()
	if err := <-done; !errors.Is(err, ErrPeerDenied) {
		t.Fatalf("peer error=%v", err)
	}
}

func TestDesiredPolicyPersistsBeforeApplicationFailure(t *testing.T) {
	applier := &fakeApplier{err: errors.New("inhibitor unavailable")}
	server := testServer(t, max(1, os.Getuid()), applier)
	if err := server.apply(context.Background(), KeepAwake, 7); err == nil {
		t.Fatal("application failure was ignored")
	}
	body, err := os.ReadFile(server.config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	if state.DesiredMode != KeepAwake || state.DesiredVersion != 7 || state.Status != "error" || state.ErrorCode != "availability_apply_failed" {
		t.Fatalf("state=%+v", state)
	}
}

func TestPersistKeepsSharedHostdTokenParentTraversable(t *testing.T) {
	root, err := os.MkdirTemp("", "pb-hostservice-shared-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hostd.token"), []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "availability-policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: &fakeApplier{}, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.apply(context.Background(), KeepAwake, 1); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("shared state directory mode=%#o, want 0755", got)
	}
	for _, path := range []string{server.config.StatePath, filepath.Join(root, "hostd.token")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode=%#o, want 0600", path, got)
		}
	}
}

func TestProtocolRejectsRemovedRestartUpdateOperation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("peer test requires a non-root enrolled user")
	}
	server := testServer(t, os.Getuid(), &fakeApplier{})
	if result := rawRequestServer(t, server, []byte(`{"schema":"paperboat.host-service/v1","operation":"activate_update","artifact":{}}`)); result.ErrorCode != "invalid_request" {
		t.Fatalf("removed update response=%+v", result)
	}
}

func testServer(t *testing.T, uid int, applier Applier) *Server {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"), UID: uid, GID: max(1, os.Getgid()), Applier: applier, Version: "test", Now: func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func requestServer(t *testing.T, server *Server, request Request) Response {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return rawRequestServer(t, server, body)
}

func rawRequestServer(t *testing.T, server *Server, body []byte) Response {
	t.Helper()
	serverSide, clientSide := unixPair(t)
	done := make(chan error, 1)
	go func() { done <- server.serve(serverSide); serverSide.Close() }()
	if _, err := clientSide.Write(append(body, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(clientSide).Decode(&response); err != nil {
		t.Fatal(err)
	}
	clientSide.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return response
}

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	placeholder, err := os.CreateTemp("/tmp", "pbh-host-socket-")
	if err != nil {
		t.Fatal(err)
	}
	path := placeholder.Name()
	placeholder.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptUnix()
	listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}
