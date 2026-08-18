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

func TestServeListenerReportsReadyAndHeartbeatsFromAcceptLoop(t *testing.T) {
	root, err := os.MkdirTemp("", "pb-hostservice-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	ready := make(chan struct{}, 1)
	heartbeat := make(chan struct{}, 1)
	server, err := New(Config{
		SocketPath: filepath.Join(root, "host.sock"), StatePath: filepath.Join(root, "policy.json"),
		UID: os.Getuid(), GID: os.Getgid(), Applier: &fakeApplier{}, Version: "test",
		Ready:     func() error { ready <- struct{}{}; return nil },
		Heartbeat: func() error { heartbeat <- struct{}{}; return nil }, HeartbeatInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
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
	select {
	case <-heartbeat:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not report heartbeat")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
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
