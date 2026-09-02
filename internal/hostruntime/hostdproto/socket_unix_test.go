//go:build darwin || linux

package hostdproto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketLifecyclePersistsFenceAndRejectsSupersededWorker(t *testing.T) {
	config := testSocketConfig(t)
	server, cancel, done := startSocketServer(t, config)
	client := testSocketClient(t, config)

	first := negotiateSocket(t, client, "runtime-old")
	if _, err := client.Request(context.Background(), readyFor(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), activateFor(first)); err != nil {
		t.Fatal(err)
	}
	if err := clientHeartbeat(client, first); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	second := negotiateSocket(t, client, "runtime-new")
	if _, err := client.Request(context.Background(), readyFor(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), activateFor(second)); err != nil {
		t.Fatal(err)
	}
	if err := clientHeartbeat(client, first); !errors.Is(err, ErrFenced) {
		t.Fatalf("old heartbeat error=%v, want ErrFenced", err)
	}
	if err := clientHeartbeat(client, second); err != nil {
		t.Fatalf("new heartbeat: %v", err)
	}
	status, err := client.Active(context.Background())
	if err != nil || status.State != StateActive || status.WorkerID != "runtime-new" || status.Epoch != second.Epoch {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if info, err := os.Stat(config.SocketPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket permissions info=%v err=%v", info, err)
	}
	if got := server.Status(); got.State != StateActive || got.Epoch != second.Epoch || got.WorkerID != "runtime-new" {
		t.Fatalf("server status=%+v", got)
	}
	stopSocketServer(t, cancel, done)

	state, err := LoadFenceState(config.StatePath)
	if err != nil || state.Epoch != 2 || state.WorkerID != "runtime-new" {
		t.Fatalf("fence state=%+v err=%v", state, err)
	}
	_, cancel, done = startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	restarted := testSocketClient(t, config)
	next := negotiateSocket(t, restarted, "runtime-next")
	if next.Epoch != second.Epoch+1 {
		t.Fatalf("restart epoch=%d, want %d", next.Epoch, second.Epoch+1)
	}
}

func TestSocketRejectsUnauthorizedUIDAndCapability(t *testing.T) {
	config := testSocketConfig(t)
	config.peerUID = func(*net.UnixConn) (int, error) { return config.UID + 1, nil }
	_, cancel, done := startSocketServer(t, config)
	client := testSocketClient(t, config)
	if _, err := client.Request(context.Background(), Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1}); err == nil {
		t.Fatal("unauthorized UID request unexpectedly succeeded")
	}
	stopSocketServer(t, cancel, done)

	config = testSocketConfig(t)
	_, cancel, done = startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	wrongToken := append([]byte(nil), config.Token...)
	wrongToken[0] ^= 0xff
	client, err := NewClient(config.SocketPath, wrongToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1}); err == nil {
		t.Fatal("invalid capability request unexpectedly succeeded")
	}
}

func TestSocketAllowsRootUpdaterOnlyWithCapability(t *testing.T) {
	config := testSocketConfig(t)
	config.peerUID = func(*net.UnixConn) (int, error) { return 0, nil }
	_, cancel, done := startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	client := testSocketClient(t, config)
	if _, err := client.Request(context.Background(), Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1}); err != nil {
		t.Fatalf("root updater request: %v", err)
	}
}

type fixedUpdateGate struct{ target UpdateGateTargetBinding }

func (g fixedUpdateGate) HandleUpdateGate(context.Context, UpdateGateRequest) (UpdateGateResponse, error) {
	return UpdateGateResponse{Target: g.target}, nil
}

func TestSocketRoundTripsUpdateGateResponse(t *testing.T) {
	config := testSocketConfig(t)
	config.UpdateGate = fixedUpdateGate{target: UpdateGateTargetBinding{
		Scope: UpdateGateScopeStandalone, MachineID: "machine_01", FailureDomain: "standalone",
	}}
	_, cancel, done := startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	client := testSocketClient(t, config)
	response, err := client.UpdateGate(context.Background(), UpdateGateRequest{
		Operation: UpdateGateTarget, TransactionID: "transaction_01", Version: "2026.09.02.6", ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Target != config.UpdateGate.(fixedUpdateGate).target {
		t.Fatalf("target=%+v", response.Target)
	}
}

func TestSocketRepliesWithTypedErrorsAndBoundsRequests(t *testing.T) {
	config := testSocketConfig(t)
	config.RequestTimeout = 100 * time.Millisecond
	config.MaxConcurrent = 1
	_, cancel, done := startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)

	connection := rawSocketConnection(t, config.SocketPath)
	defer connection.Close()
	if err := writeAll(connection, config.Token); err != nil {
		t.Fatal(err)
	}
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], MaxFrameBytes+1)
	if err := writeAll(connection, oversized[:]); err != nil {
		t.Fatal(err)
	}
	response, err := ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	remote, ok := response.(*Error)
	if !ok || remote.Code != "invalid" {
		t.Fatalf("malformed response=%+v", response)
	}
	// Each connection accepts one request. A second request cannot receive a
	// second reply from the same authenticated connection.
	if err := WriteFrame(connection, Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1}); err == nil {
		if _, err := ReadFrame(connection); err == nil {
			t.Fatal("second request unexpectedly received a reply")
		}
	}

	blocking := rawSocketConnection(t, config.SocketPath)
	defer blocking.Close()
	if err := writeAll(blocking, config.Token); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = io.ReadFull(blocking, make([]byte, 1))
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("unterminated request error=%v elapsed=%s", err, time.Since(started))
	}
}

func TestSocketClientMapsRemoteFencingError(t *testing.T) {
	config := testSocketConfig(t)
	_, cancel, done := startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	client := testSocketClient(t, config)
	first := negotiateSocket(t, client, "runtime-a")
	if _, err := client.Request(context.Background(), readyFor(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), activateFor(first)); err != nil {
		t.Fatal(err)
	}
	second := negotiateSocket(t, client, "runtime-b")
	if _, err := client.Request(context.Background(), readyFor(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), activateFor(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), heartbeatFor(first)); !errors.Is(err, ErrFenced) {
		t.Fatalf("fenced response error=%v, want ErrFenced", err)
	}
}

func TestCandidatePerformsReadyActivateAndFencesPriorWorker(t *testing.T) {
	config := testSocketConfig(t)
	_, cancel, done := startSocketServer(t, config)
	defer stopSocketServer(t, cancel, done)
	client := testSocketClient(t, config)
	first, err := NewCandidate(client, "runtime-old", "2026.08.18.1", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := NewCandidate(client, "runtime-new", "2026.08.18.2", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Heartbeat(context.Background()); !errors.Is(err, ErrFenced) {
		t.Fatalf("old worker heartbeat=%v", err)
	}
	if err := second.Heartbeat(context.Background()); err != nil {
		t.Fatalf("active worker heartbeat=%v", err)
	}
}

func testSocketConfig(t *testing.T) SocketConfig {
	t.Helper()
	// Darwin's AF_UNIX path limit is much shorter than the normal Go test temp
	// directory path. Use an explicitly short root on every supported platform.
	root, err := os.MkdirTemp("/tmp", "pbhd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	random := make([]byte, 32*16)
	for index := range random {
		random[index] = byte(index/32 + 1)
	}
	return SocketConfig{
		SocketPath: filepath.Join(root, "socket", "hostd.sock"), StatePath: filepath.Join(root, "state", "fence.json"),
		UID: os.Geteuid(), GID: os.Getegid(), Token: bytes.Repeat([]byte{0x42}, installationTokenBytes),
		APIMin: 1, APIMax: 2, Random: bytes.NewReader(random),
	}
}

func startSocketServer(t *testing.T, config SocketConfig) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		if info, err := os.Lstat(config.SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			return server, cancel, done
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("socket server exited before readiness: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s was not created", config.SocketPath)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requestSocket(t *testing.T, client *Client, request Message) (Message, error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		response, err := client.Request(context.Background(), request)
		var operation *net.OpError
		if err == nil || !errors.As(err, &operation) {
			return response, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func stopSocketServer(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("socket server did not stop")
	}
}

func testSocketClient(t *testing.T, config SocketConfig) *Client {
	t.Helper()
	client, err := NewClient(config.SocketPath, config.Token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func negotiateSocket(t *testing.T, client *Client, workerID string) Welcome {
	t.Helper()
	response, err := requestSocket(t, client, Hello{WorkerID: workerID, Version: "2026.08.18.3", APIMin: 1, APIMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	welcome, ok := response.(*Welcome)
	if !ok {
		t.Fatalf("hello response=%T", response)
	}
	return *welcome
}

func clientHeartbeat(client *Client, welcome Welcome) error {
	_, err := client.Request(context.Background(), heartbeatFor(welcome))
	return err
}

func rawSocketConnection(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var connection net.Conn
	var err error
	for {
		connection, err = net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}
