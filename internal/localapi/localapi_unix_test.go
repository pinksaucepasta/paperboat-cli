//go:build darwin || linux

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

type snapshotSourceFunc func(context.Context) (Snapshot, error)

func (f snapshotSourceFunc) Snapshot(ctx context.Context) (Snapshot, error) { return f(ctx) }

type completionSourceFunc func(context.Context) (CompletionSnapshot, error)

func (f completionSourceFunc) Completions(ctx context.Context) (CompletionSnapshot, error) {
	return f(ctx)
}

type peerStreamBrokerFunc func(context.Context, Peer, PeerStreamRequest) (net.Conn, error)

func (f peerStreamBrokerFunc) OpenPeerStream(ctx context.Context, peer Peer, request PeerStreamRequest) (net.Conn, error) {
	return f(ctx, peer, request)
}

type serializedPeerStreamBody struct {
	connection net.Conn
	reading    chan struct{}
	mu         sync.Mutex
}

func (b *serializedPeerStreamBody) Read(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	close(b.reading)
	return b.connection.Read(value)
}

func (b *serializedPeerStreamBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}

func TestPeerStreamCloseInterruptsBlockedBodyRead(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	body := &serializedPeerStreamBody{connection: local, reading: make(chan struct{})}
	stream := &peerStreamConn{Conn: local, reader: body}
	readDone := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		readDone <- err
	}()
	<-body.reading

	closeDone := make(chan error, 1)
	go func() { closeDone <- stream.Close() }()
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer stream close blocked behind an active body read")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("read err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("body read was not interrupted by peer stream close")
	}
}

func TestPeerHangupWatcherCancelsWhenAuthenticatedClientProcessExits(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	socket := filepath.Join(localAPITestDir(t), "hangup.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("Unix listener did not accept client")
	}
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchPeerHangup(ctx, server, Peer{PID: command.Process.Pid}, cancel)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed client process exited successfully")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("peer process exit did not cancel hijacked stream")
	}
}

func TestLocalAPIPeerStreamClosesWhenAuthenticatedClientProcessIsKilled(t *testing.T) {
	if os.Getenv("PAPERBOAT_TEST_PEER_STREAM_CHILD") == "1" {
		client, err := NewClient(os.Getenv("PAPERBOAT_TEST_PEER_STREAM_SOCKET"), time.Second)
		if err != nil {
			os.Exit(2)
		}
		request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
		if err != nil {
			os.Exit(3)
		}
		stream, err := client.OpenPeerStream(context.Background(), request)
		if err != nil {
			os.Exit(4)
		}
		defer stream.Close()
		if _, err := os.Stdout.WriteString("ready\n"); err != nil {
			os.Exit(5)
		}
		_, _ = stream.Read(make([]byte, 1))
		os.Exit(6)
	}

	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream-process-exit.sock")
	remoteStream := make(chan net.Conn, 1)
	server, err := NewServer(ServerConfig{
		SocketPath: socket,
		OwnerUID:   os.Geteuid(),
		OwnerGID:   os.Getegid(),
		Source:     snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		PeerStreams: peerStreamBrokerFunc(func(context.Context, Peer, PeerStreamRequest) (net.Conn, error) {
			local, remote := net.Pipe()
			remoteStream <- remote
			return local, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx) }()
	waitForSocket(t, socket)

	command := exec.Command(os.Args[0], "-test.run=^TestLocalAPIPeerStreamClosesWhenAuthenticatedClientProcessIsKilled$")
	command.Env = append(os.Environ(), "PAPERBOAT_TEST_PEER_STREAM_CHILD=1", "PAPERBOAT_TEST_PEER_STREAM_SOCKET="+socket)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	ready := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
		t.Fatalf("child readiness=%q err=%v", ready, err)
	}
	remote := <-remoteStream
	defer remote.Close()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed peer stream client exited successfully")
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("daemon-owned peer stream remained open after client death: %v", err)
	}
	cancel()
	if err := <-serverDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIPeerStreamSetupCancelsWhenAuthenticatedClientProcessIsKilled(t *testing.T) {
	if os.Getenv("PAPERBOAT_TEST_PEER_STREAM_SETUP_CHILD") == "1" {
		client, err := NewClient(os.Getenv("PAPERBOAT_TEST_PEER_STREAM_SOCKET"), time.Minute)
		if err != nil {
			os.Exit(2)
		}
		request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
		if err != nil {
			os.Exit(3)
		}
		_, _ = client.OpenPeerStream(context.Background(), request)
		os.Exit(4)
	}

	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream-setup-process-exit.sock")
	setupStarted := make(chan struct{})
	setupCanceled := make(chan struct{})
	server, err := NewServer(ServerConfig{
		SocketPath: socket,
		OwnerUID:   os.Geteuid(),
		OwnerGID:   os.Getegid(),
		Source:     snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		PeerStreams: peerStreamBrokerFunc(func(ctx context.Context, _ Peer, _ PeerStreamRequest) (net.Conn, error) {
			close(setupStarted)
			<-ctx.Done()
			close(setupCanceled)
			return nil, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx) }()
	waitForSocket(t, socket)

	command := exec.Command(os.Args[0], "-test.run=^TestLocalAPIPeerStreamSetupCancelsWhenAuthenticatedClientProcessIsKilled$")
	command.Env = append(os.Environ(), "PAPERBOAT_TEST_PEER_STREAM_SETUP_CHILD=1", "PAPERBOAT_TEST_PEER_STREAM_SOCKET="+socket)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	select {
	case <-setupStarted:
	case <-time.After(time.Second):
		t.Fatal("peer stream setup did not start")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed peer stream client exited successfully")
	}
	select {
	case <-setupCanceled:
	case <-time.After(time.Second):
		t.Fatal("peer process exit did not cancel in-flight stream setup")
	}
	cancel()
	if err := <-serverDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIPeerStreamUpgradeIsAuthenticatedAndBidirectional(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream.sock")
	server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), PeerStreams: peerStreamBrokerFunc(func(_ context.Context, peer Peer, request PeerStreamRequest) (net.Conn, error) {
		if peer.UID != os.Geteuid() || request.Consumer != "exec" {
			return nil, ErrPermission
		}
		local, remote := net.Pipe()
		go func() { defer remote.Close(); _, _ = remote.Write([]byte("reply")) }()
		return local, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, err := NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenPeerStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	buffer := make([]byte, 5)
	if _, err := stream.Read(buffer); err != nil || string(buffer) != "reply" {
		t.Fatalf("read=%q err=%v", buffer, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestPendingPeerStreamRequestDefersCredentialValidation(t *testing.T) {
	request, err := NewPendingPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", time.Now().Add(time.Minute), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if request.Validate(time.Now().UTC()) == nil || request.ValidatePending(time.Now().UTC()) != nil {
		t.Fatal("pending request was accepted as authorized or rejected as pending")
	}
}

func TestLocalAPIPeerStreamOutlivesHTTPTimeout(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream-timeout.sock")
	remoteStream := make(chan net.Conn, 1)
	const serverTimeout = 50 * time.Millisecond
	server, err := NewServer(ServerConfig{
		SocketPath: socket,
		OwnerUID:   os.Geteuid(),
		OwnerGID:   os.Getegid(),
		Source:     snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		Timeout:    serverTimeout,
		PeerStreams: peerStreamBrokerFunc(func(context.Context, Peer, PeerStreamRequest) (net.Conn, error) {
			local, remote := net.Pipe()
			remoteStream <- remote
			return local, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, err := NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenPeerStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	remote := <-remoteStream
	defer remote.Close()

	time.Sleep(3 * serverTimeout)
	deadline := time.Now().Add(time.Second)
	if err := stream.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	clientToRemote := []byte("client-to-remote")
	if _, err := stream.Write(clientToRemote); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(clientToRemote))
	if _, err := io.ReadFull(remote, buffer); err != nil || !bytes.Equal(buffer, clientToRemote) {
		t.Fatalf("remote read=%q err=%v", buffer, err)
	}
	remoteToClient := []byte("remote-to-client")
	if _, err := remote.Write(remoteToClient); err != nil {
		t.Fatal(err)
	}
	buffer = make([]byte, len(remoteToClient))
	if _, err := io.ReadFull(stream, buffer); err != nil || !bytes.Equal(buffer, remoteToClient) {
		t.Fatalf("client read=%q err=%v", buffer, err)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIPeerStreamPreservesBinaryBytesAndHalfClose(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream-raw.sock")
	server, err := NewServer(ServerConfig{
		SocketPath: socket,
		OwnerUID:   os.Geteuid(),
		OwnerGID:   os.Getegid(),
		Source:     snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		PeerStreams: peerStreamBrokerFunc(func(context.Context, Peer, PeerStreamRequest) (net.Conn, error) {
			return net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)

	payload := make([]byte, 1<<20)
	for index := range payload {
		payload[index] = byte(index * 31)
	}
	want := append([]byte(nil), payload...)
	remoteDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			remoteDone <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetReadBuffer(1024)
		time.Sleep(50 * time.Millisecond)
		got, readErr := io.ReadAll(connection)
		if readErr == nil && !bytes.Equal(got, want) {
			readErr = errors.New("raw local SSH bytes changed")
		}
		if readErr == nil {
			_, readErr = connection.Write(got)
			_ = connection.CloseWrite()
		}
		remoteDone <- readErr
	}()

	client, err := NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "ssh", "operation_ssh_1", "credential", time.Now().Add(time.Minute), 1<<40, json.RawMessage(`{"protocol":"v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenPeerStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	half, ok := stream.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("raw local peer stream does not expose half-close")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || !bytes.Equal(reply, want) {
		t.Fatalf("reply bytes=%d err=%v", len(reply), err)
	}
	if err := <-remoteDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIPeerStreamCancellationInterruptsSetup(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "peer-stream-cancel.sock")
	started := make(chan struct{})
	canceled := make(chan struct{})
	server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), PeerStreams: peerStreamBrokerFunc(func(ctx context.Context, _ Peer, _ PeerStreamRequest) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, err := NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPeerStreamRequest("machine_1", "environment_1", 2, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, openErr := client.OpenPeerStream(requestCtx, request)
		result <- openErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("peer setup did not start")
	}
	cancelRequest()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled peer setup unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("peer setup did not return after cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("server peer setup did not observe cancellation")
	}
	cancelServer()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestDecodeRemoteErrorAcceptsServerEnvelope(t *testing.T) {
	body := `{"schema":"paperboat.local-api/v1","code":"peer_stream_unavailable","message":"peer stream is unavailable","request_id":"req_0123456789abcdef01234567"}`
	err := decodeRemoteErrorReader(http.StatusServiceUnavailable, strings.NewReader(body))
	if err == nil || err.Error() != "peer_stream_unavailable: peer stream is unavailable" {
		t.Fatalf("error=%v", err)
	}
	remote, ok := err.(*RemoteError)
	if !ok || remote.Code != "peer_stream_unavailable" || remote.Message != "peer stream is unavailable" || remote.RequestID == "" {
		t.Fatalf("remote error details=%#v", err)
	}
}

func TestDecodeRemoteExecStartUncertainPreservesTypedCause(t *testing.T) {
	body := `{"schema":"paperboat.local-api/v1","code":"exec_start_uncertain","message":"remote execution start outcome is uncertain","request_id":"req_0123456789abcdef01234567"}`
	err := decodeRemoteErrorReader(http.StatusServiceUnavailable, strings.NewReader(body))
	if !errors.Is(err, ErrExecStartUncertain) {
		t.Fatalf("error=%v", err)
	}
}

func TestSafeErrorMessagePreservesJoinedCausesOnOneLine(t *testing.T) {
	err := errors.Join(errors.New("initial peer dial: EOF"), errors.New("fresh peer dial retry: session shutdown"))
	if got := safeErrorMessage(err); got != "initial peer dial: EOF; fresh peer dial retry: session shutdown" {
		t.Fatalf("message=%q", got)
	}
}

func TestSafeErrorMessageBoundsDiagnostics(t *testing.T) {
	err := errors.New(strings.Repeat("x", 700))
	got := safeErrorMessage(err)
	if len(got) != 512 || got != strings.Repeat("x", 512) {
		t.Fatalf("diagnostic length=%d", len(got))
	}
}

func TestSafeErrorMessageRedactsStructuredTransportDiagnostics(t *testing.T) {
	err := errors.New("peer path 3 failed (class 12): read Noise response (prologue=secret local=fingerprint handle=private): EOF")
	if got := safeErrorMessage(err); got != "peer path 3 failed" {
		t.Fatalf("message=%q", got)
	}
}

func TestWriteErrorBoundsFinalEnvelopeMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusServiceUnavailable, "req_0123456789abcdef01234567", "peer_stream_unavailable", "peer stream is unavailable: "+strings.Repeat("x", 700))
	err := decodeRemoteErrorReader(recorder.Code, recorder.Body)
	remote, ok := err.(*RemoteError)
	if !ok || len(remote.Message) != 512 || remote.Code != "peer_stream_unavailable" {
		t.Fatalf("remote error=%#v", err)
	}
}

type diagnosticServiceFake struct {
	snapshot DiagnosticSnapshot
	marker   string
	bundle   diagnostics.Bundle
}

func (s *diagnosticServiceFake) Diagnostics(context.Context) (DiagnosticSnapshot, error) {
	return s.snapshot, nil
}
func (s *diagnosticServiceFake) RecordBugreportMarker(_ context.Context, phase string) error {
	s.marker = phase
	return nil
}
func (s *diagnosticServiceFake) CreateBugreport(context.Context) (diagnostics.Bundle, error) {
	return s.bundle, nil
}

type staleAuthority bool

func (s staleAuthority) CanRemoveStaleSocket(context.Context, string) bool { return bool(s) }

type staleAuthorityFunc func(context.Context, string) bool

func (f staleAuthorityFunc) CanRemoveStaleSocket(ctx context.Context, path string) bool {
	return f(ctx, path)
}

type observationSinkFunc func(context.Context, Peer, TransportObservation) error

func (f observationSinkFunc) PublishObservation(ctx context.Context, peer Peer, observation TransportObservation) error {
	return f(ctx, peer, observation)
}

func validSnapshot() Snapshot {
	return Snapshot{
		Schema: SnapshotSchemaV1, Generation: 7, ObservedAt: time.Date(2026, 8, 4, 1, 2, 3, 0, time.UTC), DaemonState: "ready",
		Machines: []MachineStatus{{ID: "machine_1", Alias: "studio", Eligible: true, RuntimeState: "ready", Generation: 4, SelectedPath: "relay", RelayRegion: "bom", TransferReadiness: "ready", PreviewReadiness: "degraded", SSHReadiness: "unavailable", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown", Health: []HealthItem{{Code: "ssh_unavailable", Severity: "warning", Title: "SSH is unavailable", Recovery: "Run pb ssh doctor", ETag: "etag_1"}}}},
	}
}

func TestLocalAPIServesStrictSnapshotToOSPeer(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "paperboat.sock")
	var mu sync.Mutex
	var observed Peer
	server, err := NewServer(ServerConfig{
		SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Timeout: time.Second,
		Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		Authorize: func(peer Peer) bool {
			mu.Lock()
			observed = peer
			mu.Unlock()
			return peer.UID == os.Geteuid()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, err := NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Snapshot(context.Background())
	if err != nil || snapshot.Generation != 7 || len(snapshot.Machines) != 1 || snapshot.Machines[0].SelectedPath != "relay" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	mu.Lock()
	peer := observed
	mu.Unlock()
	if peer.UID != os.Geteuid() || peer.GID < 0 || peer.PID <= 0 {
		t.Fatalf("peer=%#v", peer)
	}
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0o600 || fileOwner(info) != os.Geteuid() {
		t.Fatalf("socket info=%#v err=%v", info, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run err=%v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket was not cleaned up: %v", err)
	}
}

func TestLocalAPIServesOwnerAuthorizedCompletionProjection(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "paperboat.sock")
	now := time.Now().UTC()
	completion := CompletionSnapshot{Schema: CompletionSchemaV1, ObservedAt: now, Items: []CompletionItem{{Kind: "machine", Value: "studio", Description: "Studio - ready", EnvironmentID: "environment_1"}, {Kind: "session", Value: "shell", Description: "shell - running", EnvironmentID: "environment_1"}}}
	server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), Completions: completionSourceFunc(func(context.Context) (CompletionSnapshot, error) { return completion, nil })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, _ := NewClient(socket, time.Second)
	got, err := client.Completions(context.Background())
	if err != nil || len(got.Items) != 2 || got.Items[1].Value != "shell" {
		t.Fatalf("completion=%#v err=%v", got, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIDiagnosticOperationsUseSeparateAuthorization(t *testing.T) {
	now := time.Now().UTC()
	event, _ := diagnostics.NewEvent(now, "daemon", "lifecycle", "info", map[string]string{"state": "ready"})
	service := &diagnosticServiceFake{snapshot: DiagnosticSnapshot{Schema: DiagnosticSnapshotSchemaV1, ObservedAt: now, Recent: []diagnostics.Event{event}}, bundle: diagnostics.Bundle{Schema: diagnostics.BundleSchemaV1, Correlation: "pb-0123456789abcdef0123456789abcdef", CreatedAt: now, Path: "/tmp/bugreport.zip", Bytes: 100, Categories: []string{"manifest", "recent_events", "redacted_events", "status"}}}
	server, err := NewServer(ServerConfig{SocketPath: filepath.Join(localAPITestDir(t), "api.sock"), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), Diagnostics: service, AuthorizeDiagnostics: func(peer Peer) bool { return peer.PID == 42 }})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/diagnostics", "/v1/diagnostics/bugreport-marker", "/v1/bugreports"} {
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid(), PID: 41}))
		recorder := httptest.NewRecorder()
		server.handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("path=%s status=%d", path, recorder.Code)
		}
	}
	peerCtx := context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid(), PID: 42})
	request := httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil).WithContext(peerCtx)
	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("diagnostics status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	markerBody := `{"schema":"paperboat.bugreport-marker/v1","phase":"start"}`
	request = httptest.NewRequest(http.MethodPost, "/v1/diagnostics/bugreport-marker", strings.NewReader(markerBody)).WithContext(peerCtx)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.marker != "start" {
		t.Fatalf("marker status=%d marker=%q body=%s", recorder.Code, service.marker, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/bugreports", nil).WithContext(peerCtx)
	recorder = httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), service.bundle.Correlation) {
		t.Fatalf("bundle status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestLocalAPIPublishesStrictOwnerTransportObservations(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "paperboat.sock")
	var mu sync.Mutex
	var received TransportObservation
	server, err := NewServer(ServerConfig{
		SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		Observations: observationSinkFunc(func(_ context.Context, peer Peer, observation TransportObservation) error {
			if peer.UID != os.Geteuid() || peer.PID <= 0 {
				return ErrPermission
			}
			mu.Lock()
			received = observation
			mu.Unlock()
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	client, _ := NewClient(socket, time.Second)
	now := time.Now().UTC()
	observation := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "relay", RelayRegion: "bom", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if err := client.PublishTransportObservation(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := received
	mu.Unlock()
	if got.SourceID != observation.SourceID || got.Sequence != 1 || got.SelectedPath != "relay" || got.RelayRegion != "bom" {
		t.Fatalf("observation=%#v", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIRejectsInvalidAndStaleTransportObservations(t *testing.T) {
	server, err := NewServer(ServerConfig{
		SocketPath: filepath.Join(localAPITestDir(t), "api.sock"), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(),
		Source:       snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }),
		Observations: observationSinkFunc(func(context.Context, Peer, TransportObservation) error { return ErrStaleObservation }),
	})
	if err != nil {
		t.Fatal(err)
	}
	peerCtx := context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid(), GID: os.Getegid(), PID: os.Getpid()})
	now := time.Now().UTC()
	valid := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "direct", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	body, _ := json.Marshal(valid)
	request := httptest.NewRequest(http.MethodPost, "/v1/observations/transport", bytes.NewReader(body)).WithContext(peerCtx)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, test := range []struct {
		method, contentType, body string
	}{
		{http.MethodGet, "application/json", string(body)},
		{http.MethodPost, "text/plain", string(body)},
		{http.MethodPost, "application/json", `{"schema":"paperboat.transport-observation/v1"}`},
		{http.MethodPost, "application/json", string(body[:len(body)-1]) + `,"unknown":true}`},
	} {
		request = httptest.NewRequest(test.method, "/v1/observations/transport", strings.NewReader(test.body)).WithContext(peerCtx)
		request.Header.Set("Content-Type", test.contentType)
		recorder = httptest.NewRecorder()
		server.handler().ServeHTTP(recorder, request)
		if recorder.Code < 400 || recorder.Code >= 500 {
			t.Fatalf("method=%s content=%s status=%d body=%s", test.method, test.contentType, recorder.Code, recorder.Body.String())
		}
	}
}

func TestLocalAPIRejectsUnauthorizedPeerMethodAndBody(t *testing.T) {
	server, err := NewServer(ServerConfig{SocketPath: filepath.Join(localAPITestDir(t), "api.sock"), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil })})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/snapshot", nil).WithContext(context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid() + 1, GID: os.Getegid(), PID: os.Getpid()}))
	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("X-Paperboat-Protocol") != ProtocolV1 {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	for _, test := range []struct {
		method      string
		contentType string
		want        int
	}{
		{http.MethodPost, "", http.StatusMethodNotAllowed},
		{http.MethodGet, "application/json", http.StatusBadRequest},
	} {
		request = httptest.NewRequest(test.method, "/v1/snapshot", nil).WithContext(context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid(), GID: os.Getegid(), PID: os.Getpid()}))
		request.Header.Set("Content-Type", test.contentType)
		recorder = httptest.NewRecorder()
		server.handler().ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Fatalf("method=%s content-type=%q status=%d body=%s", test.method, test.contentType, recorder.Code, recorder.Body.String())
		}
	}
}

func TestLocalAPIRequiresAuthorityBeforeRemovingStaleSocket(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "api.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	newServer := func(stale StaleSocketAuthority) *Server {
		server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), Stale: stale})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	if listener, err := newServer(nil).listen(context.Background()); !errors.Is(err, ErrUnsafeSocket) || listener != nil {
		t.Fatalf("listener=%v err=%v", listener, err)
	}
	server := newServer(staleAuthority(true))
	active, err := server.listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = active.Close()
	_ = os.Remove(socket)
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := server.listen(context.Background()); !errors.Is(err, ErrUnsafeSocket) || listener != nil {
		t.Fatalf("unsafe file listener=%v err=%v", listener, err)
	}
}

func TestLocalAPINeverRemovesReplacementAtSocketPath(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "api.sock")
	server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Timeout: time.Second, Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForSocket(t, socket)
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run err=%v", err)
	}
	value, err := os.ReadFile(socket)
	if err != nil || string(value) != "replacement" {
		t.Fatalf("replacement value=%q err=%v", value, err)
	}

	staleSocket := filepath.Join(root, "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: staleSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	_ = listener.Close()
	staleServer, err := NewServer(ServerConfig{SocketPath: staleSocket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil }), Stale: staleAuthorityFunc(func(context.Context, string) bool {
		_ = os.Remove(staleSocket)
		_ = os.WriteFile(staleSocket, []byte("replacement"), 0o600)
		return true
	})})
	if err != nil {
		t.Fatal(err)
	}
	if active, err := staleServer.listen(context.Background()); !errors.Is(err, ErrUnsafeSocket) || active != nil {
		t.Fatalf("active=%v err=%v", active, err)
	}
	if value, err := os.ReadFile(staleSocket); err != nil || string(value) != "replacement" {
		t.Fatalf("stale replacement value=%q err=%v", value, err)
	}
}

func TestLocalAPIClientRejectsUnknownFieldsAndVersion(t *testing.T) {
	unknown := `{"schema":"paperboat.status/v1","generation":1,"observed_at":"2026-08-04T01:02:03Z","daemon_state":"ready","machines":[],"unknown":true}`
	valid := `{"schema":"paperboat.status/v1","generation":1,"observed_at":"2026-08-04T01:02:03Z","daemon_state":"ready","machines":[]}`
	for name, response := range map[string]string{
		"unknown field": rawHTTPResponse(ProtocolV1, unknown),
		"wrong version": rawHTTPResponse("paperboat.local-api/v2", valid),
	} {
		t.Run(name, func(t *testing.T) {
			socket := filepath.Join(localAPITestDir(t), "api.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				connection, acceptErr := listener.Accept()
				if acceptErr == nil {
					buffer := make([]byte, 4096)
					_, _ = connection.Read(buffer)
					_, _ = connection.Write([]byte(response))
					_ = connection.Close()
				}
			}()
			client, _ := NewClient(socket, time.Second)
			_, err = client.Snapshot(context.Background())
			if name == "wrong version" {
				if !errors.Is(err, ErrVersionMismatch) {
					t.Fatalf("err=%v", err)
				}
			} else if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestLocalAPIWatchStreamsSnapshotFirstAndFutureGenerations(t *testing.T) {
	root := localAPITestDir(t)
	socket := filepath.Join(root, "api.sock")
	initial := validSnapshot()
	store, err := NewSnapshotStore(&initial)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: store, Timeout: time.Second, WatchDuration: time.Minute, MaxWatchEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	waitForSocket(t, socket)
	client, _ := NewClient(socket, 2*time.Second)
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	updates, watchErrors := client.Watch(watchCtx, 0)
	first := <-updates
	if first.Generation != initial.Generation {
		t.Fatalf("first generation=%d", first.Generation)
	}
	next := validSnapshot()
	next.Generation++
	next.DaemonState = "degraded"
	if _, err := store.Publish(next); err != nil {
		t.Fatal(err)
	}
	second := <-updates
	if second.Generation != next.Generation || second.DaemonState != "degraded" {
		t.Fatalf("second=%#v", second)
	}
	cancelWatch()
	select {
	case err := <-watchErrors:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("watch err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not stop after cancellation")
	}
	stopServer()
	if err := <-serverDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestLocalAPIWatchRejectsInvalidCursorAndDuplicateEvents(t *testing.T) {
	server, err := NewServer(ServerConfig{SocketPath: filepath.Join(localAPITestDir(t), "api.sock"), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshotSourceFunc(func(context.Context) (Snapshot, error) { return validSnapshot(), nil })})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/v1/watch", "/v1/watch?after=x", "/v1/watch?after=1&extra=2"} {
		request := httptest.NewRequest(http.MethodGet, target, nil).WithContext(context.WithValue(context.Background(), peerContextKey{}, Peer{UID: os.Geteuid(), GID: os.Getegid(), PID: os.Getpid()}))
		request.Header.Set("Accept", "application/x-ndjson")
		recorder := httptest.NewRecorder()
		server.handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("target=%q status=%d body=%s", target, recorder.Code, recorder.Body.String())
		}
	}

	snapshot := validSnapshot()
	event, _ := json.Marshal(StatusEvent{Schema: StatusEventSchemaV1, Snapshot: snapshot})
	body := string(event) + "\n" + string(event) + "\n"
	socket := filepath.Join(localAPITestDir(t), "watch.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			buffer := make([]byte, 4096)
			_, _ = connection.Read(buffer)
			response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nX-Paperboat-Protocol: %s\r\nContent-Length: %d\r\n\r\n%s", ProtocolV1, len(body), body)
			_, _ = connection.Write([]byte(response))
			_ = connection.Close()
		}
	}()
	client, _ := NewClient(socket, time.Second)
	updates, failures := client.Watch(context.Background(), 0)
	if first := <-updates; first.Generation != snapshot.Generation {
		t.Fatalf("first=%#v", first)
	}
	if err := <-failures; !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err=%v", err)
	}
}

func rawHTTPResponse(protocolVersion, body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Paperboat-Protocol: %s\r\nContent-Length: %d\r\n\r\n%s", protocolVersion, len(body), body)
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("local API socket was not created")
		}
		time.Sleep(time.Millisecond)
	}
}

func localAPITestDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "pb-la-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}
