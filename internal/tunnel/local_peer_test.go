package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type localPeerRemote struct {
	net.Conn
	mu             sync.Mutex
	rows, cols     uint16
	closeOnWait    bool
	runtimeVersion string
}

func (c *localPeerRemote) Resize(rows, cols uint16) error {
	c.mu.Lock()
	c.rows, c.cols = rows, cols
	c.mu.Unlock()
	return nil
}
func (c *localPeerRemote) Wait() (int, error) {
	if c.closeOnWait {
		_ = c.Conn.Close()
	}
	return 7, nil
}
func (c *localPeerRemote) CloseWrite() error              { return nil }
func (c *localPeerRemote) TerminalRuntimeVersion() string { return c.runtimeVersion }

type localPeerExecRemote struct {
	*localPeerRemote
	events              chan ExecEvent
	cancelled, detached bool
	signal              string
}

type recordingOwnedLease struct{ calls int }

func (l *recordingOwnedLease) Release() { l.calls++ }

type blockingOwnedConn struct {
	*localPeerRemote
	started chan struct{}
	release chan struct{}
}

func (c *blockingOwnedConn) Close() error {
	close(c.started)
	<-c.release
	return nil
}

type cancelBlockedOwnedConn struct {
	*localPeerRemote
	canceled <-chan struct{}
}

func (c *cancelBlockedOwnedConn) Close() error {
	<-c.canceled
	return nil
}

func TestOwnedPeerCloseCancelsBlockedCarrierBeforeClosingApplication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lease := &recordingOwnedLease{}
	connection := &ownedPeerTerminalConn{
		Conn:   &cancelBlockedOwnedConn{localPeerRemote: &localPeerRemote{}, canceled: ctx.Done()},
		cancel: cancel,
		lease:  lease,
	}
	done := make(chan error, 1)
	go func() { done <- connection.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned close did not cancel blocked application carrier")
	}
	if lease.calls != 1 {
		t.Fatalf("lease releases=%d, want exactly one", lease.calls)
	}
}

func TestOwnedPeerCloseKeepsLeaseUntilApplicationCloseCompletes(t *testing.T) {
	lease := &recordingOwnedLease{}
	connection := &ownedPeerTerminalConn{
		Conn:  &blockingOwnedConn{localPeerRemote: &localPeerRemote{}, started: make(chan struct{}), release: make(chan struct{})},
		lease: lease,
	}
	done := make(chan struct{})
	go func() {
		_ = connection.Close()
		close(done)
	}()
	select {
	case <-connection.Conn.(*blockingOwnedConn).started:
	case <-time.After(time.Second):
		t.Fatal("application close did not start")
	}
	if lease.calls != 0 {
		t.Fatalf("lease releases=%d, want 0 while application close is blocked", lease.calls)
	}
	close(connection.Conn.(*blockingOwnedConn).release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned close did not finish")
	}
	if lease.calls != 1 {
		t.Fatalf("lease releases=%d after close, want exactly once", lease.calls)
	}
}

func TestOwnedExecDetachReleasesLeaseWithoutCancelingOperation(t *testing.T) {
	lease := &recordingOwnedLease{}
	remote := &localPeerExecRemote{localPeerRemote: &localPeerRemote{}}
	connection := &ownedPeerExecConn{ownedPeerTerminalConn: &ownedPeerTerminalConn{Conn: remote, lease: lease}}
	if err := connection.Detach(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Detach(); err != nil {
		t.Fatal(err)
	}
	if lease.calls != 1 || !remote.detached {
		t.Fatalf("lease releases=%d detached=%t", lease.calls, remote.detached)
	}
}

func (c *localPeerExecRemote) Events() <-chan ExecEvent { return c.events }
func (c *localPeerExecRemote) Cancel() error {
	c.mu.Lock()
	c.cancelled = true
	c.mu.Unlock()
	return nil
}
func (c *localPeerExecRemote) Signal(signal string) error {
	c.mu.Lock()
	c.signal = signal
	c.mu.Unlock()
	return nil
}
func (c *localPeerExecRemote) Detach() error {
	c.mu.Lock()
	c.detached = true
	c.mu.Unlock()
	return nil
}

func TestOwnedPeerConnectionExposesExecOnlyForExecConnections(t *testing.T) {
	ordinary := ownPeerConnection(&ownedPeerTerminalConn{Conn: &localPeerRemote{}})
	if _, ok := ordinary.(ExecConn); ok {
		t.Fatal("ordinary owned peer connection exposed exec controls")
	}
	exec := ownPeerConnection(&ownedPeerTerminalConn{Conn: &localPeerExecRemote{localPeerRemote: &localPeerRemote{}}})
	if _, ok := exec.(ExecConn); !ok {
		t.Fatal("owned exec connection did not expose exec controls")
	}
}

func TestOwnedAndLocalPeerConnectionsPreserveRuntimeVersion(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &localPeerRemote{Conn: remoteServer, runtimeVersion: "2026.08.27.65"}
	owned := &ownedPeerTerminalConn{Conn: remote}
	if got := TerminalRuntimeVersion(owned); got != "2026.08.27.65" {
		t.Fatalf("owned runtime version=%q", got)
	}
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerDebugConn(context.Background(), localServer, owned) }()
	connection, err := newLocalPeerDebugConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	if got := TerminalRuntimeVersion(connection); got != "2026.08.27.65" {
		t.Fatalf("local runtime version=%q", got)
	}
	_ = connection.Close()
	_ = remotePeer.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local peer server did not stop")
	}
}

func TestLocalPeerDebugConnPreservesFirstFrameFromDaemonWithoutMetadata(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- ServeLocalPeerConn(context.Background(), localServer, &localPeerRemote{Conn: remoteServer})
	}()
	go func() { _, _ = remotePeer.Write([]byte("banner")) }()
	connection, err := newLocalPeerDebugConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	if got := TerminalRuntimeVersion(connection); got != "" {
		t.Fatalf("runtime version=%q", got)
	}
	buffer := make([]byte, len("banner"))
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "banner" {
		t.Fatalf("first frame=%q err=%v", buffer, err)
	}
	_ = connection.Close()
	_ = remotePeer.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local peer server did not stop")
	}
}

func TestLocalPeerConnPreservesDataResizeAndWait(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &localPeerRemote{Conn: remoteServer}
	remote.closeOnWait = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerConn(ctx, localServer, remote) }()
	connection, err := NewLocalPeerConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := connection.(ExecConn); ok {
		t.Fatal("ordinary local connection exposed exec controls")
	}
	defer connection.Close()
	defer remotePeer.Close()
	if _, err := connection.Write([]byte("input")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := remotePeer.Read(buffer); err != nil || string(buffer) != "input" {
		t.Fatalf("input=%q err=%v", buffer, err)
	}
	go func() { _, _ = remotePeer.Write([]byte("output")) }()
	buffer = make([]byte, 6)
	if _, err := connection.Read(buffer); err != nil || string(buffer) != "output" {
		t.Fatalf("output=%q err=%v", buffer, err)
	}
	if err := connection.Resize(24, 80); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		remote.mu.Lock()
		rows, cols := remote.rows, remote.cols
		remote.mu.Unlock()
		if rows == 24 && cols == 80 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	remote.mu.Lock()
	rows, cols := remote.rows, remote.cols
	remote.mu.Unlock()
	if rows != 24 || cols != 80 {
		t.Fatalf("resize=%dx%d", rows, cols)
	}
	if code, err := connection.Wait(); err != nil || code != 7 {
		t.Fatalf("wait=%d err=%v", code, err)
	}
	_ = connection.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local peer server did not stop")
	}
}

type blockingWaitRemote struct {
	*localPeerRemote
	release chan struct{}
}

type blockingWaitExecRemote struct {
	*localPeerExecRemote
	release chan struct{}
}

func (r *blockingWaitExecRemote) Wait() (int, error) {
	<-r.release
	return 0, nil
}

func (r *blockingWaitRemote) Wait() (int, error) {
	<-r.release
	_ = r.Conn.Close()
	return 0, nil
}

func TestServeLocalPeerConnWaitDoesNotBlockControlFrames(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &blockingWaitRemote{localPeerRemote: &localPeerRemote{Conn: remoteServer}, release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerConn(ctx, localServer, remote) }()
	connection, err := NewLocalPeerConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer remotePeer.Close()

	waitDone := make(chan struct{})
	go func() {
		_, _ = connection.Wait()
		close(waitDone)
	}()
	if err := connection.Resize(31, 101); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("input-after-wait")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("input-after-wait"))
	if _, err := io.ReadFull(remotePeer, buffer); err != nil || string(buffer) != "input-after-wait" {
		t.Fatalf("input=%q err=%v", buffer, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		remote.mu.Lock()
		rows, cols := remote.rows, remote.cols
		remote.mu.Unlock()
		if rows == 31 && cols == 101 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	remote.mu.Lock()
	rows, cols := remote.rows, remote.cols
	remote.mu.Unlock()
	if rows != 31 || cols != 101 {
		t.Fatalf("resize=%dx%d", rows, cols)
	}
	close(remote.release)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait did not complete")
	}
	_ = connection.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local peer server did not stop")
	}
}

func TestLocalExecPeerConnPreservesEventsAndControls(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &localPeerExecRemote{localPeerRemote: &localPeerRemote{Conn: remoteServer}, events: make(chan ExecEvent, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerConn(ctx, localServer, remote) }()
	connection, err := NewLocalExecPeerConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer remotePeer.Close()
	remote.events <- ExecEvent{OperationID: "operation_1", EventSequence: 1, Stream: "stderr", Data: []byte("failure")}
	select {
	case event := <-connection.Events():
		if event.OperationID != "operation_1" || event.Stream != "stderr" || string(event.Data) != "failure" {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("exec event timed out")
	}
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Signal("TERM"); err != nil {
		t.Fatal(err)
	}
	if err := connection.Detach(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		remote.mu.Lock()
		ready := remote.cancelled && remote.detached && remote.signal == "TERM"
		remote.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	remote.mu.Lock()
	cancelled, detached, signal := remote.cancelled, remote.detached, remote.signal
	remote.mu.Unlock()
	if !cancelled || !detached || signal != "TERM" {
		t.Fatalf("cancelled=%t detached=%t signal=%q", cancelled, detached, signal)
	}
	_ = connection.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local exec server did not stop")
	}
}

func TestLocalExecPeerConnWaitSurvivesRemoteEOFAfterTerminalEvent(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &localPeerExecRemote{localPeerRemote: &localPeerRemote{Conn: remoteServer}, events: make(chan ExecEvent, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerConn(ctx, localServer, remote) }()
	connection, err := NewLocalExecPeerConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	remote.events <- ExecEvent{OperationID: "operation_1", Stream: "stdout", Data: []byte("out")}
	remote.events <- ExecEvent{OperationID: "operation_1", Stream: "stderr", Data: []byte("err")}
	remote.events <- ExecEvent{OperationID: "operation_1", State: "exited", Result: &ExecResult{Code: 7}}
	want := []ExecEvent{{Stream: "stdout", Data: []byte("out")}, {Stream: "stderr", Data: []byte("err")}, {State: "exited", Result: &ExecResult{Code: 7}}}
	for _, expected := range want {
		select {
		case event := <-connection.Events():
			if event.Stream != expected.Stream || event.State != expected.State || string(event.Data) != string(expected.Data) || expected.Result != nil && (event.Result == nil || event.Result.Code != expected.Result.Code) {
				t.Fatalf("event=%+v expected=%+v", event, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("exec event timed out")
		}
	}
	_ = remotePeer.Close()
	if code, err := connection.Wait(); err != nil || code != 7 {
		t.Fatalf("wait=%d err=%v", code, err)
	}
	_ = connection.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("local exec server did not stop")
	}
}

func TestLocalExecPeerConnFailsWhenEventsCloseWithoutTerminalOutcome(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remotePeer := net.Pipe()
	remote := &blockingWaitExecRemote{
		localPeerExecRemote: &localPeerExecRemote{localPeerRemote: &localPeerRemote{Conn: remoteServer}, events: make(chan ExecEvent)},
		release:             make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeLocalPeerConn(ctx, localServer, remote) }()
	connection, err := NewLocalExecPeerConn(localClient)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer remotePeer.Close()

	close(remote.events)
	select {
	case _, ok := <-connection.Events():
		if ok {
			t.Fatal("events remained open after remote event stream closed")
		}
	case <-time.After(time.Second):
		t.Fatal("events did not close")
	}
	waitDone := make(chan error, 1)
	go func() {
		_, waitErr := connection.Wait()
		waitDone <- waitErr
	}()
	select {
	case waitErr := <-waitDone:
		if !errors.Is(waitErr, ErrTransportLost) {
			t.Fatalf("wait error=%v, want transport loss", waitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("wait blocked after remote event stream closed")
	}
	select {
	case serveErr := <-served:
		if !errors.Is(serveErr, ErrTransportLost) {
			t.Fatalf("serve error=%v, want transport loss", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after remote event stream closed")
	}
}
