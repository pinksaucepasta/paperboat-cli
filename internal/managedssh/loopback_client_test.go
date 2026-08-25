package managedssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type loopbackTestProcess struct {
	done         chan error
	waitReturned chan struct{}
	completeOnce sync.Once
	kill         func()
	waitCalls    atomic.Int32
	killCalls    atomic.Int32
}

func newLoopbackTestProcess() *loopbackTestProcess {
	return &loopbackTestProcess{done: make(chan error, 1), waitReturned: make(chan struct{})}
}

func (p *loopbackTestProcess) complete(err error) {
	p.completeOnce.Do(func() { p.done <- err })
}

func (p *loopbackTestProcess) Wait() error {
	p.waitCalls.Add(1)
	err := <-p.done
	close(p.waitReturned)
	return err
}

func (p *loopbackTestProcess) Kill() error {
	p.killCalls.Add(1)
	if p.kill != nil {
		p.kill()
	}
	p.complete(errors.New("test process killed"))
	return nil
}

func (*loopbackTestProcess) PID() uint32 { return 4242 }

func allowLoopbackTestOwner(context.Context, *net.TCPConn, uint32) error { return nil }

type loopbackTestStream struct {
	closed    chan struct{}
	closeOnce sync.Once
	writeErr  error
	writeSeen chan struct{}
	writeOnce sync.Once
	writeMu   sync.Mutex
	written   bytes.Buffer
	closeHits atomic.Int32
}

func newLoopbackTestStream() *loopbackTestStream {
	return &loopbackTestStream{closed: make(chan struct{})}
}

func (s *loopbackTestStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *loopbackTestStream) Write(value []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writeMu.Lock()
	_, _ = s.written.Write(value)
	s.writeMu.Unlock()
	if s.writeSeen != nil {
		s.writeOnce.Do(func() { close(s.writeSeen) })
	}
	return len(value), nil
}

func (*loopbackTestStream) CloseWrite() error { return nil }

func (s *loopbackTestStream) Close() error {
	s.closeHits.Add(1)
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestRunOneShotSSHLoopbackReturnsExactOutputAndExit(t *testing.T) {
	peer, remote := tcpConnectionPair(t)
	defer remote.Close()
	const request = "ssh-request"
	const response = "VICTUS_PB_SSH_OK"
	remoteDone := make(chan error, 1)
	go func() {
		body, err := io.ReadAll(remote)
		if err == nil && string(body) != request {
			err = errors.New("remote request mismatch")
		}
		if err == nil {
			_, err = io.WriteString(remote, response)
		}
		if closeErr := remote.CloseWrite(); err == nil {
			err = closeErr
		}
		remoteDone <- err
	}()
	process := newLoopbackTestProcess()
	var output bytes.Buffer
	err := runOneShotSSHLoopback(t.Context(), peer, time.Second, time.Second, func(port uint16) (loopbackSSHProcess, error) {
		connection, dialErr := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if dialErr != nil {
			return nil, dialErr
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		process.kill = func() { _ = connection.Close() }
		go func() {
			_, processErr := io.WriteString(connection, request)
			if closeErr := connection.CloseWrite(); processErr == nil {
				processErr = closeErr
			}
			if processErr == nil {
				_, processErr = io.Copy(&output, connection)
			}
			_ = connection.Close()
			process.complete(processErr)
		}()
		return process, nil
	}, allowLoopbackTestOwner)
	if err != nil {
		t.Fatalf("runOneShotSSHLoopback() error=%v", err)
	}
	if err := <-remoteDone; err != nil {
		t.Fatalf("remote error=%v", err)
	}
	if got := output.String(); got != response {
		t.Fatalf("output=%q want %q", got, response)
	}
	if process.waitCalls.Load() != 1 || process.killCalls.Load() != 0 {
		t.Fatalf("wait calls=%d kill calls=%d", process.waitCalls.Load(), process.killCalls.Load())
	}
	select {
	case <-process.waitReturned:
	default:
		t.Fatal("process was not reaped")
	}
}

func TestRunOneShotSSHLoopbackProcessExitBeforeAcceptCleansUp(t *testing.T) {
	stream := newLoopbackTestStream()
	process := newLoopbackTestProcess()
	process.complete(nil)
	err := runOneShotSSHLoopback(t.Context(), stream, time.Second, time.Second, func(uint16) (loopbackSSHProcess, error) {
		return process, nil
	}, allowLoopbackTestOwner)
	if !errors.Is(err, ErrSSHLoopbackProcessExited) {
		t.Fatalf("error=%v", err)
	}
	if process.waitCalls.Load() != 1 || process.killCalls.Load() != 0 {
		t.Fatalf("wait calls=%d kill calls=%d", process.waitCalls.Load(), process.killCalls.Load())
	}
	if stream.closeHits.Load() == 0 {
		t.Fatal("peer stream was not closed")
	}
}

func TestRunOneShotSSHLoopbackCancellationKillsAndReapsBeforeAccept(t *testing.T) {
	stream := newLoopbackTestStream()
	process := newLoopbackTestProcess()
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runOneShotSSHLoopback(ctx, stream, time.Second, time.Second, func(uint16) (loopbackSSHProcess, error) {
			close(started)
			return process, nil
		}, allowLoopbackTestOwner)
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	assertLoopbackProcessStopped(t, process)
}

func TestRunOneShotSSHLoopbackClosesListenerAfterFirstAccept(t *testing.T) {
	stream := newLoopbackTestStream()
	stream.writeSeen = make(chan struct{})
	process := newLoopbackTestProcess()
	portReady := make(chan uint16, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runOneShotSSHLoopback(ctx, stream, time.Second, time.Second, func(port uint16) (loopbackSSHProcess, error) {
			connection, dialErr := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if dialErr != nil {
				return nil, dialErr
			}
			process.kill = func() { _ = connection.Close() }
			portReady <- port
			go func() { _, _ = io.WriteString(connection, "owner") }()
			return process, nil
		}, allowLoopbackTestOwner)
	}()
	port := <-portReady
	<-stream.writeSeen
	second, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 100*time.Millisecond)
	if err == nil {
		_ = second.Close()
		t.Fatal("one-shot listener accepted a second connection")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	stream.writeMu.Lock()
	written := stream.written.String()
	stream.writeMu.Unlock()
	if written != "owner" {
		t.Fatalf("peer bytes=%q", written)
	}
	assertLoopbackProcessStopped(t, process)
}

func TestRunOneShotSSHLoopbackOwnerPIDMismatchFailsClosed(t *testing.T) {
	stream := newLoopbackTestStream()
	process := newLoopbackTestProcess()
	sentinel := errors.New("socket belongs to another process")
	err := runOneShotSSHLoopback(t.Context(), stream, time.Second, time.Second, func(port uint16) (loopbackSSHProcess, error) {
		connection, dialErr := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if dialErr != nil {
			return nil, dialErr
		}
		process.kill = func() { _ = connection.Close() }
		return process, nil
	}, func(_ context.Context, _ *net.TCPConn, pid uint32) error {
		if pid != process.PID() {
			t.Fatalf("validator pid=%d want %d", pid, process.PID())
		}
		return sentinel
	})
	if !errors.Is(err, ErrSSHLoopbackOwner) || !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	if stream.closeHits.Load() == 0 || stream.written.Len() != 0 {
		t.Fatalf("authenticated stream close hits=%d bytes=%d", stream.closeHits.Load(), stream.written.Len())
	}
	assertLoopbackProcessStopped(t, process)
}

func TestRunOneShotSSHLoopbackAcceptTimeoutKillsAndReaps(t *testing.T) {
	stream := newLoopbackTestStream()
	process := newLoopbackTestProcess()
	err := runOneShotSSHLoopback(t.Context(), stream, 20*time.Millisecond, time.Second, func(uint16) (loopbackSSHProcess, error) {
		return process, nil
	}, allowLoopbackTestOwner)
	if !errors.Is(err, ErrSSHLoopbackAccept) {
		t.Fatalf("error=%v", err)
	}
	assertLoopbackProcessStopped(t, process)
}

func TestRunOneShotSSHLoopbackBridgeFailureKillsAndReaps(t *testing.T) {
	sentinel := errors.New("peer write failed")
	stream := newLoopbackTestStream()
	stream.writeErr = sentinel
	process := newLoopbackTestProcess()
	err := runOneShotSSHLoopback(t.Context(), stream, time.Second, time.Second, func(port uint16) (loopbackSSHProcess, error) {
		connection, dialErr := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if dialErr != nil {
			return nil, dialErr
		}
		process.kill = func() { _ = connection.Close() }
		go func() {
			_, _ = io.WriteString(connection, "trigger bridge")
			<-process.waitReturned
			_ = connection.Close()
		}()
		return process, nil
	}, allowLoopbackTestOwner)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	assertLoopbackProcessStopped(t, process)
}

func assertLoopbackProcessStopped(t *testing.T, process *loopbackTestProcess) {
	t.Helper()
	if process.waitCalls.Load() != 1 || process.killCalls.Load() != 1 {
		t.Fatalf("wait calls=%d kill calls=%d", process.waitCalls.Load(), process.killCalls.Load())
	}
	select {
	case <-process.waitReturned:
	default:
		t.Fatal("process was not reaped")
	}
}

func tcpConnectionPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	return client, server
}
