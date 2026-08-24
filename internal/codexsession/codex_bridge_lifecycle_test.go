package codexsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const (
	testAccountRequestID = "account-secret-id"
	testHooksRequestID   = "hooks-secret-id"
)

type fakeBridgeFrame struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

type fakeBridgeSocket struct {
	reads           chan fakeBridgeFrame
	writes          chan fakeBridgeFrame
	readStarted     chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
	closeNowOnce    sync.Once
	closeNowStarted chan struct{}
	closeNowRelease chan struct{}
	writeErr        error
	readActive      atomic.Int32
	writeActive     atomic.Int32
	lastWriteLength atomic.Int64
	gracefulCalls   atomic.Int32
	closeNowCalls   atomic.Int32
}

func newFakeBridgeSocket() *fakeBridgeSocket {
	return &fakeBridgeSocket{
		reads: make(chan fakeBridgeFrame, 8), writes: make(chan fakeBridgeFrame, 8),
		readStarted: make(chan struct{}, 8), closed: make(chan struct{}),
	}
}

func (s *fakeBridgeSocket) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	s.readActive.Add(1)
	defer s.readActive.Add(-1)
	select {
	case s.readStarted <- struct{}{}:
	default:
	}
	select {
	case frame := <-s.reads:
		var closeErr websocket.CloseError
		if errors.As(frame.err, &closeErr) {
			s.closeOnce.Do(func() { close(s.closed) })
		}
		return frame.typ, append([]byte(nil), frame.data...), frame.err
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-s.closed:
		return 0, nil, errors.New("fake websocket closed")
	}
}

func (s *fakeBridgeSocket) Write(ctx context.Context, typ websocket.MessageType, data []byte) error {
	s.writeActive.Add(1)
	defer s.writeActive.Add(-1)
	copyData := append([]byte(nil), data...)
	s.lastWriteLength.Store(int64(len(copyData)))
	select {
	case s.writes <- fakeBridgeFrame{typ: typ, data: copyData}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return errors.New("fake websocket closed")
	}
	return s.writeErr
}

func (s *fakeBridgeSocket) closeGracefullyWithin(websocket.StatusCode, string, time.Duration) error {
	s.gracefulCalls.Add(1)
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *fakeBridgeSocket) CloseNow() error {
	s.closeNowCalls.Add(1)
	if s.closeNowStarted != nil {
		s.closeNowOnce.Do(func() { close(s.closeNowStarted) })
	}
	if s.closeNowRelease != nil {
		<-s.closeNowRelease
	}
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestCodexBridgeProxySurfacesSanitizedFirstCause(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*fakeBridgeSocket, *fakeBridgeSocket)
		trigger       func(*fakeBridgeSocket, *fakeBridgeSocket) int
		wantStage     string
		wantMethod    string
		wantCause     string
		wantClass     string
		wantCloseCode int
		wantReason    string
		sourceClosed  bool
	}{
		{
			name: "frame type",
			trigger: func(_ *fakeBridgeSocket, remote *fakeBridgeSocket) int {
				body := []byte("binary-secret-frame")
				remote.reads <- fakeBridgeFrame{typ: websocket.MessageBinary, data: body}
				return len(body)
			},
			wantStage: "frame_type", wantMethod: "account/read,hooks/list", wantCause: "non_text_frame", wantClass: "none",
		},
		{
			name: "codec path field",
			trigger: func(_ *fakeBridgeSocket, remote *fakeBridgeSocket) int {
				body := []byte(`{"jsonrpc":"2.0","id":"hooks-secret-id","result":{"data":[{"cwd":"D:\\outside\\codec-secret"}]}}`)
				remote.reads <- fakeBridgeFrame{typ: websocket.MessageText, data: body}
				return len(body)
			},
			wantStage: "codec", wantMethod: "hooks/list", wantCause: "codec_rejected", wantClass: "path_field",
		},
		{
			name: "destination write",
			configure: func(local, _ *fakeBridgeSocket) {
				local.writeErr = errors.New("write-secret token=/root C:\\private")
			},
			trigger: func(local, remote *fakeBridgeSocket) int {
				body := []byte(`{"jsonrpc":"2.0","id":"hooks-secret-id","result":{"data":[{"cwd":"/root"}]}}`)
				remote.reads <- fakeBridgeFrame{typ: websocket.MessageText, data: body}
				deadline := time.After(2 * time.Second)
				for local.lastWriteLength.Load() == 0 {
					select {
					case <-deadline:
						return 0
					default:
						time.Sleep(time.Millisecond)
					}
				}
				return int(local.lastWriteLength.Load())
			},
			wantStage: "write", wantMethod: "hooks/list", wantCause: "write_failed", wantClass: "none",
		},
		{
			name: "source read",
			trigger: func(_ *fakeBridgeSocket, remote *fakeBridgeSocket) int {
				remote.reads <- fakeBridgeFrame{err: errors.New("read-secret token=/root C:\\private")}
				return 0
			},
			wantStage: "read", wantMethod: "account/read,hooks/list", wantCause: "read_failed", wantClass: "none",
		},
		{
			name: "remote close",
			trigger: func(_ *fakeBridgeSocket, remote *fakeBridgeSocket) int {
				remote.reads <- fakeBridgeFrame{err: websocket.CloseError{Code: websocket.StatusInternalError, Reason: "close-secret token=/root"}}
				return 0
			},
			wantStage: "read", wantMethod: "account/read,hooks/list", wantCause: "websocket_close", wantClass: "none",
			wantCloseCode: int(websocket.StatusInternalError), wantReason: "redacted", sourceClosed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local := newFakeBridgeSocket()
			remote := newFakeBridgeSocket()
			if test.configure != nil {
				test.configure(local, remote)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			codec := mustTestCodexPathCodecConfig(t).newCodec()
			go func() { result <- proxy(ctx, local, remote, codec) }()

			queuePendingCodexRequests(t, ctx, local, remote, codec.config)
			frameLength := test.trigger(local, remote)
			var proxyErr error
			select {
			case proxyErr = <-result:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if proxyErr == nil {
				t.Fatal("proxy returned nil")
			}
			got := proxyErr.Error()
			for _, want := range []string{
				"direction=server_to_client",
				"stage=" + test.wantStage,
				"method=" + test.wantMethod,
				"frame_length=" + strconv.Itoa(frameLength),
				"cause=" + test.wantCause,
				"codec_class=" + test.wantClass,
				"close_code=" + strconv.Itoa(test.wantCloseCode),
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("error %q does not contain %q", got, want)
				}
			}
			wantReason := test.wantReason
			if wantReason == "" {
				wantReason = "none"
			}
			if !strings.Contains(got, "close_reason="+wantReason) {
				t.Fatalf("error %q has wrong close reason", got)
			}
			assertSanitizedCodexBridgeError(t, got)
			assertFakeBridgeStopped(t, local, remote)
			if local.closeNowCalls.Load() == 0 || !test.sourceClosed && remote.closeNowCalls.Load() == 0 || test.sourceClosed && remote.closeNowCalls.Load() != 0 {
				t.Fatalf("error shutdown closeNow calls local=%d remote=%d", local.closeNowCalls.Load(), remote.closeNowCalls.Load())
			}
		})
	}
}

func TestCodexBridgeProxyNormalCloseAndCancellationAreClean(t *testing.T) {
	t.Run("normal close", func(t *testing.T) {
		local := newFakeBridgeSocket()
		remote := newFakeBridgeSocket()
		remote.reads <- fakeBridgeFrame{err: websocket.CloseError{Code: websocket.StatusNormalClosure, Reason: "normal"}}
		if err := proxy(context.Background(), local, remote, nil); err != nil {
			t.Fatal(err)
		}
		assertFakeBridgeStopped(t, local, remote)
		if local.gracefulCalls.Load() != 1 || remote.gracefulCalls.Load() != 0 || local.closeNowCalls.Load() != 0 || remote.closeNowCalls.Load() != 0 {
			t.Fatalf("normal shutdown graceful=%d/%d closeNow=%d/%d", local.gracefulCalls.Load(), remote.gracefulCalls.Load(), local.closeNowCalls.Load(), remote.closeNowCalls.Load())
		}
	})

	for _, status := range []websocket.StatusCode{websocket.StatusNormalClosure, websocket.StatusGoingAway} {
		t.Run("pending "+strconv.Itoa(int(status)), func(t *testing.T) {
			local := newFakeBridgeSocket()
			remote := newFakeBridgeSocket()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			codec := mustTestCodexPathCodecConfig(t).newCodec()
			go func() { result <- proxy(ctx, local, remote, codec) }()
			queuePendingCodexRequests(t, ctx, local, remote, codec.config)
			remote.reads <- fakeBridgeFrame{err: websocket.CloseError{Code: status, Reason: "normal"}}
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "method=account/read,hooks/list") || !strings.Contains(err.Error(), "cause=websocket_close") || !strings.Contains(err.Error(), "close_code="+strconv.Itoa(int(status))) {
					t.Fatalf("pending close error = %v", err)
				}
				assertSanitizedCodexBridgeError(t, err.Error())
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			assertFakeBridgeStopped(t, local, remote)
			if local.closeNowCalls.Load() != 1 || remote.closeNowCalls.Load() != 0 || local.gracefulCalls.Load() != 0 {
				t.Fatalf("pending close shutdown graceful=%d closeNow=%d/%d", local.gracefulCalls.Load(), local.closeNowCalls.Load(), remote.closeNowCalls.Load())
			}
		})
	}

	t.Run("context cancellation", func(t *testing.T) {
		local := newFakeBridgeSocket()
		remote := newFakeBridgeSocket()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- proxy(ctx, local, remote, nil) }()
		awaitFakeRead(t, local)
		awaitFakeRead(t, remote)
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("proxy did not stop after cancellation")
		}
		assertFakeBridgeStopped(t, local, remote)
		if local.gracefulCalls.Load() != 0 || remote.gracefulCalls.Load() != 0 || local.closeNowCalls.Load() != 1 || remote.closeNowCalls.Load() != 1 {
			t.Fatalf("canceled shutdown graceful=%d/%d closeNow=%d/%d", local.gracefulCalls.Load(), remote.gracefulCalls.Load(), local.closeNowCalls.Load(), remote.closeNowCalls.Load())
		}
	})
}

func TestCodexBridgeProxyPreservesFailureWhenParentCancelsDuringTeardown(t *testing.T) {
	local := newFakeBridgeSocket()
	remote := newFakeBridgeSocket()
	local.closeNowStarted = make(chan struct{})
	local.closeNowRelease = make(chan struct{})
	parent, cancelParent := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- proxy(parent, local, remote, nil) }()
	remote.reads <- fakeBridgeFrame{err: errors.New("fixed-read-secret")}
	select {
	case <-local.closeNowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not begin teardown")
	}
	cancelParent()
	close(local.closeNowRelease)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "direction=server_to_client") || !strings.Contains(err.Error(), "stage=read") || !strings.Contains(err.Error(), "cause=read_failed") || strings.Contains(err.Error(), "fixed-read-secret") {
			t.Fatalf("proxy error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish teardown")
	}
	assertFakeBridgeStopped(t, local, remote)
}

func TestFinishCodexRunWaitsForServeAndHandlerFirstCause(t *testing.T) {
	bridge := newBridge(nil, "", "", "", nil, nil)
	bridgeCanceled := make(chan struct{})
	go func() {
		<-bridgeCanceled
		bridge.handlerStarted()
		close(bridge.serveDone)
		time.Sleep(20 * time.Millisecond)
		bridge.recordTermination(newBridgeTermination("server_to_client", "read", "hooks/list", 0, "read_failed", errors.New("must not leak")))
		bridge.handlerFinished()
	}()
	childErr := errors.New("child-error-must-lose")
	err := finishCodexRun(context.Background(), childErr, bridge, func() { close(bridgeCanceled) }, time.Second)
	if err == nil || !strings.Contains(err.Error(), "method=hooks/list") || strings.Contains(err.Error(), childErr.Error()) {
		t.Fatalf("finish error = %v", err)
	}
}

func TestFinishCodexRunCancelsAndJoinsHijackedHandler(t *testing.T) {
	remoteReady := make(chan error, 1)
	releaseRemote := make(chan struct{})
	remoteDone := make(chan struct{})
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer remote-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer close(remoteDone)
		defer connection.CloseNow()
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		typ, body, err := connection.Read(readCtx)
		if err != nil || typ != websocket.MessageText || string(body) != "ready" {
			remoteReady <- fmt.Errorf("remote ready frame type=%v body=%q err=%v", typ, body, err)
			return
		}
		remoteReady <- nil
		<-releaseRemote
	}))
	defer func() {
		select {
		case <-releaseRemote:
		default:
			close(releaseRemote)
		}
		remoteServer.Close()
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := newBridge(listener, "bridge-token", websocketURL(remoteServer.URL), "remote-token", remoteServer.Client(), nil)
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	go bridge.serve(bridgeCtx)

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()
	client, _, err := websocket.Dial(clientCtx, "ws://"+listener.Addr().String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer bridge-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(clientCtx, websocket.MessageText, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-remoteReady:
		if err != nil {
			t.Fatal(err)
		}
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}

	childErr := errors.New("child exited")
	started := time.Now()
	if err := finishCodexRun(context.Background(), childErr, bridge, bridgeCancel, 750*time.Millisecond); !errors.Is(err, childErr) {
		t.Fatalf("finish error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 700*time.Millisecond {
		t.Fatalf("blocking-peer bridge shutdown took %v", elapsed)
	}
	close(releaseRemote)
	for label, done := range map[string]<-chan struct{}{"remote": remoteDone, "serve": bridge.serveDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s side did not stop", label)
		}
	}
	bridge.mu.Lock()
	activeHandlers := bridge.activeHandlers
	connections := len(bridge.connections)
	bridge.mu.Unlock()
	if activeHandlers != 0 || connections != 0 {
		t.Fatalf("bridge leaked handlers=%d connections=%d", activeHandlers, connections)
	}
}

func TestBridgePropagatesIncomingCleanClose(t *testing.T) {
	for _, status := range []websocket.StatusCode{websocket.StatusNormalClosure, websocket.StatusGoingAway} {
		t.Run(strconv.Itoa(int(status)), func(t *testing.T) {
			testBridgePropagatesIncomingCleanClose(t, status)
		})
	}
}

func testBridgePropagatesIncomingCleanClose(t *testing.T, status websocket.StatusCode) {
	t.Helper()
	remoteCloseResult := make(chan error, 1)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			remoteCloseResult <- err
			return
		}
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		typ, body, err := connection.Read(readCtx)
		if err != nil || typ != websocket.MessageText || string(body) != "ready" {
			remoteCloseResult <- fmt.Errorf("remote ready frame type=%v body=%q err=%v", typ, body, err)
			return
		}
		remoteCloseResult <- connection.Close(status, "normal")
	}))
	defer remoteServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := newBridge(listener, "bridge-token", websocketURL(remoteServer.URL), "remote-token", remoteServer.Client(), nil)
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	go bridge.serve(bridgeCtx)

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()
	client, _, err := websocket.Dial(clientCtx, "ws://"+listener.Addr().String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer bridge-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(clientCtx, websocket.MessageText, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	_, _, readErr := client.Read(clientCtx)
	if got := websocket.CloseStatus(readErr); got != status {
		t.Fatalf("local close status=%v want=%v err=%v", got, status, readErr)
	}
	select {
	case err := <-remoteCloseResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}
	if err := finishCodexRun(context.Background(), nil, bridge, bridgeCancel, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeIncomingNormalCloseWithBlockingOppositePeerIsBounded(t *testing.T) {
	remoteCloseResult := make(chan error, 1)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			remoteCloseResult <- err
			return
		}
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		typ, body, err := connection.Read(readCtx)
		if err != nil || typ != websocket.MessageText || string(body) != "ready" {
			remoteCloseResult <- fmt.Errorf("remote ready frame type=%v body=%q err=%v", typ, body, err)
			return
		}
		remoteCloseResult <- connection.Close(websocket.StatusNormalClosure, "normal")
	}))
	defer remoteServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := newBridge(listener, "bridge-token", websocketURL(remoteServer.URL), "remote-token", remoteServer.Client(), nil)
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	go bridge.serve(bridgeCtx)
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()
	client, _, err := websocket.Dial(clientCtx, "ws://"+listener.Addr().String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer bridge-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	started := time.Now()
	if err := client.Write(clientCtx, websocket.MessageText, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-remoteCloseResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}
	waitForBridgeHandlersToStop(t, bridge, time.Second)
	if elapsed := time.Since(started); elapsed >= 700*time.Millisecond {
		t.Fatalf("bounded normal-close shutdown took %v", elapsed)
	}
	if err := finishCodexRun(context.Background(), nil, bridge, bridgeCancel, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeRemoteDialCancellationIsClean(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		t.Run(strconv.Itoa(attempt), func(t *testing.T) {
			remoteDialStarted := make(chan struct{})
			var startedOnce sync.Once
			remoteClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				startedOnce.Do(func() { close(remoteDialStarted) })
				<-request.Context().Done()
				return nil, request.Context().Err()
			})}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			bridge := newBridge(listener, "bridge-token", "ws://remote.invalid", "remote-token", remoteClient, nil)
			bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
			go bridge.serve(bridgeCtx)
			clientCtx, clientCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer clientCancel()
			client, _, err := websocket.Dial(clientCtx, "ws://"+listener.Addr().String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer bridge-token"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseNow()
			select {
			case <-remoteDialStarted:
			case <-clientCtx.Done():
				t.Fatal(clientCtx.Err())
			}
			childErr := errors.New("child exited")
			if err := finishCodexRun(context.Background(), childErr, bridge, bridgeCancel, time.Second); !errors.Is(err, childErr) {
				t.Fatalf("finish error = %v", err)
			}
			if bridge.err() != nil {
				t.Fatalf("bridge recorded shutdown dial cancellation: %v", bridge.err())
			}
		})
	}
}

func TestBridgeRemoteDialFailureWinsConcurrentShutdown(t *testing.T) {
	failureReady := make(chan struct{})
	returnFailure := make(chan struct{})
	remoteClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(failureReady)
		<-returnFailure
		return nil, errors.New("fixed-dial-secret")
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := newBridge(listener, "bridge-token", "ws://remote.invalid", "remote-token", remoteClient, nil)
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	go bridge.serve(bridgeCtx)
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer clientCancel()
	client, _, err := websocket.Dial(clientCtx, "ws://"+listener.Addr().String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer bridge-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	select {
	case <-failureReady:
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}
	canceled := make(chan struct{})
	finishResult := make(chan error, 1)
	go func() {
		finishResult <- finishCodexRun(context.Background(), errors.New("child exited"), bridge, func() {
			bridgeCancel()
			close(canceled)
		}, time.Second)
	}()
	select {
	case <-canceled:
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}
	close(returnFailure)
	select {
	case err := <-finishResult:
		if err == nil || !strings.Contains(err.Error(), "stage=remote_dial") || !strings.Contains(err.Error(), "cause=dial_failed") || strings.Contains(err.Error(), "fixed-dial-secret") {
			t.Fatalf("finish error = %v", err)
		}
	case <-clientCtx.Done():
		t.Fatal(clientCtx.Err())
	}
}

func TestBridgeServePreservesUnexpectedErrorDuringCancellation(t *testing.T) {
	serveErr := &gatedServeError{checking: make(chan struct{}), release: make(chan struct{})}
	listener := &singleErrorListener{err: serveErr}
	bridge := newBridge(listener, "bridge-token", "ws://remote.invalid", "remote-token", http.DefaultClient, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go bridge.serve(ctx)
	select {
	case <-serveErr.checking:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve error classification did not start")
	}
	cancel()
	close(serveErr.release)
	select {
	case <-bridge.serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	err := bridge.err()
	if err == nil || !strings.Contains(err.Error(), "stage=serve") || !strings.Contains(err.Error(), "cause=serve_failed") || strings.Contains(err.Error(), "fixed-serve-secret") {
		t.Fatalf("bridge error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type gatedServeError struct {
	checking chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (*gatedServeError) Error() string { return "fixed-serve-secret" }

func (e *gatedServeError) Is(target error) bool {
	if target == net.ErrClosed {
		e.once.Do(func() { close(e.checking) })
		<-e.release
	}
	return false
}

type singleErrorListener struct {
	err error
}

func (l *singleErrorListener) Accept() (net.Conn, error) { return nil, l.err }
func (*singleErrorListener) Close() error                { return nil }
func (*singleErrorListener) Addr() net.Addr              { return staticTestAddr("bridge") }

type staticTestAddr string

func (a staticTestAddr) Network() string { return string(a) }
func (a staticTestAddr) String() string  { return string(a) }

func TestFinishCodexRunJoinsAcceptedPreHandlerConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridge := newBridge(listener, "bridge-token", "ws://unused.invalid", "remote-token", http.DefaultClient, nil)
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	go bridge.serve(bridgeCtx)
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitForTrackedBridgeConnection(t, bridge)

	childErr := errors.New("child exited")
	if err := finishCodexRun(context.Background(), childErr, bridge, bridgeCancel, time.Second); !errors.Is(err, childErr) {
		t.Fatalf("finish error = %v", err)
	}
	bridge.mu.Lock()
	connections := len(bridge.connections)
	bridge.mu.Unlock()
	if connections != 0 {
		t.Fatalf("bridge leaked %d pre-handler connections", connections)
	}
}

func TestFinishCodexRunHandlerWaitIsBoundedAndCancellationWins(t *testing.T) {
	t.Run("stuck handler", func(t *testing.T) {
		bridge := newBridge(nil, "", "", "", nil, nil)
		close(bridge.serveDone)
		bridge.handlerStarted()
		childErr := errors.New("child failed")
		started := time.Now()
		err := finishCodexRun(context.Background(), childErr, bridge, func() {}, 20*time.Millisecond)
		bridge.handlerFinished()
		if err == nil || !strings.Contains(err.Error(), "stage=shutdown") || !strings.Contains(err.Error(), "cause=shutdown_timeout") || strings.Contains(err.Error(), childErr.Error()) {
			t.Fatalf("finish error = %v", err)
		}
		if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > time.Second {
			t.Fatalf("handler wait = %v", elapsed)
		}
	})

	t.Run("stuck connection without child error", func(t *testing.T) {
		bridge := newBridge(nil, "", "", "", nil, nil)
		close(bridge.serveDone)
		tracked, peer := net.Pipe()
		defer tracked.Close()
		defer peer.Close()
		bridge.connectionStateChanged(tracked, http.StateNew)
		err := finishCodexRun(context.Background(), nil, bridge, func() {}, 20*time.Millisecond)
		bridge.connectionStateChanged(tracked, http.StateClosed)
		if err == nil || !strings.Contains(err.Error(), "stage=shutdown") || !strings.Contains(err.Error(), "cause=shutdown_timeout") {
			t.Fatalf("finish error = %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		bridge := newBridge(nil, "", "", "", nil, nil)
		close(bridge.serveDone)
		bridge.recordTermination(newBridgeTermination("server_to_client", "read", "account/read", 0, "read_failed", errors.New("must not leak")))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := finishCodexRun(ctx, errors.New("child failed"), bridge, func() {}, time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("finish error = %v", err)
		}
	})
}

func TestCodexCodecFailureClassesAreFixedAndAllowlisted(t *testing.T) {
	for _, class := range []codexCodecFailureClass{
		codexCodecFailureEnvelope,
		codexCodecFailureUnknownMethod,
		codexCodecFailureCorrelation,
		codexCodecFailurePathField,
		codexCodecFailureEncode,
	} {
		t.Run(string(class), func(t *testing.T) {
			got := codexCodecFailureClassOf(newCodexCodecFailure(class, errors.New("secret detail")))
			if got != string(class) {
				t.Fatalf("class = %q", got)
			}
		})
	}
	if got := codexCodecFailureClassOf(errors.New("untyped secret")); got != string(codexCodecFailureEnvelope) {
		t.Fatalf("fallback class = %q", got)
	}
}

func queuePendingCodexRequests(t *testing.T, ctx context.Context, local, remote *fakeBridgeSocket, config *codexPathCodecConfig) {
	t.Helper()
	requests := [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":"account-secret-id","method":"account/read","params":{"secret":"DO_NOT_LOG_TOKEN"}}`),
		[]byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":"hooks-secret-id","method":"hooks/list","params":{"cwds":[%q],"secret":"DO_NOT_LOG_TOKEN"}}`, config.remoteToLocal("/root/private"))),
	}
	for _, request := range requests {
		local.reads <- fakeBridgeFrame{typ: websocket.MessageText, data: request}
	}
	for range requests {
		select {
		case <-remote.writes:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func assertSanitizedCodexBridgeError(t *testing.T, value string) {
	t.Helper()
	for _, forbidden := range []string{
		testAccountRequestID,
		testHooksRequestID,
		"DO_NOT_LOG_TOKEN",
		"binary-secret-frame",
		"codec-secret",
		"write-secret",
		"read-secret",
		"close-secret",
		"/root/private",
		`D:\outside`,
		`C:\private`,
		`/result/data`,
		`{"jsonrpc"`,
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("bridge error leaked %q: %q", forbidden, value)
		}
	}
}

func assertFakeBridgeStopped(t *testing.T, sockets ...*fakeBridgeSocket) {
	t.Helper()
	for index, socket := range sockets {
		if socket.readActive.Load() != 0 || socket.writeActive.Load() != 0 {
			t.Fatalf("socket %d active reads=%d writes=%d", index, socket.readActive.Load(), socket.writeActive.Load())
		}
	}
}

func awaitFakeRead(t *testing.T, socket *fakeBridgeSocket) {
	t.Helper()
	select {
	case <-socket.readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("fake websocket read did not start")
	}
}

func waitForTrackedBridgeConnection(t *testing.T, bridge *bridge) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		bridge.mu.Lock()
		connections := len(bridge.connections)
		changed := bridge.stateChanged
		bridge.mu.Unlock()
		if connections != 0 {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("bridge did not track accepted connection")
		}
	}
}

func waitForBridgeHandlersToStop(t *testing.T, bridge *bridge, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		bridge.mu.Lock()
		active := bridge.activeHandlers
		changed := bridge.stateChanged
		bridge.mu.Unlock()
		if active == 0 {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("bridge handler did not stop")
		}
	}
}
