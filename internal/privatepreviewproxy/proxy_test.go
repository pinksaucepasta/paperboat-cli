package privatepreviewproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
)

func TestProxyPreflightsAndForwardsFreshTCPConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	proxy, err := Start(ctx, Config{Dial: func(context.Context) (io.ReadWriteCloser, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go serveOneHTTP(server)
		return client, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if dials.Load() != 1 {
		t.Fatalf("preflight dials=%d", dials.Load())
	}
	for index := range 2 {
		response, err := http.Get(proxy.URL + "/stream")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "first\nsecond\n" {
			t.Fatalf("request %d body=%q err=%v", index, body, err)
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("dials=%d, want preflight plus one fresh stream", dials.Load())
	}
}

func TestProxyCancellationClosesListenerAndActiveStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	remoteClosed := make(chan struct{})
	proxy, err := Start(ctx, Config{Dial: func(context.Context) (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
			close(remoteClosed)
		}()
		return client, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp4", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-remoteClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("active remote stream was not closed")
	}
	_ = connection.Close()
	if err := proxy.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp4", strings.TrimPrefix(proxy.URL, "http://"), 100*time.Millisecond); err == nil {
		t.Fatal("loopback listener remained reachable")
	}
}

func TestProxyCarriesWebSocketThroughHostLoopbackProtocol(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, acceptErr := websocket.Accept(writer, request, nil)
		if acceptErr != nil {
			return
		}
		defer connection.CloseNow()
		kind, payload, readErr := connection.Read(request.Context())
		if readErr == nil {
			_ = connection.Write(request.Context(), kind, append([]byte("echo:"), payload...))
		}
	})}
	go targetServer.Serve(target)
	defer targetServer.Close()
	targetPort := uint16(target.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy, err := Start(ctx, Config{Dial: func(ctx context.Context) (io.ReadWriteCloser, error) {
		client, host := net.Pipe()
		go peerpreview.Serve(ctx, host, (&net.Dialer{}).DialContext)
		if openErr := peerpreview.Open(ctx, client, targetPort); openErr != nil {
			_ = client.Close()
			return nil, openErr
		}
		return client, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(proxy.URL, "http")+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, websocket.MessageBinary, []byte("canary")); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || string(payload) != "echo:canary" {
		t.Fatalf("kind=%v payload=%q err=%v", kind, payload, err)
	}
}

func serveOneHTTP(connection net.Conn) {
	defer connection.Close()
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		return
	}
	_ = request.Body.Close()
	_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nfirst\n")
	time.Sleep(10 * time.Millisecond)
	_, _ = io.WriteString(connection, "second\n")
}
