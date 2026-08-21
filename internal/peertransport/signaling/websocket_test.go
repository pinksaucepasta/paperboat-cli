package signaling

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWebSocketTransportUsesExactAuthenticatedBinaryProtocol(t *testing.T) {
	serverMessages := make(chan []byte, 2)
	server := signalingTLSServer(t, func(connection *websocket.Conn) {
		messageType, raw, err := connection.Read(context.Background())
		if err == nil && messageType == websocket.MessageBinary {
			serverMessages <- append([]byte(nil), raw...)
			_ = connection.Write(context.Background(), websocket.MessageBinary, []byte("remote"))
			// Keep the peer alive for the client's normal close handshake. An
			// immediate CloseNow is surfaced by Winsock as an aborted connection.
			_, _, _ = connection.Read(context.Background())
		}
	})
	defer server.Close()
	transport, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: testWebSocketCredential, TLS: testTLSConfig(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.Send(context.Background(), []byte("local")); err != nil {
		t.Fatal(err)
	}
	if got := string(<-serverMessages); got != "local" {
		t.Fatalf("server message=%q", got)
	}
	raw, err := transport.Receive(context.Background())
	if err != nil || string(raw) != "remote" {
		t.Fatalf("message=%q error=%v", raw, err)
	}
	raw[0] = 'x'
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketTransportSerializesConcurrentSends(t *testing.T) {
	const count = 20
	received := make(chan string, count)
	server := signalingTLSServer(t, func(connection *websocket.Conn) {
		for range count {
			messageType, raw, err := connection.Read(context.Background())
			if err != nil || messageType != websocket.MessageBinary {
				return
			}
			received <- string(raw)
		}
	})
	defer server.Close()
	transport, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: testWebSocketCredential, TLS: testTLSConfig(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_ = transport.Send(context.Background(), []byte{byte(index), byte(index)})
		}(index)
	}
	wait.Wait()
	for range count {
		value := []byte(<-received)
		if len(value) != 2 || value[0] != value[1] {
			t.Fatalf("interleaved=%v", value)
		}
	}
}

func TestWebSocketTransportRejectsUnsafeDialAndProtocol(t *testing.T) {
	for _, config := range []WebSocketConfig{
		{},
		{URL: "ws://example.test/v1/peer-signaling", Credential: testWebSocketCredential},
		{URL: "wss://user@example.test/v1/peer-signaling", Credential: testWebSocketCredential},
		{URL: "wss://example.test/v1/peer-signaling?token=value", Credential: testWebSocketCredential},
		{URL: "wss://example.test/v1/peer-signaling", Credential: " credential"},
		{URL: "wss://example.test/v1/peer-signaling", Credential: testWebSocketCredential, TLS: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	} {
		if _, err := DialWebSocket(context.Background(), config); !errors.Is(err, ErrTransportInvalid) {
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
	server := signalingTLSServer(t, func(*websocket.Conn) {})
	defer server.Close()
	if _, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: "header.wrong.signature", TLS: testTLSConfig(t, server)}); !errors.Is(err, ErrTransportAuthentication) {
		t.Fatalf("wrong bearer credential error=%v", err)
	}
	if _, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: testWebSocketCredential}); !errors.Is(err, ErrTransportCertificate) {
		t.Fatalf("untrusted certificate error=%v", err)
	}
}

func TestWebSocketTransportClassifiesAvailabilityWithoutDowngradingProtocol(t *testing.T) {
	for status, want := range map[int]error{http.StatusTooManyRequests: ErrTransportUnavailable, http.StatusServiceUnavailable: ErrTransportUnavailable, http.StatusNotFound: ErrTransportProtocol} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { http.Error(writer, http.StatusText(status), status) }))
		_, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: testWebSocketCredential, TLS: testTLSConfig(t, server)})
		server.Close()
		if !errors.Is(err, want) {
			t.Errorf("status %d: error=%v, want %v", status, err, want)
		}
	}
}

func TestWebSocketTransportRejectsTextAndCloseInterruptsReceive(t *testing.T) {
	server := signalingTLSServer(t, func(connection *websocket.Conn) {
		_ = connection.Write(context.Background(), websocket.MessageText, []byte("text"))
		<-time.After(time.Second)
	})
	defer server.Close()
	transport, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(server.URL), Credential: testWebSocketCredential, TLS: testTLSConfig(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Receive(context.Background()); !errors.Is(err, ErrTransportProtocol) {
		t.Fatalf("text error=%v", err)
	}
	_ = transport.Close()

	blockedServer := signalingTLSServer(t, func(connection *websocket.Conn) { <-time.After(time.Second) })
	defer blockedServer.Close()
	blocked, err := DialWebSocket(context.Background(), WebSocketConfig{URL: websocketURL(blockedServer.URL), Credential: testWebSocketCredential, TLS: testTLSConfig(t, blockedServer)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, receiveErr := blocked.Receive(context.Background()); done <- receiveErr }()
	if err := blocked.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close returned a successful receive")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt receive")
	}
}

func signalingTLSServer(t *testing.T, run func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testWebSocketCredential || !strings.Contains(request.Header.Get("Sec-WebSocket-Protocol"), WebSocketSubprotocol) {
			http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		run(connection)
	}))
}

func testTLSConfig(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()
	certificate := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
}

func websocketURL(serverURL string) string {
	return "wss" + strings.TrimPrefix(serverURL, "https") + "/v1/peer-signaling"
}

const testWebSocketCredential = "header.payload.signature"
