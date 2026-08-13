package directpath

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pion/ice/v4"
)

func TestNegotiateOverAuthenticatedTLSWebSockets(t *testing.T) {
	broker := newTestSignalingBroker()
	server := httptest.NewTLSServer(broker)
	defer server.Close()
	tlsConfig := testSignalingTLS(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	leftTransport, err := signaling.DialWebSocket(ctx, signaling.WebSocketConfig{URL: testSignalingURL(server.URL), Credential: testLeftCredential, TLS: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	rightTransport, err := signaling.DialWebSocket(ctx, signaling.WebSocketConfig{URL: testSignalingURL(server.URL), Credential: testRightCredential, TLS: tlsConfig})
	if err != nil {
		_ = leftTransport.Close()
		t.Fatal(err)
	}
	leftConfig := assemblyConfig("ufragA1", "pppppppppppppppppppppp", []byte("websocket-key-012345678901234567"))
	rightConfig := assemblyConfig("ufragB1", "qqqqqqqqqqqqqqqqqqqqqq", []byte("websocket-key-012345678901234567"))
	leftConfig.AttemptGeneration, leftConfig.NetworkGeneration = 2, 4
	rightConfig.AttemptGeneration, rightConfig.NetworkGeneration = 2, 4
	left, err := Open(ctx, leftConfig)
	if err != nil {
		_ = leftTransport.Close()
		_ = rightTransport.Close()
		t.Fatal(err)
	}
	right, err := Open(ctx, rightConfig)
	if err != nil {
		_ = left.Close()
		_ = leftTransport.Close()
		_ = rightTransport.Close()
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	leftBinding := signaling.Binding{IntentID: "intent_websocket", AttemptGeneration: 2, NetworkGeneration: 4, Role: signaling.RoleControlling}
	rightBinding := signaling.Binding{IntentID: "intent_websocket", AttemptGeneration: 2, NetworkGeneration: 4, Role: signaling.RoleControlled}
	type outcome struct {
		role       string
		connection *ice.Conn
		err        error
	}
	results := make(chan outcome, 2)
	go func() {
		connection, negotiateErr := Negotiate(ctx, NegotiationConfig{Assembly: left, Transport: leftTransport, LocalBinding: leftBinding, RemoteBinding: rightBinding, LocalUfrag: "ufragA1", LocalPassword: "pppppppppppppppppppppp"})
		results <- outcome{role: "left", connection: connection, err: negotiateErr}
	}()
	go func() {
		connection, negotiateErr := Negotiate(ctx, NegotiationConfig{Assembly: right, Transport: rightTransport, LocalBinding: rightBinding, RemoteBinding: leftBinding, LocalUfrag: "ufragB1", LocalPassword: "qqqqqqqqqqqqqqqqqqqqqq"})
		results <- outcome{role: "right", connection: connection, err: negotiateErr}
	}()
	connections := make(map[string]*ice.Conn, 2)
	for range 2 {
		result := <-results
		if result.connection != nil {
			defer result.connection.Close()
		}
		if result.err != nil || result.connection == nil || result.connection.RemoteAddr() == nil {
			t.Fatalf("connection=%v error=%v", result.connection, result.err)
		}
		connections[result.role] = result.connection
	}
	for _, exchange := range []struct {
		from, to string
		payload  string
	}{{"left", "right", "left-to-right"}, {"right", "left", "right-to-left"}} {
		if err := connections[exchange.to].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := connections[exchange.from].Write([]byte(exchange.payload)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 64)
		n, err := connections[exchange.to].Read(buffer)
		if err != nil || string(buffer[:n]) != exchange.payload {
			t.Fatalf("exchange=%s->%s payload=%q error=%v", exchange.from, exchange.to, buffer[:n], err)
		}
	}
}

type testSignalingBroker struct {
	inbox map[string]chan []byte
}

func newTestSignalingBroker() *testSignalingBroker {
	return &testSignalingBroker{inbox: map[string]chan []byte{"left": make(chan []byte, 256), "right": make(chan []byte, 256)}}
}

func (b *testSignalingBroker) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	role := ""
	switch request.Header.Get("Authorization") {
	case "Bearer " + testLeftCredential:
		role = "left"
	case "Bearer " + testRightCredential:
		role = "right"
	default:
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{signaling.WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	connection.SetReadLimit(signaling.MaximumMessage)
	defer connection.CloseNow()
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	peer := "left"
	if role == "left" {
		peer = "right"
	}
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			messageType, raw, readErr := connection.Read(ctx)
			if readErr != nil || messageType != websocket.MessageBinary {
				return
			}
			select {
			case b.inbox[peer] <- append([]byte(nil), raw...):
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case raw := <-b.inbox[role]:
				if connection.Write(ctx, websocket.MessageBinary, raw) != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	<-done
	cancel()
	_ = connection.CloseNow()
	<-done
}

func testSignalingTLS(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
}

func testSignalingURL(serverURL string) string {
	return "wss" + strings.TrimPrefix(serverURL, "https") + "/v1/peer-signaling"
}

const (
	testLeftCredential  = "left.payload.signature"
	testRightCredential = "right.payload.signature"
)
