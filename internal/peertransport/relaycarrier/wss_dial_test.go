package relaycarrier

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/wsscarrier"
)

func TestDialWSSAuthenticatesAttachmentAndBuildsBoundedMux(t *testing.T) {
	var handle [16]byte
	copy(handle[:], []byte("stream-handle-001"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/peer-relay" || r.Header.Get("Authorization") != "Bearer route.token.signature" || r.Header.Get("X-Paperboat-Stream-Handle") != base64.RawURLEncoding.EncodeToString(handle[:]) || r.Header.Get("X-Paperboat-Endpoint-Id") != "endpoint_cli" || r.Header.Get("X-Paperboat-Relay-Role") != "initiator" {
			t.Errorf("headers=%v path=%s", r.Header, r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{relayWSSSubprotocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		carrier, err := wsscarrier.New(r.Context(), connection, wsscarrier.Config{RelayID: "relay-test", MaximumDeadline: time.Minute})
		if err != nil {
			t.Error(err)
			return
		}
		mux, err := NewWSSServer(carrier, DevelopmentConfig())
		if err != nil {
			t.Error(err)
			return
		}
		defer mux.Close()
		stream, err := mux.AcceptStream(r.Context())
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(stream, stream)
	}))
	defer server.Close()
	client, err := DialWSS(context.Background(), WSSDialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v1/peer-relay", Credential: "route.token.signature", StreamHandle: handle, EndpointID: "endpoint_cli", Role: "initiator", RelayID: "relay-test", TLS: &tls.Config{MinVersion: tls.VersionTLS13}, HTTPClient: server.Client(), MaximumDeadline: time.Minute, Carrier: DevelopmentConfig()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := client.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("paperboat")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len("paperboat"))
	if _, err := io.ReadFull(stream, payload); err != nil || string(payload) != "paperboat" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
}

func TestDialWSSRejectsCredentialAndAttachmentSubstitution(t *testing.T) {
	base := WSSDialConfig{URL: "wss://relay.example.test/v1/peer-relay", Credential: "route.token.signature", StreamHandle: [16]byte{1}, EndpointID: "endpoint_cli", Role: "initiator", RelayID: "relay-test", TLS: &tls.Config{MinVersion: tls.VersionTLS13}, MaximumDeadline: time.Minute, Carrier: DevelopmentConfig()}
	for name, mutate := range map[string]func(*WSSDialConfig){
		"path":       func(value *WSSDialConfig) { value.URL = "wss://relay.example.test/other" },
		"credential": func(value *WSSDialConfig) { value.Credential = "not a token" },
		"handle":     func(value *WSSDialConfig) { value.StreamHandle = [16]byte{} },
		"endpoint":   func(value *WSSDialConfig) { value.EndpointID = "other endpoint" },
		"role":       func(value *WSSDialConfig) { value.Role = "host" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := DialWSS(context.Background(), value); err == nil {
				t.Fatal("invalid WSS attachment was accepted")
			}
		})
	}
}
