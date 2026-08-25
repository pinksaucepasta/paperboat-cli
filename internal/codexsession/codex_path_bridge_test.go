package codexsession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestCodexPathProxyTransformsBothDirectionsAndRejectsBinary(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	remoteFrames := make(chan []byte, 1)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		typ, body, err := conn.Read(ctx)
		if err != nil || typ != websocket.MessageText {
			return
		}
		remoteFrames <- body
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"jsonrpc":"2.0","id":1,"result":{"cwd":"/root"}}`))
		_, _, _ = conn.Read(ctx)
	}))
	defer remoteServer.Close()

	proxyErrors := make(chan error, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		remote, _, err := websocket.Dial(r.Context(), websocketURL(remoteServer.URL), nil)
		if err != nil {
			_ = local.Close(websocket.StatusInternalError, "remote unavailable")
			return
		}
		proxyErrors <- proxy(r.Context(), local, remote, config.newCodec())
	}))
	defer proxyServer.Close()

	client, _, err := websocket.Dial(ctx, websocketURL(proxyServer.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	request := `{"jsonrpc":"2.0","id":1,"method":"thread/start","params":{"cwd":"` + jsonEscape(config.remoteToLocal("/root")) + `"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(request)); err != nil {
		t.Fatal(err)
	}
	remote := decodeTestJSON(t, <-remoteFrames)
	assertJSONPointerString(t, remote, []string{"params", "cwd"}, "/root")
	typ, body, err := client.Read(ctx)
	if err != nil || typ != websocket.MessageText {
		t.Fatalf("read transformed response: type=%v err=%v", typ, err)
	}
	response := decodeTestJSON(t, body)
	assertJSONPointerString(t, response, []string{"result", "cwd"}, config.remoteToLocal("/root"))

	if err := client.Write(ctx, websocket.MessageBinary, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	_, _, _ = client.Read(ctx)
	select {
	case proxyErr := <-proxyErrors:
		if proxyErr == nil || !strings.Contains(proxyErr.Error(), "stage=frame_type") || !strings.Contains(proxyErr.Error(), "cause=non_text_frame") {
			t.Fatalf("proxy error = %v", proxyErr)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func websocketURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
