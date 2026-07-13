package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

func TestPapercodeWSTunnelAttachIOResizeAndExit(t *testing.T) {
	requests := make(chan rpcRequestSeen, 8)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/project/ws" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("wsTicket"); got != "pct_test" {
			t.Errorf("unexpected wsTicket %q", got)
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer ws.Close()
		waitingForAttachAck := false
		for {
			var req rpcRequestSeen
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			if req.Type == rpcAckTagValue {
				if req.RequestID != "1" {
					t.Errorf("unexpected stream acknowledgement: %#v", req)
					return
				}
				if waitingForAttachAck {
					waitingForAttachAck = false
					sendChunk(t, ws, 1, terminalEvent{Type: "output", Data: "world"})
				}
				continue
			}
			requests <- req
			switch req.Tag {
			case rpcTerminalAttach:
				sendChunk(t, ws, 1, terminalEvent{Type: "output", Data: "hello "})
				waitingForAttachAck = true
			case rpcTerminalResize:
				code := 7
				sendChunk(t, ws, 1, terminalEvent{Type: "exited", ExitCode: &code})
			}
		}
	}))
	defer server.Close()

	target := testTerminalTarget(server.URL)
	conn, err := NewPapercodeWSTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	attach := <-requests
	if attach.Type != "Request" || attach.Tag != rpcTerminalAttach {
		t.Fatalf("first request = %#v", attach)
	}
	if attach.Payload["threadId"] != "paperboat-cli" || attach.Payload["terminalId"] != "term-1" {
		t.Fatalf("bad attach payload: %#v", attach.Payload)
	}
	if attach.Payload["restartIfNotRunning"] != true || attach.Payload["cwd"] != "/workspace" {
		t.Fatalf("bad attach payload: %#v", attach.Payload)
	}
	if _, ok := attach.Payload["env"]; ok {
		t.Fatalf("unexpected attach env: %#v", attach.Payload["env"])
	}

	buf := make([]byte, 3)
	var got strings.Builder
	for got.Len() < len("hello world") {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		got.Write(buf[:n])
	}
	if got.String() != "hello world" {
		t.Fatalf("output = %q", got.String())
	}

	if _, err := conn.Write([]byte("printf hi\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	write := <-requests
	if write.Tag != rpcTerminalWrite || write.Payload["data"] != "printf hi\n" {
		t.Fatalf("bad write request: %#v", write)
	}

	if err := conn.Resize(40, 120); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	resize := <-requests
	if resize.Tag != rpcTerminalResize || resize.Payload["rows"] != float64(40) || resize.Payload["cols"] != float64(120) {
		t.Fatalf("bad resize request: %#v", resize)
	}

	code, err := conn.Wait()
	if err != nil {
		t.Fatalf("Wait error: %v", err)
	}
	if code != 7 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestPapercodeWSTunnelCheckRejectsHandshakeWithoutRPC(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := NewPapercodeWSTunnel().Check(ctx, testTerminalTarget(server.URL))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Check error = %v", err)
	}
}

func TestPapercodeWSTunnelCheckUsesNonAttachingMetadataProbe(t *testing.T) {
	requests := make(chan rpcRequestSeen, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		var req rpcRequestSeen
		if err := ws.ReadJSON(&req); err != nil {
			return
		}
		requests <- req
		sendChunk(t, ws, 1, terminalEvent{Type: terminalEventSnapshot})
		var ack rpcRequestSeen
		_ = ws.ReadJSON(&ack)
	}))
	defer server.Close()
	if err := NewPapercodeWSTunnel().Check(context.Background(), testTerminalTarget(server.URL)); err != nil {
		t.Fatal(err)
	}
	req := <-requests
	if req.Tag != rpcSubscribeTerminalMetadata {
		t.Fatalf("doctor probe sent %q, want %q", req.Tag, rpcSubscribeTerminalMetadata)
	}
}

func TestPapercodeWebSocketRequest(t *testing.T) {
	target := &resolver.TerminalTarget{
		WebSocketBaseURL: "wss://example.test/project",
		Auth:             resolver.AuthTarget{Method: "websocket_ticket", Ticket: "pct_1"},
	}
	got, headers, err := papercodeWebSocketRequest(target)
	if err != nil {
		t.Fatal(err)
	}
	if headers.Get("Authorization") != "" {
		t.Fatalf("unexpected auth header")
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/project/ws" || u.Query().Get("wsTicket") != "pct_1" {
		t.Fatalf("bad URL %s", got)
	}
}

func TestPapercodeWSConnHandlesSnapshotHistory(t *testing.T) {
	c := &papercodeWSConn{out: make(chan []byte, 1), done: make(chan struct{})}
	c.handleTerminalEvent(terminalEvent{
		Type: "snapshot",
		Snapshot: terminalSnapshot{
			Status:  "running",
			History: "previous output\r\n",
		},
	})

	buf := make([]byte, len("previous output\r\n"))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "previous output\r\n" {
		t.Fatalf("history = %q", string(buf[:n]))
	}
	select {
	case <-c.done:
		t.Fatal("running snapshot should not finish session")
	default:
	}
}

func TestPapercodeWSConnCanSuppressReconnectHistory(t *testing.T) {
	sequence := 0
	snapshotSequence := 9
	c := &papercodeWSConn{out: make(chan []byte, 1), done: make(chan struct{}), target: &resolver.TerminalTarget{ReplayHistory: false, SequenceSink: func(value int) { sequence = value }}}
	_ = c.handleTerminalEvent(terminalEvent{Type: terminalEventSnapshot, Snapshot: terminalSnapshot{Status: "running", History: "old output\n", Sequence: &snapshotSequence}})
	select {
	case <-c.out:
		t.Fatal("reconnect snapshot replayed retained history")
	default:
	}
	if sequence != 0 {
		t.Fatalf("suppressed snapshot advanced reconnect cursor to %d", sequence)
	}
}

func TestPapercodeWSConnAdvancesCursorAfterReplayOutputIsQueued(t *testing.T) {
	sequence := 0
	eventSequence := 7
	c := &papercodeWSConn{out: make(chan []byte, 1), done: make(chan struct{}), target: &resolver.TerminalTarget{ReplayHistory: false, SequenceSink: func(value int) { sequence = value }}}
	if err := c.handleTerminalEvent(terminalEvent{Type: terminalEventOutput, Sequence: &eventSequence, Data: "replayed\n"}); err != nil {
		t.Fatal(err)
	}
	if sequence != eventSequence || string(<-c.out) != "replayed\n" {
		t.Fatalf("sequence=%d output queue did not commit replay atomically", sequence)
	}
}

func TestPapercodeWSConnDoesNotAdvanceCursorWhenReplayQueueCloses(t *testing.T) {
	sequence := 0
	eventSequence := 7
	stop := make(chan struct{})
	close(stop)
	c := &papercodeWSConn{out: make(chan []byte), done: make(chan struct{}), keepaliveStop: stop, target: &resolver.TerminalTarget{ReplayHistory: false, SequenceSink: func(value int) { sequence = value }}}
	err := c.handleTerminalEvent(terminalEvent{Type: terminalEventOutput, Sequence: &eventSequence, Data: "lost\n"})
	if !errors.Is(err, ErrTransportLost) || sequence != 0 {
		t.Fatalf("err=%v sequence=%d, want transport loss without cursor advance", err, sequence)
	}
}

func TestPapercodeWSConnResynchronizesFromRestartedSnapshot(t *testing.T) {
	c := &papercodeWSConn{out: make(chan []byte, 2), done: make(chan struct{}), target: &resolver.TerminalTarget{ReplayHistory: false}}
	c.handleTerminalEvent(terminalEvent{Type: terminalEventRestarted, Snapshot: terminalSnapshot{Status: "running", History: "recovered output\n"}})
	first := <-c.out
	second := <-c.out
	if string(first) != "\x1b[2J\x1b[H" || string(second) != "recovered output\n" {
		t.Fatalf("resync output = %q then %q", first, second)
	}
}

func TestPapercodeWSConnHandlesExitedSnapshot(t *testing.T) {
	code := 7
	c := &papercodeWSConn{out: make(chan []byte, 1), done: make(chan struct{})}
	c.handleTerminalEvent(terminalEvent{
		Type: "snapshot",
		Snapshot: terminalSnapshot{
			Status:   "exited",
			History:  "done\r\n",
			ExitCode: &code,
		},
	})

	got, err := c.Wait()
	if err != nil {
		t.Fatalf("Wait error: %v", err)
	}
	if got != 7 {
		t.Fatalf("exit code = %d", got)
	}
	buf := make([]byte, len("done\r\n"))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "done\r\n" {
		t.Fatalf("history = %q", string(buf[:n]))
	}
}

func sendChunk(t *testing.T, ws *websocket.Conn, id int, ev terminalEvent) {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	err = ws.WriteJSON(map[string]any{
		"_tag":      "Chunk",
		"requestId": idString(id),
		"values":    []json.RawMessage{raw},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func idString(id int) string { return strconv.Itoa(id) }

func testTerminalTarget(httpURL string) *resolver.TerminalTarget {
	u, _ := url.Parse(httpURL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/project"
	return &resolver.TerminalTarget{
		WebSocketBaseURL: u.String(),
		Auth:             resolver.AuthTarget{Method: "websocket_ticket", Ticket: "pct_test"},
		ThreadID:         "paperboat-cli",
		TerminalID:       "term-1",
		CWD:              "/workspace",
		ReplayHistory:    true,
	}
}

type rpcRequestSeen struct {
	Type      string         `json:"_tag"`
	RequestID string         `json:"requestId"`
	Tag       string         `json:"tag"`
	Payload   map[string]any `json:"payload"`
	ID        string         `json:"id"`
	Headers   [][2]string    `json:"headers"`
}

func TestPapercodeWSConnReadEOF(t *testing.T) {
	c := &papercodeWSConn{out: make(chan []byte)}
	close(c.out)
	_, err := c.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("err = %v", err)
	}
}

func TestPapercodeWSConnWaitClosed(t *testing.T) {
	c := &papercodeWSConn{done: make(chan struct{})}
	c.finish(0, nil)
	code, err := c.Wait()
	if err != nil || code != 0 {
		t.Fatalf("Wait = %d, %v", code, err)
	}
}

func TestPapercodeWSConnUnexpectedReadFailureSurfacesError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		var req rpcRequestSeen
		if err := ws.ReadJSON(&req); err == nil && req.Tag == rpcTerminalAttach {
			sendChunk(t, ws, 1, terminalEvent{Type: "output", Data: "ready"})
			_ = ws.ReadJSON(&req)
		}
		_ = ws.Close()
	}))
	defer server.Close()

	conn, err := NewPapercodeWSTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: testTerminalTarget(server.URL)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	code, err := conn.Wait()
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(err.Error(), "papercode websocket read failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestPapercodeWSConnLocalCloseDoesNotSurfaceReadError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var destructiveClose atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer ws.Close()
		for {
			var req rpcRequestSeen
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			if req.Tag == rpcTerminalAttach {
				sendChunk(t, ws, 1, terminalEvent{Type: "output", Data: "ready"})
			} else if req.Tag == rpcTerminalClose {
				destructiveClose.Store(true)
			}
		}
	}))
	defer server.Close()

	conn, err := NewPapercodeWSTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: testTerminalTarget(server.URL)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	code, err := conn.Wait()
	if err != nil || code != 0 {
		t.Fatalf("Wait = %d, %v", code, err)
	}
	if destructiveClose.Load() {
		t.Fatal("transport detach sent destructive terminal.close")
	}
}
