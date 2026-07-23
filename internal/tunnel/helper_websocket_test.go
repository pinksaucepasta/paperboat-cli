package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

func TestCanonicalHelperTerminalFramingIOResizeAndExit(t *testing.T) {
	requests := make(chan helperFrame, 12)
	inputs := make(chan []byte, 1)
	upgrader := websocket.Upgrader{Subprotocols: []string{helperWebSocketSubprotocol}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime" || r.Header.Get("Authorization") != "Bearer helper-token" {
			t.Errorf("request path=%q auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.Close()
		for {
			messageType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.BinaryMessage {
				if len(data) < 25 || data[4] != 3 || binary.BigEndian.Uint64(data[5:13]) != 1 {
					t.Errorf("invalid input frame: %x", data)
					return
				}
				sessionLength := int(binary.BigEndian.Uint16(data[13:15]))
				attachmentLength := int(binary.BigEndian.Uint16(data[15:17]))
				generation := binary.BigEndian.Uint64(data[17:25])
				bodyStart := 25 + sessionLength + attachmentLength
				if generation != 1 || string(data[25:25+sessionLength]) != "ses_bound" || string(data[25+sessionLength:bodyStart]) != "att_1" {
					t.Errorf("invalid input binding: %x", data)
					return
				}
				inputs <- append([]byte(nil), data[bodyStart:]...)
				continue
			}
			if messageType != websocket.TextMessage {
				t.Errorf("client message type=%d", messageType)
				return
			}
			frame, err := decodeHelperFrame(data)
			if err != nil {
				t.Error(err)
				return
			}
			requests <- frame
			switch frame.Type {
			case "hello":
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1","terminal.input-stream.v1"]}`)})
			case "ack", "detach":
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{},"replay":false}`)})
			case "request":
				var payload map[string]any
				_ = json.Unmarshal(frame.Payload, &payload)
				switch payload["action"] {
				case "snapshot":
					writeHelperTestFrame(t, ws, helperFrame{Type: "error", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"code":"not_found_or_forbidden","message":"operation failed","retryable":false}`)})
				case "create":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"id":"ses_bound","generation":1},"replay":false}`)})
				case "attach":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"attachment_id":"att_1","session":{"snapshot":{"generation":1}}},"replay":false}`)})
					writeHelperTestBinary(t, ws, 0, []byte("hello"))
				case "resize":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{},"replay":false}`)})
					writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v1", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_bound","state":"exited","final_sequence":5,"exit":{"code":7}}`)})
				}
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v1", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_bound", TerminalID: "default", CWD: "/workspace", Cols: 100, Rows: 30}
	conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buffer := make([]byte, 5)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "hello" {
		t.Fatalf("output=%q err=%v", buffer, err)
	}
	if _, err := conn.Write([]byte("echo hi\n")); err != nil {
		t.Fatal(err)
	}
	if input := <-inputs; string(input) != "echo hi\n" {
		t.Fatalf("input=%q", input)
	}
	if err := conn.Resize(40, 120); err != nil {
		t.Fatal(err)
	}
	if code, err := conn.Wait(); err != nil || code != 7 {
		t.Fatalf("Wait()=%d,%v", code, err)
	}

	var sawCreate, sawAttach, sawAck, sawResize bool
	for len(requests) > 0 {
		frame := <-requests
		var payload map[string]any
		_ = json.Unmarshal(frame.Payload, &payload)
		switch {
		case frame.Type == "ack":
			sawAck = payload["session_id"] == "ses_bound" && payload["attachment_id"] == "att_1" && payload["next_sequence"] == float64(5)
		case payload["action"] == "create":
			sawCreate = payload["session_id"] == "ses_bound" && payload["columns"] == float64(100) && payload["rows"] == float64(30)
		case payload["action"] == "attach":
			sawAttach = payload["session_id"] == "ses_bound"
		case payload["action"] == "resize":
			sawResize = payload["columns"] == float64(120) && payload["rows"] == float64(40)
		}
	}
	if !sawCreate || !sawAttach || !sawAck || !sawResize {
		t.Fatalf("create=%v attach=%v ack=%v resize=%v", sawCreate, sawAttach, sawAck, sawResize)
	}
}

func TestCanonicalHelperExistingSessionRequestsFreshRedraw(t *testing.T) {
	resizeColumns := make(chan int, 1)
	redrawInputs := make(chan []byte, 1)
	upgrader := websocket.Upgrader{Subprotocols: []string{helperWebSocketSubprotocol}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.Close()
		for {
			messageType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.BinaryMessage {
				redrawInputs <- helperTestInputBody(t, data)
				continue
			}
			frame, err := decodeHelperFrame(data)
			if err != nil {
				t.Error(err)
				return
			}
			switch frame.Type {
			case "hello":
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1","terminal.input-stream.v1"]}`)})
			case "detach":
				return
			case "request":
				var payload map[string]any
				_ = json.Unmarshal(frame.Payload, &payload)
				switch payload["action"] {
				case "snapshot":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"running","generation":1,"earliest_sequence":100,"latest_sequence":200},"replay":false}`)})
				case "attach":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"attachment_id":"att_live","session":{"snapshot":{"generation":1}}},"replay":false}`)})
				case "resize":
					resizeColumns <- int(payload["columns"].(float64))
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{},"replay":false}`)})
				}
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v1", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", CWD: "/workspace"}
	conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	helperConn, ok := conn.(*helperTerminalConn)
	if !ok {
		t.Fatalf("connection type %T", conn)
	}
	foundResume := false
	for _, output := range helperConn.initial {
		if strings.Contains(string(output.data), "Earlier terminal output is unavailable") {
			t.Fatalf("normal live-boundary reconnect emitted replay-gap marker: %q", output.data)
		}
		if string(output.data) == helperTerminalResume {
			foundResume = true
		}
	}
	if !foundResume {
		t.Fatal("existing session did not restore terminal interaction modes")
	}
	if err := conn.Resize(40, 120); err != nil {
		t.Fatal(err)
	}
	if columns := <-resizeColumns; columns != 120 {
		t.Fatalf("resize columns=%d", columns)
	}
	if input := <-redrawInputs; string(input) != helperReplayRedraw {
		t.Fatalf("redraw input=%q", input)
	}
}

func TestCanonicalHelperRestartIsLimitedToInitialAttach(t *testing.T) {
	for _, test := range []struct {
		name         string
		restart      bool
		wantRestart  bool
		wantExitCode int
		generation   int
		attachmentID string
	}{
		{name: "initial attach", restart: true, wantRestart: true, wantExitCode: 11, generation: 4, attachmentID: "att_initial"},
		{name: "transport reconnect", restart: false, wantRestart: false, wantExitCode: 23, generation: 3, attachmentID: "att_reconnect"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actions := make(chan string, 4)
			upgrader := websocket.Upgrader{Subprotocols: []string{helperWebSocketSubprotocol}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer ws.Close()
				for {
					messageType, data, err := ws.ReadMessage()
					if err != nil {
						return
					}
					if messageType != websocket.TextMessage {
						t.Errorf("client message type=%d", messageType)
						return
					}
					frame, err := decodeHelperFrame(data)
					if err != nil {
						t.Error(err)
						return
					}
					if frame.Type == "hello" {
						writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1"]}`)})
						continue
					}
					if frame.Type != "request" {
						continue
					}
					var payload map[string]any
					if err := json.Unmarshal(frame.Payload, &payload); err != nil {
						t.Error(err)
						return
					}
					action, _ := payload["action"].(string)
					actions <- action
					switch action {
					case "snapshot":
						writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"exited","generation":3},"replay":false}`)})
					case "restart":
						writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"running","generation":4},"replay":false}`)})
					case "attach":
						response := fmt.Sprintf(`{"result":{"attachment_id":%q,"session":{"snapshot":{"generation":%d}}},"replay":false}`, test.attachmentID, test.generation)
						writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(response)})
						event := fmt.Sprintf(`{"event":"terminal_stream_end","session_id":"ses_retained","state":"exited","final_sequence":17,"exit":{"code":%d}}`, test.wantExitCode)
						writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v1", Payload: json.RawMessage(event)})
					}
				}
			}))
			defer server.Close()

			u, _ := url.Parse(server.URL)
			u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
			u.Path = "/v1/runtime"
			target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v1", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_retained", TerminalID: "default", RestartIfNotRunning: test.restart, AfterSequence: 9}
			conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if code, err := conn.Wait(); err != nil || code != test.wantExitCode {
				t.Fatalf("Wait()=%d,%v", code, err)
			}

			close(actions)
			var got []string
			for action := range actions {
				got = append(got, action)
			}
			want := []string{"snapshot"}
			if test.wantRestart {
				want = append(want, "restart")
			}
			want = append(want, "attach")
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("actions=%v want=%v", got, want)
			}
		})
	}
}

func TestCanonicalHelperStaleCursorJoinsAtLiveBoundary(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{helperWebSocketSubprotocol}}
	attachFrom := make(chan uint64, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.Close()
		for {
			messageType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if messageType != websocket.TextMessage {
				return
			}
			frame, err := decodeHelperFrame(data)
			if err != nil {
				t.Error(err)
				return
			}
			if frame.Type == "hello" {
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1"]}`)})
				continue
			}
			if frame.Type != "request" {
				continue
			}
			var payload struct {
				Action       string `json:"action"`
				FromSequence uint64 `json:"from_sequence"`
			}
			_ = json.Unmarshal(frame.Payload, &payload)
			switch payload.Action {
			case "snapshot":
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"running","generation":1,"earliest_sequence":10,"latest_sequence":18},"replay":false}`)})
			case "attach":
				attachFrom <- payload.FromSequence
				if payload.FromSequence < 10 {
					writeHelperTestFrame(t, ws, helperFrame{Type: "error", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"code":"replay_gap","message":"operation failed","retryable":false,"details":{"requested_sequence":2,"earliest_sequence":10,"latest_sequence":18}}`)})
					continue
				}
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"attachment_id":"att_recovered","session":{"snapshot":{"generation":1}}},"replay":true}`)})
				writeHelperTestBinary(t, ws, 18, []byte("fresh\n"))
				writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v1", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_gap","state":"exited","final_sequence":24,"exit":{"code":0}}`)})
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	var cursor atomic.Int64
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v1", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", AfterSequence: 2, SequenceSink: func(value int) { cursor.Store(int64(value)) }}
	conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	output, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(output), helperTerminalResume) || strings.Contains(string(output), "Earlier terminal output is unavailable") || !strings.HasSuffix(string(output), "fresh\n") {
		t.Fatalf("output=%q", output)
	}
	if boundary := <-attachFrom; boundary != 18 {
		t.Fatalf("attach boundary=%d", boundary)
	}
	if got := cursor.Load(); got != 24 {
		t.Fatalf("cursor=%d want 24", got)
	}
}

func writeHelperTestFrame(t *testing.T, ws *websocket.Conn, frame helperFrame) {
	t.Helper()
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(data[:4], uint32(len(encoded)))
	copy(data[4:], encoded)
	if err := ws.WriteMessage(websocket.TextMessage, data); err != nil {
		t.Fatal(err)
	}
}

func writeHelperTestBinary(t *testing.T, ws *websocket.Conn, sequence uint64, body []byte) {
	t.Helper()
	data := make([]byte, 13+len(body))
	binary.BigEndian.PutUint32(data[:4], uint32(9+len(body)))
	data[4] = 1
	binary.BigEndian.PutUint64(data[5:13], sequence)
	copy(data[13:], body)
	if err := ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.Fatal(err)
	}
}

func helperTestInputBody(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 25 || data[4] != 3 {
		t.Fatalf("invalid terminal input frame: %x", data)
	}
	sessionLength := int(binary.BigEndian.Uint16(data[13:15]))
	attachmentLength := int(binary.BigEndian.Uint16(data[15:17]))
	bodyStart := 25 + sessionLength + attachmentLength
	if bodyStart >= len(data) {
		t.Fatalf("invalid terminal input binding: %x", data)
	}
	return append([]byte(nil), data[bodyStart:]...)
}
