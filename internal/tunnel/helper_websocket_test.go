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
	"github.com/pinksaucepasta/paperboat-cli/internal/resolver"
)

func TestCanonicalHelperTerminalFramingIOResizeAndExit(t *testing.T) {
	requests := make(chan helperFrame, 12)
	inputs := make(chan []byte, 1)
	acks := make(chan uint64, 1)
	resizes := make(chan [2]uint16, 1)
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
				switch data[0] {
				case 1:
					if len(data) < 14 || binary.BigEndian.Uint32(data[1:5]) != 7 || binary.BigEndian.Uint64(data[5:13]) != 1 {
						t.Errorf("invalid input frame: %x", data)
						return
					}
					inputs <- append([]byte(nil), data[13:]...)
				case 3:
					acks <- binary.BigEndian.Uint64(data[5:13])
				case 4:
					resizes <- [2]uint16{binary.BigEndian.Uint16(data[5:7]), binary.BigEndian.Uint16(data[7:9])}
					writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v2", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_bound","state":"exited","final_sequence":5,"exit":{"code":7}}`)})
				default:
					t.Errorf("invalid binary frame: %x", data)
				}
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
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"2.0","capabilities":["health.v1","terminal.v2"]}`)})
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
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"stream_id":7,"attachment_id":"att_1","session":{"snapshot":{"generation":1}}},"replay":false}`)})
					writeHelperTestBinary(t, ws, 7, 0, []byte("h"))
					writeHelperTestBinary(t, ws, 7, 1, []byte("el"))
					writeHelperTestBinary(t, ws, 7, 3, []byte("lo"))
				}
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v2", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_bound", TerminalID: "default", CWD: "/workspace", Cols: 100, Rows: 30, Env: map[string]string{"TERM": "xterm-ghostty", "COLORTERM": "truecolor"}}
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

	var sawCreate, sawAttach bool
	for len(requests) > 0 {
		frame := <-requests
		var payload map[string]any
		_ = json.Unmarshal(frame.Payload, &payload)
		switch {
		case payload["action"] == "create":
			environment, _ := payload["environment"].(map[string]any)
			sawCreate = payload["session_id"] == "ses_bound" && payload["name"] == "ses_bound" && payload["columns"] == float64(100) && payload["rows"] == float64(30) && environment["TERM"] == "xterm-ghostty" && environment["COLORTERM"] == "truecolor"
		case payload["action"] == "attach":
			sawAttach = payload["session_id"] == "ses_bound"
		}
	}
	if ack := <-acks; ack != 5 {
		t.Fatalf("ack=%d", ack)
	}
	if resize := <-resizes; resize != [2]uint16{120, 40} {
		t.Fatalf("resize=%v", resize)
	}
	if !sawCreate || !sawAttach {
		t.Fatalf("create=%v attach=%v", sawCreate, sawAttach)
	}
}

func TestHelperBinaryOutputRetainsOwnedWebSocketPayload(t *testing.T) {
	conn := &helperTerminalConn{streamID: 7}
	message := make([]byte, 14+3)
	message[0], message[1] = 2, 1
	binary.BigEndian.PutUint32(message[2:6], 7)
	binary.BigEndian.PutUint64(message[6:14], 11)
	copy(message[14:], "abc")

	output, err := conn.decodeHelperBinary(message)
	if err != nil || output.endSequence != 14 || string(output.data) != "abc" {
		t.Fatalf("output=%#v err=%v", output, err)
	}
	message[14] = 'z'
	if string(output.data) != "zbc" {
		t.Fatal("binary output payload was copied")
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
				switch data[0] {
				case 1:
					redrawInputs <- helperTestInputBody(t, data)
				case 4:
					resizeColumns <- int(binary.BigEndian.Uint16(data[5:7]))
				}
				continue
			}
			frame, err := decodeHelperFrame(data)
			if err != nil {
				t.Error(err)
				return
			}
			switch frame.Type {
			case "hello":
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"2.0","capabilities":["health.v1","terminal.v2"]}`)})
			case "detach":
				return
			case "request":
				var payload map[string]any
				_ = json.Unmarshal(frame.Payload, &payload)
				switch payload["action"] {
				case "snapshot":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"running","generation":1,"earliest_sequence":100,"latest_sequence":200},"replay":false}`)})
				case "attach":
					writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"stream_id":8,"attachment_id":"att_live","session":{"snapshot":{"generation":1}}},"replay":false}`)})
				}
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v2", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", CWD: "/workspace"}
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
						writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"2.0","capabilities":["health.v1","terminal.v2"]}`)})
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
						response := fmt.Sprintf(`{"result":{"stream_id":9,"attachment_id":%q,"session":{"snapshot":{"generation":%d}}},"replay":false}`, test.attachmentID, test.generation)
						writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(response)})
						event := fmt.Sprintf(`{"event":"terminal_stream_end","session_id":"ses_retained","state":"exited","final_sequence":17,"exit":{"code":%d}}`, test.wantExitCode)
						writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v2", Payload: json.RawMessage(event)})
					}
				}
			}))
			defer server.Close()

			u, _ := url.Parse(server.URL)
			u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
			u.Path = "/v1/runtime"
			target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v2", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_retained", TerminalID: "default", RestartIfNotRunning: test.restart, AfterSequence: 9}
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
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"2.0","capabilities":["health.v1","terminal.v2"]}`)})
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
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"stream_id":10,"attachment_id":"att_recovered","session":{"snapshot":{"generation":1}}},"replay":true}`)})
				writeHelperTestBinary(t, ws, 10, 18, []byte("fresh\n"))
				writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v2", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_gap","state":"exited","final_sequence":24,"exit":{"code":0}}`)})
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	var cursor atomic.Int64
	target := &resolver.TerminalTarget{Kind: "paperboat_terminal_v2", WebSocketBaseURL: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", AfterSequence: 2, SequenceSink: func(value int) { cursor.Store(int64(value)) }}
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
	if err := ws.WriteMessage(websocket.TextMessage, encoded); err != nil {
		t.Fatal(err)
	}
}

func writeHelperTestBinary(t *testing.T, ws *websocket.Conn, streamID uint32, sequence uint64, body []byte) {
	t.Helper()
	data := make([]byte, 14+len(body))
	data[0] = 2
	data[1] = 1
	binary.BigEndian.PutUint32(data[2:6], streamID)
	binary.BigEndian.PutUint64(data[6:14], sequence)
	copy(data[14:], body)
	if err := ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.Fatal(err)
	}
}

func helperTestInputBody(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 14 || data[0] != 1 {
		t.Fatalf("invalid terminal input frame: %x", data)
	}
	return append([]byte(nil), data[13:]...)
}
