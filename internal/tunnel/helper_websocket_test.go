package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type capturedHelperMessageConnection struct {
	mu     sync.Mutex
	writes [][]byte
}

func TestHelperResponseTerminalModesRestoresOnlyRecordedModes(t *testing.T) {
	frame := helperFrame{Payload: json.RawMessage(`{"result":{"session":{"snapshot":{"terminal_modes":{"alternate_screen":true,"mouse_sgr":true,"bracketed_paste":true}}}}}`)}
	if got, want := helperResponseTerminalModes(frame), "\x1b[?1049h\x1b[?1006h\x1b[?2004h"; got != want {
		t.Fatalf("modes = %q, want %q", got, want)
	}
}

func (c *capturedHelperMessageConnection) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	<-ctx.Done()
	return 0, nil, ctx.Err()
}
func (c *capturedHelperMessageConnection) WriteMessage(_ context.Context, _ helperMessageType, data []byte) error {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), data...))
	c.mu.Unlock()
	return nil
}
func (*capturedHelperMessageConnection) Close() error { return nil }

type earlyOutputMessageConnection struct {
	reads chan struct {
		kind helperMessageType
		data []byte
	}
	closed       chan struct{}
	once         sync.Once
	attachBinary [][]byte
}

func newEarlyOutputMessageConnection() *earlyOutputMessageConnection {
	return &earlyOutputMessageConnection{reads: make(chan struct {
		kind helperMessageType
		data []byte
	}, 8), closed: make(chan struct{})}
}

func (c *earlyOutputMessageConnection) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	select {
	case message := <-c.reads:
		return message.kind, message.data, nil
	case <-c.closed:
		return 0, nil, io.EOF
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (c *earlyOutputMessageConnection) WriteMessage(_ context.Context, kind helperMessageType, data []byte) error {
	if kind != helperStructuredMessage {
		return nil
	}
	frame, err := decodeHelperFrame(data)
	if err != nil || frame.Type != "request" {
		return err
	}
	var payload map[string]any
	_ = json.Unmarshal(frame.Payload, &payload)
	response := helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion}
	switch payload["action"] {
	case "snapshot":
		response.Type = "error"
		response.Payload = json.RawMessage(`{"code":"not_found_or_forbidden","message":"missing","retryable":false}`)
	case "create":
		response.Payload = json.RawMessage(`{"result":{"generation":1}}`)
	case "attach":
		frames := c.attachBinary
		if len(frames) == 0 {
			binaryFrame, _ := protocol.EncodeTerminalOutput(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 7, Data: []byte("early")}, nil)
			frames = [][]byte{binaryFrame}
		}
		for _, binaryFrame := range frames {
			c.reads <- struct {
				kind helperMessageType
				data []byte
			}{helperBinaryMessage, binaryFrame}
		}
		response.Payload = json.RawMessage(`{"result":{"stream_id":7,"attachment_id":"att_early","session":{"snapshot":{"generation":1}}}}`)
	}
	encoded, _ := json.Marshal(response)
	c.reads <- struct {
		kind helperMessageType
		data []byte
	}{helperStructuredMessage, encoded}
	return nil
}

func (c *earlyOutputMessageConnection) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestNativeTerminalBuffersOutputThatPrecedesAttachResponse(t *testing.T) {
	message := newEarlyOutputMessageConnection()
	target := &resolver.TerminalTarget{SessionID: "ses_early", CWD: "/workspace"}
	connection := newHelperTerminalConn(message, target, 4)
	if err := connection.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("early"))
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "early" {
		t.Fatalf("output=%q err=%v", buffer, err)
	}
	_ = message.Close()
	connection.finish(0, nil)
}

func TestPreAttachCompressedOutputIsBoundedByDecodedBytes(t *testing.T) {
	message := newEarlyOutputMessageConnection()
	data := bytes.Repeat([]byte("x"), protocol.MaxTerminalOutputBytes)
	for sequence := uint64(0); sequence < uint64(5*len(data)); sequence += uint64(len(data)) {
		wire, err := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 7, StartSequence: sequence, Data: data}, nil)
		if err != nil || wire[2] != protocol.TerminalOutputZstd {
			t.Fatalf("encoding=%d err=%v", wire[2], err)
		}
		message.attachBinary = append(message.attachBinary, wire)
	}
	connection := newHelperTerminalConn(message, &resolver.TerminalTarget{SessionID: "ses_bound", CWD: "/workspace"}, 4)
	err := connection.initialize(context.Background())
	if err == nil || !strings.Contains(err.Error(), "excessive output") {
		t.Fatalf("err=%v", err)
	}
	if len(connection.initial) != 0 {
		t.Fatalf("decoded output admitted: %d", len(connection.initial))
	}
}

func TestHelperTerminalLargeInputUses32KiBRecords(t *testing.T) {
	message := &capturedHelperMessageConnection{}
	target := &resolver.TerminalTarget{SessionID: "ses_1"}
	connection := newHelperTerminalConn(message, target, 1)
	connection.streamID = 7
	go connection.writeLoop()
	payload := make([]byte, 70<<10)
	if written, err := connection.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("written=%d err=%v", written, err)
	}
	connection.finish(0, nil)
	message.mu.Lock()
	defer message.mu.Unlock()
	if len(message.writes) != 3 {
		t.Fatalf("records=%d", len(message.writes))
	}
	for index, record := range message.writes {
		body := helperTestInputBody(t, record)
		if len(body) > 32<<10 || index < 2 && len(body) != 32<<10 {
			t.Fatalf("record %d body bytes=%d", index, len(body))
		}
	}
}

func TestHelperTerminalInputPrecedesQueuedControlTraffic(t *testing.T) {
	connection := newHelperTerminalConn(&capturedHelperMessageConnection{}, &resolver.TerminalTarget{}, 1)
	connection.controlWrites <- helperWrite{data: []byte("control")}
	connection.ackWrites <- helperWrite{data: []byte("ack")}
	connection.inputWrites <- helperWrite{data: []byte("input")}
	write, ok := connection.nextWrite()
	if !ok || string(write.data) != "input" {
		t.Fatalf("first write=%q ok=%v", write.data, ok)
	}
}

func TestWebSocketEstablishDoesNotSendAuthenticationOrHTTPUpgrade(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	u.Path = "/v1/runtime"
	target := &resolver.TerminalTarget{Protocol: "paperboat.terminal.v1", WSSEndpoint: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}}
	prepared, err := NewWebSocketTunnel().Establish(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("transport establishment sent an authenticated HTTP request")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
}

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
					writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v1", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_bound","state":"exited","final_sequence":5,"exit":{"code":7}}`)})
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
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1"]}`)})
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
	target := &resolver.TerminalTarget{Protocol: "paperboat.terminal.v1", WSSEndpoint: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_bound", TerminalID: "default", CWD: "/workspace", Cols: 100, Rows: 30, Env: map[string]string{"TERM": "xterm-ghostty", "COLORTERM": "truecolor"}}
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
	message, err := protocol.EncodeTerminalOutput(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 7, StartSequence: 11, Data: []byte("abc")}, nil)
	if err != nil {
		t.Fatal(err)
	}

	output, err := conn.decodeHelperBinary(message)
	if err != nil || output.endSequence != 14 || string(output.data) != "abc" {
		t.Fatalf("output=%#v err=%v", output, err)
	}
	message[19] = 'z'
	if string(output.data) != "zbc" {
		t.Fatal("binary output payload was copied")
	}
	stats := conn.TerminalCompressionTelemetry()
	if stats.RawFrames != 1 || stats.ZstdFrames != 0 || stats.DecodedBytes != 3 || stats.EncodedBytes != 3 || stats.DecodeNanos == 0 || stats.DecodeFailures != 0 {
		t.Fatalf("compression telemetry=%+v", stats)
	}
}

func TestCorruptCompressedOutputIsNeverQueuedOrAcknowledged(t *testing.T) {
	message := newEarlyOutputMessageConnection()
	conn := newHelperTerminalConn(message, &resolver.TerminalTarget{SessionID: "ses_corrupt"}, 1)
	conn.streamID = 7
	wire, err := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 7, StartSequence: 20, Data: bytes.Repeat([]byte("agent output\r\n"), 200)}, nil)
	if err != nil || wire[2] != protocol.TerminalOutputZstd {
		t.Fatalf("wire encoding=%d err=%v", wire[2], err)
	}
	wire[len(wire)-1] ^= 0xff
	message.reads <- struct {
		kind helperMessageType
		data []byte
	}{helperBinaryMessage, wire}
	go conn.readLoop()
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("corrupt frame did not close connection")
	}
	if got := conn.ackLatest.Load(); got != 0 {
		t.Fatalf("ack advanced to %d", got)
	}
	if output, ok := <-conn.out; ok {
		t.Fatalf("corrupt output queued: %#v", output)
	}
}

func TestCanonicalHelperExistingSessionDoesNotInjectTerminalInput(t *testing.T) {
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
				writeHelperTestFrame(t, ws, helperFrame{Type: "welcome", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"version":"1.0","capabilities":["health.v1","terminal.v1"]}`)})
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
	target := &resolver.TerminalTarget{Protocol: "paperboat.terminal.v1", WSSEndpoint: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", CWD: "/workspace"}
	conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	helperConn, ok := conn.(*helperTerminalConn)
	if !ok {
		t.Fatalf("connection type %T", conn)
	}
	for _, output := range helperConn.initial {
		if strings.Contains(string(output.data), "\x1b[?") {
			t.Fatalf("connection synthesized terminal modes: %q", output.data)
		}
	}
	if err := conn.Resize(40, 120); err != nil {
		t.Fatal(err)
	}
	if columns := <-resizeColumns; columns != 120 {
		t.Fatalf("resize columns=%d", columns)
	}
	select {
	case input := <-redrawInputs:
		t.Fatalf("connection injected terminal input=%q", input)
	default:
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
						response := fmt.Sprintf(`{"result":{"stream_id":9,"attachment_id":%q,"session":{"snapshot":{"generation":%d}}},"replay":false}`, test.attachmentID, test.generation)
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
			target := &resolver.TerminalTarget{Protocol: "paperboat.terminal.v1", WSSEndpoint: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_retained", TerminalID: "default", RestartIfNotRunning: test.restart, AfterSequence: 9}
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

func TestCanonicalHelperStaleReconnectCursorReportsReplayGap(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{helperWebSocketSubprotocol}}
	attachFrom := make(chan uint64, 2)
	attachLive := make(chan bool, 2)
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
				AtLive       bool   `json:"at_live_boundary"`
			}
			_ = json.Unmarshal(frame.Payload, &payload)
			switch payload.Action {
			case "snapshot":
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"state":"running","generation":1,"earliest_sequence":10,"latest_sequence":18},"replay":false}`)})
			case "attach":
				attachFrom <- payload.FromSequence
				attachLive <- payload.AtLive
				if payload.FromSequence < 10 {
					writeHelperTestFrame(t, ws, helperFrame{Type: "error", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"code":"replay_gap","message":"operation failed","retryable":false,"details":{"requested_sequence":2,"earliest_sequence":10,"latest_sequence":18}}`)})
					continue
				}
				writeHelperTestFrame(t, ws, helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, Payload: json.RawMessage(`{"result":{"stream_id":10,"attachment_id":"att_recovered","session":{"snapshot":{"generation":1}}},"replay":true}`)})
				writeHelperTestBinary(t, ws, 10, 18, []byte("fresh\n"))
				writeHelperTestFrame(t, ws, helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "terminal.v1", Payload: json.RawMessage(`{"event":"terminal_stream_end","session_id":"ses_gap","state":"exited","final_sequence":24,"exit":{"code":0}}`)})
			}
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	u.Path = "/v1/runtime"
	var cursor atomic.Int64
	target := &resolver.TerminalTarget{Protocol: "paperboat.terminal.v1", WSSEndpoint: u.String(), Auth: resolver.AuthTarget{Method: "bearer", Token: "helper-token"}, SessionID: "ses_gap", TerminalID: "default", AfterSequence: 2, SequenceSink: func(value int) { cursor.Store(int64(value)) }}
	conn, err := NewWebSocketTunnel().Dial(context.Background(), resolver.ConnectInfo{Terminal: target})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	output, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "Earlier terminal output is unavailable") || !strings.HasSuffix(string(output), "fresh\n") {
		t.Fatalf("output=%q", output)
	}
	if boundary := <-attachFrom; boundary != 2 {
		t.Fatalf("initial attach boundary=%d", boundary)
	}
	if boundary := <-attachFrom; boundary != 18 {
		t.Fatalf("recovered attach boundary=%d", boundary)
	}
	if first, second := <-attachLive, <-attachLive; first || !second {
		t.Fatalf("reconnect live boundaries: %v, %v", first, second)
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
	data, err := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: streamID, StartSequence: sequence, Data: body}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
