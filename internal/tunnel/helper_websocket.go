package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

const (
	helperProtocolVersion = "1.0"
	helperMaxFrame        = 256 << 10
	helperRequestTimeout  = 30 * time.Second
	helperReplayGapMarker = "\r\n[paperboat] Earlier terminal output is unavailable; showing retained output.\r\n"
	// Existing sessions have already emitted their terminal-mode setup, but a
	// newly attached local terminal has not seen it. Restore the modes Herdr
	// establishes before asking the application to redraw. Without this, mouse
	// input becomes local scrollback and full-screen TUIs lose interactivity.
	helperTerminalResume = "\x1b[?1049h\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1015h\x1b[?1006h\x1b[?2004h\x1b[?1004h"
	helperReplayRedraw   = "\x1b[I" // Focus gained: Herdr's supported full-host redraw trigger.
)

type helperFrame struct {
	Type        string          `json:"type"`
	RequestID   string          `json:"request_id"`
	Version     string          `json:"version"`
	OperationID string          `json:"operation_id,omitempty"`
	Capability  string          `json:"capability,omitempty"`
	DeadlineMS  uint32          `json:"deadline_ms,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

type helperRemoteError struct {
	Code      string                  `json:"code"`
	Message   string                  `json:"message"`
	Retryable bool                    `json:"retryable"`
	Details   *helperReplayGapDetails `json:"details,omitempty"`
}

type helperReplayGapDetails struct {
	RequestedSequence uint64 `json:"requested_sequence"`
	EarliestSequence  uint64 `json:"earliest_sequence"`
	LatestSequence    uint64 `json:"latest_sequence"`
}

func (e *helperRemoteError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

type helperOutput struct {
	data        []byte
	endSequence uint64
}

type helperTerminalConn struct {
	ws     *websocket.Conn
	target *resolver.TerminalTarget

	writeMu sync.Mutex
	readMu  sync.Mutex
	pending []byte
	current *helperOutput
	out     chan helperOutput
	done    chan struct{}

	pendingMu sync.Mutex
	responses map[string]chan helperFrame

	attachmentID string
	generation   uint64
	inputStream  bool
	inputSeq     atomic.Uint64
	replayRedraw atomic.Bool
	closing      atomic.Bool
	finishOnce   sync.Once
	exitCode     int
	exitErr      error
	initial      []helperOutput
}

func newHelperTerminalConn(ws *websocket.Conn, target *resolver.TerminalTarget, queue int) *helperTerminalConn {
	if queue < 1 {
		queue = terminalOutputQueueChunks
	}
	return &helperTerminalConn{ws: ws, target: target, out: make(chan helperOutput, queue), done: make(chan struct{}), responses: make(map[string]chan helperFrame)}
}

func helperHandshake(ctx context.Context, ws *websocket.Conn) (bool, error) {
	payload, _ := json.Marshal(map[string]any{"min_version": helperProtocolVersion, "max_version": helperProtocolVersion, "capabilities": []string{"terminal.v1", "terminal.input-stream.v1", "health.v1"}})
	requestID := helperID("req_")
	if err := writeHelperFrame(ctx, ws, helperFrame{Type: "hello", RequestID: requestID, Version: helperProtocolVersion, Payload: payload}); err != nil {
		return false, err
	}
	frame, err := readHelperStructured(ctx, ws)
	if err != nil {
		return false, err
	}
	if frame.Type == "error" {
		return false, decodeHelperError(frame)
	}
	if frame.Type != "welcome" || frame.RequestID != requestID {
		return false, errors.New("helper returned an invalid protocol welcome")
	}
	var welcome struct {
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	if json.Unmarshal(frame.Payload, &welcome) != nil || welcome.Version != helperProtocolVersion || !containsString(welcome.Capabilities, "terminal.v1") || !containsString(welcome.Capabilities, "health.v1") {
		return false, errors.New("helper did not negotiate required capabilities")
	}
	return containsString(welcome.Capabilities, "terminal.input-stream.v1"), nil
}

func helperCheck(ctx context.Context, ws *websocket.Conn) error {
	frame, err := helperRequestSync(ctx, ws, "health.v1", json.RawMessage(`{}`))
	if err != nil {
		return err
	}
	if frame.Type != "response" {
		return errors.New("helper health probe returned an invalid response")
	}
	return nil
}

func (c *helperTerminalConn) initialize(ctx context.Context) error {
	if c.target.SessionID == "" {
		return errors.New("canonical terminal descriptor is missing session ID")
	}
	snapshotPayload, _ := json.Marshal(map[string]any{"action": "snapshot", "session_id": c.target.SessionID})
	frame, err := helperRequestSync(ctx, c.ws, "terminal.v1", snapshotPayload)
	existingSession := err == nil
	var snapshotLatest uint64
	if err != nil {
		var remote *helperRemoteError
		if !errors.As(err, &remote) || remote.Code != "not_found_or_forbidden" {
			return err
		}
		cols, rows := c.target.Cols, c.target.Rows
		if cols == 0 {
			cols = 80
		}
		if rows == 0 {
			rows = 24
		}
		name := canonicalSessionName(c.target.TerminalID)
		createPayload, _ := json.Marshal(map[string]any{"action": "create", "session_id": c.target.SessionID, "name": name, "cwd": c.target.CWD, "columns": cols, "rows": rows})
		frame, err = helperRequestSync(ctx, c.ws, "terminal.v1", createPayload)
		if err != nil {
			return fmt.Errorf("create helper terminal session: %w", err)
		}
	} else {
		state, generation, latestSequence := helperResponseSessionState(frame)
		c.generation = generation
		snapshotLatest = latestSequence
		if c.target.RestartIfNotRunning && (state == "exited" || state == "closed") {
			restartPayload, _ := json.Marshal(map[string]any{"action": "restart", "session_id": c.target.SessionID})
			frame, err = helperRequestSync(ctx, c.ws, "terminal.v1", restartPayload)
			if err != nil {
				return fmt.Errorf("restart helper terminal session: %w", err)
			}
		}
	}
	c.generation = helperResponseGeneration(frame)
	fromSequence := uint64(max(0, c.target.AfterSequence))
	if existingSession {
		c.initial = append(c.initial, helperOutput{data: []byte(helperTerminalResume), endSequence: snapshotLatest})
	}
	if existingSession && snapshotLatest > fromSequence {
		// A bounded raw byte tail is not a terminal snapshot: it can begin inside
		// an ANSI sequence or alternate-screen update and render as a blank pane.
		// Join at the live boundary and request a coherent application redraw. This
		// is normal reconnect behavior, not a replay gap visible to the user.
		fromSequence = snapshotLatest
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(snapshotLatest))
		}
	}
	attach := func(sequence uint64) (helperFrame, error) {
		payload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": c.target.SessionID, "from_sequence": sequence, "at_live_boundary": existingSession})
		return helperRequestSync(ctx, c.ws, "terminal.v1", payload)
	}
	frame, err = attach(fromSequence)
	for attempt := 0; err != nil; attempt++ {
		var remote *helperRemoteError
		if !errors.As(err, &remote) || remote.Code != "replay_gap" || remote.Details == nil || remote.Details.EarliestSequence > remote.Details.LatestSequence || attempt >= 3 {
			if attempt > 0 {
				return fmt.Errorf("recover helper terminal replay gap: %w", err)
			}
			return fmt.Errorf("attach helper terminal session: %w", err)
		}
		// Compaction or a bounded replay window is recoverable. Move the local
		// cursor to the retained boundary, make the loss explicit once, and
		// retry a bounded number of times while output is advancing.
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(remote.Details.EarliestSequence))
		}
		if attempt == 0 {
			c.initial = append(c.initial, helperOutput{data: []byte(helperReplayGapMarker), endSequence: remote.Details.EarliestSequence})
			c.replayRedraw.Store(true)
		}
		frame, err = attach(remote.Details.EarliestSequence)
	}
	var response struct {
		Result struct {
			AttachmentID string `json:"attachment_id"`
			Session      struct {
				Snapshot struct {
					Generation uint64 `json:"generation"`
				} `json:"snapshot"`
			} `json:"session"`
		} `json:"result"`
	}
	if json.Unmarshal(frame.Payload, &response) != nil || response.Result.AttachmentID == "" {
		return errors.New("helper returned an invalid terminal attachment")
	}
	c.attachmentID = response.Result.AttachmentID
	if response.Result.Session.Snapshot.Generation != 0 {
		c.generation = response.Result.Session.Snapshot.Generation
	}
	if c.generation == 0 {
		return errors.New("helper terminal session has no generation")
	}
	if existingSession {
		// An attached TUI may be idle and therefore emit no pixels on reconnect.
		// Ask it to repaint after the caller applies the local terminal size.
		c.replayRedraw.Store(true)
	}
	go c.readLoop()
	return nil
}

func helperResponseSessionState(frame helperFrame) (string, uint64, uint64) {
	var response struct {
		Result struct {
			State          string `json:"state"`
			Generation     uint64 `json:"generation"`
			LatestSequence uint64 `json:"latest_sequence"`
		} `json:"result"`
	}
	_ = json.Unmarshal(frame.Payload, &response)
	return response.Result.State, response.Result.Generation, response.Result.LatestSequence
}

func helperResponseGeneration(frame helperFrame) uint64 {
	var response struct {
		Result struct {
			Generation uint64 `json:"generation"`
		} `json:"result"`
	}
	_ = json.Unmarshal(frame.Payload, &response)
	return response.Result.Generation
}

func helperRequestSync(ctx context.Context, ws *websocket.Conn, capability string, payload json.RawMessage) (helperFrame, error) {
	requestID := helperID("req_")
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: helperID("op_"), Capability: capability, DeadlineMS: uint32(min(helperRequestTimeout, deadlineRemaining(ctx)) / time.Millisecond), Payload: payload}
	if frame.DeadlineMS == 0 {
		frame.DeadlineMS = 1
	}
	if err := writeHelperFrame(ctx, ws, frame); err != nil {
		return helperFrame{}, err
	}
	for {
		response, err := readHelperStructured(ctx, ws)
		if err != nil {
			return helperFrame{}, err
		}
		if response.Type == "heartbeat" {
			_ = writeHelperFrame(ctx, ws, response)
			continue
		}
		if response.RequestID != requestID {
			return helperFrame{}, errors.New("helper response did not match request")
		}
		if response.Type == "error" {
			return helperFrame{}, decodeHelperError(response)
		}
		return response, nil
	}
}

func (c *helperTerminalConn) request(capability string, payload any) (helperFrame, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return helperFrame{}, err
	}
	requestID := helperID("req_")
	response := make(chan helperFrame, 1)
	c.pendingMu.Lock()
	c.responses[requestID] = response
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.responses, requestID)
		c.pendingMu.Unlock()
	}()
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: helperID("op_"), Capability: capability, DeadlineMS: uint32(helperRequestTimeout / time.Millisecond), Payload: encoded}
	if err := c.writeFrame(frame); err != nil {
		return helperFrame{}, err
	}
	timer := time.NewTimer(helperRequestTimeout)
	defer timer.Stop()
	select {
	case frame := <-response:
		if frame.Type == "error" {
			return helperFrame{}, decodeHelperError(frame)
		}
		return frame, nil
	case <-c.done:
		return helperFrame{}, c.terminalError()
	case <-timer.C:
		return helperFrame{}, errors.New("helper operation outcome is uncertain")
	}
}

func (c *helperTerminalConn) writeFrame(frame helperFrame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), websocketWriteTimeout)
	defer cancel()
	return writeHelperFrame(ctx, c.ws, frame)
}

func (c *helperTerminalConn) readLoop() {
	defer close(c.out)
	for _, output := range c.initial {
		select {
		case c.out <- output:
		case <-c.done:
			return
		}
	}
	for {
		messageType, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.closing.Load() {
				c.finish(0, nil)
			} else {
				c.finish(1, errors.Join(ErrTransportLost, err))
			}
			return
		}
		switch messageType {
		case websocket.TextMessage:
			frame, err := decodeHelperFrame(data)
			if err != nil {
				c.finish(1, errors.Join(ErrTransportLost, err))
				return
			}
			if frame.Type == "heartbeat" {
				_ = c.writeFrame(frame)
				continue
			}
			if frame.Type == "event" {
				if c.handleEvent(frame) {
					return
				}
				continue
			}
			c.pendingMu.Lock()
			response := c.responses[frame.RequestID]
			c.pendingMu.Unlock()
			if response != nil {
				response <- frame
			}
		case websocket.BinaryMessage:
			output, err := decodeHelperBinary(data)
			if err != nil {
				c.finish(1, errors.Join(ErrTransportLost, err))
				return
			}
			select {
			case c.out <- output:
			case <-c.done:
				return
			}
		default:
			c.finish(1, errors.Join(ErrTransportLost, errors.New("unsupported helper websocket message")))
			return
		}
	}
}

func (c *helperTerminalConn) handleEvent(frame helperFrame) bool {
	var event struct {
		Event         string `json:"event"`
		SessionID     string `json:"session_id"`
		State         string `json:"state"`
		FinalSequence uint64 `json:"final_sequence"`
		Exit          *struct {
			Code   int    `json:"code"`
			Signal string `json:"signal"`
		} `json:"exit"`
	}
	if json.Unmarshal(frame.Payload, &event) != nil || event.Event != "terminal_stream_end" || event.SessionID != c.target.SessionID {
		c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid helper terminal event")))
		return true
	}
	if c.target.SequenceSink != nil {
		c.target.SequenceSink(int(event.FinalSequence))
	}
	code := 0
	if event.Exit != nil {
		code = event.Exit.Code
		if code == 0 && event.Exit.Signal != "" {
			code = signalExitCode(event.Exit.Signal)
		}
	}
	c.finish(code, nil)
	return true
}

func (c *helperTerminalConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for c.current == nil {
		output, ok := <-c.out
		if !ok {
			return 0, io.EOF
		}
		c.current = &output
	}
	n := copy(p, c.current.data)
	c.current.data = c.current.data[n:]
	if len(c.current.data) == 0 {
		sequence := c.current.endSequence
		c.current = nil
		c.ack(sequence)
	}
	return n, nil
}

func (c *helperTerminalConn) ack(sequence uint64) {
	if c.target.SequenceSink != nil {
		c.target.SequenceSink(int(sequence))
	}
	payload, _ := json.Marshal(map[string]any{"session_id": c.target.SessionID, "attachment_id": c.attachmentID, "next_sequence": sequence})
	_ = c.writeFrame(helperFrame{Type: "ack", RequestID: helperID("req_"), Version: helperProtocolVersion, Payload: payload})
}

func (c *helperTerminalConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.inputStream {
		inputID := fmt.Sprintf("input_%016x", c.inputSeq.Add(1))
		_, err := c.request("terminal.v1", map[string]any{"action": "input", "session_id": c.target.SessionID, "attachment_id": c.attachmentID, "generation": c.generation, "input_id": inputID, "bytes_base64": base64.StdEncoding.EncodeToString(p)})
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(c.target.SessionID) > 128 || len(c.attachmentID) > 128 || len(p) > helperMaxFrame-9-12-len(c.target.SessionID)-len(c.attachmentID) {
		return 0, errors.New("terminal input frame is invalid")
	}
	sequence := c.inputSeq.Add(1)
	body := make([]byte, 12+len(c.target.SessionID)+len(c.attachmentID)+len(p))
	binary.BigEndian.PutUint16(body[:2], uint16(len(c.target.SessionID)))
	binary.BigEndian.PutUint16(body[2:4], uint16(len(c.attachmentID)))
	binary.BigEndian.PutUint64(body[4:12], c.generation)
	copy(body[12:], c.target.SessionID)
	copy(body[12+len(c.target.SessionID):], c.attachmentID)
	copy(body[12+len(c.target.SessionID)+len(c.attachmentID):], p)
	message := make([]byte, 13+len(body))
	binary.BigEndian.PutUint32(message[:4], uint32(9+len(body)))
	message[4] = 3 // paperboat terminal-input binary channel
	binary.BigEndian.PutUint64(message[5:13], sequence)
	copy(message[13:], body)
	c.writeMu.Lock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(websocketWriteTimeout))
	err := c.ws.WriteMessage(websocket.BinaryMessage, message)
	_ = c.ws.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *helperTerminalConn) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	redraw := c.replayRedraw.Swap(false)
	_, err := c.request("terminal.v1", map[string]any{"action": "resize", "session_id": c.target.SessionID, "attachment_id": c.attachmentID, "columns": cols, "rows": rows})
	if err != nil || !redraw {
		if err != nil && redraw {
			c.replayRedraw.Store(true)
		}
		return err
	}
	// Resize alone does not make every TUI repaint. Report focus gained once so
	// Herdr redraws its complete host surface after attaching an existing session.
	if _, err = c.Write([]byte(helperReplayRedraw)); err != nil {
		c.replayRedraw.Store(true)
	}
	return err
}

func (c *helperTerminalConn) CloseWrite() error { return ErrInputEOFUnsupported }

func (c *helperTerminalConn) Close() error {
	if c.closing.Swap(true) {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{"session_id": c.target.SessionID, "attachment_id": c.attachmentID})
	_ = c.writeFrame(helperFrame{Type: "detach", RequestID: helperID("req_"), Version: helperProtocolVersion, Payload: payload})
	return c.ws.Close()
}

func (c *helperTerminalConn) Wait() (int, error) {
	<-c.done
	return c.exitCode, c.exitErr
}

func (c *helperTerminalConn) finish(code int, err error) {
	c.finishOnce.Do(func() {
		c.exitCode, c.exitErr = code, err
		close(c.done)
	})
}

func (c *helperTerminalConn) terminalError() error {
	if c.exitErr != nil {
		return c.exitErr
	}
	return io.EOF
}

func writeHelperFrame(ctx context.Context, ws *websocket.Conn, frame helperFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > 64<<10 {
		return errors.New("helper structured frame is invalid")
	}
	message := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(message[:4], uint32(len(encoded)))
	copy(message[4:], encoded)
	deadline, ok := ctx.Deadline()
	if ok {
		_ = ws.SetWriteDeadline(deadline)
		defer ws.SetWriteDeadline(time.Time{})
	}
	return ws.WriteMessage(websocket.TextMessage, message)
}

func readHelperStructured(ctx context.Context, ws *websocket.Conn) (helperFrame, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = ws.SetReadDeadline(deadline)
		defer ws.SetReadDeadline(time.Time{})
	}
	messageType, data, err := ws.ReadMessage()
	if err != nil {
		return helperFrame{}, err
	}
	if messageType != websocket.TextMessage {
		return helperFrame{}, errors.New("helper returned binary data before terminal attachment")
	}
	return decodeHelperFrame(data)
}

func decodeHelperFrame(data []byte) (helperFrame, error) {
	if len(data) < 5 {
		return helperFrame{}, errors.New("helper structured frame is truncated")
	}
	length := int(binary.BigEndian.Uint32(data[:4]))
	if length != len(data)-4 || length > 64<<10 {
		return helperFrame{}, errors.New("helper structured frame has invalid length")
	}
	decoder := json.NewDecoder(bytes.NewReader(data[4:]))
	decoder.DisallowUnknownFields()
	var frame helperFrame
	if err := decoder.Decode(&frame); err != nil {
		return helperFrame{}, err
	}
	if frame.Version != helperProtocolVersion || frame.Type == "" || frame.RequestID == "" {
		return helperFrame{}, errors.New("helper structured frame is invalid")
	}
	return frame, nil
}

func decodeHelperBinary(data []byte) (helperOutput, error) {
	if len(data) < 13 {
		return helperOutput{}, errors.New("helper binary frame is truncated")
	}
	length := int(binary.BigEndian.Uint32(data[:4]))
	if length != len(data)-4 || length > helperMaxFrame || (data[4] != 1 && data[4] != 2) {
		return helperOutput{}, errors.New("helper binary frame is invalid")
	}
	start := binary.BigEndian.Uint64(data[5:13])
	body := append([]byte(nil), data[13:]...)
	return helperOutput{data: body, endSequence: start + uint64(len(body))}, nil
}

func decodeHelperError(frame helperFrame) error {
	var remote helperRemoteError
	if json.Unmarshal(frame.Payload, &remote) != nil || remote.Code == "" {
		return errors.New("helper returned an invalid error")
	}
	return &remote
}

func helperID(prefix string) string {
	var value [12]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return prefix + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(value[:])
}

func deadlineRemaining(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
		return time.Millisecond
	}
	return helperRequestTimeout
}

func canonicalSessionName(value string) string {
	if value == "" {
		return "paperboat"
	}
	result := make([]byte, 0, min(len(value), 64))
	for i := 0; i < len(value) && len(result) < 64; i++ {
		char := value[i]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_' {
			result = append(result, char)
		} else {
			result = append(result, '-')
		}
	}
	if len(result) == 0 || result[0] == '-' {
		return "paperboat"
	}
	return string(result)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func signalExitCode(signal string) int {
	switch signal {
	case "SIGHUP":
		return 129
	case "SIGINT":
		return 130
	case "SIGKILL":
		return 137
	case "SIGTERM":
		return 143
	default:
		return 1
	}
}

var _ Conn = (*helperTerminalConn)(nil)
var _ InputHalfCloser = (*helperTerminalConn)(nil)
