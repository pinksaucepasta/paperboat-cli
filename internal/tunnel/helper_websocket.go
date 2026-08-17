package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

const (
	helperProtocolVersion         = "1.0"
	helperMaxFrame                = 256 << 10
	helperInputChunkBytes         = 32 << 10
	helperOutputQueueDecodedLimit = terminalOutputQueueChunks * protocol.MaxTerminalOutputBytes
	helperRequestTimeout          = 30 * time.Second
	helperReplayGapMarker         = "\r\n[paperboat] Earlier terminal output is unavailable; showing retained output.\r\n"
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

type TerminalInputResult struct {
	StreamID     uint32
	Sequence     uint64
	Status       string
	BytesWritten int
	ErrorCode    string
}

type helperWrite struct {
	messageType helperMessageType
	data        []byte
	result      chan error
}

type helperMessageType byte

const (
	helperStructuredMessage helperMessageType = 1
	helperBinaryMessage     helperMessageType = 2
)

type helperMessageConnection interface {
	ReadMessage(context.Context) (helperMessageType, []byte, error)
	WriteMessage(context.Context, helperMessageType, []byte) error
	Close() error
}

type helperWebSocketConnection struct{ ws *websocket.Conn }

func (c *helperWebSocketConnection) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	c.ws.SetReadLimit(helperMaxFrame)
	messageType, data, err := c.ws.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if messageType == websocket.MessageText {
		return helperStructuredMessage, data, nil
	}
	if messageType == websocket.MessageBinary {
		return helperBinaryMessage, data, nil
	}
	return 0, nil, errors.New("unsupported helper websocket message")
}

func (c *helperWebSocketConnection) WriteMessage(ctx context.Context, messageType helperMessageType, data []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, websocketWriteTimeout)
	defer cancel()
	websocketType := websocket.MessageText
	if messageType == helperBinaryMessage {
		websocketType = websocket.MessageBinary
	} else if messageType != helperStructuredMessage {
		return errors.New("invalid helper message type")
	}
	return c.ws.Write(writeCtx, websocketType, data)
}

func (c *helperWebSocketConnection) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

type helperTerminalConn struct {
	message helperMessageConnection
	target  *resolver.TerminalTarget

	readMu        sync.Mutex
	current       *helperOutput
	out           chan helperOutput
	done          chan struct{}
	inputWrites   chan helperWrite
	controlWrites chan helperWrite
	detachWrites  chan helperWrite
	ackWrites     chan helperWrite

	pendingMu sync.Mutex
	responses map[string]chan helperFrame

	attachmentID              string
	streamID                  uint32
	generation                uint64
	inputSeq                  atomic.Uint64
	resizeSeq                 atomic.Uint64
	ackLatest                 atomic.Uint64
	ackSent                   atomic.Uint64
	ackNotify                 chan struct{}
	ackMu                     sync.Mutex
	inputResultMu             sync.Mutex
	inputResults              chan TerminalInputResult
	inputQueue                *resolver.TerminalInputQueue
	closing                   atomic.Bool
	finishOnce                sync.Once
	exitCode                  int
	exitErr                   error
	initial                   []helperOutput
	initialBinary             [][]byte
	initialEncodedBytes       int
	initialDecodedBytes       int
	compressionRawFrames      atomic.Uint64
	compressionZstdFrames     atomic.Uint64
	compressionDecodedBytes   atomic.Uint64
	compressionEncodedBytes   atomic.Uint64
	compressionDecodeNanos    atomic.Uint64
	compressionDecodeFailures atomic.Uint64
}

func newHelperTerminalConn(message helperMessageConnection, target *resolver.TerminalTarget, queue int) *helperTerminalConn {
	if queue < 1 {
		queue = terminalOutputQueueChunks
	}
	if target != nil && target.InputQueue == nil {
		target.InputQueue = resolver.NewTerminalInputQueue(256)
	}
	var inputQueue *resolver.TerminalInputQueue
	if target != nil {
		inputQueue = target.InputQueue
	}
	return &helperTerminalConn{message: message, target: target, out: make(chan helperOutput, queue), done: make(chan struct{}), inputWrites: make(chan helperWrite, 64), controlWrites: make(chan helperWrite, 16), detachWrites: make(chan helperWrite, 1), ackWrites: make(chan helperWrite, 1), ackNotify: make(chan struct{}, 1), responses: make(map[string]chan helperFrame), inputResults: make(chan TerminalInputResult, 256), inputQueue: inputQueue}
}

func helperHandshake(ctx context.Context, message helperMessageConnection) (bool, error) {
	payload, _ := json.Marshal(map[string]any{"min_version": helperProtocolVersion, "max_version": helperProtocolVersion, "capabilities": helperCapabilities()})
	requestID := helperID("req_")
	if err := writeHelperFrame(ctx, message, helperFrame{Type: "hello", RequestID: requestID, Version: helperProtocolVersion, Payload: payload}); err != nil {
		return false, err
	}
	frame, err := readHelperStructured(ctx, message)
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
	return true, nil
}

func helperCapabilities() []string {
	return []string{"terminal.v1", "health.v1", "exec.v1", "ssh.v1"}
}

func helperCheck(ctx context.Context, message helperMessageConnection) error {
	frame, err := helperRequestSync(ctx, message, "health.v1", json.RawMessage(`{}`))
	if err != nil {
		return err
	}
	if frame.Type != "response" {
		return errors.New("helper health probe returned an invalid response")
	}
	return nil
}

// initialize attaches the canonical terminal session with a create-or-get
// fast path: one create round trip both creates a fresh session and resolves
// an already-running one, so the common fresh-session startup needs two round
// trips (create, attach) instead of three (snapshot, create, attach).
func (c *helperTerminalConn) initialize(ctx context.Context) error {
	if c.target.SessionID == "" {
		return errors.New("canonical terminal descriptor is missing session ID")
	}
	cols, rows := c.target.Cols, c.target.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	// The server-bound session ID remains unique across machine re-enrollment.
	// Terminal IDs such as "term-1" can be reused and collide with durable
	// helper history left by the previous machine identity.
	name := canonicalSessionName(c.target.SessionID)
	createPayload, _ := json.Marshal(map[string]any{"action": "create", "session_id": c.target.SessionID, "name": name, "cwd": c.target.CWD, "columns": cols, "rows": rows, "environment": c.target.Env, "existing_snapshot": true})
	frame, err := c.requestSync(ctx, "terminal.v1", createPayload)
	if err != nil {
		var remote *helperRemoteError
		if !errors.As(err, &remote) || remote.Code != "invalid_request" && remote.Code != "session_exists" {
			return err
		}
		// Host runtimes without create-or-get reject the extra field, and name
		// collisions surface as session_exists. The legacy sequence preserves
		// the historical behavior for both cases.
		return c.initializeLegacy(ctx)
	}
	existingSession := helperResponseSessionExisting(frame)
	snapshotLatest := uint64(0)
	if existingSession {
		var state string
		state, _, snapshotLatest = helperResponseSessionState(frame)
		if c.target.RestartIfNotRunning && (state == "exited" || state == "closed") {
			restartPayload, _ := json.Marshal(map[string]any{"action": "restart", "session_id": c.target.SessionID})
			frame, err = c.requestSync(ctx, "terminal.v1", restartPayload)
			if err != nil {
				return fmt.Errorf("restart helper terminal session: %w", err)
			}
		}
	}
	c.generation = helperResponseGeneration(frame)
	fromSequence := uint64(max(0, c.target.AfterSequence))
	if existingSession && c.target.AfterSequence <= 0 && snapshotLatest > fromSequence {
		// A bounded raw byte tail is not a terminal snapshot: it can begin inside
		// an ANSI sequence or alternate-screen update and render as a blank pane.
		// An initial attach joins at the live boundary and requests a coherent
		// application redraw. Reconnects carry a committed sequence and replay all
		// retained output after that cursor.
		fromSequence = snapshotLatest
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(snapshotLatest))
		}
	}
	attach := func(sequence uint64, liveBoundary bool) (helperFrame, error) {
		payload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": c.target.SessionID, "attachment_id": c.target.InputAttachmentID, "from_sequence": sequence, "at_live_boundary": liveBoundary})
		return c.requestSync(ctx, "terminal.v1", payload)
	}
	frame, err = attach(fromSequence, existingSession && c.target.AfterSequence <= 0)
	for attempt := 0; err != nil; attempt++ {
		var remote *helperRemoteError
		if !errors.As(err, &remote) || remote.Code != "replay_gap" || remote.Details == nil || remote.Details.EarliestSequence > remote.Details.LatestSequence || attempt >= 3 {
			if attempt > 0 {
				return fmt.Errorf("recover helper terminal replay gap: %w", err)
			}
			return fmt.Errorf("attach helper terminal session: %w", err)
		}
		// Once compaction has passed the committed cursor, a numeric retry can
		// race a high-output terminal and become stale again before it arrives.
		// Join at the helper's atomic live boundary, make the loss explicit once,
		// and request a coherent redraw.
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(remote.Details.LatestSequence))
		}
		if attempt == 0 {
			if c.target.ReplayGapSink != nil {
				c.target.ReplayGapSink(remote.Details.RequestedSequence, remote.Details.EarliestSequence, remote.Details.LatestSequence)
			}
			c.initial = append(c.initial, helperOutput{data: []byte(helperReplayGapMarker), endSequence: remote.Details.LatestSequence})
		}
		frame, err = attach(remote.Details.LatestSequence, true)
	}
	var response struct {
		Result struct {
			StreamID      uint32 `json:"stream_id"`
			AttachmentID  string `json:"attachment_id"`
			InputSequence uint64 `json:"input_sequence"`
			Session       struct {
				Snapshot struct {
					Generation uint64 `json:"generation"`
				} `json:"snapshot"`
			} `json:"session"`
		} `json:"result"`
	}
	if json.Unmarshal(frame.Payload, &response) != nil || response.Result.StreamID == 0 || response.Result.AttachmentID == "" {
		return errors.New("helper returned an invalid terminal attachment")
	}
	if existingSession && c.target.AfterSequence <= 0 {
		if modes := helperResponseTerminalModes(frame); modes != "" {
			c.initial = append([]helperOutput{{data: []byte(modes), endSequence: snapshotLatest}}, c.initial...)
		}
	}
	c.attachmentID = response.Result.AttachmentID
	c.target.InputAttachmentID = response.Result.AttachmentID
	c.streamID = response.Result.StreamID
	c.inputSeq.Store(response.Result.InputSequence)
	for _, pending := range c.inputQueue.Reconcile(response.Result.InputSequence) {
		c.publishInputResult(TerminalInputResult{StreamID: c.streamID, Sequence: pending.Sequence, Status: "uncertain", BytesWritten: 0, ErrorCode: "delivery_reconciled_without_result"})
	}
	if response.Result.Session.Snapshot.Generation != 0 {
		c.generation = response.Result.Session.Snapshot.Generation
	}
	if c.generation == 0 {
		return errors.New("helper terminal session has no generation")
	}
	diagnosticlog.TryInfo("peer terminal attachment initialized", "session_id", c.target.SessionID, "existing", existingSession, "snapshot_latest", snapshotLatest, "from_sequence", fromSequence, "initial_binary_frames", len(c.initialBinary), "initial_binary_bytes", c.initialDecodedBytes)
	for _, data := range c.initialBinary {
		output, decodeErr := c.decodeHelperBinary(data)
		if decodeErr != nil {
			return decodeErr
		}
		c.initial = append(c.initial, output)
	}
	c.initialBinary = nil
	c.initialEncodedBytes = 0
	c.initialDecodedBytes = 0
	go c.writeLoop()
	go c.readLoop()
	go c.ackLoop()
	return nil
}

func helperResponseSessionExisting(frame helperFrame) bool {
	var response struct {
		Result struct {
			Existing bool `json:"existing"`
		} `json:"result"`
	}
	_ = json.Unmarshal(frame.Payload, &response)
	return response.Result.Existing
}

// initializeLegacy reproduces the historical snapshot/create/attach sequence
// for host runtimes that predate create-or-get.
func (c *helperTerminalConn) initializeLegacy(ctx context.Context) error {
	if c.target.SessionID == "" {
		return errors.New("canonical terminal descriptor is missing session ID")
	}
	snapshotPayload, _ := json.Marshal(map[string]any{"action": "snapshot", "session_id": c.target.SessionID})
	frame, err := c.requestSync(ctx, "terminal.v1", snapshotPayload)
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
		// The server-bound session ID remains unique across machine re-enrollment.
		// Terminal IDs such as "term-1" can be reused and collide with durable
		// helper history left by the previous machine identity.
		name := canonicalSessionName(c.target.SessionID)
		createPayload, _ := json.Marshal(map[string]any{"action": "create", "session_id": c.target.SessionID, "name": name, "cwd": c.target.CWD, "columns": cols, "rows": rows, "environment": c.target.Env})
		frame, err = c.requestSync(ctx, "terminal.v1", createPayload)
		if err != nil {
			return fmt.Errorf("create helper terminal session: %w", err)
		}
	} else {
		state, generation, latestSequence := helperResponseSessionState(frame)
		c.generation = generation
		snapshotLatest = latestSequence
		if c.target.RestartIfNotRunning && (state == "exited" || state == "closed") {
			restartPayload, _ := json.Marshal(map[string]any{"action": "restart", "session_id": c.target.SessionID})
			frame, err = c.requestSync(ctx, "terminal.v1", restartPayload)
			if err != nil {
				return fmt.Errorf("restart helper terminal session: %w", err)
			}
		}
	}
	c.generation = helperResponseGeneration(frame)
	fromSequence := uint64(max(0, c.target.AfterSequence))
	if existingSession && c.target.AfterSequence <= 0 && snapshotLatest > fromSequence {
		// A bounded raw byte tail is not a terminal snapshot: it can begin inside
		// an ANSI sequence or alternate-screen update and render as a blank pane.
		// An initial attach joins at the live boundary and requests a coherent
		// application redraw. Reconnects carry a committed sequence and replay all
		// retained output after that cursor.
		fromSequence = snapshotLatest
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(snapshotLatest))
		}
	}
	attach := func(sequence uint64, liveBoundary bool) (helperFrame, error) {
		payload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": c.target.SessionID, "attachment_id": c.target.InputAttachmentID, "from_sequence": sequence, "at_live_boundary": liveBoundary})
		return c.requestSync(ctx, "terminal.v1", payload)
	}
	frame, err = attach(fromSequence, existingSession && c.target.AfterSequence <= 0)
	for attempt := 0; err != nil; attempt++ {
		var remote *helperRemoteError
		if !errors.As(err, &remote) || remote.Code != "replay_gap" || remote.Details == nil || remote.Details.EarliestSequence > remote.Details.LatestSequence || attempt >= 3 {
			if attempt > 0 {
				return fmt.Errorf("recover helper terminal replay gap: %w", err)
			}
			return fmt.Errorf("attach helper terminal session: %w", err)
		}
		// Once compaction has passed the committed cursor, a numeric retry can
		// race a high-output terminal and become stale again before it arrives.
		// Join at the helper's atomic live boundary, make the loss explicit once,
		// and request a coherent redraw.
		if c.target.SequenceSink != nil {
			c.target.SequenceSink(int(remote.Details.LatestSequence))
		}
		if attempt == 0 {
			if c.target.ReplayGapSink != nil {
				c.target.ReplayGapSink(remote.Details.RequestedSequence, remote.Details.EarliestSequence, remote.Details.LatestSequence)
			}
			c.initial = append(c.initial, helperOutput{data: []byte(helperReplayGapMarker), endSequence: remote.Details.LatestSequence})
		}
		frame, err = attach(remote.Details.LatestSequence, true)
	}
	var response struct {
		Result struct {
			StreamID      uint32 `json:"stream_id"`
			AttachmentID  string `json:"attachment_id"`
			InputSequence uint64 `json:"input_sequence"`
			Session       struct {
				Snapshot struct {
					Generation uint64 `json:"generation"`
				} `json:"snapshot"`
			} `json:"session"`
		} `json:"result"`
	}
	if json.Unmarshal(frame.Payload, &response) != nil || response.Result.StreamID == 0 || response.Result.AttachmentID == "" {
		return errors.New("helper returned an invalid terminal attachment")
	}
	if existingSession && c.target.AfterSequence <= 0 {
		if modes := helperResponseTerminalModes(frame); modes != "" {
			c.initial = append([]helperOutput{{data: []byte(modes), endSequence: snapshotLatest}}, c.initial...)
		}
	}
	c.attachmentID = response.Result.AttachmentID
	c.target.InputAttachmentID = response.Result.AttachmentID
	c.streamID = response.Result.StreamID
	c.inputSeq.Store(response.Result.InputSequence)
	for _, pending := range c.inputQueue.Reconcile(response.Result.InputSequence) {
		c.publishInputResult(TerminalInputResult{StreamID: c.streamID, Sequence: pending.Sequence, Status: "uncertain", BytesWritten: 0, ErrorCode: "delivery_reconciled_without_result"})
	}
	if response.Result.Session.Snapshot.Generation != 0 {
		c.generation = response.Result.Session.Snapshot.Generation
	}
	if c.generation == 0 {
		return errors.New("helper terminal session has no generation")
	}
	diagnosticlog.TryInfo("peer terminal attachment initialized (legacy)", "session_id", c.target.SessionID, "existing", existingSession, "snapshot_latest", snapshotLatest, "from_sequence", fromSequence, "initial_binary_frames", len(c.initialBinary), "initial_binary_bytes", c.initialDecodedBytes)
	for _, data := range c.initialBinary {
		output, decodeErr := c.decodeHelperBinary(data)
		if decodeErr != nil {
			return decodeErr
		}
		c.initial = append(c.initial, output)
	}
	c.initialBinary = nil
	c.initialEncodedBytes = 0
	c.initialDecodedBytes = 0
	go c.writeLoop()
	go c.readLoop()
	go c.ackLoop()
	return nil
}

func (c *helperTerminalConn) requestSync(ctx context.Context, capability string, payload json.RawMessage) (helperFrame, error) {
	operationCtx, cancel := context.WithTimeout(ctx, helperRequestTimeout)
	defer cancel()
	requestID := helperID("req_")
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: helperID("op_"), Capability: capability, DeadlineMS: uint32(min(helperRequestTimeout, deadlineRemaining(operationCtx)) / time.Millisecond), Payload: payload}
	if frame.DeadlineMS == 0 {
		frame.DeadlineMS = 1
	}
	if err := writeHelperFrame(operationCtx, c.message, frame); err != nil {
		return helperFrame{}, err
	}
	for {
		messageType, data, err := c.message.ReadMessage(operationCtx)
		if err != nil {
			return helperFrame{}, err
		}
		if messageType == helperBinaryMessage {
			info, inspectErr := protocol.InspectTerminalOutput(data)
			decodedBytes := int(info.UncompressedLength)
			if inspectErr != nil || len(c.initialBinary) >= 64 || c.initialEncodedBytes > 4*helperMaxFrame-len(data) || c.initialDecodedBytes > 4*helperMaxFrame-decodedBytes {
				return helperFrame{}, errors.New("helper sent excessive output before terminal attachment")
			}
			c.initialBinary = append(c.initialBinary, bytes.Clone(data))
			c.initialEncodedBytes += len(data)
			c.initialDecodedBytes += decodedBytes
			continue
		}
		if messageType != helperStructuredMessage {
			return helperFrame{}, errors.New("helper returned an unsupported message before terminal attachment")
		}
		response, err := decodeHelperFrame(data)
		if err != nil {
			return helperFrame{}, err
		}
		if response.Type == "heartbeat" {
			_ = writeHelperFrame(operationCtx, c.message, response)
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

func helperResponseTerminalModes(frame helperFrame) string {
	var response struct {
		Result struct {
			Session struct {
				Snapshot struct {
					TerminalModes struct {
						AlternateScreen bool `json:"alternate_screen"`
						MouseClick      bool `json:"mouse_click"`
						MouseDrag       bool `json:"mouse_drag"`
						MouseMotion     bool `json:"mouse_motion"`
						MouseURXVT      bool `json:"mouse_urxvt"`
						MouseSGR        bool `json:"mouse_sgr"`
						FocusEvents     bool `json:"focus_events"`
						BracketedPaste  bool `json:"bracketed_paste"`
					} `json:"terminal_modes"`
				} `json:"snapshot"`
			} `json:"session"`
		} `json:"result"`
	}
	if json.Unmarshal(frame.Payload, &response) != nil {
		return ""
	}
	m := response.Result.Session.Snapshot.TerminalModes
	var out strings.Builder
	for _, item := range []struct {
		on bool
		id string
	}{{m.AlternateScreen, "1049"}, {m.MouseClick, "1000"}, {m.MouseDrag, "1002"}, {m.MouseMotion, "1003"}, {m.MouseURXVT, "1015"}, {m.MouseSGR, "1006"}, {m.BracketedPaste, "2004"}, {m.FocusEvents, "1004"}} {
		if item.on {
			out.WriteString("\x1b[?")
			out.WriteString(item.id)
			out.WriteByte('h')
		}
	}
	return out.String()
}

func helperRequestSync(ctx context.Context, message helperMessageConnection, capability string, payload json.RawMessage) (helperFrame, error) {
	operationCtx, cancel := context.WithTimeout(ctx, helperRequestTimeout)
	defer cancel()
	requestID := helperID("req_")
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: helperID("op_"), Capability: capability, DeadlineMS: uint32(min(helperRequestTimeout, deadlineRemaining(operationCtx)) / time.Millisecond), Payload: payload}
	if frame.DeadlineMS == 0 {
		frame.DeadlineMS = 1
	}
	if err := writeHelperFrame(operationCtx, message, frame); err != nil {
		return helperFrame{}, err
	}
	for {
		response, err := readHelperStructured(operationCtx, message)
		if err != nil {
			return helperFrame{}, err
		}
		if response.Type == "heartbeat" {
			_ = writeHelperFrame(operationCtx, message, response)
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

func (c *helperTerminalConn) writeFrame(frame helperFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		return errors.New("helper structured frame is invalid")
	}
	queue := c.controlWrites
	if frame.Type == "detach" {
		queue = c.detachWrites
	}
	return c.queueWrite(queue, helperWrite{messageType: helperStructuredMessage, data: encoded, result: make(chan error, 1)})
}

func (c *helperTerminalConn) queueWrite(queue chan helperWrite, write helperWrite) error {
	select {
	case queue <- write:
	case <-c.done:
		return c.terminalError()
	}
	select {
	case err := <-write.result:
		return err
	case <-c.done:
		return c.terminalError()
	}
}

func (c *helperTerminalConn) writeLoop() {
	for {
		write, ok := c.nextWrite()
		if !ok {
			return
		}
		err := c.message.WriteMessage(context.Background(), write.messageType, write.data)
		write.result <- err
		if err != nil {
			c.finish(1, errors.Join(ErrTransportLost, err))
			return
		}
	}
}

func (c *helperTerminalConn) nextWrite() (helperWrite, bool) {
	for _, queue := range []chan helperWrite{c.inputWrites, c.controlWrites, c.detachWrites, c.ackWrites} {
		select {
		case write := <-queue:
			return write, true
		default:
		}
	}
	select {
	case write := <-c.inputWrites:
		return write, true
	case write := <-c.controlWrites:
		return write, true
	case write := <-c.detachWrites:
		return write, true
	case write := <-c.ackWrites:
		return write, true
	case <-c.done:
		return helperWrite{}, false
	}
}

func (c *helperTerminalConn) readLoop() {
	defer close(c.out)
	firstOutput := true
	for _, output := range c.initial {
		if firstOutput {
			diagnosticlog.TryInfo("peer terminal first output", "session_id", c.target.SessionID, "source", "initial", "bytes", len(output.data))
			firstOutput = false
		}
		select {
		case c.out <- output:
		case <-c.done:
			return
		}
	}
	for {
		messageType, data, err := c.message.ReadMessage(context.Background())
		if err != nil {
			if c.closing.Load() {
				c.finish(0, nil)
			} else {
				c.finish(1, errors.Join(ErrTransportLost, err))
			}
			return
		}
		switch messageType {
		case helperStructuredMessage:
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
		case helperBinaryMessage:
			output, err := c.decodeHelperBinary(data)
			if err != nil {
				c.finish(1, errors.Join(ErrTransportLost, err))
				return
			}
			if firstOutput {
				diagnosticlog.TryInfo("peer terminal first output", "session_id", c.target.SessionID, "source", "live", "bytes", len(output.data))
				firstOutput = false
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
		StreamID      uint32 `json:"stream_id"`
		Sequence      uint64 `json:"sequence"`
		Status        string `json:"status"`
		BytesWritten  int    `json:"bytes_written"`
		ErrorCode     string `json:"error_code,omitempty"`
		State         string `json:"state"`
		FinalSequence uint64 `json:"final_sequence"`
		Exit          *struct {
			Code   int    `json:"code"`
			Signal string `json:"signal"`
		} `json:"exit"`
	}
	if json.Unmarshal(frame.Payload, &event) != nil {
		c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid helper terminal event")))
		return true
	}
	if event.Event == "terminal_input_result" {
		if event.StreamID == 0 || event.StreamID != c.streamID || event.Sequence == 0 || event.Status == "" {
			c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid helper terminal input result")))
			return true
		}
		c.inputQueue.Complete(event.Sequence, event.Status)
		c.publishInputResult(TerminalInputResult{StreamID: event.StreamID, Sequence: event.Sequence, Status: event.Status, BytesWritten: event.BytesWritten, ErrorCode: event.ErrorCode})
		return false
	}
	if event.Event != "terminal_stream_end" || c.target == nil || event.SessionID != c.target.SessionID {
		c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid helper terminal event")))
		return true
	}
	if c.target.SequenceSink != nil {
		c.target.SequenceSink(int(event.FinalSequence))
	}
	c.flushAck()
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

func (c *helperTerminalConn) publishInputResult(result TerminalInputResult) {
	if c.inputResults == nil {
		return
	}
	select {
	case c.inputResults <- result:
	case <-c.done:
	default:
		// A full decision queue is a local safety fault. Do not discard the
		// durable status silently; close the connection so the caller observes
		// a bounded failure and can reconcile through a fresh attachment.
		c.finish(1, errors.Join(ErrTransportLost, errors.New("terminal input result queue is full")))
	}
}

func (c *helperTerminalConn) InputResults() <-chan TerminalInputResult {
	return c.inputResults
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
		c.queueAck(sequence)
	}
	return n, nil
}

func (c *helperTerminalConn) queueAck(sequence uint64) {
	if c.target.SequenceSink != nil {
		c.target.SequenceSink(int(sequence))
	}
	for {
		current := c.ackLatest.Load()
		if sequence <= current || c.ackLatest.CompareAndSwap(current, sequence) {
			break
		}
	}
	select {
	case c.ackNotify <- struct{}{}:
	default:
	}
}

func (c *helperTerminalConn) ackLoop() {
	const (
		ackDebounce = 5 * time.Millisecond
		ackBytes    = 64 << 10
	)
	for {
		select {
		case <-c.ackNotify:
			latest := c.ackLatest.Load()
			if latest-c.ackSent.Load() < ackBytes {
				timer := time.NewTimer(ackDebounce)
				select {
				case <-timer.C:
				case <-c.done:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					c.flushAck()
					return
				}
			}
			c.flushAck()
		case <-c.done:
			c.flushAck()
			return
		}
	}
}

func (c *helperTerminalConn) flushAck() {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	latest := c.ackLatest.Load()
	if latest > c.ackSent.Load() && c.sendAck(latest) == nil {
		c.ackSent.Store(latest)
	}
}

func (c *helperTerminalConn) sendAck(sequence uint64) error {
	message := make([]byte, 13)
	message[0] = 3
	binary.BigEndian.PutUint32(message[1:5], c.streamID)
	binary.BigEndian.PutUint64(message[5:13], sequence)
	return c.queueWrite(c.ackWrites, helperWrite{messageType: helperBinaryMessage, data: message, result: make(chan error, 1)})
}

func (c *helperTerminalConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.streamID == 0 {
		return 0, errors.New("terminal input frame is invalid")
	}
	if c.inputQueue == nil {
		c.inputQueue = resolver.NewTerminalInputQueue(256)
	}
	written := 0
	for len(p) > 0 {
		size := min(len(p), helperInputChunkBytes)
		sequence, queueErr := c.inputQueue.Enqueue(p[:size])
		if queueErr != nil {
			return written, queueErr
		}
		c.inputSeq.Store(sequence)
		message := make([]byte, 13+size)
		message[0] = 1
		binary.BigEndian.PutUint32(message[1:5], c.streamID)
		binary.BigEndian.PutUint64(message[5:13], sequence)
		copy(message[13:], p[:size])
		if err := c.queueWrite(c.inputWrites, helperWrite{messageType: helperBinaryMessage, data: message, result: make(chan error, 1)}); err != nil {
			c.inputQueue.Complete(sequence, "uncertain")
			c.publishInputResult(TerminalInputResult{StreamID: c.streamID, Sequence: sequence, Status: "uncertain", ErrorCode: "transport_write_uncertain"})
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func (c *helperTerminalConn) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	message := make([]byte, 17)
	message[0] = 4
	binary.BigEndian.PutUint32(message[1:5], c.streamID)
	binary.BigEndian.PutUint16(message[5:7], cols)
	binary.BigEndian.PutUint16(message[7:9], rows)
	binary.BigEndian.PutUint64(message[9:17], c.resizeSeq.Add(1))
	err := c.queueWrite(c.controlWrites, helperWrite{messageType: helperBinaryMessage, data: message, result: make(chan error, 1)})
	return err
}

func (c *helperTerminalConn) CloseWrite() error { return ErrInputEOFUnsupported }

func (c *helperTerminalConn) Close() error {
	if c.closing.Swap(true) {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{"session_id": c.target.SessionID, "attachment_id": c.attachmentID})
	_ = c.writeFrame(helperFrame{Type: "detach", RequestID: helperID("req_"), Version: helperProtocolVersion, Payload: payload})
	return c.message.Close()
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

func writeHelperFrame(ctx context.Context, message helperMessageConnection, frame helperFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > 64<<10 {
		return errors.New("helper structured frame is invalid")
	}
	return message.WriteMessage(ctx, helperStructuredMessage, encoded)
}

func readHelperStructured(ctx context.Context, message helperMessageConnection) (helperFrame, error) {
	messageType, data, err := message.ReadMessage(ctx)
	if err != nil {
		return helperFrame{}, err
	}
	if messageType != helperStructuredMessage {
		return helperFrame{}, errors.New("helper returned binary data before terminal attachment")
	}
	return decodeHelperFrame(data)
}

func decodeHelperFrame(data []byte) (helperFrame, error) {
	if len(data) == 0 || len(data) > 64<<10 {
		return helperFrame{}, errors.New("helper structured frame is truncated")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var frame helperFrame
	if err := decoder.Decode(&frame); err != nil {
		return helperFrame{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return helperFrame{}, errors.New("helper structured frame has trailing data")
	}
	if frame.Version != helperProtocolVersion || frame.Type == "" || frame.RequestID == "" {
		return helperFrame{}, errors.New("helper structured frame is invalid")
	}
	return frame, nil
}

func (c *helperTerminalConn) decodeHelperBinary(data []byte) (helperOutput, error) {
	started := time.Now()
	frame, err := protocol.DecodeTerminalOutput(data)
	c.compressionDecodeNanos.Add(uint64(time.Since(started).Nanoseconds()))
	if err != nil || frame.StreamID != c.streamID {
		c.compressionDecodeFailures.Add(1)
		return helperOutput{}, errors.New("helper binary frame is invalid")
	}
	c.compressionDecodedBytes.Add(uint64(len(frame.Data)))
	c.compressionEncodedBytes.Add(uint64(len(data) - protocol.TerminalOutputHeaderBytes))
	if frame.Encoding == protocol.TerminalOutputZstd {
		c.compressionZstdFrames.Add(1)
	} else {
		c.compressionRawFrames.Add(1)
	}
	return helperOutput{data: frame.Data, endSequence: frame.StartSequence + uint64(len(frame.Data))}, nil
}

func (c *helperTerminalConn) TerminalCompressionTelemetry() TerminalCompressionTelemetry {
	return TerminalCompressionTelemetry{
		RawFrames: c.compressionRawFrames.Load(), ZstdFrames: c.compressionZstdFrames.Load(),
		DecodedBytes: c.compressionDecodedBytes.Load(), EncodedBytes: c.compressionEncodedBytes.Load(),
		DecodeNanos: c.compressionDecodeNanos.Load(), DecodeFailures: c.compressionDecodeFailures.Load(),
	}
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
