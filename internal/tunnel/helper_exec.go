package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type ExecRequest struct {
	OperationID  string
	Argv         []string
	CWD          string
	Environment  map[string]string
	Timeout      time.Duration
	PTY          bool
	Columns      uint16
	Rows         uint16
	FromSequence uint64
}

type ExecResult struct {
	Code     int       `json:"code"`
	Signal   string    `json:"signal,omitempty"`
	ExitedAt time.Time `json:"exited_at"`
}

type ExecEvent struct {
	OperationID   string
	EventSequence uint64
	Stream        string
	Sequence      uint64
	Data          []byte
	State         string
	Result        *ExecResult
	ErrorCode     string
}

type RemoteExecError struct {
	Code string
}

func (e *RemoteExecError) Error() string { return e.Code }

type ExecStartUncertainError struct {
	Cause error
}

func (e *ExecStartUncertainError) Error() string {
	if e == nil || e.Cause == nil {
		return "remote execution start outcome is uncertain"
	}
	return "remote execution start outcome is uncertain: " + e.Cause.Error()
}
func (e *ExecStartUncertainError) Unwrap() error        { return e.Cause }
func (e *ExecStartUncertainError) LocalAPICode() string { return "exec_start_uncertain" }

type ExecConn interface {
	Conn
	Events() <-chan ExecEvent
	Cancel() error
	Signal(string) error
	CloseWrite() error
	Detach() error
}

type helperExecConn struct {
	message            helperMessageConnection
	target             *resolver.TerminalTarget
	request            ExecRequest
	streamID           uint32
	events             chan ExecEvent
	done               chan struct{}
	inputSeq           atomic.Uint64
	resizeSeq          atomic.Uint64
	writeMu            sync.Mutex
	pendingMu          sync.Mutex
	pending            map[string]chan helperFrame
	readMu             sync.Mutex
	readPending        []byte
	lastOutputSequence uint64
	pendingEnd         *helperFrame
	finishOnce         sync.Once
	terminalSeen       atomic.Bool
	closeOnce          sync.Once
	exitCode           int
	exitErr            error
}

func (t *PeerTerminalTunnel) DialExec(ctx context.Context, info resolver.ConnectInfo, request ExecRequest) (ExecConn, error) {
	connection, err := t.dial(ctx, info, "exec", peerApplication{operationID: request.OperationID, helper: func(attachCtx context.Context, message helperMessageConnection, target *resolver.TerminalTarget) (Conn, error) {
		exec := &helperExecConn{message: message, target: target, request: request, events: make(chan ExecEvent, 256), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
		if err := exec.initialize(attachCtx); err != nil {
			return nil, err
		}
		return exec, nil
	}}, nil)
	if err != nil {
		return nil, err
	}
	exec, ok := connection.(ExecConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrPeerTerminalInvalid
	}
	return exec, nil
}

func (c *helperExecConn) initialize(ctx context.Context) error {
	if c.request.OperationID == "" || len(c.request.Argv) == 0 || c.request.Timeout < 0 || c.request.Timeout > 24*time.Hour {
		return errors.New("invalid remote execution request")
	}
	action := "start"
	if c.request.FromSequence > 0 {
		action = "attach"
	}
	payload, err := json.Marshal(map[string]any{
		"action": action, "operation_id": c.request.OperationID, "argv": c.request.Argv, "cwd": c.request.CWD,
		"environment": c.request.Environment, "timeout_ms": c.request.Timeout.Milliseconds(), "pty": c.request.PTY,
		"columns": c.request.Columns, "rows": c.request.Rows, "from_sequence": c.request.FromSequence,
	})
	if err != nil {
		return err
	}
	frame, err := helperRequestSyncOperation(ctx, c.message, "exec.v1", c.request.OperationID, payload)
	if err != nil {
		return err
	}
	var response struct {
		Result struct {
			StreamID uint32 `json:"stream_id"`
			Snapshot struct {
				OperationID string      `json:"operation_id"`
				State       string      `json:"state"`
				Result      *ExecResult `json:"result"`
				ErrorCode   string      `json:"error_code"`
			} `json:"snapshot"`
		} `json:"result"`
	}
	if json.Unmarshal(frame.Payload, &response) != nil || response.Result.StreamID == 0 || response.Result.Snapshot.OperationID != c.request.OperationID {
		return errors.New("helper returned an invalid execution attachment")
	}
	c.streamID = response.Result.StreamID
	c.emit(ExecEvent{OperationID: c.request.OperationID, State: "started"})
	go c.readLoop()
	return nil
}

func helperRequestSyncOperation(ctx context.Context, message helperMessageConnection, capability, operationID string, payload json.RawMessage) (helperFrame, error) {
	requestID := helperID("req_")
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: operationID, Capability: capability, DeadlineMS: uint32(helperRequestTimeout / time.Millisecond), Payload: payload}
	if err := writeHelperFrame(ctx, message, frame); err != nil {
		return helperFrame{}, err
	}
	response, err := readHelperStructured(ctx, message)
	if err != nil {
		return helperFrame{}, &ExecStartUncertainError{Cause: err}
	}
	if response.RequestID != requestID {
		return helperFrame{}, errors.New("helper returned an unrelated execution response")
	}
	if response.Type == "error" {
		return helperFrame{}, decodeHelperError(response)
	}
	if response.Type != "response" {
		return helperFrame{}, errors.New("helper returned an invalid execution response")
	}
	return response, nil
}

func (c *helperExecConn) readLoop() {
	defer close(c.events)
	for {
		kind, data, err := c.message.ReadMessage(context.Background())
		if err != nil {
			if c.terminalSeen.Load() {
				return
			}
			c.finish(1, errors.Join(ErrTransportLost, err))
			return
		}
		switch kind {
		case helperBinaryMessage:
			frame, decodeErr := protocol.DecodeTerminalOutput(data)
			if decodeErr != nil || frame.StreamID != c.streamID || len(frame.Data) < 9 || frame.Data[0] != 1 {
				c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid execution output frame")))
				return
			}
			eventSequence := binary.BigEndian.Uint64(frame.Data[1:9])
			stream := "stdout"
			if frame.Channel == protocol.Stderr {
				stream = "stderr"
			}
			c.emit(ExecEvent{OperationID: c.request.OperationID, EventSequence: eventSequence, Stream: stream, Sequence: frame.StartSequence, Data: append([]byte(nil), frame.Data[9:]...)})
			if eventSequence > c.lastOutputSequence {
				c.lastOutputSequence = eventSequence
			}
			if c.pendingEnd != nil {
				pending := *c.pendingEnd
				if c.handleEnd(pending) {
					return
				}
			}
		case helperStructuredMessage:
			frame, decodeErr := decodeHelperFrame(data)
			if decodeErr != nil {
				c.finish(1, errors.Join(ErrTransportLost, decodeErr))
				return
			}
			if frame.Type == "heartbeat" {
				_ = writeHelperFrame(context.Background(), c.message, frame)
				continue
			}
			if frame.Type == "event" {
				if c.handleEnd(frame) {
					return
				}
				continue
			}
			if frame.Type == "error" && frame.RequestID == "stream" {
				remoteErr := decodeHelperError(frame)
				code := "exec_result_unavailable"
				var remote *helperRemoteError
				if errors.As(remoteErr, &remote) && remote.Code != "replay_gap" {
					code = remote.Code
				}
				c.emit(ExecEvent{OperationID: c.request.OperationID, State: "failed", ErrorCode: code})
				c.finish(1, &RemoteExecError{Code: code})
				return
			}
			c.pendingMu.Lock()
			response := c.pending[frame.RequestID]
			c.pendingMu.Unlock()
			if response != nil {
				response <- frame
			}
		}
	}
}

func (c *helperExecConn) handleEnd(frame helperFrame) bool {
	var event struct {
		Event              string      `json:"event"`
		OperationID        string      `json:"operation_id"`
		State              string      `json:"state"`
		Result             *ExecResult `json:"result"`
		ErrorCode          string      `json:"error_code"`
		Sequence           uint64      `json:"sequence"`
		LastOutputSequence uint64      `json:"last_output_sequence"`
	}
	if json.Unmarshal(frame.Payload, &event) != nil || event.Event != "exec_stream_end" || event.OperationID != c.request.OperationID {
		c.finish(1, errors.Join(ErrTransportLost, errors.New("invalid execution terminal event")))
		return true
	}
	if event.LastOutputSequence > c.lastOutputSequence {
		pending := frame
		c.pendingEnd = &pending
		return false
	}
	c.pendingEnd = nil
	c.terminalSeen.Store(true)
	c.emit(ExecEvent{OperationID: event.OperationID, EventSequence: event.Sequence, State: event.State, Result: event.Result, ErrorCode: event.ErrorCode})
	code := 0
	if event.Result != nil {
		code = event.Result.Code
		if code == 0 && event.Result.Signal != "" {
			code = signalExitCode(event.Result.Signal)
		}
	}
	if event.State == "failed" || event.State == "canceled" {
		c.finish(code, &RemoteExecError{Code: firstNonEmptyExec(event.ErrorCode, event.State)})
	} else {
		c.finish(code, nil)
	}
	return true
}

func (c *helperExecConn) emit(event ExecEvent) {
	select {
	case c.events <- event:
	case <-c.done:
	}
}

func (c *helperExecConn) control(action string, values map[string]any) error {
	requestID, frame, err := c.controlFrame(action, values)
	if err != nil {
		return err
	}
	response := make(chan helperFrame, 1)
	c.pendingMu.Lock()
	c.pending[requestID] = response
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, requestID)
		c.pendingMu.Unlock()
	}()
	if err := c.writeControl(context.Background(), frame); err != nil {
		return err
	}
	select {
	case frame := <-response:
		if frame.Type == "error" {
			return decodeHelperError(frame)
		}
		return nil
	case <-c.done:
		return c.waitError()
	case <-time.After(helperRequestTimeout):
		return errors.New("helper execution control outcome is uncertain")
	}
}

func (c *helperExecConn) controlFrame(action string, values map[string]any) (string, helperFrame, error) {
	values["action"], values["operation_id"] = action, c.request.OperationID
	payload, err := json.Marshal(values)
	if err != nil {
		return "", helperFrame{}, err
	}
	requestID := helperID("req_")
	frame := helperFrame{Type: "request", RequestID: requestID, Version: helperProtocolVersion, OperationID: c.request.OperationID, Capability: "exec.v1", DeadlineMS: uint32(helperRequestTimeout / time.Millisecond), Payload: payload}
	return requestID, frame, nil
}

func (c *helperExecConn) writeControl(ctx context.Context, frame helperFrame) error {
	c.writeMu.Lock()
	err := writeHelperFrame(ctx, c.message, frame)
	c.writeMu.Unlock()
	return err
}

func (c *helperExecConn) Events() <-chan ExecEvent { return c.events }

func (c *helperExecConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readPending) == 0 {
		event, ok := <-c.events
		if !ok {
			return 0, io.EOF
		}
		c.readPending = append(c.readPending, event.Data...)
	}
	n := copy(p, c.readPending)
	c.readPending = c.readPending[n:]
	return n, nil
}

func (c *helperExecConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for len(p) > 0 {
		size := min(len(p), helperInputChunkBytes)
		message := make([]byte, 13+size)
		message[0] = 1
		binary.BigEndian.PutUint32(message[1:5], c.streamID)
		binary.BigEndian.PutUint64(message[5:13], c.inputSeq.Add(1))
		copy(message[13:], p[:size])
		c.writeMu.Lock()
		err := c.message.WriteMessage(context.Background(), helperBinaryMessage, message)
		c.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func (c *helperExecConn) CloseWrite() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, frame, err := c.controlFrame("close-input", map[string]any{})
	if err != nil {
		return err
	}
	return c.writeControl(ctx, frame)
}
func (c *helperExecConn) Cancel() error { return c.control("cancel", map[string]any{}) }
func (c *helperExecConn) Signal(signal string) error {
	return c.control("signal", map[string]any{"signal": signal})
}
func (c *helperExecConn) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	message := make([]byte, 17)
	message[0] = 4
	binary.BigEndian.PutUint32(message[1:5], c.streamID)
	binary.BigEndian.PutUint16(message[5:7], cols)
	binary.BigEndian.PutUint16(message[7:9], rows)
	binary.BigEndian.PutUint64(message[9:17], c.resizeSeq.Add(1))
	c.writeMu.Lock()
	err := c.message.WriteMessage(context.Background(), helperBinaryMessage, message)
	c.writeMu.Unlock()
	return err
}
func (c *helperExecConn) Close() error {
	c.closeOnce.Do(func() {
		cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, frame, frameErr := c.controlFrame("cancel", map[string]any{})
		if frameErr == nil {
			_ = c.writeControl(cancelCtx, frame)
		}
		cancel()
		_ = c.message.Close()
	})
	return nil
}
func (c *helperExecConn) Detach() error {
	c.closeOnce.Do(func() {
		_ = c.message.Close()
	})
	return nil
}
func (c *helperExecConn) Wait() (int, error) {
	<-c.done
	return c.exitCode, c.exitErr
}
func (c *helperExecConn) finish(code int, err error) {
	c.finishOnce.Do(func() {
		c.exitCode, c.exitErr = code, err
		close(c.done)
	})
}
func (c *helperExecConn) waitError() error {
	if c.exitErr != nil {
		return c.exitErr
	}
	return io.EOF
}

func firstNonEmptyExec(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "remote execution failed"
}
