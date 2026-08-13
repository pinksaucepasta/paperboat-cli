package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type execMessage struct {
	kind helperMessageType
	data []byte
}

func TestHelperExecClassifiesLostStartResponseAsUncertain(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/true"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, target: &resolver.TerminalTarget{}, request: request, events: make(chan ExecEvent, 1), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-message.writes
		cancel()
	}()
	err := connection.initialize(ctx)
	var uncertain *ExecStartUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want uncertain start wrapping cancellation", err)
	}
}

func TestHelperExecReconnectUsesAttachAction(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/true"}, CWD: "/workspace", FromSequence: 4}
	connection := &helperExecConn{message: message, target: &resolver.TerminalTarget{}, request: request, events: make(chan ExecEvent, 1), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	captured := make(chan helperFrame, 1)
	go func() {
		written := <-message.writes
		var frame helperFrame
		if json.Unmarshal(written.data, &frame) != nil {
			return
		}
		captured <- frame
		payload, _ := json.Marshal(map[string]any{"result": map[string]any{"stream_id": 4, "snapshot": map[string]any{"operation_id": request.OperationID, "state": "running"}}})
		response, _ := json.Marshal(helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, OperationID: request.OperationID, Payload: payload})
		message.reads <- execMessage{kind: helperStructuredMessage, data: response}
	}()
	if err := connection.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal((<-captured).Payload, &payload); err != nil || payload.Action != "attach" {
		t.Fatalf("action=%q err=%v", payload.Action, err)
	}
	_ = connection.Detach()
}

func TestHelperExecMapsReplayGapToTerminalResultUnavailable(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/true"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, target: &resolver.TerminalTarget{}, request: request, events: make(chan ExecEvent, 8), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	go func() {
		written := <-message.writes
		var frame helperFrame
		_ = json.Unmarshal(written.data, &frame)
		payload, _ := json.Marshal(map[string]any{"result": map[string]any{"stream_id": 4, "snapshot": map[string]any{"operation_id": request.OperationID, "state": "running"}}})
		response, _ := json.Marshal(helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, OperationID: request.OperationID, Payload: payload})
		message.reads <- execMessage{kind: helperStructuredMessage, data: response}
	}()
	if err := connection.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	errorPayload := json.RawMessage(`{"code":"replay_gap","message":"output stream closed","retryable":false}`)
	wire, _ := json.Marshal(helperFrame{Type: "error", RequestID: "stream", Version: helperProtocolVersion, Payload: errorPayload})
	message.reads <- execMessage{kind: helperStructuredMessage, data: wire}
	var terminal ExecEvent
	for event := range connection.Events() {
		if event.State == "failed" {
			terminal = event
		}
	}
	_, err := connection.Wait()
	var remote *RemoteExecError
	if !errors.As(err, &remote) || remote.Code != "exec_result_unavailable" || terminal.ErrorCode != "exec_result_unavailable" {
		t.Fatalf("event=%#v err=%v", terminal, err)
	}
}

type execMessageConnection struct {
	reads  chan execMessage
	writes chan execMessage
	closed chan struct{}
	once   sync.Once
}

func newExecMessageConnection() *execMessageConnection {
	return &execMessageConnection{reads: make(chan execMessage, 8), writes: make(chan execMessage, 8), closed: make(chan struct{})}
}

func (c *execMessageConnection) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	select {
	case message := <-c.reads:
		return message.kind, message.data, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-c.closed:
		return 0, nil, context.Canceled
	}
}
func (c *execMessageConnection) WriteMessage(_ context.Context, kind helperMessageType, data []byte) error {
	c.writes <- execMessage{kind: kind, data: append([]byte(nil), data...)}
	return nil
}
func (c *execMessageConnection) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestHelperExecControlPreservesAuthenticatedOperation(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/true"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, request: request, events: make(chan ExecEvent, 1), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	captured := make(chan helperFrame, 1)
	go func() {
		written := <-message.writes
		var frame helperFrame
		_ = json.Unmarshal(written.data, &frame)
		captured <- frame
		response, _ := json.Marshal(helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion})
		message.reads <- execMessage{kind: helperStructuredMessage, data: response}
	}()
	go connection.readLoop()
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	frame := <-captured
	if frame.OperationID != request.OperationID {
		t.Fatalf("control operation id = %q, want authenticated execution id", frame.OperationID)
	}
	var payload struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(frame.Payload, &payload); err != nil || payload.OperationID != request.OperationID {
		t.Fatalf("payload operation id = %q err=%v", payload.OperationID, err)
	}
}

func TestHelperExecCloseDoesNotWaitForCancelResponse(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/sleep", "30"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, request: request, events: make(chan ExecEvent, 1), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	done := make(chan error, 1)
	go func() { done <- connection.Close() }()
	select {
	case written := <-message.writes:
		var frame helperFrame
		if err := json.Unmarshal(written.data, &frame); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Action      string `json:"action"`
			OperationID string `json:"operation_id"`
		}
		if err := json.Unmarshal(frame.Payload, &payload); err != nil || payload.Action != "cancel" || payload.OperationID != request.OperationID {
			t.Fatalf("cancel payload=%+v err=%v", payload, err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not send authenticated cancellation")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for a cancellation response")
	}
}

func TestHelperExecCloseWriteDoesNotWaitForResponse(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/cat"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, request: request, events: make(chan ExecEvent, 1), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	done := make(chan error, 1)
	go func() { done <- connection.CloseWrite() }()
	select {
	case written := <-message.writes:
		var frame helperFrame
		if err := json.Unmarshal(written.data, &frame); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Action      string `json:"action"`
			OperationID string `json:"operation_id"`
		}
		if err := json.Unmarshal(frame.Payload, &payload); err != nil || payload.Action != "close-input" || payload.OperationID != request.OperationID {
			t.Fatalf("close-input payload=%+v err=%v", payload, err)
		}
	case <-time.After(time.Second):
		t.Fatal("close-write did not send authenticated input EOF")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close-write waited for a control response")
	}
}

func TestHelperExecStreamsSeparatedOutputAndExactExit(t *testing.T) {
	message := newExecMessageConnection()
	request := ExecRequest{OperationID: "operation_exec_1", Argv: []string{"/bin/sh", "-c", "exit 7"}, CWD: "/workspace"}
	connection := &helperExecConn{message: message, target: &resolver.TerminalTarget{}, request: request, events: make(chan ExecEvent, 8), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	go func() {
		written := <-message.writes
		var frame helperFrame
		if json.Unmarshal(written.data, &frame) != nil {
			return
		}
		payload, _ := json.Marshal(map[string]any{"result": map[string]any{"stream_id": 4, "snapshot": map[string]any{"operation_id": request.OperationID, "state": "running"}}})
		response, _ := json.Marshal(helperFrame{Type: "response", RequestID: frame.RequestID, Version: helperProtocolVersion, OperationID: request.OperationID, Payload: payload})
		message.reads <- execMessage{kind: helperStructuredMessage, data: response}
	}()
	if err := connection.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	stdout, _ := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.Stdout, StreamID: 4, StartSequence: 0, Data: append([]byte{1, 0, 0, 0, 0, 0, 0, 0, 2}, []byte("out")...)}, nil)
	stderr, _ := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.Stderr, StreamID: 4, StartSequence: 0, Data: append([]byte{1, 0, 0, 0, 0, 0, 0, 0, 3}, []byte("err")...)}, nil)
	endPayload, _ := json.Marshal(map[string]any{"event": "exec_stream_end", "operation_id": request.OperationID, "state": "exited", "sequence": 4, "last_output_sequence": 3, "result": map[string]any{"code": 7, "exited_at": time.Now().UTC()}})
	end, _ := json.Marshal(helperFrame{Type: "event", RequestID: "stream", Version: helperProtocolVersion, Capability: "exec.v1", Payload: endPayload})
	message.reads <- execMessage{kind: helperStructuredMessage, data: end}
	message.reads <- execMessage{kind: helperBinaryMessage, data: stdout}
	message.reads <- execMessage{kind: helperBinaryMessage, data: stderr}
	events := make([]ExecEvent, 0, 4)
	for event := range connection.Events() {
		events = append(events, event)
	}
	code, err := connection.Wait()
	if err != nil || code != 7 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if len(events) != 4 || events[0].State != "started" || events[1].EventSequence != 2 || events[1].Stream != "stdout" || string(events[1].Data) != "out" || events[2].EventSequence != 3 || events[2].Stream != "stderr" || string(events[2].Data) != "err" || events[3].EventSequence != 4 || events[3].State != "exited" {
		t.Fatalf("events=%#v", events)
	}
}
