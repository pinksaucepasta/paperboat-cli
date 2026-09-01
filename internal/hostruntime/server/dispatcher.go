package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configapply"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/history"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

type HealthSource interface{ Snapshot() health.Snapshot }
type SessionLauncher interface {
	Launch(context.Context, process.LaunchRequest) (session.Snapshot, error)
}

type DispatcherConfig struct {
	Sessions        *session.Manager
	ConfigApply     configapply.Handler
	Health          HealthSource
	SessionLauncher SessionLauncher
	WorkspaceRoot   string
	Random          io.Reader
	Now             func() time.Time
	Writers         *filetransfer.WriterRegistry
	Exec            *execprocess.Manager
	SSH             *managedssh.Host
}

type Dispatcher struct {
	config DispatcherConfig
	ssh    sshStreamRegistry
}

type terminalOutputStream struct {
	manager      *session.Manager
	sessionID    string
	attachmentID string
	writers      *filetransfer.WriterRegistry
}

const terminalExitObservationInterval = 100 * time.Millisecond

func NewDispatcher(config DispatcherConfig) (*Dispatcher, error) {
	if config.Sessions == nil || config.Health == nil || config.SessionLauncher == nil || !filepath.IsAbs(config.WorkspaceRoot) || config.Random == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Dispatcher{config: config}, nil
}

func (d *Dispatcher) Capabilities() []string {
	capabilities := []string{"terminal.v1", "health.v1"}
	if d.config.ConfigApply != nil {
		capabilities = append(capabilities, "config.apply.v1")
	}
	if d.config.Exec != nil {
		capabilities = append(capabilities, "exec.v1")
	}
	if d.config.SSH != nil {
		capabilities = append(capabilities, "ssh.v1")
	}
	return capabilities
}

func (d *Dispatcher) Handle(ctx context.Context, authorization Authorization, capability string, payload json.RawMessage) operation.Outcome {
	switch capability {
	case "terminal.v1":
		return d.terminal(ctx, authorization, payload)
	case "health.v1":
		return result(d.config.Health.Snapshot())
	case "config.apply.v1":
		return d.configApply(ctx, authorization, payload)
	case "exec.v1":
		return d.exec(ctx, payload)
	case "ssh.v1":
		return d.sshRequest(payload)
	default:
		return failure("capability_required")
	}
}

func (d *Dispatcher) HandleOperation(ctx context.Context, authorization Authorization, capability, operationID string, payload json.RawMessage) operation.Outcome {
	if capability == "exec.v1" {
		var request execRequest
		if decodeStrict(payload, &request) != nil || request.OperationID != operationID {
			return failure("invalid_request")
		}
	}
	if capability == "ssh.v1" {
		var request sshRequest
		if decodeStrict(payload, &request) != nil || request.OperationID != operationID {
			return failure("invalid_request")
		}
	}
	return d.Handle(ctx, authorization, capability, payload)
}

type configApplyRequest struct {
	Action           string `json:"action"`
	AssignmentID     string `json:"assignment_id"`
	ExpectedRevision string `json:"expected_revision"`
	ObservedRevision string `json:"observed_revision"`
}

func (d *Dispatcher) configApply(ctx context.Context, authorization Authorization, payload json.RawMessage) operation.Outcome {
	if d.config.ConfigApply == nil {
		return failure("capability_required")
	}
	var request configApplyRequest
	if decodeStrict(payload, &request) != nil || authorization.ResourceID == "" || request.AssignmentID != authorization.ResourceID {
		return failure("not_found_or_forbidden")
	}
	value, err := d.config.ConfigApply.Handle(ctx, configapply.Request{
		Action: request.Action, AssignmentID: request.AssignmentID,
		ExpectedRevision: request.ExpectedRevision, ObservedRevision: request.ObservedRevision,
	})
	return domainResult(value, err)
}

type attachmentControl struct {
	SessionID    string `json:"session_id"`
	AttachmentID string `json:"attachment_id"`
	NextSequence uint64 `json:"next_sequence,omitempty"`
}

func (d *Dispatcher) HandleTerminalInput(_ context.Context, authorization Authorization, sessionID, attachmentID string, generation, inputSequence uint64, data []byte) (session.InputDecision, error) {
	if authorization.ClientID == "" || sessionID == "" || attachmentID == "" || generation == 0 || (authorization.SessionID != "" && authorization.SessionID != sessionID) {
		return session.InputDecision{InputSequence: inputSequence}, session.ErrInvalidInput
	}
	decision, err := d.config.Sessions.Write(sessionID, session.InputKey{ClientID: authorization.ClientID, AttachmentID: attachmentID, Generation: generation, InputSequence: inputSequence}, data)
	if err == nil && d.config.Writers != nil && decision.Status != session.InputUncertain {
		d.config.Writers.Input(sessionID, attachmentID, authorization.ClientID, d.config.Now())
	}
	if decision.InputSequence == 0 {
		decision.InputSequence = inputSequence
	}
	return decision, err
}

func (d *Dispatcher) HandleTerminalACK(_ context.Context, authorization Authorization, sessionID, attachmentID string, nextSequence uint64) error {
	if authorization.ClientID == "" || sessionID == "" || attachmentID == "" || (authorization.SessionID != "" && authorization.SessionID != sessionID) {
		return session.ErrInvalidInput
	}
	return d.config.Sessions.Acknowledge(sessionID, attachmentID, nextSequence)
}

func (d *Dispatcher) HandleTerminalResize(_ context.Context, authorization Authorization, sessionID, attachmentID string, columns, rows uint16) error {
	if authorization.ClientID == "" || sessionID == "" || attachmentID == "" || columns == 0 || rows == 0 || (authorization.SessionID != "" && authorization.SessionID != sessionID) {
		return session.ErrInvalidInput
	}
	return d.config.Sessions.Resize(sessionID, attachmentID, pty.Dimensions{Columns: columns, Rows: rows}, d.config.Now())
}

func (d *Dispatcher) HandleExecInput(_ context.Context, authorization Authorization, operationID string, data []byte) error {
	if d.config.Exec == nil || authorization.ClientID == "" || operationID == "" || len(data) == 0 {
		return execprocess.ErrInvalid
	}
	execution, err := d.config.Exec.Get(operationID)
	if err != nil {
		return err
	}
	_, err = execution.Write(data)
	return err
}

func (d *Dispatcher) HandleExecResize(_ context.Context, authorization Authorization, operationID string, columns, rows uint16) error {
	if d.config.Exec == nil || authorization.ClientID == "" || operationID == "" || columns == 0 || rows == 0 {
		return execprocess.ErrInvalid
	}
	execution, err := d.config.Exec.Get(operationID)
	if err != nil {
		return err
	}
	return execution.Resize(pty.Dimensions{Columns: columns, Rows: rows})
}

func (d *Dispatcher) HandleControl(_ context.Context, authorization Authorization, frame protocol.Frame) operation.Outcome {
	var control attachmentControl
	if decodeStrict(frame.Payload, &control) != nil || control.SessionID == "" || control.AttachmentID == "" || authorization.ClientID == "" {
		return failure("invalid_request")
	}
	if authorization.SessionID != "" && authorization.SessionID != control.SessionID {
		return failure("not_found_or_forbidden")
	}
	var err error
	switch frame.Type {
	case "ack":
		err = d.config.Sessions.Acknowledge(control.SessionID, control.AttachmentID, control.NextSequence)
	case "detach":
		err = d.config.Sessions.Detach(control.SessionID, control.AttachmentID)
		if err == nil && d.config.Writers != nil {
			d.config.Writers.Detach(control.SessionID, control.AttachmentID)
		}
	default:
		return failure("invalid_request")
	}
	return domainResult(struct{}{}, err)
}

func (d *Dispatcher) OpenStream(ctx context.Context, authorization Authorization, capability string, payload json.RawMessage, outcome operation.Outcome, replay bool) (OutputStream, bool, error) {
	if capability == "ssh.v1" {
		return d.openSSHStream(ctx, authorization, payload, outcome)
	}
	if capability == "exec.v1" && outcome.ErrorCode == "" {
		var request execRequest
		if decodeStrict(payload, &request) != nil || request.OperationID == "" || request.Action != "start" && request.Action != "attach" {
			return nil, false, nil
		}
		execution, err := d.config.Exec.Get(request.OperationID)
		if err != nil {
			return nil, false, err
		}
		from := request.FromSequence
		if from == 0 {
			from = 1
		}
		reader, err := execution.OpenReader(from)
		if err != nil {
			return nil, false, err
		}
		return &execOutputStream{execution: execution, reader: reader}, true, nil
	}
	if capability != "terminal.v1" || outcome.ErrorCode != "" {
		return nil, false, nil
	}
	var request terminalRequest
	if decodeStrict(payload, &request) != nil || request.Action != "attach" {
		return nil, false, nil
	}
	var response struct {
		AttachmentID  string `json:"attachment_id"`
		InputSequence uint64 `json:"input_sequence"`
	}
	if json.Unmarshal(outcome.Result, &response) != nil || response.AttachmentID == "" {
		return nil, false, ErrInvalidConfiguration
	}
	if replay {
		var err error
		if request.AtLiveBoundary {
			_, err = d.config.Sessions.AttachLive(request.SessionID, response.AttachmentID)
		} else {
			_, err = d.config.Sessions.Attach(request.SessionID, response.AttachmentID, request.FromSequence)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if d.config.Writers != nil {
		d.config.Writers.Attach(request.SessionID, response.AttachmentID, authorization.ClientID, authorization.SourceMachineID)
	}
	return &terminalOutputStream{manager: d.config.Sessions, sessionID: request.SessionID, attachmentID: response.AttachmentID, writers: d.config.Writers}, true, nil
}

type execRequest struct {
	Action       string            `json:"action"`
	OperationID  string            `json:"operation_id"`
	Argv         []string          `json:"argv,omitempty"`
	CWD          string            `json:"cwd,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
	TimeoutMS    uint32            `json:"timeout_ms,omitempty"`
	PTY          bool              `json:"pty,omitempty"`
	Columns      uint16            `json:"columns,omitempty"`
	Rows         uint16            `json:"rows,omitempty"`
	FromSequence uint64            `json:"from_sequence,omitempty"`
	Data         []byte            `json:"data,omitempty"`
	Signal       string            `json:"signal,omitempty"`
}

func (d *Dispatcher) exec(ctx context.Context, payload json.RawMessage) operation.Outcome {
	if d.config.Exec == nil {
		return failure("capability_required")
	}
	var request execRequest
	if decodeStrict(payload, &request) != nil || request.OperationID == "" {
		return failure("invalid_request")
	}
	switch request.Action {
	case "start":
		execution, replay, err := d.config.Exec.Start(ctx, execprocess.Request{OperationID: request.OperationID, Argv: request.Argv, CWD: request.CWD, Environment: request.Environment, Timeout: time.Duration(request.TimeoutMS) * time.Millisecond, PTY: request.PTY, Dimensions: pty.Dimensions{Columns: request.Columns, Rows: request.Rows}})
		if err != nil {
			return execResult(nil, err)
		}
		return result(struct {
			Snapshot execprocess.Snapshot `json:"snapshot"`
			Replay   bool                 `json:"replay"`
		}{execution.Snapshot(), replay})
	case "attach":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err != nil {
			return execResult(nil, err)
		}
		return result(struct {
			Snapshot execprocess.Snapshot `json:"snapshot"`
			Replay   bool                 `json:"replay"`
		}{execution.Snapshot(), true})
	case "status":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err != nil {
			return execResult(nil, err)
		}
		return result(execution.Snapshot())
	case "input":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err == nil {
			_, err = execution.Write(request.Data)
		}
		return execResult(struct{}{}, err)
	case "close-input":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err == nil {
			err = execution.CloseInput()
		}
		return execResult(struct{}{}, err)
	case "signal":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err == nil {
			err = execution.Signal(pty.Signal(request.Signal))
		}
		return execResult(struct{}{}, err)
	case "resize":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err == nil {
			err = execution.Resize(pty.Dimensions{Columns: request.Columns, Rows: request.Rows})
		}
		return execResult(struct{}{}, err)
	case "cancel":
		execution, err := d.config.Exec.Get(request.OperationID)
		if err == nil {
			cancelCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = execution.Cancel(cancelCtx)
			cancel()
		}
		return execResult(struct{}{}, err)
	default:
		return failure("invalid_request")
	}
}

func execResult(value any, err error) operation.Outcome {
	switch {
	case err == nil:
		return result(value)
	case errors.Is(err, execprocess.ErrNotFound):
		return failure("not_found_or_forbidden")
	case errors.Is(err, execprocess.ErrConflict):
		return failure("exec_already_running")
	case errors.Is(err, execprocess.ErrCapacity):
		return failure("resource_limit")
	case errors.Is(err, execprocess.ErrReplayUnavailable):
		return failure("exec_result_unavailable")
	default:
		return failure("invalid_request")
	}
}

type execOutputStream struct {
	execution          *execprocess.Execution
	reader             *execprocess.Reader
	lastOutputSequence uint64
}

const execOutputEnvelopeVersion = byte(1)

func encodeExecOutput(sequence uint64, data []byte) []byte {
	encoded := make([]byte, 9+len(data))
	encoded[0] = execOutputEnvelopeVersion
	binary.BigEndian.PutUint64(encoded[1:9], sequence)
	copy(encoded[9:], data)
	return encoded
}

func (s *execOutputStream) Next(ctx context.Context) (protocol.BinaryFrame, error) {
	for {
		event, release, err := s.reader.Next(ctx)
		if errors.Is(err, execprocess.ErrReplayUnavailable) {
			return protocol.BinaryFrame{}, &StreamError{Code: "replay_gap", CloseCode: protocol.CloseReplayGap}
		}
		if err != nil {
			return protocol.BinaryFrame{}, err
		}
		if len(event.Data) != 0 {
			s.lastOutputSequence = event.Sequence
			channel := protocol.Stdout
			if event.Stream == "stderr" {
				channel = protocol.Stderr
			}
			return protocol.BinaryFrame{Channel: channel, StartSequence: event.StreamSequence, Data: encodeExecOutput(event.Sequence, event.Data), Release: release}, nil
		}
		release()
		if event.State == execprocess.StateExited || event.State == execprocess.StateSignaled || event.State == execprocess.StateCanceled || event.State == execprocess.StateFailed {
			payload, marshalErr := json.Marshal(struct {
				Event              string              `json:"event"`
				OperationID        string              `json:"operation_id"`
				State              execprocess.State   `json:"state"`
				Result             *execprocess.Result `json:"result,omitempty"`
				ErrorCode          string              `json:"error_code,omitempty"`
				Sequence           uint64              `json:"sequence"`
				LastOutputSequence uint64              `json:"last_output_sequence,omitempty"`
			}{"exec_stream_end", s.execution.Snapshot().OperationID, event.State, event.Result, event.ErrorCode, event.Sequence, s.lastOutputSequence})
			if marshalErr != nil {
				return protocol.BinaryFrame{}, marshalErr
			}
			return protocol.BinaryFrame{}, &StreamEnd{Payload: payload}
		}
	}
}

func (s *execOutputStream) Close() error {
	if s == nil || s.reader == nil {
		return nil
	}
	return s.reader.Close()
}

func (s *terminalOutputStream) Next(ctx context.Context) (protocol.BinaryFrame, error) {
	for {
		waitCtx, cancel := context.WithTimeout(ctx, terminalExitObservationInterval)
		event, err := s.manager.WaitNext(waitCtx, s.sessionID, s.attachmentID)
		cancel()
		if err == nil {
			return protocol.BinaryFrame{Channel: event.Channel, StartSequence: event.StartSequence, Data: event.Data, Release: event.Release}, nil
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			snapshot, snapshotErr := s.manager.Snapshot(s.sessionID)
			if snapshotErr != nil {
				return protocol.BinaryFrame{}, snapshotErr
			}
			if snapshot.State != session.Exited && snapshot.State != session.Closed {
				continue
			}
			payload, marshalErr := json.Marshal(struct {
				Event         string          `json:"event"`
				SessionID     string          `json:"session_id"`
				State         session.State   `json:"state"`
				FinalSequence uint64          `json:"final_sequence"`
				Exit          *pty.ExitResult `json:"exit,omitempty"`
			}{"terminal_stream_end", snapshot.ID, snapshot.State, snapshot.LatestSequence, snapshot.Exit})
			if marshalErr != nil {
				return protocol.BinaryFrame{}, marshalErr
			}
			return protocol.BinaryFrame{}, &StreamEnd{Payload: payload}
		}
		if errors.Is(err, session.ErrAttachmentEvicted) {
			_, queued, _ := s.manager.AttachmentStatus(s.sessionID, s.attachmentID)
			details, _ := json.Marshal(struct {
				QueuedBytes uint64 `json:"queued_bytes"`
			}{queued})
			return protocol.BinaryFrame{}, &StreamError{Code: "slow_consumer", Details: details, CloseCode: protocol.CloseSlowConsumer}
		}
		if errors.Is(err, session.ErrInvalidTransition) || errors.Is(err, session.ErrAttachmentUnknown) {
			return protocol.BinaryFrame{}, ErrStreamClosed
		}
		return protocol.BinaryFrame{}, err
	}
}

func (s *terminalOutputStream) Close() error {
	err := s.manager.Detach(s.sessionID, s.attachmentID)
	if s.writers != nil {
		s.writers.Detach(s.sessionID, s.attachmentID)
	}
	return err
}

type terminalRequest struct {
	Action         string            `json:"action"`
	OperationID    string            `json:"operation_id,omitempty"`
	Name           string            `json:"name,omitempty"`
	CWD            string            `json:"cwd,omitempty"`
	SessionID      string            `json:"session_id,omitempty"`
	AttachmentID   string            `json:"attachment_id,omitempty"`
	FromSequence   uint64            `json:"from_sequence,omitempty"`
	AtLiveBoundary bool              `json:"at_live_boundary,omitempty"`
	Generation     uint64            `json:"generation,omitempty"`
	Columns        uint16            `json:"columns,omitempty"`
	Rows           uint16            `json:"rows,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	Signal         string            `json:"signal,omitempty"`
	// ExistingSnapshot asks create to return the current snapshot instead of
	// failing when the session already exists. Responses to such creates carry
	// an "existing" flag so the client can pick the right attach boundary.
	ExistingSnapshot bool `json:"existing_snapshot,omitempty"`
}

type terminalAttachResponse struct {
	StreamID      uint32 `json:"stream_id,omitempty"`
	AttachmentID  string `json:"attachment_id"`
	InputSequence uint64 `json:"input_sequence,omitempty"`
	Session       struct {
		Snapshot session.Snapshot `json:"snapshot"`
		Replay   struct {
			FromSequence     uint64 `json:"from_sequence"`
			ToSequence       uint64 `json:"to_sequence"`
			EarliestSequence uint64 `json:"earliest_sequence"`
			LatestSequence   uint64 `json:"latest_sequence"`
		} `json:"replay"`
	} `json:"session"`
}

func newTerminalAttachResponse(attachmentID string, attached session.AttachResult) terminalAttachResponse {
	response := terminalAttachResponse{AttachmentID: attachmentID}
	response.Session.Snapshot = attached.Snapshot
	response.Session.Replay.FromSequence = attached.Replay.FromSequence
	response.Session.Replay.ToSequence = attached.Replay.ToSequence
	response.Session.Replay.EarliestSequence = attached.Replay.EarliestSequence
	response.Session.Replay.LatestSequence = attached.Replay.LatestSequence
	return response
}

func (d *Dispatcher) terminal(ctx context.Context, authorization Authorization, payload json.RawMessage) operation.Outcome {
	var request terminalRequest
	if decodeStrict(payload, &request) != nil || authorization.ClientID == "" {
		return failure("invalid_request")
	}
	if authorization.SessionID != "" && request.SessionID != "" && authorization.SessionID != request.SessionID {
		return failure("not_found_or_forbidden")
	}
	switch request.Action {
	case "list":
		if authorization.SessionID != "" {
			value, err := d.config.Sessions.Snapshot(authorization.SessionID)
			if err != nil {
				return domainResult(nil, err)
			}
			return result(struct {
				Sessions []session.Snapshot `json:"sessions"`
			}{[]session.Snapshot{value}})
		}
		return result(struct {
			Sessions []session.Snapshot `json:"sessions"`
		}{d.config.Sessions.List()})
	case "get", "snapshot":
		value, err := d.config.Sessions.Snapshot(request.SessionID)
		return domainResult(value, err)
	case "transfer-destinations":
		value, err := d.config.Sessions.Snapshot(request.SessionID)
		if err != nil {
			return domainResult(nil, err)
		}
		eligible := []string{}
		if d.config.Writers != nil {
			eligible = d.config.Writers.EligibleMachines(request.SessionID)
		}
		return result(struct {
			session.Snapshot
			EligibleTransferDestinationMachineIDs []string `json:"eligible_transfer_destination_machine_ids"`
		}{Snapshot: value, EligibleTransferDestinationMachineIDs: eligible})
	case "create":
		cwd, ok := d.cwd(request.CWD)
		if request.SessionID == "" {
			request.SessionID = authorization.SessionID
		}
		if !ok || request.Columns == 0 || request.Rows == 0 {
			return failure("invalid_request")
		}
		value, err := d.config.SessionLauncher.Launch(ctx, process.LaunchRequest{ID: request.SessionID, Name: request.Name, CWD: cwd, Dimensions: pty.Dimensions{Columns: request.Columns, Rows: request.Rows}, Environment: request.Environment})
		if request.ExistingSnapshot {
			// create-or-get lets one round trip both create a fresh session
			// and resolve an already-running one. A name collision without a
			// matching session ID keeps the original failure so clients
			// cannot claim another session's name.
			if errors.Is(err, session.ErrSessionExists) {
				if snapshot, snapshotErr := d.config.Sessions.Snapshot(request.SessionID); snapshotErr == nil {
					return result(struct {
						session.Snapshot
						Existing bool `json:"existing"`
					}{Snapshot: snapshot, Existing: true})
				}
			}
			if err == nil {
				return result(struct {
					session.Snapshot
					Existing bool `json:"existing"`
				}{Snapshot: value, Existing: false})
			}
		}
		return domainResult(value, err)
	case "attach", "replay":
		attachmentID := request.AttachmentID
		if attachmentID == "" {
			attachmentID = d.randomID("att_")
		}
		if attachmentID == "" {
			return failure("unavailable")
		}
		var value session.AttachResult
		var err error
		if request.Action == "attach" && request.AtLiveBoundary {
			value, err = d.config.Sessions.AttachLive(request.SessionID, attachmentID)
		} else {
			value, err = d.config.Sessions.Attach(request.SessionID, attachmentID, request.FromSequence)
		}
		if err != nil {
			return domainResult(nil, err)
		}
		attachResponse := newTerminalAttachResponse(attachmentID, value)
		if attachResponse.InputSequence, err = d.config.Sessions.InputSequence(request.SessionID, authorization.ClientID, attachmentID, value.Snapshot.Generation); err != nil {
			return domainResult(nil, err)
		}
		// Replay bytes travel as binary frames after this control response. Keeping
		// them out of JSON prevents a terminal-sized replay from overflowing the
		// structured-frame limit and avoids delivering the same output twice.
		return result(attachResponse)
	case "detach":
		err := d.config.Sessions.Detach(request.SessionID, request.AttachmentID)
		if err == nil && d.config.Writers != nil {
			d.config.Writers.Detach(request.SessionID, request.AttachmentID)
		}
		return domainResult(struct{}{}, err)
	case "resize":
		err := d.config.Sessions.Resize(request.SessionID, request.AttachmentID, pty.Dimensions{Columns: request.Columns, Rows: request.Rows}, d.config.Now())
		return domainResult(struct{}{}, err)
	case "signal":
		err := d.config.Sessions.Signal(request.SessionID, request.Generation, pty.Signal(request.Signal))
		return domainResult(struct{}{}, err)
	case "clear":
		sequence, err := d.config.Sessions.Clear(request.SessionID)
		return domainResult(struct {
			Sequence uint64 `json:"sequence"`
		}{sequence}, err)
	case "restart":
		value, err := d.config.Sessions.Restart(request.SessionID)
		return domainResult(value, err)
	case "close":
		value, err := d.config.Sessions.Close(ctx, request.SessionID)
		if errors.Is(err, session.ErrSessionUnknown) {
			return result(session.Snapshot{ID: request.SessionID, State: session.Closed})
		}
		return domainResult(value, err)
	case "delete":
		err := d.config.Sessions.Delete(request.SessionID)
		if errors.Is(err, session.ErrSessionUnknown) {
			return result(struct{}{})
		}
		return domainResult(struct{}{}, err)
	default:
		return failure("invalid_request")
	}
}

func (d *Dispatcher) cwd(value string) (string, bool) {
	if value == "" {
		value = d.config.WorkspaceRoot
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(d.config.WorkspaceRoot, value)
	}
	clean := filepath.Clean(value)
	relative, err := filepath.Rel(d.config.WorkspaceRoot, clean)
	return clean, err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (d *Dispatcher) randomID(prefix string) string {
	var data [16]byte
	if _, err := io.ReadFull(d.config.Random, data[:]); err != nil {
		return ""
	}
	return prefix + hex.EncodeToString(data[:])
}

func decodeStrict(payload []byte, target any) error {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func result(value any) operation.Outcome {
	encoded, err := json.Marshal(value)
	if err != nil {
		return failure("unavailable")
	}
	return operation.Outcome{Result: encoded}
}

func failure(code string) operation.Outcome { return operation.Outcome{ErrorCode: code} }

func failureDetails(code string, details any) operation.Outcome {
	encoded, err := json.Marshal(details)
	if err != nil {
		return failure("unavailable")
	}
	return operation.Outcome{ErrorCode: code, Result: encoded}
}

func domainResult(value any, err error) operation.Outcome {
	if err == nil {
		return result(value)
	}
	var gap *history.GapError
	if errors.As(err, &gap) {
		return failureDetails("replay_gap", struct {
			RequestedSequence uint64 `json:"requested_sequence"`
			EarliestSequence  uint64 `json:"earliest_sequence"`
			LatestSequence    uint64 `json:"latest_sequence"`
		}{gap.RequestedSequence, gap.EarliestSequence, gap.LatestSequence})
	}
	var stale *session.StaleGenerationError
	if errors.As(err, &stale) {
		return failureDetails("stale_generation", struct {
			CurrentGeneration uint64 `json:"current_generation"`
		}{stale.CurrentGeneration})
	}
	switch {
	case errors.Is(err, context.Canceled):
		return failure("operation_canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return failure("deadline_exceeded")
	case errors.Is(err, session.ErrSessionUnknown):
		return failure("not_found_or_forbidden")
	case errors.Is(err, session.ErrSessionExists):
		return failure("session_exists")
	case errors.Is(err, session.ErrSessionRunning):
		return failure("session_running")
	case errors.Is(err, session.ErrStaleGeneration):
		return failure("stale_generation")
	case errors.Is(err, session.ErrInputConflict):
		return failure("input_id_conflict")
	case errors.Is(err, session.ErrInputUnknown):
		return failure("input_unknown")
	case errors.Is(err, session.ErrResourceLimit), errors.Is(err, session.ErrInputJournalFull):
		return failure("resource_limit")
	case errors.Is(err, configapply.ErrRevisionConflict):
		return failure("config_revision_conflict")
	case errors.Is(err, configapply.ErrInvalidRequest):
		return failure("invalid_request")
	default:
		return failure("invalid_request")
	}
}
