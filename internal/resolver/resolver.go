// Package resolver turns a project name into the information needed to connect:
// which environment and how to reach it through `paperboat-tunnel`. Production resolution calls
// paperboat-server's pre-connect broker.
package resolver

import (
	"context"
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
)

var ErrTerminalInputQueueFull = errors.New("terminal input queue is full")
var ErrTerminalInputUncertain = errors.New("terminal input delivery is uncertain")

type TerminalInput struct {
	Sequence uint64
	Data     []byte
}

// TerminalInputQueue is shared by all transport attempts for one terminal.
// It retains only bounded, unacknowledged input and never retransmits bytes on
// its own. A reconnect reconciles entries against the host's durable cursor;
// entries whose result cannot be recovered become uncertain and stop the
// queue until the caller explicitly handles them.
type TerminalInputQueue struct {
	mu        sync.Mutex
	next      uint64
	limit     int
	pending   map[uint64]TerminalInput
	uncertain bool
}

func NewTerminalInputQueue(limit int) *TerminalInputQueue {
	if limit < 1 {
		limit = 256
	}
	return &TerminalInputQueue{limit: limit, pending: make(map[uint64]TerminalInput)}
}

func (q *TerminalInputQueue) Enqueue(data []byte) (uint64, error) {
	if q == nil || len(data) == 0 {
		return 0, ErrTerminalInputQueueFull
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.uncertain {
		return 0, ErrTerminalInputUncertain
	}
	if len(q.pending) >= q.limit {
		return 0, ErrTerminalInputQueueFull
	}
	q.next++
	if q.next == 0 {
		return 0, ErrTerminalInputQueueFull
	}
	q.pending[q.next] = TerminalInput{Sequence: q.next, Data: append([]byte(nil), data...)}
	return q.next, nil
}

func (q *TerminalInputQueue) Complete(sequence uint64, status string) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.pending, sequence)
	if status == "uncertain" {
		q.uncertain = true
	}
	if sequence > q.next {
		q.next = sequence
	}
}

// Reconcile marks pending operations at or before the host cursor as
// uncertain. The host proves that those sequence numbers have a durable
// decision, but a lost response must never be interpreted as accepted.
func (q *TerminalInputQueue) Reconcile(hostSequence uint64) []TerminalInput {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	var uncertain []TerminalInput
	for sequence, item := range q.pending {
		if sequence <= hostSequence {
			uncertain = append(uncertain, item)
			delete(q.pending, sequence)
		}
	}
	if len(uncertain) != 0 {
		q.uncertain = true
	}
	if hostSequence > q.next {
		q.next = hostSequence
	}
	return uncertain
}

func (q *TerminalInputQueue) Pending() []TerminalInput {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	result := make([]TerminalInput, 0, len(q.pending))
	for _, item := range q.pending {
		result = append(result, TerminalInput{Sequence: item.Sequence, Data: append([]byte(nil), item.Data...)})
	}
	return result
}

// ConnectRequest describes what the user asked to connect to.
type ConnectRequest struct {
	Project string
	// Credential is the current Paperboat client-session access credential.
	Credential config.Credential
	// TerminalSessionID is the immutable server catalog ID. It is required for
	// terminal connections; pb creates a fresh session before resolving.
	TerminalSessionID string
	// ResolvedMachine carries a machine catalog entry the caller has already
	// resolved. When set, the resolver skips its own target lookup round trips
	// and proceeds directly to the connection descriptor.
	ResolvedMachine *ResolvedMachine
	// CreateTerminalSession asks the resolver to create a durable terminal
	// session and issue its connection descriptor in one round trip. It is
	// mutually exclusive with TerminalSessionID.
	CreateTerminalSession *TerminalSessionCreate
}

// ResolvedMachine is a machine catalog entry the caller resolved before
// requesting a connection descriptor.
type ResolvedMachine struct {
	ID         string
	Name       string
	State      string
	Generation uint64
}

// TerminalSessionCreate describes the durable terminal session the resolver
// should create while issuing the connection descriptor.
type TerminalSessionCreate struct {
	Name           string
	IdempotencyKey string
}

// ConnectInfo is what the resolver hands back to the tunnel + session layers.
type ConnectInfo struct {
	// TargetKind identifies the Paperboat environment provider. It is
	// "project" for a hosted Fly environment and "machine" for an
	// enrolled customer machine.
	TargetKind        string
	ProjectID         string
	Project           string
	ProjectState      string
	MachineGeneration uint64
	Transport         string
	// TunnelTarget identifies how the tunnel layer should reach the helper.
	TunnelTarget string
	// Local is true when this resolves to a local dev target (no real VM).
	Local bool
	// Terminal is the helper WebSocket attach descriptor returned by paperboat-server's
	// pre-connect broker.
	Terminal     *TerminalTarget
	FileTransfer *FileTransferTarget
	// TerminalSession describes the durable session the resolver created or
	// selected. It is populated when the resolver created the session as part
	// of a create-and-connect round trip.
	TerminalSession *TerminalSessionInfo
}

// TerminalSessionInfo carries the durable terminal session the resolver
// created or selected.
type TerminalSessionInfo struct {
	ID             string
	Name           string
	EvictedSession *api.TerminalSession
}

// AuthTarget is short-lived, scoped auth material returned by the broker.
type AuthTarget struct {
	Method    string
	Ticket    string
	Token     string
	ExpiresAt string
	Scopes    []string
}

// TerminalTarget is the client-safe environment WebSocket endpoint returned
// by the broker. It carries scoped terminal auth, not
// raw machine addresses, SSH credentials, or tunnel control tokens.
type TerminalTarget struct {
	Protocol      string
	EnvironmentID string
	QUICEndpoint  string
	WSSEndpoint   string
	Auth          AuthTarget
	ThreadID      string
	TerminalID    string
	SessionID     string
	CWD           string
	// Debug requests connection-scoped runtime diagnostics for the local
	// status bar. It is never sent to the control plane or remote shell.
	Debug bool
	// Env is local-terminal environment forwarded on attach (TERM, COLORTERM,
	// ...) so the remote PTY spawns with the client's terminal capabilities.
	// Applied by the Paperboat host runtime when the PTY (re)starts.
	Env map[string]string
	// Cols/Rows seed the remote PTY size at attach time so retained history
	// replays at the local geometry instead of the server default until the
	// first resize lands.
	Cols uint16
	Rows uint16
	// RestartIfNotRunning is true only for the initial user-requested attach.
	// Transport reconnects must observe an exited session and its final status.
	RestartIfNotRunning bool
	// ReplayHistory controls whether an attach should emit retained terminal
	// history. Reconnects suppress it because the local session already has it.
	ReplayHistory bool
	AfterSequence int
	SequenceSink  func(int)
	ReplayGapSink func(requested, earliest, latest uint64)
	// InputAttachmentID is stable across transport reconnects. The host uses it
	// as part of the durable input idempotency key; it is never a transport
	// stream identifier and is safe to reuse after a detached stream is closed.
	InputAttachmentID string
	InputQueue        *TerminalInputQueue
}

type FileTransferTarget struct {
	Endpoint             string
	SourceMachineID      string
	DestinationMachineID string
	InitiatingUserID     string
	Auth                 AuthTarget
	Policy               api.FileTransferPolicy
}

// ProjectResolver resolves a project name to connect info.
type ProjectResolver interface {
	Resolve(ctx context.Context, req ConnectRequest) (ConnectInfo, error)
}
