// Package resolver turns a project name into the information needed to connect:
// which environment and how to reach it through `paperboat-tunnel`. Production resolution calls
// paperboat-server's pre-connect broker.
package resolver

import (
	"context"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

// ConnectRequest describes what the user asked to connect to.
type ConnectRequest struct {
	Project string
	// Credential is the current Paperboat client-session access credential.
	Credential config.Credential
	// TerminalSessionID is the immutable server catalog ID. Empty selects the
	// project's default session for backward-compatible attaches.
	TerminalSessionID string
}

// ConnectInfo is what the resolver hands back to the tunnel + session layers.
type ConnectInfo struct {
	// TargetKind identifies the Paperboat environment provider. It is
	// "project" for a hosted Fly environment and "connected_machine" for an
	// enrolled customer machine.
	TargetKind   string
	ProjectID    string
	Project      string
	ProjectState string
	// TunnelTarget identifies how the tunnel layer should reach the VM. Its
	// meaning is tunnel-implementation specific. Legacy descriptor readers may
	// still carry an Agentunnel tunnel ID during the bounded rollback window.
	TunnelTarget string
	// Local is true when this resolves to a local dev target (no real VM).
	Local bool
	// Terminal is the helper WebSocket attach descriptor returned by paperboat-server's
	// pre-connect broker.
	Terminal *TerminalTarget
	// Upload is the helper image-upload endpoint hint from the broker. Nil
	// when the broker did not return one.
	Upload *UploadTarget
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
	Kind             string
	EnvironmentID    string
	HTTPBaseURL      string
	WebSocketBaseURL string
	Auth             AuthTarget
	ThreadID         string
	TerminalID       string
	SessionID        string
	CWD              string
	// Env is local-terminal environment forwarded on attach (TERM, COLORTERM,
	// ...) so the remote PTY spawns with the client's terminal capabilities.
	// Applied by paperboat-helper when the PTY (re)starts.
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
}

// UploadTarget is the helper upload endpoint reachable through
// `paperboat-tunnel`, with the server-authoritative size/MIME policy.
type UploadTarget struct {
	HTTPBaseURL      string
	Path             string
	Auth             AuthTarget
	MaxBytes         int64
	AllowedMIMETypes []string
	RetentionSeconds int64
}

// ProjectResolver resolves a project name to connect info.
type ProjectResolver interface {
	Resolve(ctx context.Context, req ConnectRequest) (ConnectInfo, error)
}
