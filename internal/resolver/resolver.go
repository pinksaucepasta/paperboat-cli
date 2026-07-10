// Package resolver turns a project name into the information needed to connect:
// which VM and how to reach it through agentunnel. The real
// implementation calls paperboat-server (pre-connect broker); until then a
// local dev stub returns a target that runs a shell locally so the whole CLI is
// exercisable end-to-end.
package resolver

import (
	"context"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

// ConnectRequest describes what the user asked to connect to.
type ConnectRequest struct {
	Project string
	// Credential is transitional auth used until the Paperboat device flow lands.
	Credential config.Credential
}

// ConnectInfo is what the resolver hands back to the tunnel + session layers.
type ConnectInfo struct {
	Project string
	// TunnelTarget identifies how the tunnel layer should reach the VM. Its
	// meaning is tunnel-implementation specific (agentunnel tcp-tunnel id in
	// production, a local shell marker in the dev stub).
	TunnelTarget string
	// Local is true when this resolves to a local dev target (no real VM).
	Local bool
	// Terminal is the papercode WebSocket attach descriptor returned by paperboat-server's
	// pre-connect broker. Nil for the local dev stub (Local == true).
	Terminal *TerminalTarget
	// Upload is the papercode image-upload endpoint hint from the broker. Nil
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

// TerminalTarget is the client-safe papercode WebSocket endpoint carried
// through agentunnel. It carries route metadata and scoped papercode auth, not
// raw machine addresses, SSH credentials, or agentunnel control tokens.
type TerminalTarget struct {
	HTTPBaseURL      string
	WebSocketBaseURL string
	Auth             AuthTarget
	ThreadID         string
	TerminalID       string
	CWD              string
}

// UploadTarget is the papercode-server upload endpoint reachable through
// agentunnel, with the server-authoritative size/MIME policy.
type UploadTarget struct {
	HTTPBaseURL      string
	Auth             AuthTarget
	MaxBytes         int64
	AllowedMIMETypes []string
}

// ProjectResolver resolves a project name to connect info.
type ProjectResolver interface {
	Resolve(ctx context.Context, req ConnectRequest) (ConnectInfo, error)
}
