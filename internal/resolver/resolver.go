// Package resolver turns a project name into the information needed to connect:
// which VM, how to reach it through agentunnel, and what to launch. The real
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
	// Agent / Size are the validated, session-scoped overrides (may be empty,
	// meaning "use the project's configured values"). Size selects the shape to
	// boot when the idle VM is resumed for this session.
	Agent string
	Size  string
	// Credential is the reused papercode auth used for pre-connect authz.
	Credential config.Credential
}

// ConnectInfo is what the resolver hands back to the tunnel + session layers.
type ConnectInfo struct {
	Project string
	// TunnelTarget identifies how the tunnel layer should reach the VM. Its
	// meaning is tunnel-implementation specific (agentunnel tcp-tunnel id in
	// production, a local shell marker in the dev stub).
	TunnelTarget string
	// Agent is the resolved agent to launch on the VM (post-override).
	Agent string
	// Size is the resolved machine shape to boot on resume (post-override).
	Size string
	// Local is true when this resolves to a local dev target (no real VM).
	Local bool
}

// ProjectResolver resolves a project name to connect info.
type ProjectResolver interface {
	Resolve(ctx context.Context, req ConnectRequest) (ConnectInfo, error)
}
