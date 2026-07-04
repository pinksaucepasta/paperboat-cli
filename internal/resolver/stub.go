package resolver

import (
	"context"
	"strings"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

// StubResolver resolves every project to a local dev target. It stands in for
// paperboat-server's project resolution + pre-connect broker so `pb <project>`
// works before the server exists. Real resolution drops in behind the same
// ProjectResolver interface.
type StubResolver struct {
	cfg *config.Config
}

// NewStubResolver returns a resolver seeded with CLI defaults.
func NewStubResolver(cfg *config.Config) *StubResolver {
	return &StubResolver{cfg: cfg}
}

// Resolve implements ProjectResolver, filling agent/size from request overrides
// then config defaults.
func (r *StubResolver) Resolve(_ context.Context, req ConnectRequest) (ConnectInfo, error) {
	agent := firstNonEmpty(req.Agent, r.cfg.DefaultAgent)
	size := firstNonEmpty(req.Size, r.cfg.DefaultSize)
	return ConnectInfo{
		Project:      strings.TrimSpace(req.Project),
		TunnelTarget: "local-shell",
		Agent:        agent,
		Size:         size,
		Local:        true,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
