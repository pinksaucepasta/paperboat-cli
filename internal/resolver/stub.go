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

// Resolve implements ProjectResolver for local development.
func (r *StubResolver) Resolve(_ context.Context, req ConnectRequest) (ConnectInfo, error) {
	return ConnectInfo{
		Project:      strings.TrimSpace(req.Project),
		TunnelTarget: "local-shell",
		Local:        true,
	}, nil
}
