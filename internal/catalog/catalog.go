// Package catalog exposes the dynamic, server-owned lists of agent presets and
// machine shapes the CLI validates flags against. The real implementation will
// fetch these from paperboat-server; until then a config/stub-backed catalog
// keeps the CLI runnable. Nothing here is hardcoded into command logic — the
// values live behind the Catalog interface.
package catalog

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Agent is a selectable coding-agent preset (Claude Code, Codex, Cursor, …).
type Agent struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

// Size is a selectable machine shape. Weight is the credit-per-hour multiplier
// relative to 1x; it is illustrative here and authoritative server-side.
type Size struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"display_name"`
	VCPUs       int     `json:"vcpus"`
	MemoryMB    int     `json:"memory_mb"`
	Weight      float64 `json:"weight"`
	Default     bool    `json:"default,omitempty"`
}

// Catalog resolves the dynamic agent and machine-size lists for a user/project.
type Catalog interface {
	Agents(ctx context.Context) ([]Agent, error)
	Sizes(ctx context.Context) ([]Size, error)
}

// ValidateAgent returns the matching agent id, or an error listing valid ids.
func ValidateAgent(ctx context.Context, c Catalog, id string) (Agent, error) {
	agents, err := c.Agents(ctx)
	if err != nil {
		return Agent{}, err
	}
	for _, a := range agents {
		if strings.EqualFold(a.ID, id) {
			return a, nil
		}
	}
	return Agent{}, fmt.Errorf("unknown agent %q; available: %s", id, joinAgentIDs(agents))
}

// ValidateSize returns the matching size id, or an error listing valid ids.
func ValidateSize(ctx context.Context, c Catalog, id string) (Size, error) {
	sizes, err := c.Sizes(ctx)
	if err != nil {
		return Size{}, err
	}
	for _, s := range sizes {
		if strings.EqualFold(s.ID, id) {
			return s, nil
		}
	}
	return Size{}, fmt.Errorf("unknown machine size %q; available: %s", id, joinSizeIDs(sizes))
}

func joinAgentIDs(agents []Agent) string {
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func joinSizeIDs(sizes []Size) string {
	ids := make([]string, 0, len(sizes))
	for _, s := range sizes {
		ids = append(ids, s.ID)
	}
	return strings.Join(ids, ", ")
}
