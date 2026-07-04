package catalog

import "context"

// StubCatalog is the local dev catalog used until paperboat-server exposes the
// real one. It stands in for a server response; it is NOT a hardcoded product
// catalog baked into command logic — swap in a server-backed Catalog behind the
// same interface and nothing else changes.
type StubCatalog struct {
	agents []Agent
	sizes  []Size
}

// NewStubCatalog returns a catalog seeded with representative agents and the
// fixed machine multiples described in USERSTORY.md (1x baseline = 4 vCPU/8 GB).
func NewStubCatalog() *StubCatalog {
	return &StubCatalog{
		agents: []Agent{
			{ID: "claude", DisplayName: "Claude Code", Description: "Anthropic Claude Code", Default: true},
			{ID: "codex", DisplayName: "Codex", Description: "OpenAI Codex CLI"},
			{ID: "cursor", DisplayName: "Cursor", Description: "Cursor agent"},
		},
		sizes: []Size{
			{ID: "1x", DisplayName: "1x", VCPUs: 4, MemoryMB: 8192, Weight: 1, Default: true},
			{ID: "2x", DisplayName: "2x", VCPUs: 8, MemoryMB: 16384, Weight: 2},
			{ID: "4x", DisplayName: "4x", VCPUs: 16, MemoryMB: 32768, Weight: 4},
		},
	}
}

// Agents implements Catalog.
func (c *StubCatalog) Agents(_ context.Context) ([]Agent, error) { return c.agents, nil }

// Sizes implements Catalog.
func (c *StubCatalog) Sizes(_ context.Context) ([]Size, error) { return c.sizes, nil }
