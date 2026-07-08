package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
)

type fakeClient struct {
	projects   []api.Project
	connectSeq []api.ConnectResponse // returned by CLIConnect in order
	statusSeq  []api.ConnectResponse // returned by ConnectionStatus in order
	connectN   int
	statusN    int
}

func (f *fakeClient) ListProjects(context.Context) ([]api.Project, error) { return f.projects, nil }

func (f *fakeClient) CLIConnect(context.Context, string) (api.ConnectResponse, error) {
	i := f.connectN
	if i >= len(f.connectSeq) {
		i = len(f.connectSeq) - 1
	}
	f.connectN++
	return f.connectSeq[i], nil
}

func (f *fakeClient) ConnectionStatus(context.Context, string) (api.ConnectResponse, error) {
	i := f.statusN
	if i >= len(f.statusSeq) {
		i = len(f.statusSeq) - 1
	}
	f.statusN++
	return f.statusSeq[i], nil
}

func newTestResolver(fc *fakeClient) *APIResolver {
	cfg := &config.Config{}
	cfg.Connect.ReadyTimeoutSeconds = 30
	cfg.Connect.PollIntervalSeconds = 1
	r := NewAPIResolver(fc, cfg)
	r.sleep = func(context.Context, time.Duration) error { return nil } // no real waiting
	return r
}

func readyTerminal() *api.Terminal {
	return &api.Terminal{
		Kind:             "papercode_websocket",
		HTTPBaseURL:      "https://agentunnel.dev/projects/prj_1",
		WebSocketBaseURL: "wss://agentunnel.dev/projects/prj_1",
		Auth:             api.AuthMaterial{Method: "websocket_ticket", Ticket: "pct_1", Scopes: []string{"terminal:operate"}},
		ThreadID:         "paperboat-cli",
		TerminalID:       "term-1",
		CWD:              "/workspace",
	}
}

func routeOnlyTerminal() *api.Terminal {
	return &api.Terminal{
		Kind:             "papercode_websocket",
		HTTPBaseURL:      "https://agentunnel.dev/projects/prj_1",
		WebSocketBaseURL: "wss://agentunnel.dev/projects/prj_1",
		ThreadID:         "paperboat-cli",
		TerminalID:       "term-1",
		CWD:              "/workspace",
	}
}

func TestResolveImmediatelyConnectable(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "My App", State: "running"}},
		connectSeq: []api.ConnectResponse{{ProjectID: "prj_1", Connectable: true, Terminal: readyTerminal()}},
	}
	r := newTestResolver(fc)

	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "my app", Agent: "codex", Size: "2x"}) // case-insensitive name
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Local || info.Terminal == nil || info.Terminal.WebSocketBaseURL != "wss://agentunnel.dev/projects/prj_1" {
		t.Fatalf("info = %+v", info)
	}
	if info.Project != "My App" {
		t.Fatalf("project = %q", info.Project)
	}
	if info.Agent != "codex" || info.Size != "2x" {
		t.Fatalf("overrides = %q/%q", info.Agent, info.Size)
	}
}

func TestResolveMatchesByID(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{{Connectable: true, Terminal: readyTerminal()}},
	}
	r := newTestResolver(fc)
	if _, err := r.Resolve(context.Background(), ConnectRequest{Project: "prj_1"}); err != nil {
		t.Fatalf("Resolve by id: %v", err)
	}
}

func TestResolvePollsUntilReady(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{{Connectable: false, Status: "starting", Reason: "machine_start_queued"}},
		statusSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "starting"},
			{Connectable: true, Terminal: readyTerminal()},
		},
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app", Agent: "claude", Size: "1x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || info.Terminal.WebSocketBaseURL != "wss://agentunnel.dev/projects/prj_1" {
		t.Fatalf("info = %+v", info)
	}
	if fc.statusN < 3 {
		t.Fatalf("expected >=3 status polls, got %d", fc.statusN)
	}
}

func TestResolveRebrokersWhenStatusLacksTerminalDescriptor(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},       // initial cli-connect
			{Connectable: true, Terminal: readyTerminal()}, // re-broker after ready
		},
		statusSeq: []api.ConnectResponse{{Connectable: true, Terminal: nil}}, // ready but no routing detail
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app", Agent: "claude", Size: "1x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || info.Terminal.Auth.Ticket != "pct_1" {
		t.Fatalf("expected re-broker terminal, got %+v", info.Terminal)
	}
	if fc.connectN != 2 {
		t.Fatalf("expected 2 CLIConnect calls (initial + re-broker), got %d", fc.connectN)
	}
}

func TestResolveRebrokersWhenStatusLacksAuthMaterial(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},       // initial cli-connect
			{Connectable: true, Terminal: readyTerminal()}, // re-broker after route-only status
		},
		statusSeq: []api.ConnectResponse{{Connectable: true, Terminal: routeOnlyTerminal()}},
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || info.Terminal.Auth.Ticket != "pct_1" {
		t.Fatalf("expected re-brokered auth material, got %+v", info.Terminal)
	}
	if fc.connectN != 2 {
		t.Fatalf("expected 2 CLIConnect calls (initial + re-broker), got %d", fc.connectN)
	}
}

func TestResolveProjectNotFound(t *testing.T) {
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}}
	r := newTestResolver(fc)
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "nope"})
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("err = %v, want ErrProjectNotFound", err)
	}
}
