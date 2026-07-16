package resolver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
)

type resolverEventSink struct{ events []telemetry.Event }

func (s *resolverEventSink) Record(e telemetry.Event) { s.events = append(s.events, e) }

type fakeClient struct {
	projects          []api.Project
	machines          []api.ConnectedMachine
	connectSeq        []api.ConnectResponse // returned by CLIConnect in order
	statusSeq         []api.ConnectResponse // returned by ConnectionStatus in order
	connectN          int
	statusN           int
	connectSessionIDs []string
	statusSessionIDs  []string
}

func (f *fakeClient) ListProjects(context.Context) ([]api.Project, error) { return f.projects, nil }

func (f *fakeClient) ListConnectedMachines(context.Context) ([]api.ConnectedMachine, error) {
	return f.machines, nil
}

func (f *fakeClient) nextConnect() (api.ConnectResponse, error) {
	i := f.connectN
	if i >= len(f.connectSeq) {
		i = len(f.connectSeq) - 1
	}
	f.connectN++
	return f.connectSeq[i], nil
}

func (f *fakeClient) CLIConnect(context.Context, string) (api.ConnectResponse, error) {
	return f.nextConnect()
}

func (f *fakeClient) CLIConnectSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectResponse, error) {
	f.connectSessionIDs = append(f.connectSessionIDs, terminalSessionID)
	return f.nextConnect()
}

func (f *fakeClient) nextStatus() (api.ConnectResponse, error) {
	i := f.statusN
	if i >= len(f.statusSeq) {
		i = len(f.statusSeq) - 1
	}
	f.statusN++
	return f.statusSeq[i], nil
}

func (f *fakeClient) ConnectionStatus(context.Context, string) (api.ConnectResponse, error) {
	return f.nextStatus()
}

func (f *fakeClient) ConnectionStatusSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectResponse, error) {
	f.statusSessionIDs = append(f.statusSessionIDs, terminalSessionID)
	return f.nextStatus()
}

func (f *fakeClient) ConnectConnectedMachine(context.Context, string) (api.ConnectResponse, error) {
	return f.nextConnect()
}

func (f *fakeClient) ConnectedMachineConnectionStatus(context.Context, string) (api.ConnectResponse, error) {
	return f.nextStatus()
}

func (f *fakeClient) ConnectConnectedMachineSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectResponse, error) {
	f.connectSessionIDs = append(f.connectSessionIDs, terminalSessionID)
	return f.nextConnect()
}

func (f *fakeClient) ConnectedMachineConnectionStatusSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectResponse, error) {
	f.statusSessionIDs = append(f.statusSessionIDs, terminalSessionID)
	return f.nextStatus()
}

func newTestResolver(fc *fakeClient) *APIResolver {
	cfg := &config.Config{}
	cfg.ServerURL = "https://api.paperboat.test"
	cfg.Connect.ReadyTimeoutSeconds = 30
	cfg.Connect.PollIntervalSeconds = 1
	cfg.Connect.AcceptedTerminalKinds = []string{"papercode_websocket"}
	r := NewAPIResolver(fc, cfg)
	r.sleep = func(context.Context, time.Duration) error { return nil } // no real waiting
	return r
}

func readyTerminal() *api.Terminal {
	return &api.Terminal{
		Kind:             "papercode_websocket",
		HTTPBaseURL:      "https://agentunnel.dev/projects/prj_1",
		WebSocketBaseURL: "wss://agentunnel.dev/projects/prj_1",
		Auth:             api.AuthMaterial{Method: "websocket_ticket", Ticket: "pct_1", ExpiresAt: time.Now().Add(time.Hour), Scopes: []string{"terminal:operate"}},
		ThreadID:         "paperboat-cli",
		TerminalID:       "term-1",
		CWD:              "/workspace",
	}
}

func readyResponse(term *api.Terminal) api.ConnectResponse {
	expires := time.Now().Add(time.Hour)
	term.Auth.ExpiresAt = expires.Add(-time.Minute)
	return api.ConnectResponse{Issuer: "https://api.paperboat.test", ProjectID: "prj_1", Connectable: true, ExpiresAt: expires, Environment: &api.Environment{EnvironmentID: "env_1", ProjectID: "prj_1", ProjectRoot: "/workspace"}, Terminal: term, Upload: &api.Upload{Kind: "papercode_staged_image", HTTPBaseURL: term.HTTPBaseURL, Path: "/projects/prj_1/api/files/staged-images", Auth: api.AuthMaterial{Method: "bearer", Token: "file-token", ExpiresAt: expires.Add(-time.Minute), Scopes: []string{"file:stage"}}, MaxBytes: 1024, AllowedMIMETypes: []string{"image/png"}, RetentionSeconds: 60}}
}

func readyConnectedMachineResponse(term *api.Terminal) api.ConnectResponse {
	expires := time.Now().Add(time.Hour)
	term.Auth.ExpiresAt = expires.Add(-time.Minute)
	return api.ConnectResponse{Issuer: "https://api.paperboat.test", ConnectedMachineID: "cm_1", ConnectedMachineState: "online", Connectable: true, ExpiresAt: expires, Environment: &api.Environment{EnvironmentID: "env_cm_1", ConnectedMachineID: "cm_1", ProjectRoot: "/Users/paperboat"}, Terminal: term, Upload: &api.Upload{Kind: "papercode_staged_image", HTTPBaseURL: term.HTTPBaseURL, Path: "/connected-machines/cm_1/api/files/staged-images", Auth: api.AuthMaterial{Method: "bearer", Token: "file-token", ExpiresAt: expires.Add(-time.Minute), Scopes: []string{"file:stage"}}, MaxBytes: 1024, AllowedMIMETypes: []string{"image/png"}, RetentionSeconds: 60}}
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
		connectSeq: []api.ConnectResponse{readyResponse(readyTerminal())},
	}
	r := newTestResolver(fc)

	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "my app"}) // case-insensitive name
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Local || info.Terminal == nil || info.Terminal.WebSocketBaseURL != "wss://agentunnel.dev/projects/prj_1" {
		t.Fatalf("info = %+v", info)
	}
	if info.Project != "My App" {
		t.Fatalf("project = %q", info.Project)
	}
}

func TestResolveRecordsMetadataOnlyConnectResult(t *testing.T) {
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{readyResponse(readyTerminal())}}
	r := newTestResolver(fc)
	sink := &resolverEventSink{}
	times := []time.Time{time.Unix(20, 0), time.Unix(20, 15_000_000)}
	r.Telemetry = sink
	r.Now = func() time.Time { v := times[0]; times = times[1:]; return v }
	if _, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"}); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %+v", sink.events)
	}
	e := sink.events[0]
	if e.Name != "connect.result" || e.Outcome != "success" || e.ProjectID != "prj_1" || e.EnvironmentID != "env_1" || e.LatencyMS != 15 {
		t.Fatalf("event = %+v", e)
	}
}

func TestResolveMatchesByID(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{readyResponse(readyTerminal())},
	}
	r := newTestResolver(fc)
	if _, err := r.Resolve(context.Background(), ConnectRequest{Project: "prj_1"}); err != nil {
		t.Fatalf("Resolve by id: %v", err)
	}
}

func TestResolveConnectedMachineByDisplayName(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = "https://agentunnel.dev/connected-machines/cm_1"
	term.WebSocketBaseURL = "wss://agentunnel.dev/connected-machines/cm_1"
	fc := &fakeClient{
		machines:   []api.ConnectedMachine{{ID: "cm_1", DisplayName: "Studio Mac", State: "online", Online: true}},
		connectSeq: []api.ConnectResponse{readyConnectedMachineResponse(term)},
	}
	info, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "studio mac"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.TargetKind != targetConnectedMachine || info.ProjectID != "cm_1" || info.Project != "Studio Mac" || info.ProjectState != "online" {
		t.Fatalf("info = %+v", info)
	}
}

func TestResolveRejectsConnectedMachineDescriptorForDifferentMachine(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = "https://agentunnel.dev/connected-machines/cm_1"
	term.WebSocketBaseURL = "wss://agentunnel.dev/connected-machines/cm_1"
	response := readyConnectedMachineResponse(term)
	response.ConnectedMachineID = "cm_other"
	fc := &fakeClient{
		machines:   []api.ConnectedMachine{{ID: "cm_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectResponse{response},
	}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "cm_1"})
	if err == nil || !strings.Contains(err.Error(), "wrong connected machine") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveConnectedMachineRebrokersAfterReadiness(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = "https://agentunnel.dev/connected-machines/cm_1"
	term.WebSocketBaseURL = "wss://agentunnel.dev/connected-machines/cm_1"
	fc := &fakeClient{
		machines: []api.ConnectedMachine{{ID: "cm_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectResponse{
			{ConnectedMachineID: "cm_1", Connectable: false, Status: "connector_connecting"},
			readyConnectedMachineResponse(term),
		},
		statusSeq: []api.ConnectResponse{{ConnectedMachineID: "cm_1", Connectable: true}},
	}
	info, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "cm_1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || fc.connectN != 2 || fc.statusN != 1 {
		t.Fatalf("info=%+v connect=%d status=%d", info, fc.connectN, fc.statusN)
	}
}

func TestResolveKeepsSelectedConnectedMachineSessionThroughReadinessPolling(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = "https://agentunnel.dev/connected-machines/cm_1"
	term.WebSocketBaseURL = "wss://agentunnel.dev/connected-machines/cm_1"
	fc := &fakeClient{
		machines: []api.ConnectedMachine{{ID: "cm_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectResponse{
			{ConnectedMachineID: "cm_1", Connectable: false, Status: "connector_connecting"},
			readyConnectedMachineResponse(term),
		},
		statusSeq: []api.ConnectResponse{{ConnectedMachineID: "cm_1", Connectable: true}},
	}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "cm_1", TerminalSessionID: "pts_api"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fc.connectSessionIDs, ","); got != "pts_api,pts_api" {
		t.Fatalf("connected-machine connect session IDs = %q", got)
	}
	if got := strings.Join(fc.statusSessionIDs, ","); got != "pts_api" {
		t.Fatalf("connected-machine status session IDs = %q", got)
	}
}

func TestResolvePollsUntilReady(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{{Connectable: false, Status: "starting", Reason: "machine_start_queued"}},
		statusSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "starting"},
			readyResponse(readyTerminal()),
		},
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
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
			{Connectable: false, Status: "starting"}, // initial cli-connect
			readyResponse(readyTerminal()),           // re-broker after ready
		},
		statusSeq: []api.ConnectResponse{{Connectable: true, Terminal: nil}}, // ready but no routing detail
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
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

func TestResolveKeepsSelectedSessionThroughReadinessPollingAndRebroker(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectResponse{{Connectable: true, Terminal: nil}},
	}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app", TerminalSessionID: "pts_api"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fc.connectSessionIDs, ","); got != "pts_api,pts_api" {
		t.Fatalf("cli-connect session IDs = %q, want pts_api,pts_api", got)
	}
	if got := strings.Join(fc.statusSessionIDs, ","); got != "pts_api" {
		t.Fatalf("status session IDs = %q, want pts_api", got)
	}
}

func TestResolveKeepsPollingWhenRebrokerRegressesToNotReady(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "reconciling"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectResponse{
			{Connectable: true, Terminal: nil},
			{Connectable: true, Terminal: nil},
		},
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || info.Terminal.Auth.Ticket != "pct_1" {
		t.Fatalf("expected final re-brokered terminal, got %+v", info.Terminal)
	}
	if fc.connectN != 3 || fc.statusN != 2 {
		t.Fatalf("connect calls = %d, status calls = %d", fc.connectN, fc.statusN)
	}
}

func TestResolveRebrokersWhenStatusLacksAuthMaterial(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"}, // initial cli-connect
			readyResponse(readyTerminal()),           // re-broker after route-only status
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

func TestResolveKeepsPollingWhenRebrokerIsStillStarting(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "papercode_starting", Reason: "papercode_unhealthy"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectResponse{
			{Connectable: true, Terminal: routeOnlyTerminal()},
			readyResponse(readyTerminal()),
		},
	}
	r := newTestResolver(fc)
	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || info.Terminal.Auth.Ticket != "pct_1" {
		t.Fatalf("terminal = %+v", info.Terminal)
	}
	if fc.connectN != 2 || fc.statusN != 2 {
		t.Fatalf("connect calls=%d status calls=%d, want 2/2", fc.connectN, fc.statusN)
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

func TestResolveRejectsAmbiguousProjectName(t *testing.T) {
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}, {ID: "prj_2", Name: "APP"}}}
	r := newTestResolver(fc)
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "App"})
	if !errors.Is(err, ErrProjectAmbiguous) || !strings.Contains(err.Error(), "prj_1, prj_2") {
		t.Fatalf("err = %v, want ambiguity with both IDs", err)
	}
}

func TestResolveAcceptsDistinctEnvironmentIdentity(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Environment.EnvironmentID = "env_other"
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{response},
	}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveRejectsEnvironmentOwnedByAnotherProject(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Environment.ProjectID = "prj_other"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "invalid environment") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsNonWSSTerminal(t *testing.T) {
	term := readyTerminal()
	term.WebSocketBaseURL = "https://route.example"
	response := readyResponse(term)
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectResponse{response},
	}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "WebSocket endpoint") {
		t.Fatalf("err = %v, want wss validation", err)
	}
}

func TestResolveEnforcesConfiguredRouteHostPolicy(t *testing.T) {
	term := readyTerminal()
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{readyResponse(term)}}
	cfg := &config.Config{}
	cfg.ServerURL = "https://api.paperboat.test"
	cfg.Connect.ReadyTimeoutSeconds = 30
	cfg.Connect.PollIntervalSeconds = 1
	cfg.Connect.AllowedRouteHosts = []string{"relay.example.com"}
	cfg.Connect.AcceptedTerminalKinds = []string{"papercode_websocket"}
	r := NewAPIResolver(fc, cfg)
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "host is not allowed") {
		t.Fatalf("err = %v, want host policy rejection", err)
	}
}

func TestResolveRejectsUnexpectedIssuer(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Issuer = "https://evil.example"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "unexpected issuer") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsInvalidUploadDescriptor(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Upload.Auth.Scopes = []string{"terminal:operate"}
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "upload descriptor") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveAcceptsFrozenTerminalWithoutHTTPBaseURL(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = ""
	response := readyResponse(term)
	response.Upload.HTTPBaseURL = "https://agentunnel.dev/projects/prj_1"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveRejectsTerminalHTTPPortMismatch(t *testing.T) {
	term := readyTerminal()
	term.HTTPBaseURL = "https://agentunnel.dev:8443/projects/prj_1"
	response := readyResponse(term)
	response.Upload.HTTPBaseURL = term.HTTPBaseURL
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "hosts do not match") {
		t.Fatalf("err = %v, want origin mismatch", err)
	}
}

func TestResolveRejectsUploadPortMismatch(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Upload.HTTPBaseURL = "https://agentunnel.dev:8443/projects/prj_1"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "validated terminal route") {
		t.Fatalf("err = %v, want upload origin mismatch", err)
	}
}

func TestResolveRequiresProfileConnectionPolicy(t *testing.T) {
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	_, err := NewAPIResolver(&fakeClient{}, cfg).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "ready_timeout_seconds") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveCapsRetryHintAtReadyDeadline(t *testing.T) {
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectResponse{{ProjectID: "prj_1", Connectable: false, RetryAfterSeconds: 300, Status: "starting"}}}
	r := newTestResolver(fc)
	r.readyTimeout = 30 * time.Second
	var waited time.Duration
	r.sleep = func(_ context.Context, d time.Duration) error { waited = d; return context.Canceled }
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || waited <= 0 || waited > 30*time.Second {
		t.Fatalf("err=%v waited=%s", err, waited)
	}
}
