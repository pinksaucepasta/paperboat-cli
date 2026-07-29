package resolver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-cli/internal/api"
	"github.com/pinksaucepasta/paperboat-cli/internal/config"
	"github.com/pinksaucepasta/paperboat-cli/internal/telemetry"
)

type resolverEventSink struct{ events []telemetry.Event }

func (s *resolverEventSink) Record(e telemetry.Event) { s.events = append(s.events, e) }

type fakeClient struct {
	projects          []api.Project
	projectsErr       error
	machines          []api.UserMachine
	connectSeq        []api.ConnectionDescriptor // returned by ProjectConnectionDescriptor in order
	statusSeq         []api.ConnectionDescriptor // returned by ConnectionReadiness in order
	connectN          int
	statusN           int
	connectSessionIDs []string
	statusSessionIDs  []string
}

func (f *fakeClient) ListProjects(context.Context) ([]api.Project, error) {
	return f.projects, f.projectsErr
}

func (f *fakeClient) ListUserMachines(context.Context) ([]api.UserMachine, error) {
	return f.machines, nil
}

func (f *fakeClient) nextConnect() (api.ConnectionDescriptor, error) {
	i := f.connectN
	if i >= len(f.connectSeq) {
		i = len(f.connectSeq) - 1
	}
	f.connectN++
	return f.connectSeq[i], nil
}

func (f *fakeClient) ProjectConnectionDescriptor(context.Context, string) (api.ConnectionDescriptor, error) {
	return f.nextConnect()
}

func (f *fakeClient) ProjectConnectionDescriptorForSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectionDescriptor, error) {
	f.connectSessionIDs = append(f.connectSessionIDs, terminalSessionID)
	return f.nextConnect()
}

func (f *fakeClient) nextStatus() (api.ConnectionDescriptor, error) {
	i := f.statusN
	if i >= len(f.statusSeq) {
		i = len(f.statusSeq) - 1
	}
	f.statusN++
	return f.statusSeq[i], nil
}

func (f *fakeClient) ConnectionReadiness(context.Context, string) (api.ConnectionDescriptor, error) {
	return f.nextStatus()
}

func (f *fakeClient) ProjectConnectionReadinessForSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectionDescriptor, error) {
	f.statusSessionIDs = append(f.statusSessionIDs, terminalSessionID)
	return f.nextStatus()
}

func (f *fakeClient) UserMachineConnectionDescriptor(context.Context, string) (api.ConnectionDescriptor, error) {
	return f.nextConnect()
}

func (f *fakeClient) UserMachineConnectionReadiness(context.Context, string) (api.ConnectionDescriptor, error) {
	return f.nextStatus()
}

func (f *fakeClient) UserMachineConnectionDescriptorForSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectionDescriptor, error) {
	f.connectSessionIDs = append(f.connectSessionIDs, terminalSessionID)
	return f.nextConnect()
}

func (f *fakeClient) UserMachineConnectionReadinessForSession(_ context.Context, _ string, terminalSessionID string) (api.ConnectionDescriptor, error) {
	f.statusSessionIDs = append(f.statusSessionIDs, terminalSessionID)
	return f.nextStatus()
}

func newTestResolver(fc *fakeClient) *APIResolver {
	cfg := &config.Config{}
	cfg.ServerURL = "https://api.paperboat.test"
	cfg.Connect.ReadyTimeoutSeconds = 30
	cfg.Connect.PollIntervalSeconds = 1
	r := NewAPIResolver(fc, cfg)
	r.sleep = func(context.Context, time.Duration) error { return nil } // no real waiting
	return r
}

func TestFindTargetAllowsUserMachineWithoutHostedPlan(t *testing.T) {
	fc := &fakeClient{
		projectsErr: &api.APIError{Code: "payment_required"},
		machines:    []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac", State: "online"}},
	}
	target, err := newTestResolver(fc).findTarget(context.Background(), "um_1")
	if err != nil {
		t.Fatal(err)
	}
	if target.kind != targetUserMachine || target.id != "um_1" {
		t.Fatalf("target = %+v", target)
	}
}

func readyTerminal() *api.Terminal {
	return &api.Terminal{
		Protocol:   "paperboat.terminal.v2",
		Endpoints:  api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"},
		Auth:       api.AuthMaterial{Method: "websocket_ticket", Ticket: "pct_1", ExpiresAt: time.Now().Add(time.Hour), Scopes: []string{"terminal:operate"}},
		ThreadID:   "paperboat-cli",
		TerminalID: "term-1",
		CWD:        "/workspace",
	}
}

func TestValidateReadyAcceptsEnvironmentTerminalBearer(t *testing.T) {
	terminal := readyTerminal()
	terminal.Endpoints = api.TerminalEndpoints{QUIC: "quic://machine.example:443", WSS: "wss://machine.example/v1/runtime"}
	terminal.Auth = api.AuthMaterial{Method: "bearer", Token: "helper-token", ExpiresAt: time.Now().Add(time.Minute), Scopes: []string{"terminal:operate"}}
	response := readyUserMachineResponse(terminal)
	response.ExpiresAt = time.Now().Add(2 * time.Minute)
	response.Terminal.Auth.ExpiresAt = time.Now().Add(time.Minute)
	response.FileTransfer.Endpoint = "https://machine.example/v1/file-transfers"
	response.FileTransfer.Auth.ExpiresAt = time.Now().Add(time.Minute)
	if _, err := newTestResolver(&fakeClient{}).validateDescriptor(response, target{kind: targetUserMachine, id: "um_1"}); err != nil {
		t.Fatal(err)
	}
}

func readyResponse(term *api.Terminal) api.ConnectionDescriptor {
	expires := time.Now().Add(time.Hour)
	term.Auth.ExpiresAt = expires.Add(-time.Minute)
	return api.ConnectionDescriptor{Issuer: "https://api.paperboat.test", ProjectID: "prj_1", Connectable: true, ExpiresAt: expires, Environment: &api.Environment{EnvironmentID: "env_1", ProjectID: "prj_1", ProjectRoot: "/workspace"}, Terminal: term, FileTransfer: readyFileTransfer(expires)}
}

func readyUserMachineResponse(term *api.Terminal) api.ConnectionDescriptor {
	expires := time.Now().Add(time.Hour)
	term.Auth.ExpiresAt = expires.Add(-time.Minute)
	return api.ConnectionDescriptor{Issuer: "https://api.paperboat.test", UserMachineID: "um_1", UserMachineState: "online", Connectable: true, ExpiresAt: expires, Environment: &api.Environment{EnvironmentID: "env_um_1", UserMachineID: "um_1", ProjectRoot: "/Users/paperboat"}, Terminal: term, FileTransfer: readyFileTransfer(expires)}
}

func readyFileTransfer(expires time.Time) *api.FileTransfer {
	return &api.FileTransfer{Endpoint: "https://edge.paperboat.test/v1/file-transfers", Auth: api.AuthMaterial{Method: "bearer", Token: "file-token", ExpiresAt: expires.Add(-time.Minute), Scopes: []string{"file:transfer"}}, Policy: api.FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}}
}

func TestValidateFileTransferRequiresExactRouteScopeAndPolicy(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	transfer := &api.FileTransfer{
		Endpoint: "https://edge.paperboat.test/v1/file-transfers",
		Auth:     api.AuthMaterial{Method: "bearer", Token: "transfer-token", ExpiresAt: expires.Add(-time.Minute), Scopes: []string{"file:transfer"}},
		Policy:   api.FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30},
	}
	terminalURL, _ := secureEndpoint("wss://edge.paperboat.test/v1/runtime", "wss")
	r := newTestResolver(&fakeClient{})
	if err := r.validateFileTransfer(transfer, terminalURL, expires); err != nil {
		t.Fatal(err)
	}
	bad := *transfer
	bad.Auth = transfer.Auth
	bad.Auth.Scopes = []string{"file:stage"}
	if err := r.validateFileTransfer(&bad, terminalURL, expires); err == nil {
		t.Fatal("accepted legacy scope")
	}
	bad = *transfer
	bad.Endpoint = "https://other.paperboat.test/v1/file-transfers"
	if err := r.validateFileTransfer(&bad, terminalURL, expires); err == nil {
		t.Fatal("accepted mismatched route")
	}
	bad = *transfer
	bad.Policy = transfer.Policy
	bad.Policy.MaxBatchFiles = 11
	if err := r.validateFileTransfer(&bad, terminalURL, expires); err == nil {
		t.Fatal("accepted policy outside bounds")
	}
}

func routeOnlyTerminal() *api.Terminal {
	return &api.Terminal{
		Protocol:   "paperboat.terminal.v2",
		Endpoints:  api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"},
		ThreadID:   "paperboat-cli",
		TerminalID: "term-1",
		CWD:        "/workspace",
	}
}

func TestResolveImmediatelyConnectable(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "My App", State: "running"}},
		connectSeq: []api.ConnectionDescriptor{readyResponse(readyTerminal())},
	}
	r := newTestResolver(fc)

	info, err := r.Resolve(context.Background(), ConnectRequest{Project: "my app"}) // case-insensitive name
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Local || info.Terminal == nil || info.Terminal.WSSEndpoint != "wss://edge.paperboat.test/v1/runtime" {
		t.Fatalf("info = %+v", info)
	}
	if info.Project != "My App" {
		t.Fatalf("project = %q", info.Project)
	}
}

func TestResolveRecordsMetadataOnlyConnectResult(t *testing.T) {
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{readyResponse(readyTerminal())}}
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
		connectSeq: []api.ConnectionDescriptor{readyResponse(readyTerminal())},
	}
	r := newTestResolver(fc)
	if _, err := r.Resolve(context.Background(), ConnectRequest{Project: "prj_1"}); err != nil {
		t.Fatalf("Resolve by id: %v", err)
	}
}

func TestResolveUserMachineByDisplayName(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	fc := &fakeClient{
		machines:   []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac", State: "online", Online: true}},
		connectSeq: []api.ConnectionDescriptor{readyUserMachineResponse(term)},
	}
	info, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "studio mac"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.TargetKind != targetUserMachine || info.ProjectID != "um_1" || info.Project != "Studio Mac" || info.ProjectState != "online" {
		t.Fatalf("info = %+v", info)
	}
}

func TestResolveUserMachineRevocationStopsWithoutPolling(t *testing.T) {
	fc := &fakeClient{
		machines:   []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac", State: "disconnected"}},
		connectSeq: []api.ConnectionDescriptor{{UserMachineID: "um_1", UserMachineState: "disconnected", Status: "user_machine_revoked", Reason: "access_revoked"}},
	}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "Studio Mac"})
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "user_machine_revoked" {
		t.Fatalf("err=%v", err)
	}
	if fc.statusN != 0 {
		t.Fatalf("revoked target polled status %d times", fc.statusN)
	}
}

func TestResolveRejectsUserMachineDescriptorForDifferentMachine(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	response := readyUserMachineResponse(term)
	response.UserMachineID = "um_other"
	fc := &fakeClient{
		machines:   []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectionDescriptor{response},
	}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "um_1"})
	if err == nil || !strings.Contains(err.Error(), "wrong user machine") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveUserMachineRebrokersAfterReadiness(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	fc := &fakeClient{
		machines: []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectionDescriptor{
			{UserMachineID: "um_1", Connectable: false, Status: "connector_connecting"},
			readyUserMachineResponse(term),
		},
		statusSeq: []api.ConnectionDescriptor{{UserMachineID: "um_1", Connectable: true}},
	}
	info, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "um_1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Terminal == nil || fc.connectN != 2 || fc.statusN != 1 {
		t.Fatalf("info=%+v connect=%d status=%d", info, fc.connectN, fc.statusN)
	}
}

func TestResolveKeepsSelectedUserMachineSessionThroughReadinessPolling(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	fc := &fakeClient{
		machines: []api.UserMachine{{ID: "um_1", DisplayName: "Studio Mac"}},
		connectSeq: []api.ConnectionDescriptor{
			{UserMachineID: "um_1", Connectable: false, Status: "connector_connecting"},
			readyUserMachineResponse(term),
		},
		statusSeq: []api.ConnectionDescriptor{{UserMachineID: "um_1", Connectable: true}},
	}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "um_1", TerminalSessionID: "pts_api"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fc.connectSessionIDs, ","); got != "pts_api,pts_api" {
		t.Fatalf("user-machine connect session IDs = %q", got)
	}
	if got := strings.Join(fc.statusSessionIDs, ","); got != "pts_api" {
		t.Fatalf("user-machine status session IDs = %q", got)
	}
}

func TestResolvePollsUntilReady(t *testing.T) {
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectionDescriptor{{Connectable: false, Status: "starting", Reason: "machine_start_queued"}},
		statusSeq: []api.ConnectionDescriptor{
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
	if info.Terminal == nil || info.Terminal.WSSEndpoint != "wss://edge.paperboat.test/v1/runtime" {
		t.Fatalf("info = %+v", info)
	}
	if fc.statusN < 3 {
		t.Fatalf("expected >=3 status polls, got %d", fc.statusN)
	}
}

func TestResolveRebrokersWhenStatusLacksTerminalDescriptor(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectionDescriptor{
			{Connectable: false, Status: "starting"}, // initial cli-connect
			readyResponse(readyTerminal()),           // re-broker after ready
		},
		statusSeq: []api.ConnectionDescriptor{{Connectable: true, Terminal: nil}}, // ready but no routing detail
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
		t.Fatalf("expected 2 ProjectConnectionDescriptor calls (initial + re-broker), got %d", fc.connectN)
	}
}

func TestResolveKeepsSelectedSessionThroughReadinessPollingAndRebroker(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectionDescriptor{
			{Connectable: false, Status: "starting"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectionDescriptor{{Connectable: true, Terminal: nil}},
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
		connectSeq: []api.ConnectionDescriptor{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "reconciling"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectionDescriptor{
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
		connectSeq: []api.ConnectionDescriptor{
			{Connectable: false, Status: "starting"}, // initial cli-connect
			readyResponse(readyTerminal()),           // re-broker after route-only status
		},
		statusSeq: []api.ConnectionDescriptor{{Connectable: true, Terminal: routeOnlyTerminal()}},
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
		t.Fatalf("expected 2 ProjectConnectionDescriptor calls (initial + re-broker), got %d", fc.connectN)
	}
}

func TestResolveKeepsPollingWhenRebrokerIsStillStarting(t *testing.T) {
	fc := &fakeClient{
		projects: []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectionDescriptor{
			{Connectable: false, Status: "starting"},
			{Connectable: false, Status: "Paperboat_starting", Reason: "Paperboat_unhealthy"},
			readyResponse(readyTerminal()),
		},
		statusSeq: []api.ConnectionDescriptor{
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
		connectSeq: []api.ConnectionDescriptor{response},
	}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveRejectsEnvironmentOwnedByAnotherProject(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Environment.ProjectID = "prj_other"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "invalid environment") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsNonWSSTerminal(t *testing.T) {
	term := readyTerminal()
	term.Endpoints.WSS = "https://route.example"
	response := readyResponse(term)
	fc := &fakeClient{
		projects:   []api.Project{{ID: "prj_1", Name: "app"}},
		connectSeq: []api.ConnectionDescriptor{response},
	}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "WebSocket endpoint") {
		t.Fatalf("err = %v, want wss validation", err)
	}
}

func TestResolveEnforcesConfiguredRouteHostPolicy(t *testing.T) {
	term := readyTerminal()
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{readyResponse(term)}}
	cfg := &config.Config{}
	cfg.ServerURL = "https://api.paperboat.test"
	cfg.Connect.ReadyTimeoutSeconds = 30
	cfg.Connect.PollIntervalSeconds = 1
	cfg.Connect.AllowedRouteHosts = []string{"relay.example.com"}
	r := NewAPIResolver(fc, cfg)
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "host is not allowed") {
		t.Fatalf("err = %v, want host policy rejection", err)
	}
}

func TestResolveRejectsUnexpectedIssuer(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.Issuer = "https://evil.example"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "unexpected issuer") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsInvalidFileTransferDescriptor(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.FileTransfer.Auth.Scopes = []string{"terminal:operate"}
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "file transfer descriptor") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveAcceptsFrozenTerminalWithoutHTTPBaseURL(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	response := readyResponse(term)
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	if _, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveRejectsTerminalHTTPPortMismatch(t *testing.T) {
	term := readyTerminal()
	term.Endpoints = api.TerminalEndpoints{QUIC: "quic://edge.paperboat.test:8443", WSS: "wss://edge.paperboat.test/v1/runtime"}
	response := readyResponse(term)
	response.FileTransfer.Endpoint = "https://edge.paperboat.test:8443/v1/file-transfers"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "hosts do not match") {
		t.Fatalf("err = %v, want origin mismatch", err)
	}
}

func TestResolveRejectsFileTransferPortMismatch(t *testing.T) {
	response := readyResponse(readyTerminal())
	response.FileTransfer.Endpoint = "https://edge.paperboat.test:8443/v1/file-transfers"
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{response}}
	_, err := newTestResolver(fc).Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || !strings.Contains(err.Error(), "validated terminal route") {
		t.Fatalf("err = %v, want file transfer origin mismatch", err)
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
	fc := &fakeClient{projects: []api.Project{{ID: "prj_1", Name: "app"}}, connectSeq: []api.ConnectionDescriptor{{ProjectID: "prj_1", Connectable: false, RetryAfterSeconds: 300, Status: "starting"}}}
	r := newTestResolver(fc)
	r.readyTimeout = 30 * time.Second
	var waited time.Duration
	r.sleep = func(_ context.Context, d time.Duration) error { waited = d; return context.Canceled }
	_, err := r.Resolve(context.Background(), ConnectRequest{Project: "app"})
	if err == nil || waited <= 0 || waited > 30*time.Second {
		t.Fatalf("err=%v waited=%s", err, waited)
	}
}
