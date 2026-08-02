package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
	"github.com/pinksaucepasta/paperboat/internal/statusbar"
	"github.com/pinksaucepasta/paperboat/internal/telemetry"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func writeAPIData(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{"data": data}); err != nil {
		t.Fatal(err)
	}
}

func TestCommandLineArgsNormalizesAndroidPIEArgv(t *testing.T) {
	executable := "/data/data/com.termux/files/home/.local/bin/pb"
	got := commandLineArgs("android", executable, []string{"pb", executable, "auth", "login"})
	if !slices.Equal(got, []string{"auth", "login"}) {
		t.Fatalf("Android args = %v", got)
	}
	for name, test := range map[string]struct {
		goos string
		argv []string
		want []string
	}{
		"ordinary Android invocation": {goos: "android", argv: []string{executable, "pb"}, want: []string{"pb"}},
		"stale Termux marker":         {goos: "android", argv: []string{executable, "login"}, want: []string{"login"}},
		"other platforms":             {goos: "linux", argv: []string{executable, executable, "auth"}, want: []string{executable, "auth"}},
		"empty argv":                  {goos: "android"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := commandLineArgs(test.goos, executable, test.argv); !slices.Equal(got, test.want) {
				t.Fatalf("args = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUserFacingErrorSanitizesInfrastructureFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   string
		forbid []string
	}{
		{
			name:   "network details",
			err:    fmt.Errorf("list projects: call GET /v1/projects: %w", &net.DNSError{Err: "no such host", Name: "api.secret.example"}),
			want:   "Paperboat is unreachable.",
			forbid: []string{"GET", "/v1/projects", "api.secret.example"},
		},
		{
			name:   "server outage",
			err:    &api.APIError{Status: http.StatusBadGateway, RequestID: "req_123"},
			want:   "Paperboat is temporarily unavailable.",
			forbid: []string{"status 502", "paperboat-server"},
		},
		{
			name:   "terminal loss",
			err:    errors.Join(tunnel.ErrTransportLost, errors.New("Application error 0x5042 (remote): server draining")),
			want:   "The terminal connection was lost",
			forbid: []string{"0x5042", "server draining", "transport lost"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := userFacingError(test.err)
			if !strings.Contains(got, test.want) {
				t.Fatalf("message = %q, want %q", got, test.want)
			}
			for _, forbidden := range test.forbid {
				if strings.Contains(got, forbidden) {
					t.Fatalf("message = %q contains %q", got, forbidden)
				}
			}
		})
	}
}

func TestRunTreatsCancellationAsUserCancellation(t *testing.T) {
	if got := userFacingError(context.Canceled); got != "Operation canceled." {
		t.Fatalf("message = %q", got)
	}
}

func TestCollectLocalDoctorDoesNotCreateUnconfiguredIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-state")
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", root)
	report := collectLocalDoctor()
	if report.SetupState != "not_set_up" || report.IdentityState != "missing" || !slices.Contains(report.RecoveryActions, "run pb setup") {
		t.Fatalf("report=%+v", report)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor mutated unconfigured state: %v", err)
	}
}

func TestCollectLocalDoctorReportsMachineInboxCredentialAndPreviews(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", root)
	store, err := identity.Open(identity.Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(root, "Paperboat Inbox")
	if err := os.Mkdir(inboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := identity.Registration{ServerURL: "https://api.example.test", MachineID: "machine_local", EnvironmentID: "env_local", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: inboxPath, InstallationGeneration: 4, SetupRoles: []string{"interactive", "host"}, UpdatedAt: time.Now().UTC()}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMachineControl(identity.MachineControl{MachineID: registration.MachineID, EnvironmentID: registration.EnvironmentID, InstallationGeneration: registration.InstallationGeneration, Credential: strings.Repeat("x", 32), ExpiresAt: time.Now().UTC().Add(time.Hour), KeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	descriptor, _ := json.Marshal(map[string]any{"schema": "paperboat.preview-runtime/v1", "name": "docs", "port": 3000, "indefinite": false, "expires_at": expires, "service_definition": ""})
	if err := os.WriteFile(filepath.Join(active, "docs.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	report := collectLocalDoctor()
	if report.SetupState != "configured" || report.IdentityState != "valid" || report.MachineID != "machine_local" || report.InstallationGeneration != 4 || !slices.Equal(report.SetupRoles, []string{"interactive", "host"}) || report.InboxState != "ready" || report.CredentialState != "valid" || report.ActivePreviews != 1 || report.InvalidPreviews != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestDoctorValidatesServedPreviewSourceWithoutReportingPath(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "site")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	source, _ := servepkg.ResolveSource(sourcePath)
	identityValue, _ := source.Identity()
	expires := time.Now().UTC().Add(time.Hour)
	descriptor, _ := json.Marshal(map[string]any{
		"schema": "paperboat.preview-runtime/v1", "name": "site", "bind_address": "127.0.0.1", "port": 32000, "service_generation": 1, "indefinite": false, "expires_at": expires, "service_definition": "",
		"serve": map[string]any{"source_path": source.Path, "source_kind": source.Kind, "source_identity": identityValue, "spa": false, "owner_mode": "detached"},
	})
	directory := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "site.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	report := localDoctorReport{}
	inspectLocalPreviewDescriptors(&report, directory, time.Now().UTC())
	if report.ActivePreviews != 1 || report.ServedPreviews != 1 || report.InvalidPreviews != 0 || report.InvalidServeSources != 0 {
		t.Fatalf("report = %#v", report)
	}
	encoded, _ := json.Marshal(report)
	if bytes.Contains(encoded, []byte(source.Path)) {
		t.Fatalf("doctor leaked source path: %s", encoded)
	}
}

func TestDoctorComparesServedRoutesWithLocalWorkloads(t *testing.T) {
	report := localDoctorReport{MachineID: "machine_local", ActiveServedPreviews: 1, RuntimeForegroundServes: 1}
	compareLocalServedPreviewRoutes(&report, []api.Preview{
		{ID: "detached", ResourceID: "machine_local", SourceKind: "directory", State: "ready"},
		{ID: "foreground", ResourceID: "machine_local", SourceKind: "file", State: "ready"},
		{ID: "other", ResourceID: "machine_other", SourceKind: "file", State: "ready"},
	})
	if report.RouteReadiness != "ready" || report.RemoteServedPreviews != 2 {
		t.Fatalf("report=%+v", report)
	}
	report = localDoctorReport{MachineID: "machine_local", ActiveServedPreviews: 1}
	compareLocalServedPreviewRoutes(&report, []api.Preview{{ID: "orphan", ResourceID: "machine_local", SourceKind: "file", State: "ready"}, {ID: "orphan2", ResourceID: "machine_local", SourceKind: "file", State: "ready"}})
	if report.RouteReadiness != "workload_route_drift" || len(report.RecoveryActions) == 0 {
		t.Fatalf("drift report=%+v", report)
	}
}

func TestHostRuntimeEntryPointIsHiddenAndStrict(t *testing.T) {
	root := newRootCommand()
	command, _, err := root.Find([]string{"__runtime-host"})
	if err != nil || command == nil || !command.Hidden {
		t.Fatalf("runtime command = %#v, %v", command, err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"__runtime-host", "extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 || strings.Contains(stdout.String(), "__runtime-host") {
		t.Fatalf("help exposed runtime command: code=%d output=%q", code, stdout.String())
	}
}

func TestConnectTelemetryFailsOpenWithWarning(t *testing.T) {
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Observability: config.ObservabilityConfig{EventLogPath: filepath.Join(blockedParent, "telemetry.jsonl")}}
	var warnings bytes.Buffer
	sink, closeSink := connectTelemetry(cfg, &warnings)
	defer closeSink()
	if _, ok := sink.(telemetry.NopSink); !ok {
		t.Fatalf("sink type = %T, want telemetry.NopSink", sink)
	}
	if warnings.String() != "warning: telemetry disabled: local event log unavailable\n" {
		t.Fatalf("warning = %q", warnings.String())
	}
}

func TestRetryableInitialConnectError(t *testing.T) {
	if retryableInitialConnectError(fmt.Errorf("connect to project: %w", resolver.ErrProjectNotFound)) {
		t.Fatal("project lookup failure must not retry")
	}
	if !retryableInitialConnectError(&api.APIError{Code: "machine_not_ready"}) {
		t.Fatal("machine_not_ready should retry")
	}
}

func TestSelectTerminalSessionDoesNotHideAmbiguousProjectWithUserMachine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"prj_1","name":"studio"},{"id":"prj_2","name":"Studio"}],"pagination":{"next_offset":null}}}`))
		case "/v1/machines":
			t.Fatal("machine lookup must not hide an ambiguous project name")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := selectTerminalSession(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "studio", "", "named")
	if !errors.Is(err, resolver.ErrProjectAmbiguous) {
		t.Fatalf("err = %v, want project ambiguity", err)
	}
}

func TestSelectTerminalSessionCreatesFreshSessionByDefault(t *testing.T) {
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "studio", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			created = true
			writeAPIData(t, w, map[string]any{"id": "pts_1", "name": "quiet-harbor", "state": "open", "created_at": time.Now(), "updated_at": time.Now()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, err := selectTerminalSession(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "studio", "", "")
	if err != nil || got.ID != "pts_1" || got.Name != "quiet-harbor" || !created {
		t.Fatalf("fresh session = %+v, %v; created=%t", got, err, created)
	}
}

func TestTerminalArgsAcceptsOnlyOptionalNewKeyword(t *testing.T) {
	validate := terminalArgs(0)
	for _, values := range [][]string{nil, {"studio"}, {"studio", "new"}} {
		if err := validate(nil, values); err != nil {
			t.Fatalf("values %q rejected: %v", values, err)
		}
	}
	if err := validate(nil, []string{"studio", "attach"}); err == nil {
		t.Fatal("unexpected second keyword accepted")
	}
}

type refreshTestAuth struct {
	current   config.Credential
	refreshed config.Credential
	refreshes int
}

func (a *refreshTestAuth) Credential() (config.Credential, error) { return a.current, nil }
func (a *refreshTestAuth) Refresh() (config.Credential, error) {
	a.refreshes++
	return a.refreshed, nil
}

func TestPollConfigSyncUsesAttachedProjectState(t *testing.T) {
	requested := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("request = %s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/config-sync/status":
			_, _ = w.Write([]byte(`{"data":{"state":"healthy","environments":[{"environment_id":"other","state":"healthy","mode":"pull_only","manifest_health":"empty"},{"environment_id":"attached","state":"warning","mode":"bidirectional","manifest_health":"healthy","managed_path_count":2,"pending_clean_path_count":1}]}}`))
			requested <- struct{}{}
		case "/v1/usage-summary":
			_, _ = w.Write([]byte(`{"data":{"credits":{"balance":"100.000000"},"storage":{"available_gb":12}}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputReader.Close()
	bar := statusbar.New(statusbar.Options{
		Mode:           statusbar.ModeAuto,
		Term:           "xterm-256color",
		NoticeDuration: time.Second,
		Input:          input,
		Output:         output,
		IsTerminal:     func(int) bool { return true },
		GetSize:        func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("config-sync poll was not requested")
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync needs attention") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync needs attention") {
		t.Fatalf("attached environment state was not selected: %q", got)
	}
	deadline = time.Now().Add(time.Second)
	for !strings.Contains(bar.Render(80), "credits 100") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Render(80); !strings.Contains(got, "credits 100") {
		t.Fatalf("usage summary was not rendered: %q", got)
	}
	cancel()
	<-done
	_ = bar.Close()
	_ = output.Close()
	raw, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Config sync needs attention") || !strings.Contains(string(raw), "credits 100") {
		t.Fatalf("status/usage were not rendered: %q", raw)
	}
}

func TestPollConfigSyncWaitsForAttachedProjectStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"state":"healthy","projects":[]}}`))
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	_, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	bar := statusbar.New(statusbar.Options{
		Mode: statusbar.ModeAuto, Term: "xterm-256color", NoticeDuration: time.Second,
		Input: input, Output: output, IsTerminal: func(int) bool { return true },
		GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync awaiting status") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync awaiting status") || strings.Contains(got, "unavailable") {
		t.Fatalf("missing-project status = %q", got)
	}
	cancel()
	<-done
}

func TestPollConfigSyncKeepsAuthenticationFailuresVisible(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"Authentication is required."}}`))
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	_, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	bar := statusbar.New(statusbar.Options{
		Mode: statusbar.ModeAuto, Term: "xterm-256color", NoticeDuration: time.Second,
		Input: input, Output: output, IsTerminal: func(int) bool { return true },
		GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("config-sync request was not sent")
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync status unavailable") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync status unavailable") {
		t.Fatalf("authentication failure was hidden: %q", got)
	}
	cancel()
	<-done
}

func TestFormatStatusCredits(t *testing.T) {
	for raw, want := range map[string]string{
		"100":        "100",
		"100.000000": "100",
		"0.000000":   "0",
		"12.340000":  "12.34",
	} {
		if got := formatStatusCredits(raw); got != want {
			t.Fatalf("formatStatusCredits(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestConnectWithServerURLUsesBackendResolver(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "runtime")
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
	identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(dir, "Paperboat Inbox")
	if err := os.MkdirAll(inboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.SaveRegistration(identity.Registration{ServerURL: "https://api.example.test", MachineID: "machine_source", EnvironmentID: "env_source", PublicKeyID: identityStore.Current().ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityStore.Current().Public()), InboxPath: inboxPath, InstallationGeneration: 1, SetupRoles: []string{"interactive"}, UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	var sawProjects bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/projects" {
			sawProjects = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"items":[],"pagination":{"limit":200,"offset":0,"total":0,"next_offset":null}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	writeTestProfile(t, dir, configPath, server.URL)

	err = newApp().Run([]string{"pb", "--config", configPath, "--server", server.URL, "demo"})
	if err == nil {
		t.Fatal("expected project lookup error")
	}
	if !sawProjects {
		t.Fatal("expected backend project list request")
	}
	if !strings.Contains(err.Error(), "project not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestHelpCommandDoesNotCallBackend(t *testing.T) {
	var output bytes.Buffer
	app := newApp()
	app.Writer = &output
	app.ErrWriter = &output
	if err := app.Run([]string{"pb", "help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Usage:") || !strings.Contains(output.String(), "Available Commands:") {
		t.Fatalf("help output = %q", output.String())
	}
}

func TestVersionFlags(t *testing.T) {
	previous := buildinfo.Version
	buildinfo.Version = "2026.07.25.0"
	t.Cleanup(func() { buildinfo.Version = previous })
	for _, flag := range []string{"--version", "-v"} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{flag}, &stdout, &stderr); code != 0 || stdout.String() != versionDisplay("2026.07.25.0") || stderr.Len() != 0 {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", flag, code, stdout.String(), stderr.String())
		}
	}
}

func TestVersionDisplayIncludesBrandAndVersion(t *testing.T) {
	display := versionDisplay("2026.08.02.0")
	if !strings.Contains(display, "Paperboat") || !strings.Contains(display, "Version 2026.08.02.0") {
		t.Fatalf("version display = %q", display)
	}
}

func TestBrandDisplayAlignsMetadataByTerminalCellWidth(t *testing.T) {
	display := brandDisplay("2026.08.02.0", "person@example.com")
	details := []string{"Paperboat", "Version 2026.08.02.0", "person@example.com"}
	lines := strings.Split(display, "\n")
	if len(lines) != len(details) {
		t.Fatalf("brand lines = %q", lines)
	}
	column := -1
	for index, detail := range details {
		position := strings.Index(lines[index], detail)
		if position < 0 {
			t.Fatalf("line %d missing %q: %q", index, detail, lines[index])
		}
		cell := ansi.StringWidth(lines[index][:position])
		if column < 0 {
			column = cell
		} else if cell != column {
			t.Fatalf("line %d metadata column = %d, want %d: %q", index, cell, column, lines[index])
		}
	}
}

func TestUpdateSelectedTransportUsesSelectorOutcome(t *testing.T) {
	bar := statusbar.New(statusbar.Options{
		Mode:   statusbar.ModeOff,
		Layout: statusbar.Layout{Right: []string{"connection"}},
	})
	bar.SetConnection("connected")

	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "quic"}, "selected")
	if line := bar.Render(40); !strings.HasSuffix(line, "connected  Q") {
		t.Fatalf("selected QUIC transport missing from status bar: %q", line)
	}
	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "wss"}, "selected")
	if line := bar.Render(40); !strings.HasSuffix(line, "connected  W") {
		t.Fatalf("selected WSS transport missing from status bar: %q", line)
	}
	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "quic"}, "failure")
	if line := bar.Render(40); !strings.HasSuffix(line, "connected  W") {
		t.Fatalf("failed selection changed status bar transport: %q", line)
	}
}

func TestCanonicalCommandsAreDiscoverable(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{{"login"}, {"logout"}, {"pair"}, {"session", "attach"}, {"session", "list"}, {"machine", "add"}, {"machine", "list"}, {"machine", "revoke"}, {"machine", "availability"}, {"preview", "list"}, {"preview", "revoke"}} {
		command, remaining, err := root.Find(path)
		if err != nil || len(remaining) != 0 || command == root {
			t.Fatalf("command %q not discoverable: command=%v remaining=%q err=%v", path, command, remaining, err)
		}
	}
	for _, removed := range []string{"create", "projects"} {
		command, remaining, err := root.Find([]string{removed})
		if err != nil || command != root || len(remaining) != 1 {
			t.Fatalf("removed command %q is still discoverable: command=%v remaining=%q err=%v", removed, command, remaining, err)
		}
	}
}

func TestMachineSessionActivityUsesNewestAvailableTimestamp(t *testing.T) {
	created := time.Unix(10, 0)
	updated := time.Unix(20, 0)
	active := time.Unix(30, 0)
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created, UpdatedAt: updated, LastActiveAt: &active}}).activity(); !got.Equal(active) {
		t.Fatalf("activity=%v want=%v", got, active)
	}
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created, UpdatedAt: updated}}).activity(); !got.Equal(updated) {
		t.Fatalf("activity=%v want=%v", got, updated)
	}
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created}}).activity(); !got.Equal(created) {
		t.Fatalf("activity=%v want=%v", got, created)
	}
}

func TestFavoritesSortFirstWithoutReorderingPeers(t *testing.T) {
	values := []struct {
		id       string
		favorite bool
	}{{"first", false}, {"star-a", true}, {"second", false}, {"star-b", true}}
	slices.SortStableFunc(values, func(a, b struct {
		id       string
		favorite bool
	}) int {
		return compareFavorites(a.favorite, b.favorite)
	})
	got := make([]string, 0, len(values))
	for _, value := range values {
		got = append(got, value.id)
	}
	if strings.Join(got, ",") != "star-a,star-b,first,second" {
		t.Fatalf("order=%v", got)
	}
}

func TestMaskEmailHidesAddressUntilExplicitReveal(t *testing.T) {
	if got := maskEmail("person@example.com"); got != "██████@███████.███" {
		t.Fatalf("masked email=%q", got)
	}
	if got := maskEmail("Not signed in"); got != "Not signed in" {
		t.Fatalf("non-email=%q", got)
	}
}

func TestMachineAvailabilityRequiresConfirmationAndReturnsAppliedJSON(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"machine", "availability", "um_1", "--mode", "keep-awake"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("confirmation error=%v", err)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio", "availability": map[string]any{"schema": "paperboat.availability-policy/v1", "desired_mode": "allow_sleep", "desired_version": 3, "observed_version": 3, "status": "applied"}}}, "pagination": map[string]any{"next_offset": nil}})
		case "PUT /v1/machines/um_1/availability-policy":
			if r.Header.Get("Idempotency-Key") == "" {
				t.Fatal("missing idempotency key")
			}
			writeAPIData(t, w, map[string]any{"schema": "paperboat.availability-policy/v1", "desired_mode": "keep_awake", "desired_version": 4, "observed_mode": "keep_awake", "observed_version": 4, "status": "applied", "observed_at": "2026-07-26T12:00:00Z", "host_service_version": "test", "host_service_scope": "system"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "availability", "Studio", "--mode", "keep-awake", "--yes", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var output struct {
		Version      string                 `json:"version"`
		Outcome      string                 `json:"outcome"`
		Retry        string                 `json:"retry"`
		Availability api.AvailabilityPolicy `json:"availability"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output.Version != "1" || output.Outcome != "applied" || output.Retry != "automatic" || output.Availability.DesiredVersion != 4 {
		t.Fatalf("output=%q decoded=%+v err=%v", stdout.String(), output, err)
	}
	if !strings.Contains(stderr.String(), "Machine: Studio (um_1)") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestUserMachineDoctorStateCoversBootConnectorAndAvailability(t *testing.T) {
	ready := api.UserMachine{
		SetupMode:          "host",
		RuntimeDiagnostics: api.RuntimeDiagnostics{WorkerGeneration: 7, OSBootID: "boot-1", WorkerServiceScope: "system", ConnectorState: "ready", ConnectorGeneration: 3},
		Availability:       api.AvailabilityPolicy{DesiredMode: "keep_awake", DesiredVersion: 2, ObservedMode: "keep_awake", ObservedVersion: 2, Status: "applied"},
	}
	if state, code := userMachineDoctorState(ready); state != "ready" || code != "" {
		t.Fatalf("ready state=%q code=%q", state, code)
	}
	legacy := ready
	legacy.RuntimeDiagnostics.WorkerServiceScope = "user"
	if state, code := userMachineDoctorState(legacy); state != "error" || code != "boot_service_not_system" {
		t.Fatalf("legacy state=%q code=%q", state, code)
	}
	recovering := ready
	recovering.RuntimeDiagnostics.ConnectorState = "unavailable"
	if state, code := userMachineDoctorState(recovering); state != "degraded" || code != "connector_recovering" {
		t.Fatalf("connector state=%q code=%q", state, code)
	}
	drift := ready
	drift.Availability.ObservedVersion = 1
	if state, code := userMachineDoctorState(drift); state != "degraded" || code != "availability_drift" {
		t.Fatalf("availability state=%q code=%q", state, code)
	}
}

func TestCreateCatalogFiltersUnavailableOptions(t *testing.T) {
	if got := activeMachineCodes([]api.CatalogMachineType{{Code: "off"}, {Code: "on", Active: true}}); len(got) != 1 || got[0] != "on" {
		t.Fatalf("machine codes=%v", got)
	}
	if got := enabledRegionCodes([]api.CatalogRegion{{Code: "off"}, {Code: "on", Enabled: true}}); len(got) != 1 || got[0] != "on" {
		t.Fatalf("region codes=%v", got)
	}
}

func TestMachineRevokeRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"machine", "revoke", "um_1"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v, want confirmation error", err)
	}
}

func TestPreviewRevokeDisplaysResolvedContextBeforeConfirmation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected mutation before confirmation: %s %s", r.Method, r.URL.Path)
		}
		writeAPIData(t, w, []map[string]any{{"id": "prv_1", "environment_id": "env_1", "project_id": "prj_1", "resource_id": "um_1", "user_id": "usr_1", "logical_name": "web", "environment_name": "studio", "environment_kind": "byod", "owner_email": "owner@example.test", "url": "https://preview.example.test", "state": "ready", "target_port": 3000}})
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--config", configPath, "preview", "revoke", "prv_1"}, &bytes.Buffer{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "Preview: web (studio, byod)") || !strings.Contains(stderr.String(), "Project: prj_1  Resource: um_1  User: usr_1") || len(requests) != 1 {
		t.Fatalf("code=%d stderr=%q requests=%v", code, stderr.String(), requests)
	}
}

func TestSessionCloseRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"session", "close", "um_1", "shell-2"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v, want confirmation error", err)
	}
}

func TestSessionCloseAllRequiresConfirmationAndRejectsSessionArgument(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	mutated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}}, "pagination": map[string]any{"next_offset": nil}})
		default:
			mutated = true
			t.Fatalf("unexpected request before confirmation: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "sessions", "close", "demo", "--all"}, &output, &output); code != 1 || mutated || !strings.Contains(output.String(), "Environment: demo (prj_1)") || !strings.Contains(output.String(), "Open sessions to close: 1") || !strings.Contains(output.String(), "requires --yes") {
		t.Fatalf("code=%d mutated=%t output=%q", code, mutated, output.String())
	}

	root := newRootCommand()
	root.SetArgs([]string{"session", "close", "um_1", "shell-2", "--all", "--yes"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "usage: pb session close") {
		t.Fatalf("err=%v, want mutually exclusive usage error", err)
	}
}

func TestSessionCloseAllClosesEveryOpenSession(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}, {"id": "ses_2", "name": "api", "state": "open"}, {"id": "ses_3", "name": "old", "state": "closed"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/close"):
			closed = append(closed, r.URL.Path)
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "session", "close", "demo", "--all", "--yes"}, &output, &output); code != 0 {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
	if len(closed) != 2 || !strings.Contains(closed[0], "ses_1") || !strings.Contains(closed[1], "ses_2") {
		t.Fatalf("closed=%v", closed)
	}
	if !strings.Contains(output.String(), "Closed 2 sessions in demo.") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestSessionsCloseAllClosesEveryOpenSessionAndRetainsHistory(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}, {"id": "ses_2", "name": "api", "state": "open"}, {"id": "ses_3", "name": "old", "state": "closed"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/close"):
			closed = append(closed, r.URL.Path)
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "sessions", "close", "demo", "--all", "--yes"}, &output, &output); code != 0 {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
	if len(closed) != 2 || !strings.Contains(output.String(), "Open sessions to close: 2") || !strings.Contains(output.String(), "Session history was retained") {
		t.Fatalf("closed=%v output=%q", closed, output.String())
	}
}

func TestPreviewsListsAndPurgesOnlySelectedEnvironment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var revoked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/previews":
			writeAPIData(t, w, []map[string]any{
				{"id": "prv_1", "environment_id": "prj_1", "project_id": "prj_1", "logical_name": "web", "environment_name": "demo", "state": "ready", "url": "https://one.example.test", "target_port": 3000},
				{"id": "prv_2", "environment_id": "prj_2", "project_id": "prj_2", "logical_name": "other", "environment_name": "other", "state": "ready", "url": "https://two.example.test", "target_port": 4000},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/previews/"):
			revoked = append(revoked, r.URL.Path)
			writeAPIData(t, w, map[string]any{"id": "prv_1", "state": "removed"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "previews"}, &output, &output); code != 0 || !strings.Contains(output.String(), "web") || !strings.Contains(output.String(), "other") {
		t.Fatalf("list code=%d output=%q", code, output.String())
	}
	output.Reset()
	if code := run(context.Background(), []string{"--config", configPath, "previews", "revoke", "demo", "--all"}, &output, &output); code != 1 || len(revoked) != 0 || !strings.Contains(output.String(), "Active previews to revoke: 1") || !strings.Contains(output.String(), "requires --yes") {
		t.Fatalf("unconfirmed revoke code=%d revoked=%v output=%q", code, revoked, output.String())
	}
	output.Reset()
	if code := run(context.Background(), []string{"--config", configPath, "previews", "revoke", "demo", "--all", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("revoke code=%d output=%q", code, output.String())
	}
	if len(revoked) != 1 || revoked[0] != "/v1/previews/prv_1" || !strings.Contains(output.String(), `"revoked":1`) {
		t.Fatalf("revoked=%v output=%q", revoked, output.String())
	}
}

func TestSessionListAcceptsDefaultEnvironment(t *testing.T) {
	root := newRootCommand()
	command, remaining, err := root.Find([]string{"session", "list"})
	if err != nil || command == root || len(remaining) != 0 {
		t.Fatalf("session list lookup command=%v remaining=%q err=%v", command, remaining, err)
	}
	if err := command.Args(command, nil); err != nil {
		t.Fatalf("session list rejected omitted environment: %v", err)
	}
}

func TestResolveMachineTargetRejectsAmbiguousNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAPIData(t, w, map[string]any{"items": []map[string]any{
			{"id": "um_1", "display_name": "Studio"}, {"id": "um_2", "display_name": "studio"},
		}, "pagination": map[string]any{"next_offset": nil}})
	}))
	defer srv.Close()
	_, _, err := resolveUserMachineTarget(context.Background(), api.New(srv.URL, config.Credential{AccessToken: "token"}, srv.Client()), "studio")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v, want ambiguity", err)
	}
}

func TestResolveSetupModeRequiresExplicitModeWithoutTTY(t *testing.T) {
	if _, err := resolveSetupMode("", false, io.Discard); err == nil || !strings.Contains(err.Error(), "requires --mode") {
		t.Fatalf("err=%v, want non-interactive mode requirement", err)
	}
	for _, mode := range []string{"receive", "session", "host"} {
		got, err := resolveSetupMode(mode, false, io.Discard)
		if err != nil || got != mode {
			t.Fatalf("resolveSetupMode(%q)=(%q,%v)", mode, got, err)
		}
	}
	if _, err := resolveSetupMode("interactive", false, io.Discard); err == nil || !strings.Contains(err.Error(), "receive, session, or host") {
		t.Fatalf("err=%v, want supported modes", err)
	}
}

func TestMachineHomeActionsFollowConfiguredCapabilities(t *testing.T) {
	machine := api.UserMachine{ID: "machine_actions", SetupMode: "receive", Capabilities: api.MachineCapabilities{
		FileReceive: api.MachineCapability{Configured: true}, PreviewLaunch: api.MachineCapability{Configured: true},
	}}
	actions := machineHomeActions(machine)
	ids := make([]string, len(actions))
	for index, action := range actions {
		ids[index] = action.ID
	}
	if !slices.Equal(ids, []string{"send", "preview", "previews"}) {
		t.Fatalf("receive actions=%v", ids)
	}
	machine.SetupMode = "host"
	machine.Capabilities.TerminalHost.Configured = true
	actions = machineHomeActions(machine)
	ids = ids[:0]
	for _, action := range actions {
		ids = append(ids, action.ID)
	}
	if !slices.Equal(ids, []string{"terminal", "codex", "send", "preview", "sessions", "previews", "allow-sleep", "keep-awake"}) {
		t.Fatalf("host actions=%v", ids)
	}
}

func TestMachineStatusSummarySeparatesAvailabilityFromMode(t *testing.T) {
	tests := []struct {
		name    string
		machine api.UserMachine
		want    string
	}{
		{
			name:    "online host",
			machine: api.UserMachine{Online: true, SetupMode: "host", Platform: "linux", Architecture: "arm64"},
			want:    "Online  ·  Host",
		},
		{
			name:    "offline receive",
			machine: api.UserMachine{SetupMode: "receive", Platform: "darwin", Architecture: "arm64"},
			want:    "Offline  ·  Receive only",
		},
		{
			name:    "inactive session",
			machine: api.UserMachine{SetupMode: "session"},
			want:    "Session only",
		},
		{
			name:    "legacy host inferred from capability",
			machine: api.UserMachine{State: "disconnected", Capabilities: api.MachineCapabilities{TerminalHost: api.MachineCapability{Configured: true}}},
			want:    "Offline  ·  Host",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := machineStatusSummary(test.machine); got != test.want {
				t.Fatalf("summary=%q want=%q", got, test.want)
			}
		})
	}
}

func TestAsyncHomeValueStartsImmediatelyAndTracksFreshness(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	value := startAsyncHomeValue(context.Background(), func(context.Context) (string, error) {
		close(started)
		<-release
		return "ready", nil
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background load did not start")
	}
	if value.ready() {
		t.Fatal("blocked load reported ready")
	}
	close(release)
	got, err := value.await(context.Background())
	if err != nil || got != "ready" || !value.fresh() {
		t.Fatalf("value=%q err=%v fresh=%t", got, err, value.fresh())
	}
	value.fetchedAt = time.Now().Add(-homePrefetchFreshness - time.Second)
	if value.fresh() {
		t.Fatal("expired prefetch remained fresh")
	}
}

func TestMachinesSortCurrentDeviceLast(t *testing.T) {
	machines := []api.UserMachine{{ID: "current", DisplayName: "Local"}, {ID: "favorite", DisplayName: "Favorite"}, {ID: "remote", DisplayName: "Remote"}}
	favorites := favoriteSet{}
	favorites.Set("machine", "current", true)
	favorites.Set("machine", "favorite", true)
	sortMachinesForDisplay(machines, favorites, "current")
	if got := []string{machines[0].ID, machines[1].ID, machines[2].ID}; !slices.Equal(got, []string{"favorite", "remote", "current"}) {
		t.Fatalf("machine order=%v", got)
	}
	if got := machineDisplayTitle(machines[2], "current"); got != "Local (this device)" {
		t.Fatalf("current title=%q", got)
	}
}

func TestDroppedFilePathsParsesQuotedAndEscapedPaths(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first file.txt")
	second := filepath.Join(directory, "second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	value := strconv.Quote(first) + " " + strings.ReplaceAll(second, " ", "\\ ")
	paths, err := droppedFilePaths(value)
	if err != nil || !slices.Equal(paths, []string{first, second}) {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	if _, err := droppedFilePaths(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing dropped file was accepted")
	}
}

func TestSetupRollbackContextSurvivesCanceledCommand(t *testing.T) {
	type contextKey string
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), contextKey("operation"), "setup"))
	cancelParent()

	rollback, cancelRollback := setupRollbackContext(parent)
	defer cancelRollback()
	if err := rollback.Err(); err != nil {
		t.Fatalf("rollback context inherited cancellation: %v", err)
	}
	if got := rollback.Value(contextKey("operation")); got != "setup" {
		t.Fatalf("rollback context value=%v", got)
	}
	if deadline, ok := rollback.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 15*time.Second {
		t.Fatalf("rollback deadline=(%v,%t)", deadline, ok)
	}
}

func TestConfigCommandsAreDiscoverableAndUnassignRequiresConfirmation(t *testing.T) {
	root := newRootCommand()
	for _, path := range []string{"config assign", "config unassign", "config show", "config path"} {
		command, _, err := root.Find(strings.Fields(path))
		if err != nil || command.CommandPath() != "pb "+path {
			t.Fatalf("find %q command=%v err=%v", path, command, err)
		}
	}
	root.SetArgs([]string{"config", "unassign", "prj_1"})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompatibilityOnlyCommandsAreAbsent(t *testing.T) {
	root := newRootCommand()
	for parentName, removed := range map[string][]string{
		"config":   {"enable", "disable"},
		"preview":  {"remove", "purge"},
		"previews": {"purge"},
		"session":  {"purge"},
		"sessions": {"purge"},
	} {
		parent, _, err := root.Find([]string{parentName})
		if err != nil {
			t.Fatal(err)
		}
		for _, removedName := range removed {
			for _, child := range parent.Commands() {
				if child.Name() == removedName {
					t.Fatalf("compatibility-only command %q is still registered under %q", removedName, parentName)
				}
			}
		}
	}
}

func TestConfigSetRejectsRemovedTerminalProfile(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "config", "set", "terminal-profile", "full"})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "usage: pb config set server <url>") {
		t.Fatalf("err=%v", err)
	}
}

func TestStatusBarConfigCommandsPersistValidatePreviewAndReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, args := range [][]string{
		{"--config", path, "config", "status-bar", "set", "theme", "dark"},
		{"--config", path, "config", "status-bar", "set", "privacy", "true"},
		{"--config", path, "config", "status-bar", "set", "center", "none"},
		{"--config", path, "config", "status-bar", "set", "right", "activity,connection"},
	} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
			t.Fatalf("%v exited %d", args, code)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StatusBar.Theme != "dark" || !cfg.StatusBar.Privacy || strings.Join(cfg.StatusBar.Right, ",") != "activity,connection" {
		t.Fatalf("persisted status bar = %+v", cfg.StatusBar)
	}
	var preview bytes.Buffer
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "preview", "--width", "60"}, &preview, &preview); code != 0 {
		t.Fatalf("preview exited %d: %q", code, preview.String())
	}
	if lines := strings.Count(strings.TrimSpace(preview.String()), "\n") + 1; lines != 3 {
		t.Fatalf("preview lines = %d: %q", lines, preview.String())
	}
	var invalid bytes.Buffer
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "set", "accent", "not-a-color"}, &invalid, &invalid); code != 2 {
		t.Fatalf("invalid color exited %d: %q", code, invalid.String())
	}
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "reset"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("reset exited %d", code)
	}
	cfg, err = config.Load(path)
	if err != nil || cfg.StatusBar.Theme != config.DefaultStatusBarTheme || cfg.StatusBar.Privacy {
		t.Fatalf("reset status bar = %+v err=%v", cfg.StatusBar, err)
	}
}

func TestConnectStatusBarOverridesAreValidated(t *testing.T) {
	var output bytes.Buffer
	if code := run(context.Background(), []string{"connect", "demo", "--status-bar-theme", "rainbow"}, &output, &output); code != 2 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
}

func TestConfigAssignHostedMachineJSONContract(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "mch_1", "environment_id": "prj_1", "display_name": "demo", "machine_kind": "hosted", "setup_roles": []string{"host"}}}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/config-repositories":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "provider": "github", "external_ref": "acme/config", "display_name": "Shared"}}})
		case "GET /v1/machines/mch_1/config-assignment":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "not_found_or_forbidden", "message": "not found"}})
		case "PUT /v1/machines/mch_1/config-assignment":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["mode"] != "push_only" {
				t.Fatalf("assignment body=%v err=%v", body, err)
			}
			assigned = true
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "machine_id": "mch_1", "environment_id": "prj_1", "repository_id": "cfgrepo_1", "mode": "push_only", "consent_state": "not_required", "version": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Shared", "demo", "--mode", "push-only", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !assigned {
		t.Fatal("assignment endpoint was not called")
	}
	var got struct {
		Version    string               `json:"version"`
		Outcome    string               `json:"outcome"`
		Assignment api.ConfigAssignment `json:"assignment"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.Version != "1" || got.Outcome != "confirmed" || got.Assignment.EnvironmentID != "prj_1" || got.Assignment.Mode != "push_only" {
		t.Fatalf("output=%q decoded=%+v err=%v", output.String(), got, err)
	}
}

func TestConfigAssignMachineRequiresPlaintextConsentAndAcceptsExactRevision(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	mutations := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "environment_id": "env_1", "display_name": "Studio"}}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/config-repositories":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "display_name": "Dotfiles"}}})
		case "GET /v1/machines/um_1/config-assignment":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found_or_forbidden","message":"not found"}}`))
		case "PUT /v1/machines/um_1/config-assignment":
			mutations++
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "environment_id": "env_1", "repository_id": "cfgrepo_1", "mode": "bidirectional", "consent_state": "pending", "warning_revision": "plain-v1", "version": 1})
		case "GET /v1/machines/um_1/config-assignment/warning":
			writeAPIData(t, w, map[string]any{"revision": "plain-v1", "machine_name": "Studio", "repository_name": "Dotfiles", "repository_visibility": "ordinary plaintext", "history_retention": "Git history retains versions", "access_consequence": "repository access may read content"})
		case "POST /v1/machines/um_1/config-assignment/consent":
			mutations++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["warning_revision"] != "plain-v1" || body["expected_version"] != float64(1) {
				t.Fatalf("consent body=%v err=%v", body, err)
			}
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "environment_id": "env_1", "repository_id": "cfgrepo_1", "mode": "bidirectional", "consent_state": "accepted", "warning_revision": "plain-v1", "version": 2})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var rejected bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Dotfiles", "Studio", "--mode", "bidirectional"}, &rejected, &rejected); code == 0 || mutations != 0 || !strings.Contains(rejected.String(), "ordinary plaintext") {
		t.Fatalf("exit=%d mutations=%d output=%q", code, mutations, rejected.String())
	}
	var accepted bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Dotfiles", "Studio", "--mode", "bidirectional", "--yes", "--json"}, &accepted, &accepted); code != 0 {
		t.Fatalf("exit=%d output=%q", code, accepted.String())
	}
	if mutations != 2 || !strings.Contains(accepted.String(), `"consent_state":"accepted"`) {
		t.Fatalf("mutations=%d output=%q", mutations, accepted.String())
	}
}

func TestMachineRevokeJSONOutputContract(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var disconnected bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio"}}, "pagination": map[string]any{"next_offset": nil}})
		case "POST /v1/machines/um_1/disconnect":
			disconnected = true
			writeAPIData(t, w, map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "revoke", "Studio", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("exit code=%d output=%q", code, output.String())
	}
	if !disconnected {
		t.Fatal("disconnect endpoint was not called")
	}
	var got struct {
		Version     string `json:"version"`
		UserMachine struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			State       string `json:"state"`
		} `json:"machine"`
		Outcome string `json:"outcome"`
		Retry   string `json:"retry"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode output %q: %v", output.String(), err)
	}
	if got.Version != "1" || got.UserMachine.ID != "um_1" || got.UserMachine.DisplayName != "Studio" || got.UserMachine.State != "disconnected" || got.Outcome != "confirmed" || got.Retry != "not_required" {
		t.Fatalf("output=%s", output.String())
	}
}

func TestMachineAddUsesServerOwnedMachinesURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/client-configuration" {
			http.NotFound(w, r)
			return
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Fatalf("authorization=%q", authorization)
		}
		writeAPIData(t, w, api.ClientConfiguration{
			Version:            "1",
			CLIVerificationURL: "https://dashboard.paperboat.test/cli/authorize",
			MachinesURL:        "https://dashboard.paperboat.test/dashboard/machines",
		})
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	originalOpenBrowser := openBrowser
	t.Cleanup(func() { openBrowser = originalOpenBrowser })
	var opened string
	openBrowser = func(target string) error {
		opened = target
		return nil
	}

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "add"}, &output, &output); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	want := "https://dashboard.paperboat.test/dashboard/machines"
	if opened != want || !strings.Contains(output.String(), "Continue machine enrollment at "+want) {
		t.Fatalf("opened=%q output=%q", opened, output.String())
	}
}

func TestDefaultEnvironmentUsesStableRememberedIDWithoutListing(t *testing.T) {
	client := api.New("https://api.paperboat.test", config.Credential{AccessToken: "token"}, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("remembered target should not list environments")
		return nil, nil
	})})
	got, err := defaultEnvironment(context.Background(), client, "um_1")
	if err != nil || got != "um_1" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func TestDefaultEnvironmentSelectsOnlyAvailableTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 0}})
		case "/v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio", "online": true, "capabilities": map[string]any{"terminal_host": map[string]any{"configured": true, "observed": true}}}}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := defaultEnvironment(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "")
	if err != nil || got != "um_1" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func TestRootWithoutArgumentsAttemptsPrimaryWorkflow(t *testing.T) {
	var output bytes.Buffer
	app := newApp()
	app.Writer = &output
	app.ErrWriter = &output
	err := app.Run([]string{"pb", "--config", filepath.Join(t.TempDir(), "config.json")})
	if err == nil {
		t.Fatal("expected an actionable setup error")
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("root stopped at generic help: %q", output.String())
	}
}

func TestCobraRootWithoutArgumentsAttemptsPrimaryWorkflow(t *testing.T) {
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "config.json")}, &output, &output); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("root stopped at generic help: %q", output.String())
	}
}

func TestConnectDoesNotExposeSessionOverrides(t *testing.T) {
	for _, flag := range []string{"--size", "--agent"} {
		t.Run(flag, func(t *testing.T) {
			err := newApp().Run([]string{"pb", flag, "value", "demo"})
			if err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestConnectWithoutServerDoesNotRunLocalShell(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := newApp().Run([]string{"pb", "--config", configPath, "demo"})
	if err == nil || !strings.Contains(err.Error(), "server is not configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestDoctorReturnsFailureWhenBackendIsUnconfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"connect":{"ready_timeout_seconds":30,"poll_interval_seconds":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newApp().Run([]string{"pb", "--config", path, "doctor"}); err == nil {
		t.Fatal("doctor returned success for missing server")
	}
}

func TestCobraAcceptsPersistentFlagsAfterNestedCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var output bytes.Buffer
	if code := run(context.Background(), []string{"config", "path", "--server", "https://api.example.com", "--config", path}, &output, &output); code != 0 {
		t.Fatalf("exit code = %d, output = %q", code, output.String())
	}
}

func TestCobraParsesNestedSessionFlagsWithoutRewriting(t *testing.T) {
	var output bytes.Buffer
	code := run(context.Background(), []string{"sessions", "delete", "demo", "api", "--yes", "--server", "http://127.0.0.1:1"}, &output, &output)
	if code != 1 || strings.Contains(output.String(), "unknown flag") {
		t.Fatalf("exit code = %d output = %q", code, output.String())
	}
}

func TestCobraUsageErrorsReturnExitCodeTwo(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "unknown"},
		{"connect", "demo", "--", "--new"},
		{"demo", "--new", "--session", "api"},
		{"config", "path", "extra"},
	} {
		var output bytes.Buffer
		if code := run(context.Background(), args, &output, &output); code != 2 {
			t.Fatalf("args=%q exit code=%d output=%q", args, code, output.String())
		}
		if !strings.Contains(output.String(), "Usage:") {
			t.Fatalf("args=%q missing usage: %q", args, output.String())
		}
	}
}

func TestBareServerFlagPersistsNormalizedServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if code := run(context.Background(), []string{"--config", path, "--server", "https://api.example.com/"}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://api.example.com" {
		t.Fatalf("server URL = %q", cfg.ServerURL)
	}
}

func TestFileCredentialFallbackPersistsSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := fileCredentialFallback(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.AllowFileFallback {
		t.Fatal("file credential fallback was not enabled")
	}
	if _, ok := store.Secrets.(config.FileSecretStore); !ok {
		t.Fatalf("secret store = %T, want config.FileSecretStore", store.Secrets)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Auth.AllowFileFallback {
		t.Fatal("file credential fallback consent was not persisted")
	}
}

func TestSessionNameReservesOnlyAutomaticShellNames(t *testing.T) {
	if err := validateSessionName("shell-tools"); err != nil {
		t.Fatalf("shell-tools should be valid: %v", err)
	}
	if err := validateSessionName("shell-2"); err == nil {
		t.Fatal("shell-2 should be reserved")
	}
}

func quote(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}

func writeTestProfile(t *testing.T, dir, configPath, serverURL string) {
	t.Helper()
	profileDir := filepath.Join(dir, "credentials")
	configJSON := `{"server_url":` + quote(serverURL) + `,"auth":{"allow_file_fallback":true,"profile_dir":` + quote(profileDir) + `},"connect":{"ready_timeout_seconds":30,"poll_interval_seconds":1,"dial_retries":0}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	store := config.ProfileStore{Path: profileDir, Secrets: config.FileSecretStore{Dir: filepath.Join(profileDir, "secrets")}}
	expires := time.Now().Add(time.Hour)
	err := store.Save(config.Profile{Issuer: serverURL, CLIClientSessionID: "cls_test", AccessExpiresAt: expires}, config.Credential{AccessToken: "token", RefreshToken: "refresh", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthLogoutIsLocalEvenWhenRemoteRevocationFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke" {
			http.NotFound(w, r)
			return
		}
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"unavailable","message":"try again"}}`))
	}))
	defer server.Close()
	writeTestProfile(t, dir, configPath, server.URL)

	if err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"}); err != nil {
		t.Fatalf("logout err = %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(server.URL); !errors.Is(err, config.ErrNoCredentials) {
		t.Fatalf("active profile err = %v", err)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
	if attempts != 1 {
		t.Fatalf("remote revocation attempts = %d", attempts)
	}
}

func TestAuthLogoutIgnoresFailedHistoricalRevocationAfterCurrentSucceeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer refresh-old" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"old revocation failed"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	writeTestProfile(t, dir, configPath, server.URL)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(server.URL, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"}); err != nil {
		t.Fatalf("logout err = %v", err)
	}
	if _, err := store.Load(server.URL); !errors.Is(err, config.ErrNoCredentials) {
		t.Fatalf("active profile err = %v", err)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %#v", pending)
	}
}

func TestDrainPendingRevocationsProcessesMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	store := config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	var revoked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revoked = append(revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	if err := store.QueueRevocation(server.URL, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(server.URL, "cls_failed_login", "refresh-new"); err != nil {
		t.Fatal(err)
	}
	if err := drainPendingRevocations(context.Background(), server.URL, store); err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked = %#v", revoked)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
}

func TestCleanupIssuedSessionQueuesAndRevokesSwitchSession(t *testing.T) {
	dir := t.TempDir()
	store := config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	var revoked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revoked = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	if err := cleanupIssuedSession(server.URL, "cls_new", "refresh-new", store); err != nil {
		t.Fatal(err)
	}
	if revoked != "refresh-new" {
		t.Fatalf("revoked token = %q", revoked)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
}

func TestForwardedTerminalEnvFiltersInvalidAndUnset(t *testing.T) {
	t.Setenv("PB_TEST_TERM", "xterm-256color")
	t.Setenv("PB_TEST_EMPTY", "")
	env := forwardedTerminalEnv([]string{"PB_TEST_TERM", "PB_TEST_EMPTY", "PB_TEST_UNSET_VAR", "bad-key!"})
	if len(env) != 1 || env["PB_TEST_TERM"] != "xterm-256color" {
		t.Fatalf("env = %#v", env)
	}
}

func TestTerminalHostErrorDistinguishesCapabilityAndAvailability(t *testing.T) {
	receive := api.UserMachine{Online: true}
	var apiErr *api.APIError
	if err := terminalHostError(receive); !errors.As(err, &apiErr) || apiErr.Code != "machine_capability_unavailable" {
		t.Fatalf("receive error = %#v", err)
	}
	host := receive
	host.Capabilities.TerminalHost.Configured = true
	if err := terminalHostError(host); !errors.As(err, &apiErr) || apiErr.Code != "machine_offline" {
		t.Fatalf("offline host error = %#v", err)
	}
	host.Capabilities.TerminalHost.Observed = true
	if err := terminalHostError(host); err != nil {
		t.Fatalf("ready host error = %v", err)
	}
}

func TestServeCommandContractValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing path", args: []string{"serve"}, want: "requires <path>"},
		{name: "public acknowledgement", args: []string{"serve", file}, want: "pass --public"},
		{name: "duration conflict", args: []string{"serve", file, "--public", "--duration", "1h", "--indefinite"}, want: "--duration"},
		{name: "spa file", args: []string{"serve", file, "--public", "--spa"}, want: "--spa requires a directory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := newRootCommand()
			root.SetArgs(test.args)
			err := root.ExecuteContext(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestServeCommandIsLocalOnly(t *testing.T) {
	root := newRootCommand()
	serveEntry, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	if serveEntry.Flags().Lookup("machine") != nil {
		t.Fatal("serve exposes a machine selector")
	}
	for _, name := range []string{"name", "duration", "indefinite", "detach", "spa", "public", "json"} {
		if serveEntry.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s", name)
		}
	}
}

func TestServeJSONInvocationFailureUsesEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"serve", "--json"}, &stdout, &stderr)
	if code != 2 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code               string `json:"code"`
			Category           string `json:"category"`
			PublicStateCreated any    `json:"public_state_created"`
			Cleanup            string `json:"cleanup"`
		} `json:"error"`
	}
	if json.Unmarshal(stdout.Bytes(), &envelope) != nil || envelope.SchemaVersion != "1.0" || envelope.OK || envelope.Error.Code != "serve_invocation_invalid" || envelope.Error.Category != "usage" || envelope.Error.PublicStateCreated != "unknown" || envelope.Error.Cleanup != "not_required" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestServeProtocolIncompatibleUsesTypedEnvelope(t *testing.T) {
	envelope := serveErrorEnvelope(errServeProtocolIncompatible)
	if envelope["code"] != "protocol_incompatible" || envelope["category"] != "protocol" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestNormalizeServeName(t *testing.T) {
	if got := normalizeServeName("", "My Report (Final).HTML"); got != "my-report-final-html" {
		t.Fatalf("derived name = %q", got)
	}
	if got := normalizeServeName("docs_v2", "ignored"); got != "docs_v2" {
		t.Fatalf("explicit name = %q", got)
	}
}

func TestEnrichLocalServeSources(t *testing.T) {
	stateRoot := t.TempDir()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
	directory := filepath.Join(stateRoot, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "site")
	descriptor := func(id, path string) []byte {
		return []byte(fmt.Sprintf(`{"schema":"paperboat.preview-runtime/v1","record":{"id":%q},"serve":{"source_path":%q}}`, id, path))
	}
	if err := os.WriteFile(filepath.Join(directory, "valid.json"), descriptor("served", source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "permissive.json"), descriptor("unsafe", "/private/unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, descriptor("linked", "/private/linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "linked.json")); err != nil {
		t.Fatal(err)
	}
	items := enrichLocalServeSources([]api.Preview{
		{ID: "served", SourceKind: "directory"},
		{ID: "unsafe", SourceKind: "file"},
		{ID: "linked", SourceKind: "file"},
		{ID: "served", SourceKind: "application"},
	})
	if items[0].SourcePath != filepath.Clean(source) {
		t.Fatalf("valid source path = %q", items[0].SourcePath)
	}
	for index := 1; index < len(items); index++ {
		if items[index].SourcePath != "" {
			t.Fatalf("unsafe item %d was enriched with %q", index, items[index].SourcePath)
		}
	}
}
