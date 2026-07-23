package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
	"github.com/pujan-modha/paperboat-cli/internal/statusbar"
	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
	"github.com/pujan-modha/paperboat-cli/internal/upload"
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

func TestSelectTerminalSessionDoesNotHideAmbiguousProjectWithConnectedMachine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/projects":
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"prj_1","name":"studio"},{"id":"prj_2","name":"Studio"}],"pagination":{"next_offset":null}}}`))
		case "/api/connected-machines":
			t.Fatal("connected-machine lookup must not hide an ambiguous project name")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := selectTerminalSession(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "studio", false, "", "")
	if !errors.Is(err, resolver.ErrProjectAmbiguous) {
		t.Fatalf("err = %v, want project ambiguity", err)
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

func TestReportActivityRefreshesAndRetriesUnauthorized(t *testing.T) {
	var authHeaders []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		if len(authHeaders) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"accepted":true}}`))
	}))
	defer srv.Close()
	auth := &refreshTestAuth{current: config.Credential{AccessToken: "old"}, refreshed: config.Credential{AccessToken: "new"}}
	if err := reportActivity(context.Background(), srv.URL, auth, "prj_1", "human_input"); err != nil {
		t.Fatal(err)
	}
	if auth.refreshes != 1 || strings.Join(authHeaders, ",") != "Bearer old,Bearer new" {
		t.Fatalf("refreshes=%d headers=%v", auth.refreshes, authHeaders)
	}
	if bodies[1]["source"] != "cli_activity" {
		t.Fatalf("body=%#v", bodies[1])
	}
	metadata, _ := bodies[1]["metadata"].(map[string]any)
	if metadata["event"] != "human_input" {
		t.Fatalf("metadata=%#v", metadata)
	}
}

func TestPollConfigSyncUsesAttachedProjectState(t *testing.T) {
	requested := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("request = %s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/config-sync/status":
			_, _ = w.Write([]byte(`{"data":{"state":"healthy","projects":[{"project_id":"other","state":"healthy"},{"project_id":"attached","state":"warning"}]}}`))
			requested <- struct{}{}
		case "/api/dashboard/usage-summary":
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
		t.Fatalf("active project state was not selected: %q", got)
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

func TestUploadAuthRefreshRebrokersWithFreshControlPlaneCredential(t *testing.T) {
	var controlPlaneAuth, uploadAuth []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/projects":
			controlPlaneAuth = append(controlPlaneAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer control-new" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"prj_1","name":"Demo","state":"running"}],"pagination":{"limit":200,"offset":0,"total":1,"next_offset":null}}}`))
		case "/api/projects/prj_1/cli-connect":
			controlPlaneAuth = append(controlPlaneAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer control-new" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
				return
			}
			now := time.Now().UTC()
			wsURL := "wss" + strings.TrimPrefix(server.URL, "https")
			response := map[string]any{"data": map[string]any{
				"issuer": server.URL, "project_id": "prj_1", "connectable": true, "expires_at": now.Add(5 * time.Minute),
				"environment": map[string]any{"environment_id": "env_1", "project_id": "prj_1", "project_root": "/workspace"},
				"terminal":    map[string]any{"kind": "papercode_websocket", "http_base_url": server.URL, "websocket_base_url": wsURL, "auth": map[string]any{"method": "websocket_ticket", "ticket": "terminal-ticket", "expires_at": now.Add(4 * time.Minute), "scopes": []string{"terminal:operate"}}, "thread_id": "paperboat-cli", "terminal_id": "term_1", "cwd": "/workspace"},
				"upload":      map[string]any{"kind": "papercode_staged_image", "http_base_url": server.URL, "path": "/api/files/staged-images", "auth": map[string]any{"method": "bearer", "token": "upload-new", "expires_at": now.Add(4 * time.Minute), "scopes": []string{"file:stage"}}, "max_bytes": 1024, "allowed_mime_types": []string{"image/png"}, "retention_seconds": 60},
			}}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Fatal(err)
			}
		case "/api/files/staged-images":
			uploadAuth = append(uploadAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer upload-new" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"server rejected the credential"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"path":"/workspace/.paperboat/staged/image.png"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.Config{ServerURL: server.URL, Connect: config.ConnectConfig{ReadyTimeoutSeconds: 30, PollIntervalSeconds: 1, AcceptedTerminalKinds: []string{"papercode_websocket"}}}
	auth := &refreshTestAuth{current: config.Credential{AccessToken: "control-new"}}
	uploader := upload.NewHTTPUploader(server.URL, "/api/files/staged-images", upload.Auth{Method: "bearer", Token: "upload-expired"})
	uploader.HTTPClient = server.Client()
	uploader.RefreshAuth = func(ctx context.Context) (upload.Auth, error) {
		return refreshUploadAuthorization(ctx, auth, func(credential config.Credential) resolver.ProjectResolver {
			return resolver.NewAPIResolver(api.New(server.URL, credential, server.Client()), cfg)
		}, "Demo", "prj_1", "")
	}

	path, err := uploader.Upload(context.Background(), upload.Image{Name: "image.png", MimeType: "image/png", Bytes: []byte("image-bytes")})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/workspace/.paperboat/staged/image.png" {
		t.Fatalf("path = %q", path)
	}
	if got := strings.Join(controlPlaneAuth, ","); got != "Bearer control-new,Bearer control-new" {
		t.Fatalf("control-plane authorization = %q", got)
	}
	if got := strings.Join(uploadAuth, ","); got != "Bearer upload-expired,Bearer upload-new" {
		t.Fatalf("upload authorization = %q", got)
	}
}

func TestConnectWithServerURLUsesBackendResolver(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var sawProjects bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/projects" {
			sawProjects = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"items":[],"pagination":{"limit":200,"offset":0,"total":0,"next_offset":null}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	writeTestProfile(t, dir, configPath, server.URL)

	err := newApp().Run([]string{"pb", "--config", configPath, "--server", server.URL, "demo"})
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

func TestCanonicalPhaseSixCommandsAreDiscoverable(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{{"login"}, {"logout"}, {"create"}, {"session", "attach"}, {"session", "list"}, {"machine", "add"}, {"machine", "list"}, {"machine", "revoke"}, {"preview", "list"}, {"preview", "revoke"}} {
		command, remaining, err := root.Find(path)
		if err != nil || len(remaining) != 0 || command == root {
			t.Fatalf("command %q not discoverable: command=%v remaining=%q err=%v", path, command, remaining, err)
		}
	}
}

func TestPromptChoiceRejectsOutOfRangeAndSelectsStableIndex(t *testing.T) {
	if _, err := promptChoice(bufio.NewReader(strings.NewReader("0\n")), "Region", 2, func(index int) string { return []string{"iad", "lhr"}[index] }); err == nil {
		t.Fatal("out-of-range selection was accepted")
	}
	got, err := promptChoice(bufio.NewReader(strings.NewReader("2\n")), "Region", 2, func(index int) string { return []string{"iad", "lhr"}[index] })
	if err != nil || got != 1 {
		t.Fatalf("selection=%d err=%v", got, err)
	}
}

func TestCreateCatalogFiltersUnavailableOptions(t *testing.T) {
	if got := activeMachineCodes([]api.CatalogMachineType{{Code: "off"}, {Code: "on", Active: true}}); len(got) != 1 || got[0] != "on" {
		t.Fatalf("machine codes=%v", got)
	}
	if got := enabledRegionCodes([]api.CatalogRegion{{Code: "off"}, {Code: "on", Enabled: true}}); len(got) != 1 || got[0] != "on" {
		t.Fatalf("region codes=%v", got)
	}
	if got := activeIdleTimeoutCodes([]api.CatalogIdleTimeout{{Code: "off"}, {Code: "on", Active: true}}); len(got) != 1 || got[0] != "on" {
		t.Fatalf("idle codes=%v", got)
	}
}

func TestMachineRevokeRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"machine", "revoke", "cm_1"})
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
		writeAPIData(t, w, []map[string]any{{"id": "prv_1", "environment_id": "env_1", "project_id": "prj_1", "machine_id": "cm_1", "user_id": "usr_1", "logical_name": "web", "environment_name": "studio", "environment_kind": "byod", "owner_email": "owner@example.test", "url": "https://preview.example.test", "state": "ready", "target_port": 3000}})
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--config", configPath, "preview", "revoke", "prv_1"}, &bytes.Buffer{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "Preview: web (studio, byod)") || !strings.Contains(stderr.String(), "Project: prj_1  Machine: cm_1  User: usr_1") || len(requests) != 1 {
		t.Fatalf("code=%d stderr=%q requests=%v", code, stderr.String(), requests)
	}
}

func TestSessionCloseRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"session", "close", "cm_1", "shell-2"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v, want confirmation error", err)
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
			{"id": "cm_1", "display_name": "Studio"}, {"id": "cm_2", "display_name": "studio"},
		}, "pagination": map[string]any{"next_offset": nil}})
	}))
	defer srv.Close()
	_, _, err := resolveMachineTarget(context.Background(), api.New(srv.URL, config.Credential{AccessToken: "token"}, srv.Client()), "studio")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v, want ambiguity", err)
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

func TestConfigAssignHostedJSONContract(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /api/config-repositories":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "provider": "github", "external_ref": "acme/config", "display_name": "Shared"}}})
		case "GET /api/environments/prj_1/config-assignment":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "not_found_or_forbidden", "message": "not found"}})
		case "PUT /api/environments/prj_1/config-assignment":
			assigned = true
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "environment_id": "prj_1", "repository_id": "cfgrepo_1", "consent_state": "not_required", "version": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Shared", "demo", "--json"}, &output, &output); code != 0 {
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
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.Version != "1" || got.Outcome != "confirmed" || got.Assignment.EnvironmentID != "prj_1" {
		t.Fatalf("output=%q decoded=%+v err=%v", output.String(), got, err)
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
		case "GET /api/connected-machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cm_1", "display_name": "Studio"}}, "pagination": map[string]any{"next_offset": nil}})
		case "POST /api/connected-machines/cm_1/disconnect":
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
		Version string `json:"version"`
		Machine struct {
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
	if got.Version != "1" || got.Machine.ID != "cm_1" || got.Machine.DisplayName != "Studio" || got.Machine.State != "disconnected" || got.Outcome != "confirmed" || got.Retry != "not_required" {
		t.Fatalf("output=%s", output.String())
	}
}

func TestDefaultEnvironmentUsesStableRememberedIDWithoutListing(t *testing.T) {
	client := api.New("https://api.paperboat.test", config.Credential{AccessToken: "token"}, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("remembered target should not list environments")
		return nil, nil
	})})
	got, err := defaultEnvironment(context.Background(), client, "cm_1")
	if err != nil || got != "cm_1" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func TestDefaultEnvironmentSelectsOnlyAvailableTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 0}})
		case "/api/connected-machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cm_1", "display_name": "Studio"}}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := defaultEnvironment(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "")
	if err != nil || got != "cm_1" {
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

func TestKeepAliveCommandCallsBackend(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hours       string
		wantSeconds int
	}{
		{name: "two hours", hours: "2", wantSeconds: 7200},
		{name: "tiny positive", hours: "0.0000001", wantSeconds: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			var gotKeepAlive bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/projects":
					_, _ = w.Write([]byte(`{"data":{"items":[{"id":"prj_1","name":"Demo","state":"running"}],"pagination":{"limit":200,"offset":0,"total":1,"next_offset":null}}}`))
				case "/api/projects/prj_1/keep-alive":
					gotKeepAlive = true
					if r.Header.Get("Authorization") != "Bearer token" {
						t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
					}
					var body struct {
						DurationSeconds int  `json:"duration_seconds"`
						Clear           bool `json:"clear"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body.DurationSeconds != tc.wantSeconds || body.Clear {
						t.Fatalf("keep-alive body = %#v, want duration %d", body, tc.wantSeconds)
					}
					_, _ = w.Write([]byte(`{"data":{"project":{"id":"prj_1","name":"Demo","state":"running"},"keep_alive_until":"2026-07-08T12:00:00Z"}}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			writeTestProfile(t, dir, configPath, server.URL)
			if code := run(context.Background(), []string{"keep-alive", "Demo", "--hours", tc.hours, "--config", configPath, "--server", server.URL}, os.Stdout, os.Stderr); code != 0 {
				t.Fatalf("exit code = %d", code)
			}
			if !gotKeepAlive {
				t.Fatal("expected keep-alive request")
			}
		})
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
	if err := os.WriteFile(path, []byte(`{"connect":{"accepted_terminal_kinds":["papercode_websocket"],"ready_timeout_seconds":30,"poll_interval_seconds":1}}`), 0o600); err != nil {
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
	configJSON := `{"server_url":` + quote(serverURL) + `,"auth":{"allow_file_fallback":true,"profile_dir":` + quote(profileDir) + `},"connect":{"ready_timeout_seconds":30,"poll_interval_seconds":1,"dial_retries":0,"accepted_terminal_kinds":["papercode_websocket"]}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	store := config.ProfileStore{Path: profileDir, Secrets: config.FileSecretStore{Dir: filepath.Join(profileDir, "secrets")}}
	expires := time.Now().Add(time.Hour)
	err := store.Save(config.Profile{Issuer: serverURL, ClientSessionID: "cls_test", AccessExpiresAt: expires}, config.Credential{AccessToken: "token", RefreshToken: "refresh", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUploadLimitsHonorBrokeredUploadPolicy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Upload.MaxImageBytes = 1
	cfg.Upload.MaxDataURLChars = 100
	cfg.Upload.MaxAttachments = 2
	cfg.Upload.AllowedMimePrefixes = []string{"image/"}

	limits := uploadLimits(cfg, &resolver.UploadTarget{
		MaxBytes:         4096,
		AllowedMIMETypes: []string{"image/png", "image/webp"},
	})

	if limits.MaxImageBytes != 4096 {
		t.Fatalf("MaxImageBytes = %d", limits.MaxImageBytes)
	}
	if len(limits.AllowedMimePrefixes) != 0 {
		t.Fatalf("AllowedMimePrefixes = %#v", limits.AllowedMimePrefixes)
	}
	if strings.Join(limits.AllowedMIMETypes, ",") != "image/png,image/webp" {
		t.Fatalf("AllowedMIMETypes = %#v", limits.AllowedMIMETypes)
	}
	if limits.MaxDataURLChars != 100 || limits.MaxAttachments != 2 {
		t.Fatalf("local-only limits changed: %#v", limits)
	}
}

func TestAuthLogoutRetainsPendingRevocationUntilRetrySucceeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/token/revoke" {
			http.NotFound(w, r)
			return
		}
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"unavailable","message":"try again"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	writeTestProfile(t, dir, configPath, server.URL)

	err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"})
	if err == nil || !strings.Contains(err.Error(), "remains pending") {
		t.Fatalf("first logout err = %v", err)
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
	if len(pending) != 1 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
	credential, err := store.PendingRevocationCredential(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	if credential.RefreshToken != "refresh" {
		t.Fatalf("pending refresh token = %q", credential.RefreshToken)
	}

	if err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"}); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations after retry = %d", len(pending))
	}
}

func TestAuthLogoutIgnoresFailedHistoricalRevocationAfterCurrentSucceeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/token/revoke" {
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
	if len(pending) != 1 || pending[0].ClientSessionID != "cls_old" {
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
