package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
)

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
			if err := newApp().Run(normalizeArgs([]string{"pb", "--config", configPath, "--server", server.URL, "keep-alive", "Demo", "--hours", tc.hours})); err != nil {
				t.Fatal(err)
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
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
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

func TestWarnPlaintextCredentialStorage(t *testing.T) {
	var output bytes.Buffer
	cfg := &config.Config{}
	cfg.Auth.AllowFileFallback = true
	warnPlaintextCredentialStorage(cfg, &output)
	got := output.String()
	if !strings.Contains(got, "WARNING:") || !strings.Contains(got, "plaintext") || !strings.Contains(got, "0600") {
		t.Fatalf("warning = %q", got)
	}

	output.Reset()
	cfg.Auth.AllowFileFallback = false
	warnPlaintextCredentialStorage(cfg, &output)
	if output.Len() != 0 {
		t.Fatalf("unexpected secure-store warning = %q", output.String())
	}
}

func TestNormalizeArgsMovesTrailingRootFlagsBeforeNestedAuthCommand(t *testing.T) {
	got := normalizeArgs([]string{"pb", "auth", "login", "--server", "https://api.example.com", "--config", "/tmp/pb.json"})
	want := []string{"pb", "--server", "https://api.example.com", "--config", "/tmp/pb.json", "auth", "login"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalizeArgs = %#v, want %#v", got, want)
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
