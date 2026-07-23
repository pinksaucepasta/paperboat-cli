package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

func writeData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func TestListProjectsFollowsPagination(t *testing.T) {
	var offsets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offsets = append(offsets, r.URL.Query().Get("offset"))
		if r.URL.Query().Get("offset") == "0" {
			next := 1
			writeData(w, http.StatusOK, ProjectPage{Items: []Project{{ID: "prj_1", Name: "A"}}, Pagination: Pagination{Limit: 200, Total: 2, NextOffset: &next}})
			return
		}
		writeData(w, http.StatusOK, ProjectPage{Items: []Project{{ID: "prj_2", Name: "B"}}, Pagination: Pagination{Limit: 200, Offset: 1, Total: 2}})
	}))
	defer srv.Close()

	projects, err := New(srv.URL, config.Credential{AccessToken: "t"}, nil).ListProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 || projects[1].ID != "prj_2" || len(offsets) != 2 || offsets[0] != "0" || offsets[1] != "1" {
		t.Fatalf("projects = %#v, offsets = %#v", projects, offsets)
	}
}

func TestCreateProjectUsesBearerAndIdempotencyKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/projects" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Idempotency-Key") != "create-1" {
			t.Fatalf("authorization=%q idempotency=%q", r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"))
		}
		var input CreateProjectInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.RepositoryURL != "https://github.com/acme/app.git" || input.MachineTypeCode != "shared-2x" {
			t.Fatalf("input=%+v", input)
		}
		writeData(w, http.StatusCreated, Project{ID: "prj_1", Name: "app", State: "provisioning"})
	}))
	defer srv.Close()
	project, err := New(srv.URL, config.Credential{AccessToken: "token"}, nil).CreateProject(context.Background(), CreateProjectInput{
		RepositoryURL: "https://github.com/acme/app.git", StorageGB: 20, MachineTypeCode: "shared-2x", RegionCode: "iad", IdleTimeoutCode: "30m",
	}, "create-1")
	if err != nil || project.ID != "prj_1" {
		t.Fatalf("project=%+v err=%v", project, err)
	}
}

func TestConfigAssignmentRequestsUseBearerAndSnakeCase(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		switch r.Method + " " + r.URL.Path {
		case "GET /api/config-repositories":
			writeData(w, http.StatusOK, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "provider": "github", "external_ref": "acme/config", "display_name": "Config"}}})
		case "GET /api/environments/prj_1/config-assignment":
			writeData(w, http.StatusOK, map[string]any{"id": "cfgasn_1", "environment_id": "prj_1", "repository_id": "cfgrepo_1", "consent_state": "not_required", "version": 2})
		case "PUT /api/environments/prj_1/config-assignment":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["repository_id"] != "cfgrepo_1" || body["expected_version"] != float64(2) {
				t.Fatalf("body=%v", body)
			}
			writeData(w, http.StatusOK, map[string]any{"id": "cfgasn_1", "environment_id": "prj_1", "repository_id": "cfgrepo_1", "consent_state": "not_required", "version": 3})
		case "DELETE /api/environments/prj_1/config-assignment":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, config.Credential{AccessToken: "token"}, srv.Client())
	repos, err := c.ListConfigRepositories(context.Background())
	if err != nil || len(repos) != 1 || repos[0].ID != "cfgrepo_1" {
		t.Fatalf("repos=%v err=%v", repos, err)
	}
	assignment, err := c.ConfigAssignment(context.Background(), "prj_1")
	if err != nil || assignment.Version != 2 || assignment.RepositoryID == nil {
		t.Fatalf("assignment=%+v err=%v", assignment, err)
	}
	if _, err := c.AssignConfig(context.Background(), "prj_1", "cfgrepo_1", 2); err != nil {
		t.Fatal(err)
	}
	if err := c.UnassignConfig(context.Background(), "prj_1", 3); err != nil {
		t.Fatal(err)
	}
	if got := requests[len(requests)-1]; got != "DELETE /api/environments/prj_1/config-assignment?expected_version=3" {
		t.Fatalf("last request=%q", got)
	}
}

func TestPreviewRequestsUseAccountScopeAndIdempotency(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		preview := map[string]any{"id": "prv_1", "environment_id": "env_1", "project_id": "prj_1", "machine_id": "cm_1", "user_id": "usr_1", "logical_name": "web", "preview_key": "p-abcdefghijklmnopqrstuvwxyz", "url": "https://p-abcdefghijklmnopqrstuvwxyz.preview.example.test", "target_port": 3000, "state": "registering", "version": 1}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/previews":
			writeData(w, http.StatusOK, []any{preview})
		case "DELETE /api/previews/prv_1":
			if r.Header.Get("Idempotency-Key") != "preview-remove-1" {
				t.Fatalf("idempotency=%q", r.Header.Get("Idempotency-Key"))
			}
			preview["state"] = "removed"
			writeData(w, http.StatusOK, preview)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := New(srv.URL, config.Credential{AccessToken: "token"}, srv.Client())
	items, err := client.ListPreviews(context.Background())
	if err != nil || len(items) != 1 || items[0].LogicalName != "web" || items[0].ProjectID != "prj_1" || items[0].MachineID != "cm_1" || items[0].UserID != "usr_1" {
		t.Fatalf("items=%v err=%v", items, err)
	}
	removed, err := client.RemovePreview(context.Background(), "prv_1", "preview-remove-1")
	if err != nil || removed.State != "removed" {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests=%v", requests)
	}
}

func TestCreateProjectChoicesDecodeFromScopedRoutes(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/github/repositories":
			writeData(w, http.StatusOK, []GitHubRepository{{FullName: "acme/app", CloneURL: "https://github.com/acme/app.git"}})
		case "/api/catalog/machine-types":
			writeData(w, http.StatusOK, []CatalogMachineType{{Code: "shared-2x", Active: true}})
		case "/api/catalog/regions":
			writeData(w, http.StatusOK, []CatalogRegion{{Code: "iad", Enabled: true}})
		case "/api/catalog/idle-timeouts":
			writeData(w, http.StatusOK, []CatalogIdleTimeout{{Code: "30m", Active: true}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, config.Credential{AccessToken: "token"}, nil)
	repositories, err := c.ListGitHubRepositories(context.Background())
	if err != nil || len(repositories) != 1 || repositories[0].FullName != "acme/app" {
		t.Fatalf("repositories=%v err=%v", repositories, err)
	}
	machines, err := c.ListCatalogMachineTypes(context.Background())
	if err != nil || len(machines) != 1 || machines[0].Code != "shared-2x" {
		t.Fatalf("machines=%v err=%v", machines, err)
	}
	regions, err := c.ListCatalogRegions(context.Background())
	if err != nil || len(regions) != 1 || regions[0].Code != "iad" {
		t.Fatalf("regions=%v err=%v", regions, err)
	}
	idle, err := c.ListCatalogIdleTimeouts(context.Background())
	if err != nil || len(idle) != 1 || idle[0].Code != "30m" {
		t.Fatalf("idle=%v err=%v", idle, err)
	}
	if len(seen) != 4 {
		t.Fatalf("routes=%v", seen)
	}
}

func TestConnectedMachineRequestsUseScopedRoutes(t *testing.T) {
	var paths []string
	var connectBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		switch r.URL.Path {
		case "/api/connected-machines":
			writeData(w, http.StatusOK, ConnectedMachinePage{Items: []ConnectedMachine{{ID: "cm_1", DisplayName: "Studio Mac", Online: true}}, Pagination: Pagination{}})
		case "/api/connected-machines/cm_1/connect":
			body, _ := io.ReadAll(r.Body)
			connectBodies = append(connectBodies, string(body))
			writeData(w, http.StatusOK, ConnectResponse{ConnectedMachineID: "cm_1", Connectable: false})
		case "/api/connected-machines/cm_1/connection-status":
			writeData(w, http.StatusOK, ConnectResponse{ConnectedMachineID: "cm_1", Connectable: false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "t"}, nil)
	machines, err := c.ListConnectedMachines(context.Background())
	if err != nil || len(machines) != 1 || machines[0].ID != "cm_1" {
		t.Fatalf("machines=%+v err=%v", machines, err)
	}
	if _, err := c.ConnectConnectedMachine(context.Background(), "cm_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConnectConnectedMachineSession(context.Background(), "cm_1", "pts_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConnectedMachineConnectionStatus(context.Background(), "cm_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConnectedMachineConnectionStatusSession(context.Background(), "cm_1", "pts_1"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths, ","); !strings.Contains(got, "GET /api/connected-machines?limit=200&offset=0&sort=display_name") || !strings.Contains(got, "POST /api/connected-machines/cm_1/connect") || !strings.Contains(got, "GET /api/connected-machines/cm_1/connection-status?terminal_session_id=pts_1") {
		t.Fatalf("paths=%q", got)
	}
	if got := strings.Join(connectBodies, ","); got != `,{"terminal_session_id":"pts_1"}` {
		t.Fatalf("connect bodies=%q", got)
	}
}

func TestConnectedMachineRevokeRequestsUseBearer(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		writeData(w, http.StatusOK, map[string]any{"ok": true})
	}))
	defer srv.Close()
	c := New(srv.URL, config.Credential{AccessToken: "token"}, nil)
	if err := c.DisconnectConnectedMachine(context.Background(), "cm_1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteConnectedMachine(context.Background(), "cm_1"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(seen, ","); got != "POST /api/connected-machines/cm_1/disconnect Bearer token,DELETE /api/connected-machines/cm_1 Bearer token" {
		t.Fatalf("requests=%q", got)
	}
}

func TestConnectedMachineTerminalSessionRequests(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /api/connected-machines/cm_1/terminal-sessions":
			if r.Header.Get("Idempotency-Key") != "key-1" {
				t.Fatalf("missing idempotency key")
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pts_1","name":"api","state":"running","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
		case "GET /api/connected-machines/cm_1/terminal-sessions":
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"pts_1","name":"api","state":"running","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],"pagination":{"next_offset":null}}}`))
		case "PATCH /api/connected-machines/cm_1/terminal-sessions/pts_1":
			_, _ = w.Write([]byte(`{"data":{"id":"pts_1","name":"renamed","state":"running","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
		case "POST /api/connected-machines/cm_1/terminal-sessions/pts_1/close", "DELETE /api/connected-machines/cm_1/terminal-sessions/pts_1":
			writeData(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, config.Credential{AccessToken: "token"}, nil)
	if session, err := c.CreateConnectedMachineTerminalSession(context.Background(), "cm_1", "api", "key-1"); err != nil || session.ID != "pts_1" {
		t.Fatalf("create session=%+v err=%v", session, err)
	}
	if sessions, err := c.ListConnectedMachineTerminalSessions(context.Background(), "cm_1"); err != nil || len(sessions) != 1 || sessions[0].ID != "pts_1" {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
	if _, err := c.RenameConnectedMachineTerminalSession(context.Background(), "cm_1", "pts_1", "renamed"); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseConnectedMachineTerminalSession(context.Background(), "cm_1", "pts_1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteConnectedMachineTerminalSession(context.Background(), "cm_1", "pts_1"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("requests=%v", seen)
	}
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func TestClientSendsBearer(t *testing.T) {
	var gotToken, gotProtocol string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("Authorization")
		gotProtocol = r.Header.Get("X-Paperboat-Protocol")
		writeData(w, http.StatusOK, Me{ID: "usr_1", Email: "a@b.dev"})
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "sess-token"}, nil)
	me, err := c.Me(context.Background())
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if gotToken != "Bearer sess-token" {
		t.Fatalf("authorization = %q", gotToken)
	}
	if gotProtocol == "" {
		t.Fatal("missing protocol negotiation header")
	}
	if me.Email != "a@b.dev" {
		t.Fatalf("me.Email = %q", me.Email)
	}
}

func TestClientIncompatibleVersionIsActionable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = io.WriteString(w, `{"error":{"code":"incompatible_client_version","message":"upgrade required","details":{"required_protocol":"2"}}}`)
	}))
	defer srv.Close()
	_, err := New(srv.URL, config.Credential{}, nil).Me(context.Background())
	var versionErr *ErrIncompatibleVersion
	if !errors.As(err, &versionErr) || versionErr.Required != "2" || !strings.Contains(versionErr.Error(), "upgrade") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeviceAuthorizeIncompatibleVersionIsActionable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = io.WriteString(w, `{"error":{"code":"incompatible_client_version","message":"upgrade pb before signing in","details":{"required_protocol":"2"}}}`)
	}))
	defer srv.Close()
	_, err := DeviceAuthorize(context.Background(), srv.URL, "device", "desktop", "darwin", nil)
	var versionErr *ErrIncompatibleVersion
	if !errors.As(err, &versionErr) || versionErr.Required != "2" || !strings.Contains(versionErr.Error(), "upgrade pb") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientUnauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{}, nil)
	_, err := c.ListProjects(context.Background())
	if err != ErrUnauthenticated {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestListProjectsDecodesPaginatedResponse(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Query().Get("offset") {
		case "0":
			writeData(w, http.StatusOK, map[string]any{
				"items":      []Project{{ID: "prj_1", Name: "One"}},
				"pagination": map[string]any{"next_offset": 1},
			})
		case "1":
			writeData(w, http.StatusOK, map[string]any{
				"items":      []Project{{ID: "prj_2", Name: "Two"}},
				"pagination": map[string]any{"next_offset": nil},
			})
		default:
			t.Fatalf("unexpected offset %q", r.URL.Query().Get("offset"))
		}
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "token"}, nil)
	projects, err := c.ListProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(projects) != 2 || projects[0].ID != "prj_1" || projects[1].ID != "prj_2" {
		t.Fatalf("requests=%d projects=%#v", requests, projects)
	}
}

func TestClientStructuredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Request-Id", "req_123")
		writeErr(w, http.StatusConflict, "machine_not_ready", "Machine is not ready.")
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "t"}, nil)
	_, err := c.CLIConnect(context.Background(), "prj_1")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("err type = %T, want *APIError", err)
	}
	if apiErr.Code != "machine_not_ready" || apiErr.Status != http.StatusConflict || apiErr.RequestID != "req_123" || !strings.Contains(apiErr.Error(), "request req_123") {
		t.Fatalf("apiErr = %+v", apiErr)
	}
}

func TestIncompatibleVersionAlwaysIncludesUpgradeGuidance(t *testing.T) {
	err := (&ErrIncompatibleVersion{Message: "protocol 1 is unsupported"}).Error()
	if !strings.Contains(err, "upgrade pb") {
		t.Fatalf("error = %q", err)
	}
}

func TestClientRejectsUnsafeRequestID(t *testing.T) {
	for _, value := range []string{"secret value", "path/value", "line\nbreak"} {
		if got := safeRequestID(value); got != "" {
			t.Fatalf("safeRequestID(%q) = %q", value, got)
		}
	}
}

func TestClientMutationUsesBearerWithoutCSRF(t *testing.T) {
	var gotAuthorization string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/projects/prj_1/keep-alive" {
			gotAuthorization = r.Header.Get("Authorization")
			writeData(w, http.StatusOK, KeepAliveResponse{Project: Project{ID: "prj_1", Name: "Demo", State: "running"}})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "initial-session"}, nil)
	if _, err := c.SetKeepAlive(context.Background(), "prj_1", 3600, false); err != nil {
		t.Fatalf("SetKeepAlive: %v", err)
	}
	if gotAuthorization != "Bearer initial-session" {
		t.Fatalf("authorization = %q", gotAuthorization)
	}
}

func TestCLIConnectDecodesPapercodeWebSocketTerminal(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/projects/prj_1/cli-connect" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ = io.ReadAll(r.Body)
		writeData(w, http.StatusOK, ConnectResponse{
			ProjectID:   "prj_1",
			Connectable: true,
			Terminal: &Terminal{
				Kind:             "papercode_websocket",
				HTTPBaseURL:      "https://agentunnel.dev/projects/prj_1",
				WebSocketBaseURL: "wss://agentunnel.dev/projects/prj_1",
				Auth:             AuthMaterial{Method: "websocket_ticket", Ticket: "pct_1", Scopes: []string{"terminal:operate"}},
				ThreadID:         "paperboat-cli",
				TerminalID:       "term-1",
				CWD:              "/workspace",
			},
			Upload: &Upload{Kind: "papercode_staged_image", HTTPBaseURL: "https://agentunnel.dev/projects/prj_1", Path: "/projects/prj_1/api/files/staged-images", MaxBytes: 10485760, RetentionSeconds: 604800},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "t"}, nil)
	resp, err := c.CLIConnect(context.Background(), "prj_1")
	if err != nil {
		t.Fatalf("CLIConnect: %v", err)
	}
	if !resp.Connectable || resp.Terminal == nil || resp.Terminal.Kind != "papercode_websocket" || resp.Terminal.WebSocketBaseURL != "wss://agentunnel.dev/projects/prj_1" {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Terminal.Auth.Method != "websocket_ticket" || resp.Terminal.Auth.Ticket != "pct_1" {
		t.Fatalf("terminal auth = %+v", resp.Terminal.Auth)
	}
	if resp.Upload == nil || resp.Upload.Kind != "papercode_staged_image" || resp.Upload.HTTPBaseURL != "https://agentunnel.dev/projects/prj_1" || resp.Upload.Path != "/projects/prj_1/api/files/staged-images" || resp.Upload.RetentionSeconds != 604800 {
		t.Fatalf("upload = %+v", resp.Upload)
	}
	if len(body) != 0 {
		t.Fatalf("cli-connect request body = %q, want empty", string(body))
	}
}

func TestTerminalSessionRequests(t *testing.T) {
	var createKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/projects/prj_1/terminal-sessions":
			createKey = r.Header.Get("Idempotency-Key")
			_, _ = w.Write([]byte(`{"data":{"id":"pts_1","name":"api","state":"running","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
		case "GET /api/projects/prj_1/terminal-sessions":
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"pts_1","name":"api","state":"running","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],"pagination":{"limit":200,"offset":0,"total":1,"next_offset":null}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, config.Credential{AccessToken: "token"}, nil)
	created, err := c.CreateTerminalSession(context.Background(), "prj_1", "api", "key-1")
	if err != nil || created.ID != "pts_1" || createKey != "key-1" {
		t.Fatalf("created=%+v key=%q err=%v", created, createKey, err)
	}
	sessions, err := c.ListTerminalSessions(context.Background(), "prj_1")
	if err != nil || len(sessions) != 1 || sessions[0].Name != "api" {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
}

func TestConnectionStatusSessionUsesSelectedTerminalID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/projects/prj_1/connection-status" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("terminal_session_id"); got != "pts_api" {
			t.Fatalf("terminal_session_id = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"project_id": "prj_1", "connectable": false}})
	}))
	defer server.Close()

	client := New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
	if _, err := client.ConnectionStatusSession(context.Background(), "prj_1", "pts_api"); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeCanonicalConnectionDescriptor(t *testing.T) {
	expires := time.Now().Add(time.Minute).UTC()
	response := ConnectResponse{
		Schema: ConnectionSchemaV1, Issuer: "https://api.paperboat.test", Connectable: true, ExpiresAt: expires,
		Environment: &Environment{ID: "env_1", Kind: "byod", ResourceID: "cm_1", DisplayName: "Studio", State: "ready", Root: "/Users/paperboat"},
		Terminal:    &Terminal{Endpoint: "wss://edge.paperboat.test/e/env_1/terminal", HTTPEndpoint: "https://edge.paperboat.test", SessionID: "session_1"},
		Upload:      &Upload{Endpoint: "https://edge.paperboat.test/e/env_1/uploads"},
	}
	if err := response.NormalizeConnectionDescriptor(); err != nil {
		t.Fatal(err)
	}
	if response.ConnectedMachineID != "cm_1" || response.Environment.EnvironmentID != "env_1" || response.Environment.ProjectRoot != "/Users/paperboat" {
		t.Fatalf("canonical environment was not normalized: %#v", response)
	}
	if response.Terminal.Kind != "paperboat_terminal_v1" || response.Terminal.WebSocketBaseURL != response.Terminal.Endpoint {
		t.Fatalf("canonical terminal was not normalized: %#v", response.Terminal)
	}
	if response.Upload.Kind != "paperboat_staged_image_v1" || response.Upload.HTTPBaseURL != "https://edge.paperboat.test" || response.Upload.Path != "/e/env_1/uploads" {
		t.Fatalf("canonical upload was not normalized: %#v", response.Upload)
	}
}

func TestNormalizeConnectionDescriptorRejectsUnknownSchema(t *testing.T) {
	response := ConnectResponse{Schema: "paperboat.environment-connection/v2"}
	if err := response.NormalizeConnectionDescriptor(); err == nil {
		t.Fatal("expected unknown schema to fail closed")
	}
}

func TestCLIConnectDecodesCanonicalDescriptor(t *testing.T) {
	expires := time.Now().Add(time.Minute).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, http.StatusOK, map[string]any{
			"schema": ConnectionSchemaV1, "issuer": "https://api.paperboat.test", "connectable": true, "expires_at": expires,
			"environment": map[string]any{"id": "env_1", "kind": "hosted", "resource_id": "prj_1", "state": "ready", "root": "/workspace"},
			"terminal":    map[string]any{"endpoint": "wss://edge.paperboat.test/e/env_1/terminal", "http_endpoint": "https://edge.paperboat.test", "session_id": "session_1", "thread_id": "thread_1", "terminal_id": "term_1", "cwd": "/workspace"},
			"upload":      map[string]any{"endpoint": "https://edge.paperboat.test/e/env_1/uploads"},
		})
	}))
	defer server.Close()

	client := New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
	response, err := client.CLIConnect(context.Background(), "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	if response.ProjectID != "prj_1" || response.Terminal.WebSocketBaseURL != "wss://edge.paperboat.test/e/env_1/terminal" || response.Upload.Path != "/e/env_1/uploads" {
		t.Fatalf("canonical response not decoded: %#v", response)
	}
}
