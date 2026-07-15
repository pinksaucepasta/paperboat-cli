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
