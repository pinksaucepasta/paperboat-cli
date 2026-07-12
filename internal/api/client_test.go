package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("Authorization")
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
	if me.Email != "a@b.dev" {
		t.Fatalf("me.Email = %q", me.Email)
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

func TestClientStructuredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusConflict, "machine_not_ready", "Machine is not ready.")
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "t"}, nil)
	_, err := c.CLIConnect(context.Background(), "prj_1")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("err type = %T, want *APIError", err)
	}
	if apiErr.Code != "machine_not_ready" || apiErr.Status != http.StatusConflict {
		t.Fatalf("apiErr = %+v", apiErr)
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
