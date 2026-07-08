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

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func TestClientSendsSessionCookie(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SessionCookieName); err == nil {
			gotToken = c.Value
		}
		writeData(w, http.StatusOK, Me{ID: "usr_1", Email: "a@b.dev"})
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "sess-token"}, nil)
	me, err := c.Me(context.Background())
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if gotToken != "sess-token" {
		t.Fatalf("session cookie = %q, want sess-token", gotToken)
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
		if r.URL.Path == "/api/auth/csrf" {
			writeData(w, http.StatusOK, map[string]string{"csrf_token": "csrf"})
			return
		}
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

func TestClientUnsafeRequestsFetchAndSendCSRF(t *testing.T) {
	var sawCSRF bool
	var gotSession string
	var gotCSRFHeader string
	var gotCSRFCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/csrf":
			sawCSRF = true
			if c, err := r.Cookie(SessionCookieName); err != nil || c.Value != "initial-session" {
				t.Fatalf("csrf session cookie = %#v, err = %v", c, err)
			}
			http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "csrf-token", Path: "/"})
			writeData(w, http.StatusOK, map[string]string{"csrf_token": "csrf-token"})
		case "/api/projects/prj_1/keep-alive":
			if c, err := r.Cookie(SessionCookieName); err == nil {
				gotSession = c.Value
			}
			if c, err := r.Cookie(csrfCookieName); err == nil {
				gotCSRFCookie = c.Value
			}
			gotCSRFHeader = r.Header.Get(csrfHeaderName)
			writeData(w, http.StatusOK, KeepAliveResponse{Project: Project{ID: "prj_1", Name: "Demo", State: "running"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, config.Credential{AccessToken: "initial-session"}, nil)
	if _, err := c.SetKeepAlive(context.Background(), "prj_1", 3600, false); err != nil {
		t.Fatalf("SetKeepAlive: %v", err)
	}
	if !sawCSRF {
		t.Fatal("expected csrf fetch")
	}
	if gotSession != "initial-session" {
		t.Fatalf("session cookie = %q, want initial-session", gotSession)
	}
	if gotCSRFCookie != "csrf-token" || gotCSRFHeader != "csrf-token" {
		t.Fatalf("csrf cookie/header = %q/%q", gotCSRFCookie, gotCSRFHeader)
	}
}

func TestCLIConnectDecodesPapercodeWebSocketTerminal(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/auth/csrf" {
			writeData(w, http.StatusOK, map[string]string{"csrf_token": "csrf"})
			return
		}
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
			Upload: &Upload{Kind: "papercode_file_upload", HTTPBaseURL: "https://agentunnel.dev/projects/prj_1", MaxBytes: 10485760},
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
	if resp.Upload == nil || resp.Upload.Kind != "papercode_file_upload" || resp.Upload.HTTPBaseURL != "https://agentunnel.dev/projects/prj_1" {
		t.Fatalf("upload = %+v", resp.Upload)
	}
	if len(body) != 0 {
		t.Fatalf("cli-connect request body = %q, want empty", string(body))
	}
}
