package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

func TestConnectWithServerURLUsesBackendResolver(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	configPath := filepath.Join(dir, "config.json")
	var sawProjects bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/projects" {
			sawProjects = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	if err := os.WriteFile(authPath, []byte(`{"access_token":"token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"papercode_config_path":`+quote(authPath)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := newApp().Run([]string{"pb", "--config", configPath, "--server", server.URL, "--agent", "backend-agent", "demo"})
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
			authPath := filepath.Join(dir, "auth.json")
			configPath := filepath.Join(dir, "config.json")
			var gotKeepAlive bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/projects":
					_, _ = w.Write([]byte(`{"data":[{"id":"prj_1","name":"Demo","state":"running"}]}`))
				case "/api/auth/csrf":
					http.SetCookie(w, &http.Cookie{Name: "paperboat_csrf", Value: "csrf-token", Path: "/"})
					_, _ = w.Write([]byte(`{"data":{"csrf_token":"csrf-token"}}`))
				case "/api/projects/prj_1/keep-alive":
					gotKeepAlive = true
					if r.Header.Get("X-CSRF-Token") != "csrf-token" {
						t.Fatalf("csrf header = %q", r.Header.Get("X-CSRF-Token"))
					}
					if c, err := r.Cookie("paperboat_csrf"); err != nil || c.Value != "csrf-token" {
						t.Fatalf("csrf cookie = %#v, err = %v", c, err)
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
			if err := os.WriteFile(authPath, []byte(`{"access_token":"token"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte(`{"papercode_config_path":`+quote(authPath)+`}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := newApp().Run(normalizeArgs([]string{"pb", "--config", configPath, "--server", server.URL, "keep-alive", "Demo", "--hours", tc.hours})); err != nil {
				t.Fatal(err)
			}
			if !gotKeepAlive {
				t.Fatal("expected keep-alive request")
			}
		})
	}
}

func TestConnectWithServerURLRejectsSizeOverrideUntilBrokerContractExists(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	configPath := filepath.Join(dir, "config.json")
	var sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		http.NotFound(w, r)
	}))
	defer server.Close()

	if err := os.WriteFile(authPath, []byte(`{"access_token":"token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"papercode_config_path":`+quote(authPath)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := newApp().Run([]string{"pb", "--config", configPath, "--server", server.URL, "--size", "2x", "demo"})
	if err == nil {
		t.Fatal("expected size override error")
	}
	if sawRequest {
		t.Fatal("backend should not be called for unsupported size override")
	}
	if !strings.Contains(err.Error(), "--size is not supported with server_url") {
		t.Fatalf("err = %v", err)
	}
}

func quote(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
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
