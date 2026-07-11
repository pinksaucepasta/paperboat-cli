package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

func TestConcurrentCredentialRefreshUsesTokenOnce(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/token/refresh" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer refresh-old" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"access_token": "access-new", "refresh_token": "refresh-new", "token_type": "Bearer", "expires_in": 900, "scope": "account:read", "client_session_id": "cls_1"}})
	}))
	defer server.Close()
	dir := t.TempDir()
	store := config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	expired := time.Now().Add(-time.Minute)
	if err := store.Save(config.Profile{Issuer: server.URL, ClientSessionID: "cls_1", AccessExpiresAt: expired}, config.Credential{AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAt: expired}); err != nil {
		t.Fatal(err)
	}
	source := &Source{Store: store, Issuer: server.URL}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cred, err := source.Credential()
			if err == nil && cred.AccessToken != "access-new" {
				t.Errorf("access token = %q", cred.AccessToken)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}
}
