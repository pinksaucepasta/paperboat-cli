package machinecontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

func TestSourceRenewsWithExactMachineProofAndPersistsResult(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "runtime")
	store, err := identity.Open(identity.Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	if err := store.SaveRegistration(identity.Registration{ServerURL: "https://unused.test", MachineID: "mch_1", EnvironmentID: "env_1", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 2, SetupRoles: []string{"interactive"}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	oldToken := strings.Repeat("o", 40)
	if err := store.SaveMachineControl(identity.MachineControl{MachineID: "mch_1", EnvironmentID: "env_1", InstallationGeneration: 2, Credential: oldToken, ExpiresAt: now.Add(time.Minute), KeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	newToken := strings.Repeat("n", 40)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/machine-control-renewals" || r.Header.Get("Authorization") != "Bearer "+oldToken {
			t.Errorf("request path/auth = %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		if proofErr != nil || len(proof) == 0 {
			t.Error("missing machine proof")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credential": newToken, "expires_at": now.Add(time.Hour)}})
	}))
	defer server.Close()
	source, err := NewSource(Config{ControlURL: server.URL, StateRoot: root, Transport: server.Client().Transport, Clock: func() time.Time { return now }, OperationID: func() (string, error) { return "operation-renew-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.Token(t.Context())
	if err != nil || token != newToken {
		t.Fatalf("token=%q err=%v", token, err)
	}
	persisted, err := store.MachineControl(now, 0)
	if err != nil || persisted.Credential != newToken {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
}
