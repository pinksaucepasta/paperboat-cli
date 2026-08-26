package machinecontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
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

func TestEnsureInitialUsesHelperIdentityAndRetriesWithStableOperation(t *testing.T) {
	now := time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "runtime")
	const helperToken = "helper-identity-credential-012345678901234567890"
	const machineToken = "machine-control-credential-012345678901234567890"
	const rotatedMachineToken = "machine-control-credential-rotated-012345678901234567890"
	helperExpiresAt := time.Now().UTC().Add(24 * time.Hour)
	var operations []string
	var machineControlCalls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/helper-enrollments":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"helper_id": "hlp_1", "machine_id": "mch_1", "environment_id": "env_1", "credential": helperToken, "expires_at": helperExpiresAt}})
		case "/v1/machine-control-credentials":
			machineControlCalls++
			if r.Header.Get("Authorization") != "Bearer "+helperToken {
				t.Errorf("initial authorization=%q", r.Header.Get("Authorization"))
			}
			proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(proof, &envelope); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var claims struct {
				HelperID    string `json:"helper_id"`
				OperationID string `json:"operation_id"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil || claims.HelperID != "hlp_1" {
				t.Fatalf("initial proof claims=%s err=%v", payload, err)
			}
			operations = append(operations, claims.OperationID)
			credential := machineToken
			if machineControlCalls > 2 {
				credential = rotatedMachineToken
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credential": credential, "expires_at": now.Add(time.Minute)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := enrollment.NewClient(server.Client().Transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(t.Context(), enrollment.Config{ControlURL: server.URL, StateRoot: root, EnrollmentCredential: strings.Repeat("e", 32)}); err != nil {
		t.Fatal(err)
	}
	store, err := identity.Open(identity.Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	if err := store.SaveRegistration(identity.Registration{ServerURL: server.URL, MachineID: "mch_1", EnvironmentID: "env_1", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupMode: "host", SetupRoles: []string{"host"}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(Config{ControlURL: server.URL, StateRoot: root, Transport: server.Client().Transport, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := source.EnsureInitial(t.Context()); err != nil || token != machineToken {
		t.Fatalf("initial token=%q err=%v", token, err)
	}
	if err := os.Remove(filepath.Join(root, "machine-control.json")); err != nil {
		t.Fatal(err)
	}
	if token, err := source.EnsureInitial(t.Context()); err != nil || token != machineToken {
		t.Fatalf("retry token=%q err=%v", token, err)
	}
	if err := os.Remove(filepath.Join(root, "machine-control.json")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if token, err := source.EnsureInitial(t.Context()); err != nil || token != rotatedMachineToken {
		t.Fatalf("expired retry token=%q err=%v", token, err)
	}
	if len(operations) != 3 || operations[0] == "" || operations[0] != operations[1] || operations[1] != operations[2] {
		t.Fatalf("initial operations=%q", operations)
	}
	persisted, err := store.MachineControl(now, 0)
	if err != nil || persisted.Credential != rotatedMachineToken {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
}
