package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestStoreCreatesPrivateStableSigningIdentityAndRotatesAtomically(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	random := append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...)
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(random), Clock: fixedClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	first := store.Current()
	if first.ID == "" || first.Thumbprint == "" || first.CreatedAt != now {
		t.Fatal("invalid initial key metadata")
	}
	message := []byte("helper identity proof")
	if !ed25519.Verify(first.Public(), message, first.Sign(message)) {
		t.Fatal("signature failed")
	}
	path := filepath.Join(root, "machine-identity.json")
	info, err := os.Stat(path)
	if err != nil || !secureIdentityPath(path, info, true) {
		t.Fatalf("info=%v err=%v", info, err)
	}
	reopened, err := Open(Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current().ID != first.ID {
		t.Fatal("identity changed on reopen")
	}
	second, err := store.Rotate(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("rotation retained key")
	}
	reopened, err = Open(Config{StateRoot: root})
	if err != nil || reopened.Current().ID != second.ID {
		t.Fatalf("rotated identity did not persist: %v", err)
	}
	if _, err := store.Rotate(first.ID); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("stale rotate err=%v", err)
	}
}

func TestMachineControlIsBoundToRegistrationAndSignsExactRequest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := Registration{ServerURL: "https://api.example.test", MachineID: "mch_1", EnvironmentID: "env_1", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 3, SetupRoles: []string{"interactive"}, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	credential := MachineControl{MachineID: registration.MachineID, EnvironmentID: registration.EnvironmentID, InstallationGeneration: 3, Credential: strings.Repeat("x", 32), ExpiresAt: now.Add(time.Hour), KeyID: key.ID}
	if err := store.SaveMachineControl(credential); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.MachineControl(now, 0)
	if err != nil || loaded.Credential != credential.Credential {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	body := []byte(`{"operation_id":"operation-1"}`)
	proof, err := store.MachineProof("operation-1", http.MethodPost, "/v1/machine-control-renewals", body, now)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Payload, Signature string }
	if err := json.Unmarshal(proof, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(envelope.Payload)
	signature, _ := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if !ed25519.Verify(key.Public(), payload, signature) {
		t.Fatal("machine proof signature is invalid")
	}
	if _, err := store.MachineProof("operation-delete", http.MethodDelete, "/v1/peer-attempts/intent_1/1", nil, now); err != nil {
		t.Fatalf("delete machine proof: %v", err)
	}
	var claims struct {
		BodySHA256 string `json:"body_sha256"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("machine proof is not bound to the exact body")
	}
	if _, err := store.MachineControl(now.Add(2*time.Hour), 0); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("expired credential err=%v", err)
	}
}

func TestNonHostRegistrationRejectsSSHConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := Registration{
		ServerURL: "https://api.example.test", MachineID: "mch_1", EnvironmentID: "env_1",
		PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()),
		InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupMode: "client",
		SetupRoles: []string{"interactive"}, SSHUser: "developer", SSHPort: 22, UpdatedAt: time.Now().UTC(),
	}
	if err := store.SaveRegistration(registration); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("non-host SSH registration error = %v", err)
	}
}

func TestLegacySessionRegistrationLoadsAsClient(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := Registration{
		ServerURL: "https://api.example.test", MachineID: "mch_legacy", EnvironmentID: "env_legacy",
		PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()),
		InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupMode: "client",
		SetupRoles: []string{"interactive"}, UpdatedAt: time.Now().UTC(),
	}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "machine-registration.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte(`"setup_mode":"client"`), []byte(`"setup_mode":"session"`), 1)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Registration()
	if err != nil || loaded.SetupMode != "client" {
		t.Fatalf("legacy registration=%+v err=%v", loaded, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestFailedRotationPreservesCurrentIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	first := store.Current()
	store.config.Random = failingReader{}
	if _, err := store.Rotate(first.ID); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v", err)
	}
	reopened, err := Open(Config{StateRoot: root})
	if err != nil || reopened.Current().ID != first.ID {
		t.Fatalf("failed rotation changed identity: %v", err)
	}
}

func TestStoreRejectsSymlinkHardlinkAndDuplicateJSON(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(base, "link")
	if err := os.Symlink(realRoot, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{StateRoot: symlink}); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("symlink err=%v", err)
	}
	store, err := Open(Config{StateRoot: realRoot, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realRoot, "machine-identity.json")
	link := filepath.Join(realRoot, "copied-secret")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rotate(store.Current().ID); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("hardlink rotate err=%v", err)
	}
	if _, err := Open(Config{StateRoot: realRoot}); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("hardlink open err=%v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"version":1,"key_id":"x","seed_base64url":"x","created_at":"2026-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{StateRoot: realRoot}); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("duplicate err=%v", err)
	}
}
