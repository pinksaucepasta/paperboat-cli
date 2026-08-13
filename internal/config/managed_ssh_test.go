package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestManagedSSHIdentityIsDurableConcurrentAndDeletable(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	const issuer = "https://api.example.test"
	const session = "cli_session_01"
	results := make(chan ManagedSSHIdentity, 16)
	errorsFound := make(chan error, 16)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			identity, err := store.ManagedSSHIdentity(issuer, session)
			results <- identity
			errorsFound <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected ManagedSSHIdentity
	for identity := range results {
		if identity.Algorithm != ssh.KeyAlgoED25519 || identity.PublicKey == "" || identity.Fingerprint == [32]byte{} || identity.Signer == nil {
			t.Fatalf("identity=%+v", identity)
		}
		if expected.PublicKey == "" {
			expected = identity
		} else if identity.PublicKey != expected.PublicKey || identity.Fingerprint != expected.Fingerprint {
			t.Fatal("concurrent creation returned different identities")
		}
		payload := []byte("managed SSH signing test")
		signature, err := identity.Signer.Sign(rand.Reader, payload)
		if err != nil || identity.Signer.PublicKey().Verify(payload, signature) != nil {
			t.Fatalf("signature verification error=%v", err)
		}
	}
	reloaded, err := store.ManagedSSHIdentity(issuer, session)
	if err != nil || reloaded.PublicKey != expected.PublicKey {
		t.Fatalf("reloaded=%+v error=%v", reloaded, err)
	}
	if err := store.DeleteManagedSSHIdentity(issuer, session); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteManagedSSHIdentity(issuer, session); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	replacement, err := store.ManagedSSHIdentity(issuer, session)
	if err != nil || replacement.PublicKey == expected.PublicKey {
		t.Fatalf("replacement=%+v error=%v", replacement, err)
	}
}

func TestManagedSSHIdentityWithholdsSignerWhenUnlockFails(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	want := errors.New("unlock failed")
	ref := managedSSHSecretRef("https://api.example.test", "cli_session_01")

	for _, operation := range []string{"create", "load"} {
		identity, err := store.managedSSHIdentity(ref, failingCredentialLock{unlock: want})
		if !errors.Is(err, want) || identity.Signer != nil || identity.PublicKey != "" || identity.Fingerprint != [32]byte{} || identity.Algorithm != "" {
			t.Fatalf("%s identity=%+v error=%v", operation, identity, err)
		}
	}
}

func TestManagedSSHIdentityRejectsCorruptionWrongAlgorithmAndInvalidScope(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	issuer, session := "https://api.example.test", "cli_session_01"
	ref := managedSSHSecretRef(issuer, session)
	if err := secrets.Set(ref, "not a private key"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ManagedSSHIdentity(issuer, session); err == nil {
		t.Fatal("corrupt managed SSH identity was accepted")
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, managedSSHKeyComment)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(ref, string(pem.EncodeToMemory(block))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ManagedSSHIdentity(issuer, session); err == nil {
		t.Fatal("RSA managed SSH identity was accepted")
	}
	if _, err := store.ManagedSSHIdentity(issuer, "bad\nsession"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("invalid session error=%v", err)
	}
	stored, err := secrets.Get(ref)
	if err != nil || bytes.Contains([]byte(stored), []byte("PRIVATE KEY-----\nnot")) {
		t.Fatalf("stored identity error=%v", err)
	}
}

func TestManagedSSHIdentityRejectsSymlinkedFileFallback(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	issuer, session := "https://api.example.test", "cli_session_01"
	identity, err := store.ManagedSSHIdentity(issuer, session)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := secrets.path(managedSSHSecretRef(issuer, session))
	target := filepath.Join(root, "copied-private-key")
	encoded, err := os.ReadFile(secretPath)
	if err != nil || os.WriteFile(target, encoded, 0o600) != nil {
		t.Fatalf("prepare symlink target: %v", err)
	}
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, secretPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := store.ManagedSSHIdentity(issuer, session); err == nil {
		t.Fatalf("symlinked identity %s was accepted", identity.PublicKey)
	}
}

func TestProfileRemovalAndRevocationCleanupDeleteManagedSSHIdentity(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	issuer := "https://api.example.test"
	profile := Profile{Issuer: issuer, CLIClientSessionID: "cli_active"}
	if err := store.Save(profile, Credential{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ManagedSSHIdentity(issuer, profile.CLIClientSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Get(managedSSHSecretRef(issuer, profile.CLIClientSessionID)); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("active managed key remains: %v", err)
	}
	if _, err := store.ManagedSSHIdentity(issuer, "cli_pending"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(issuer, "cli_pending", "pending-refresh"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v error=%v", records, err)
	}
	if err := store.CompleteRevocation(records[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Get(managedSSHSecretRef(issuer, "cli_pending")); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("revoked managed key remains: %v", err)
	}
}
