//go:build darwin || linux

package managedssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestManagedIdentityPublicKeyLifecycleIsIdempotent(t *testing.T) {
	home := openSSHTestHome(t)
	publicKey := managedIdentityTestPublicKey(t)
	uid := uint32(os.Getuid())
	if err := InstallManagedIdentityPublicKey(home, uid, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := InstallManagedIdentityPublicKey(home, uid, publicKey); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	if err := ValidateManagedIdentityPublicKey(home, uid, publicKey); err != nil {
		t.Fatalf("validate installed identity: %v", err)
	}
	if err := UninstallManagedIdentityPublicKey(home, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ManagedIdentityPublicKeyPath(home)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed public identity remains: %v", err)
	}
	if err := UninstallManagedIdentityPublicKey(home, uid); err != nil {
		t.Fatalf("idempotent uninstall: %v", err)
	}
}

func managedIdentityTestPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestManagedIdentityPublicKeyPreservesConflictingFile(t *testing.T) {
	home := openSSHTestHome(t)
	path := filepath.Join(home, ".ssh", ManagedIdentityPublicKeyFilename)
	if err := os.WriteFile(path, []byte("user-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallManagedIdentityPublicKey(home, uint32(os.Getuid()), managedIdentityTestPublicKey(t)); !errors.Is(err, ErrManagedIdentityFileConflict) {
		t.Fatalf("install conflict error=%v", err)
	}
	if value, err := os.ReadFile(path); err != nil || string(value) != "user-owned\n" {
		t.Fatalf("conflicting file changed: %q error=%v", value, err)
	}
}

func TestManagedIdentityPublicKeyRotatesOwnedSelector(t *testing.T) {
	home := openSSHTestHome(t)
	first := managedIdentityTestPublicKey(t)
	second := managedIdentityTestPublicKey(t)
	if err := InstallManagedIdentityPublicKey(home, uint32(os.Getuid()), first); err != nil {
		t.Fatal(err)
	}
	if err := InstallManagedIdentityPublicKey(home, uint32(os.Getuid()), second); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedIdentityPublicKey(home, uint32(os.Getuid()), second); err != nil {
		t.Fatal(err)
	}
}
