package windowsopenssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestReconcileAuthorizedKeysUsesDedicatedPaperboatFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ssh")
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(testQualificationSigner(t).PublicKey())))
	changed, err := ReconcileAuthorizedKeys(root, []string{key, key})
	if err != nil || !changed {
		t.Fatalf("initial reconcile changed=%t err=%v", changed, err)
	}
	path := filepath.Join(root, "authorized_keys", "paperboat")
	body, err := os.ReadFile(path)
	if err != nil || string(body) != key+"\n" {
		t.Fatalf("dedicated authorized keys = %q err=%v", body, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ssh")); !os.IsNotExist(err) {
		t.Fatalf("reconciliation created a user-style .ssh directory: %v", err)
	}
	changed, err = ReconcileAuthorizedKeys(root, []string{key})
	if err != nil || changed {
		t.Fatalf("idempotent reconcile changed=%t err=%v", changed, err)
	}
	changed, err = ReconcileAuthorizedKeys(root, nil)
	if err != nil || !changed {
		t.Fatalf("revocation reconcile changed=%t err=%v", changed, err)
	}
	body, err = os.ReadFile(path)
	if err != nil || len(body) != 0 {
		t.Fatalf("revoked authorized keys = %q err=%v", body, err)
	}
}

func TestReconcileAuthorizedKeysHonorsCanceledContextBeforeWriting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := filepath.Join(t.TempDir(), "ssh")
	if _, err := ReconcileAuthorizedKeysContext(ctx, root, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context canceled", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled reconciliation created state: %v", err)
	}
}

func TestReconcileAuthorizedKeysRejectsInvalidReplacementWithoutChangingFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ssh")
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(testQualificationSigner(t).PublicKey())))
	if _, err := ReconcileAuthorizedKeys(root, []string{key}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "authorized_keys", "paperboat")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileAuthorizedKeys(root, []string{"ssh-ed25519 not-a-key"}); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("authorized keys changed after invalid replacement: before=%q after=%q err=%v", before, after, err)
	}
}
