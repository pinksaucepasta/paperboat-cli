package windowsopenssh

import (
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
