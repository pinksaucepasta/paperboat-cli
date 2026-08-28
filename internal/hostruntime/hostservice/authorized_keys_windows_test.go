//go:build windows

package hostservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestWindowsAuthorizedKeysOwnsFixedDedicatedFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ssh")
	reconciler, err := newWindowsAuthorizedKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	changed, err := reconciler.ReconcileAuthorizedKeys(context.Background(), []string{line})
	if err != nil || !changed {
		t.Fatalf("changed=%t err=%v", changed, err)
	}
	path := filepath.Join(root, "authorized_keys", "paperboat")
	body, err := os.ReadFile(path)
	if err != nil || string(body) != line+"\n" {
		t.Fatalf("authorized keys=%q err=%v", body, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ssh")); !os.IsNotExist(err) {
		t.Fatalf("unexpected user SSH path: %v", err)
	}
}
