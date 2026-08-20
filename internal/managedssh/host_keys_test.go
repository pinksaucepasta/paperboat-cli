package managedssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestReadHostPublicKeysCanonicalizesAndFingerprintsOrderIndependently(t *testing.T) {
	directory := t.TempDir()
	first := writeHostPublicKey(t, directory, "ssh_host_ed25519_key.pub", "ed25519")
	second := writeHostPublicKey(t, directory, "ssh_host_rsa_key.pub", "rsa")
	left, err := ReadHostPublicKeys([]string{first, second}, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	right, err := ReadHostPublicKeys([]string{second, first}, uint32(os.Getuid()))
	if err != nil || left.Fingerprint != right.Fingerprint || len(left.Keys) != 2 || left.Fingerprint == [32]byte{} {
		t.Fatalf("left=%+v right=%+v error=%v", left, right, err)
	}
	for _, key := range left.Keys {
		if key.PublicKey == "" || key.Fingerprint == [32]byte{} || key.Algorithm == "" {
			t.Fatalf("key=%+v", key)
		}
	}
}

func TestReadHostPublicKeysRejectsDuplicateSymlinkAndWritableFile(t *testing.T) {
	directory := t.TempDir()
	path := writeHostPublicKey(t, directory, "ssh_host_ed25519_key.pub", "ed25519")
	if _, err := ReadHostPublicKeys([]string{path, path}, uint32(os.Getuid())); err == nil {
		t.Fatal("duplicate path was accepted")
	}
	alias := filepath.Join(directory, "ssh_host_alias_key.pub")
	if err := os.Symlink(path, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReadHostPublicKeys([]string{alias}, uint32(os.Getuid())); err == nil {
		t.Fatal("symlinked host key was accepted")
	}
	if os.PathSeparator != '/' {
		return
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHostPublicKeys([]string{path}, uint32(os.Getuid())); err == nil {
		t.Fatal("writable host key was accepted")
	}
}

func writeHostPublicKey(t *testing.T, directory, name, kind string) string {
	t.Helper()
	var public any
	if kind == "rsa" {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		public = &private.PublicKey
	} else {
		value, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public = value
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	value := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " host comment\n"
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
