//go:build darwin || linux

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentTokenFileIsProtectedAndConsumed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment-token")
	const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnrollmentTokenFile(path)
	if err != nil || got != token {
		t.Fatalf("ReadEnrollmentTokenFile() = %q, %v", got, err)
	}
	if err := ConsumeEnrollmentTokenFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("token file still exists: %v", err)
	}
}

func TestEnrollmentTokenFileRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment-token")
	if err := os.WriteFile(path, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentTokenFile(path); err == nil {
		t.Fatal("broadly readable token file was accepted")
	}
}
