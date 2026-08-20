//go:build windows

package managedssh

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallOpenSSHConfigIgnoresUnmanagedSSHDirectory(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := UninstallOpenSSHConfig(home, 0)
	if err != nil || result.Changed {
		t.Fatalf("uninstall unmanaged directory: result=%+v error=%v", result, err)
	}
	if _, err := os.Stat(knownHosts); err != nil {
		t.Fatalf("unmanaged known_hosts changed: %v", err)
	}
}

func TestUninstallManagedIdentityIgnoresUnmanagedSSHDirectory(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UninstallManagedIdentityPublicKey(home, 0); err != nil {
		t.Fatalf("uninstall absent managed identity: %v", err)
	}
	if _, err := os.Stat(knownHosts); err != nil {
		t.Fatalf("unmanaged known_hosts changed: %v", err)
	}
}

func TestUninstallOpenSSHConfigDoesNotIgnorePartialManagedState(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config"), []byte("Host *\n# "+openSSHIncludeMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallOpenSSHConfig(home, 0); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("partial managed state error=%v", err)
	}
}
