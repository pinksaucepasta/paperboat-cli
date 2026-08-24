//go:build windows

package managedssh

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateInstalledOpenSSHConfigAcceptsTargetBlocks(t *testing.T) {
	home := managedSSHWindowsTestHome(t)
	agentSocket := `\\.\pipe\paperboat-ssh-agent-test`
	config := OpenSSHConfig{
		Home:              home,
		AliasSuffix:       "pprbt",
		ProxyCommand:      `"C:\Program Files\Paperboat\bin\pb.exe" __ssh-proxy --host %h --port %p --user %r`,
		KnownHostsCommand: `"C:\Program Files\Paperboat\bin\pb.exe" __ssh-known-hosts --host %h --port %p`,
		AgentSocket:       agentSocket,
		IdentityFile:      ManagedIdentityPublicKeyPath(home),
		Targets: []OpenSSHAliasTarget{
			{Alias: "hn", DisplayName: "hn", User: "root", Port: 22},
			{Alias: "victus", DisplayName: "Victus", User: "Pujan", Port: 38222},
		},
	}
	if _, err := InstallOpenSSHConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstalledOpenSSHConfig(home, 0, config.AliasSuffix, agentSocket); err != nil {
		t.Fatalf("target-bearing installed config was rejected: %v", err)
	}
	if err := ValidateInstalledOpenSSHConfig(home, 0, config.AliasSuffix, `\\.\pipe\paperboat-ssh-agent-other`); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("mismatched agent socket error=%v", err)
	}
}

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
