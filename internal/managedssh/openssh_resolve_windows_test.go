//go:build windows

package managedssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveBareWindowsOpenSSHUsesNativeCandidatePrecedence(t *testing.T) {
	root := t.TempDir()
	gitSSH := filepath.Join(root, "Git", "usr", "bin", "ssh.exe")
	nativeFirst := filepath.Join(root, "native-first", "ssh.exe")
	nativeSecond := filepath.Join(root, "native-second", "ssh.exe")
	for _, path := range []string{gitSSH, nativeFirst, nativeSecond} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	resolved, err := resolveBareWindowsOpenSSHExecutable([]string{gitSSH, nativeSecond, nativeFirst})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(nativeSecond)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want {
		t.Fatalf("resolved=%q, want first trusted native candidate %q", resolved, want)
	}
	if isGitBundledWindowsOpenSSH(resolved) {
		t.Fatalf("resolved Git for Windows client: %q", resolved)
	}
}

func TestResolveBareWindowsOpenSSHRejectsGitOnlyCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Git", "usr", "bin", "ssh.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBareWindowsOpenSSHExecutable([]string{path}); err == nil {
		t.Fatal("Git for Windows ssh.exe was accepted as native OpenSSH")
	}
}

func TestResolveWindowsOpenSSHExplicitAbsolutePathIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom", "ssh.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveOpenSSHExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(path)
	if resolved != want {
		t.Fatalf("resolved=%q, want %q", resolved, want)
	}
	if _, err := resolveOpenSSHExecutable(filepath.Join(filepath.Dir(path), "missing.exe")); err == nil {
		t.Fatal("missing explicit OpenSSH path was accepted")
	}
	if _, err := resolveOpenSSHExecutable(strings.TrimSuffix(path, ".exe")); err == nil {
		t.Fatal("non-executable explicit OpenSSH path was accepted")
	}
}

func TestResolveWindowsOpenSSHRejectsUntrustedConfiguredPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Git", "usr", "bin", "ssh.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_OPENSSH_PATH", path)
	if _, err := resolveOpenSSHExecutable("ssh.exe"); err == nil {
		t.Fatal("untrusted configured OpenSSH path was accepted")
	}
}
