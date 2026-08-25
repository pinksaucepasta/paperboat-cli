package managedssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProbeOpenSSHReportsRequiredCapabilities(t *testing.T) {
	capabilities, err := ProbeOpenSSH(context.Background(), "ssh", 2*time.Second)
	if runtime.GOOS != "windows" && errors.Is(err, ErrOpenSSHUnavailable) {
		t.Skip("supported OpenSSH client is not installed")
	}
	if err != nil || !capabilities.Ready() || capabilities.Version == "" || capabilities.Executable == "" {
		t.Fatalf("capabilities=%+v error=%v", capabilities, err)
	}
	if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(strings.ReplaceAll(capabilities.Executable, "/", `\`)), `\git\`) {
		t.Fatalf("bare Windows OpenSSH probe selected Git for Windows client: %q", capabilities.Executable)
	}
}

func TestProbeOpenSSHRejectsMissingClientAndCancellation(t *testing.T) {
	if _, err := ProbeOpenSSH(context.Background(), "/not/a/real/ssh", time.Second); !errors.Is(err, ErrOpenSSHUnavailable) {
		t.Fatalf("missing client error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeOpenSSH(ctx, "ssh", time.Second); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
}

func TestIsolatedOpenSSHProbeEnvironmentDoesNotInheritUserState(t *testing.T) {
	t.Setenv("HOME", "/real/home")
	t.Setenv("USERPROFILE", `C:\\Users\\real`)
	t.Setenv("SSH_AUTH_SOCK", "/real/agent.sock")
	t.Setenv("PATH", "/preserved/path")

	environment := isolatedOpenSSHProbeEnvironment(filepath.Join(t.TempDir(), "probe"))
	values := make(map[string]string, len(environment))
	for _, value := range environment {
		name, content, ok := strings.Cut(value, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", value)
		}
		if runtime.GOOS == "windows" {
			name = strings.ToUpper(name)
		}
		values[name] = content
	}
	if values["HOME"] == "/real/home" || values["USERPROFILE"] == `C:\\Users\\real` {
		t.Fatalf("real home state leaked into probe environment: %#v", values)
	}
	if _, ok := values["SSH_AUTH_SOCK"]; ok {
		t.Fatalf("agent socket leaked into probe environment: %#v", values)
	}
	if values["PATH"] != "/preserved/path" {
		t.Fatalf("PATH = %q, want preserved path", values["PATH"])
	}
}

func TestProbeOpenSSHIgnoresUserConfiguration(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	// If ProbeOpenSSH accidentally falls back to the user's config, this
	// invalid option makes the native client fail before the isolated probe.
	if err := os.WriteFile(filepath.Join(sshDirectory, "config"), []byte("Host *\n    PaperboatProbeInvalidOption yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	capabilities, err := ProbeOpenSSH(context.Background(), "ssh", 2*time.Second)
	if runtime.GOOS != "windows" && errors.Is(err, ErrOpenSSHUnavailable) {
		t.Skip("supported OpenSSH client is not installed")
	}
	if err != nil || !capabilities.Ready() {
		t.Fatalf("user configuration affected probe: capabilities=%+v error=%v", capabilities, err)
	}
}

func TestOpenSSHProbeProcessHelper(t *testing.T) {
	if os.Getenv("PAPERBOAT_MANAGEDSSH_PROBE_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestRunOpenSSHProbeHonorsContextDeadline(t *testing.T) {
	t.Setenv("PAPERBOAT_MANAGEDSSH_PROBE_HELPER", "1")
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err = runOpenSSHProbe(ctx, executable, "-test.run=^TestOpenSSHProbeProcessHelper$", "-test.count=1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe error=%v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("probe cancellation took %s", elapsed)
	}
}
