package connect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderUserServiceEscapesArguments(t *testing.T) {
	spec := ServiceSpec{Label: "com.paperboat.connect", Executable: "/opt/Paperboat Connect/paperboat-connect", Arguments: []string{"serve", "--state", "/tmp/a b&c"}, WorkingDirectory: "/tmp/work", LogDirectory: "/tmp/logs"}
	launchd, err := RenderUserService(spec, "darwin")
	if err != nil || !strings.Contains(string(launchd), "a b&amp;c") || !strings.Contains(string(launchd), "<array>") {
		t.Fatalf("launchd = %s, err = %v", launchd, err)
	}
	systemd, err := RenderUserService(spec, "linux")
	if err != nil || !strings.Contains(string(systemd), "ExecStart=\"/opt/Paperboat Connect/paperboat-connect\"") {
		t.Fatalf("systemd = %s, err = %v", systemd, err)
	}
}

func TestInstallUserServiceRestrictsFile(t *testing.T) {
	home := t.TempDir()
	path, err := InstallUserService(ServiceSpec{Label: "com.paperboat.connect", Executable: "/opt/paperboat-connect", Arguments: []string{"serve"}, WorkingDirectory: "/tmp/work", LogDirectory: "/tmp/logs"}, home, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "systemd", "user", "com.paperboat.connect.service"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", info.Mode().Perm(), err)
	}
}

type recordedCommands struct{ calls []string }

func (r *recordedCommands) Run(name string, arguments ...string) error {
	r.calls = append(r.calls, name+" "+strings.Join(arguments, " "))
	return nil
}

func TestActivateLinuxUserService(t *testing.T) {
	runner := &recordedCommands{}
	if err := ActivateUserService("/tmp/.config/systemd/user/com.paperboat.connect.service", "linux", runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0] != "systemctl --user daemon-reload" || runner.calls[1] != "systemctl --user enable --now com.paperboat.connect.service" {
		t.Fatalf("calls = %#v", runner.calls)
	}
}
