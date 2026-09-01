//go:build linux

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is intentionally opt-in because it mutates only the fixed Paperboat
// hostd/updated system units on a test machine. The test refuses existing
// declarations and always removes the exact units it created.
func TestNativeSystemdComposedLifecycle(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 on an isolated host with systemd")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable = installNativeServiceTestExecutable(t, executable)
	user := os.Getenv("USER")
	if user == "" {
		user = "root"
	}
	definitions := []string{"/etc/systemd/system/paperboat-hostd.service", "/etc/systemd/system/paperboat-updated.service"}
	for _, path := range definitions {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace existing service definition %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	hostd, err := New(Config{
		Platform: "linux", Kind: HostdKind, ConfigRoot: "/", Executable: executable, User: user, Group: user,
		Arguments:   []string{"-test.run=^TestNativeSystemdServiceProcess$", "-test.v"},
		Environment: map[string]string{"PAPERBOAT_NATIVE_SERVICE_CHILD": "1", "PAPERBOAT_NATIVE_SERVICE_ROLE": "hostd"},
		Controller:  SystemdController{Runner: ExecRunner{}, Unit: "paperboat-hostd.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := New(Config{
		Platform: "linux", Kind: UpdaterKind, ConfigRoot: "/", Executable: executable, User: user, Group: user,
		Arguments:   []string{"-test.run=^TestNativeSystemdServiceProcess$", "-test.v"},
		Environment: map[string]string{"PAPERBOAT_NATIVE_SERVICE_CHILD": "1", "PAPERBOAT_NATIVE_SERVICE_ROLE": "updater"},
		Controller:  SystemdController{Runner: ExecRunner{}, Unit: "paperboat-updated.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := NewHTTPReadinessProbe(nativeLinuxHealthURL)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: filepath.Join(t.TempDir(), "service-lifecycle"), Hostd: hostd, Updater: updater, HostdProbe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	t.Cleanup(func() {
		if installed {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			_ = manager.Uninstall(ctx)
		}
	})
	operation := func(name string, call func(context.Context) error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := call(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	operation("install", manager.Install)
	installed = true
	if err := probe(context.Background()); err != nil {
		t.Fatalf("hostd exact /healthz readiness: %v", err)
	}
	operation("repair", manager.Repair)
	operation("stop", manager.Stop)
	statuses, err := manager.Inspect(context.Background())
	if err != nil || len(statuses) != 2 {
		t.Fatalf("stopped statuses=%+v err=%v", statuses, err)
	}
	for _, status := range statuses {
		if !status.Installed || !status.Enabled || status.Running || status.Ready {
			t.Fatalf("stop did not preserve declaration/enablement: %+v", status)
		}
	}
	operation("repair after stop", manager.Repair)
	if err := probe(context.Background()); err != nil {
		t.Fatalf("repaired hostd readiness: %v", err)
	}
	operation("uninstall", manager.Uninstall)
	installed = false
	for _, path := range definitions {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("definition remains after uninstall %s: %v", path, err)
		}
	}
}
