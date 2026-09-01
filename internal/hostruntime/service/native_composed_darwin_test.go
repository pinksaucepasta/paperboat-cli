//go:build darwin

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in test exercises the complete two-service launchd transaction on
// an isolated macOS machine. It refuses pre-existing declarations.
func TestNativeLaunchdComposedLifecycle(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 in an isolated logged-in macOS session")
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
	definitions := []string{
		filepath.Join("/Library", "LaunchDaemons", HostdLabel+".plist"),
		filepath.Join("/Library", "LaunchDaemons", UpdaterLabel+".plist"),
	}
	for _, path := range definitions {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace existing service definition %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	hostd, err := New(Config{
		Platform: "darwin", Kind: HostdKind, ConfigRoot: "/", Executable: executable, User: user, Group: "staff",
		Arguments:   []string{"-test.run=^TestNativeLaunchdServiceProcess$", "-test.v"},
		Environment: map[string]string{"PAPERBOAT_NATIVE_SERVICE_CHILD": "1", "PAPERBOAT_NATIVE_SERVICE_ROLE": "hostd"},
		Controller:  LaunchdController{Runner: ExecRunner{}, UID: os.Getuid(), Label: HostdLabel},
	})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := New(Config{
		Platform: "darwin", Kind: UpdaterKind, ConfigRoot: "/", Executable: executable, User: user, Group: "staff",
		Arguments:   []string{"-test.run=^TestNativeLaunchdServiceProcess$", "-test.v"},
		Environment: map[string]string{"PAPERBOAT_NATIVE_SERVICE_CHILD": "1", "PAPERBOAT_NATIVE_SERVICE_ROLE": "updater"},
		Controller:  LaunchdController{Runner: ExecRunner{}, UID: os.Getuid(), Label: UpdaterLabel},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := NewHTTPReadinessProbe(nativeDarwinHealthURL)
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
		if !status.Installed || status.Running || status.Ready {
			t.Fatalf("stop did not preserve declaration or stop the job: %+v", status)
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
