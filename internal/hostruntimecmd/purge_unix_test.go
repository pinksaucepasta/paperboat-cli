//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestLinuxPurgeStopsAndRemovesCurrentAndLegacyServices(t *testing.T) {
	plan, err := newUnixPurgePlan("linux")
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]string, 0)
	removed := make([]string, 0)
	run := func(_ context.Context, executable string, arguments ...string) error {
		commands = append(commands, strings.Join(append([]string{executable}, arguments...), " "))
		return nil
	}
	remove := func(path string) error {
		removed = append(removed, path)
		return nil
	}
	if err := applyUnixPurgePlan(context.Background(), plan, run, remove); err != nil {
		t.Fatal(err)
	}

	wantUnits := []string{
		"paperboat-runtime-host.service",
		"paperboat-runtime-privileged.service",
		"paperboat-hostd.service",
		"paperboat-updated.service",
		"paperboat-helper.service",
		"paperboat-host-service.service",
		"paperboat-console.service",
	}
	for _, unit := range wantUnits {
		if !strings.Contains(commands[0], unit) || !strings.Contains(commands[1], unit) {
			t.Fatalf("systemd stop/disable commands omitted %q: %v", unit, commands[:2])
		}
		if !containsString(removed, "/etc/systemd/system/"+unit) {
			t.Fatalf("systemd definition %q was not removed: %v", unit, removed)
		}
	}
	if !reflect.DeepEqual(commands[2:], []string{
		"/usr/bin/systemctl daemon-reload",
		"/usr/bin/systemctl reset-failed " + strings.Join(wantUnits, " "),
	}) {
		t.Fatalf("systemd post-removal commands=%v", commands[2:])
	}
	for _, path := range []string{"/var/lib/paperboat-updated", "/var/run/paperboat-hostd", "/var/run/paperboat-updated"} {
		if !containsString(removed, path) {
			t.Fatalf("current updater/hostd state path %q was not removed: %v", path, removed)
		}
	}
}

func TestDarwinPurgeStopsAndRemovesCurrentAndLegacyLaunchDaemons(t *testing.T) {
	plan, err := newUnixPurgePlan("darwin")
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]string, 0)
	removed := make([]string, 0)
	run := func(_ context.Context, executable string, arguments ...string) error {
		commands = append(commands, strings.Join(append([]string{executable}, arguments...), " "))
		return nil
	}
	remove := func(path string) error {
		removed = append(removed, path)
		return nil
	}
	if err := applyUnixPurgePlan(context.Background(), plan, run, remove); err != nil {
		t.Fatal(err)
	}

	wantLabels := []string{service.Label, service.HostLabel, service.HostdLabel, service.UpdaterLabel}
	wantCommands := make([]string, 0, len(wantLabels))
	for _, label := range wantLabels {
		wantCommands = append(wantCommands, "/bin/launchctl bootout system/"+label)
		if !containsString(removed, "/Library/LaunchDaemons/"+label+".plist") {
			t.Fatalf("launchd definition %q was not removed: %v", label, removed)
		}
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("launchd bootout commands=%v want=%v", commands, wantCommands)
	}
	if !containsString(removed, "/var/run/paperboat-updated") || !containsString(removed, "/var/run/paperboat-hostd") {
		t.Fatalf("current updater/hostd runtime paths were not removed: %v", removed)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
