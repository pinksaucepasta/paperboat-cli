package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func splitLayout(t *testing.T, platform string) Layout {
	t.Helper()
	root := filepath.Join(t.TempDir(), "paperboat")
	releases := filepath.Join(root, "releases")
	layout := Layout{
		Platform: platform, InstallRoot: root, ReleasesRoot: releases,
		HostdBinary:     filepath.Join(root, "components", "paperboat-hostd"),
		UpdaterBinary:   filepath.Join(root, "components", "paperboat-updated"),
		Launcher:        filepath.Join(root, "launcher", "pb"),
		RuntimeCurrent:  filepath.Join(releases, "runtime-current", "paperboat-runtime"),
		RuntimeRollback: filepath.Join(releases, "runtime-rollback", "paperboat-runtime"),
		RuntimeStaged:   filepath.Join(releases, "runtime-staged", "paperboat-runtime"),
		CLICurrent:      filepath.Join(releases, "cli-current", "pb"),
		CLIRollback:     filepath.Join(releases, "cli-rollback", "pb"),
		UpdateStateRoot: filepath.Join(t.TempDir(), "updated"),
		HostdSocket:     filepath.Join(t.TempDir(), "hostd", "hostd.sock"),
	}
	for _, binary := range []string{layout.HostdBinary, layout.UpdaterBinary} {
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := layout.Validate(); err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestDefaultSplitLayoutsAreFixedAndBounded(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		t.Run(platform, func(t *testing.T) {
			layout, err := DefaultLayout(platform)
			if err != nil {
				t.Fatal(err)
			}
			if err := layout.Validate(); err != nil || !withinForPlatform(platform, layout.InstallRoot, layout.HostdBinary) || !withinForPlatform(platform, layout.ReleasesRoot, layout.RuntimeCurrent) {
				t.Fatalf("layout=%+v err=%v", layout, err)
			}
			if layout.RuntimeCurrent == layout.RuntimeRollback || layout.RuntimeCurrent == layout.RuntimeStaged || layout.CLICurrent == layout.CLIRollback {
				t.Fatalf("release retention paths overlap: %+v", layout)
			}
		})
	}
}

func TestSplitLayoutRejectsEscapingComponents(t *testing.T) {
	layout := splitLayout(t, "linux")
	layout.UpdaterBinary = "/tmp/paperboat-updated"
	if err := layout.Validate(); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("escaping component err=%v", err)
	}
}

func TestHostdAndUpdaterInstallersUseSeparateStableServices(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			layout := splitLayout(t, platform)
			control := &controller{}
			hostd, err := NewHostdInstaller(ComponentConfig{Layout: layout, User: "alice", Group: "staff", UID: 501, Controller: control})
			if err != nil {
				t.Fatal(err)
			}
			updater, err := NewUpdaterInstaller(ComponentConfig{Layout: layout, UID: 501, Controller: control})
			if err != nil {
				t.Fatal(err)
			}
			if hostd.config.UpgradeMode != UpgradeReload || updater.config.UpgradeMode != UpgradeReload {
				t.Fatal("stable components must not restart on definition upgrades")
			}
			if platform == "linux" {
				if !strings.HasSuffix(hostd.DefinitionPath(), "/etc/systemd/system/paperboat-hostd.service") || !strings.HasSuffix(updater.DefinitionPath(), "/etc/systemd/system/paperboat-updated.service") {
					t.Fatalf("paths hostd=%q updater=%q", hostd.DefinitionPath(), updater.DefinitionPath())
				}
				hostdDefinition, err := hostd.render()
				if err != nil {
					t.Fatal(err)
				}
				updaterDefinition, err := updater.render()
				if err != nil {
					t.Fatal(err)
				}
				for _, expected := range []string{"User=alice", "Group=staff", "RuntimeDirectory=paperboat-hostd", "NoNewPrivileges=true", "PAPERBOAT_HOSTD_SOCKET=" + layout.HostdSocket} {
					if !strings.Contains(string(hostdDefinition), expected) {
						t.Fatalf("hostd missing %q:\n%s", expected, hostdDefinition)
					}
				}
				for _, expected := range []string{"User=root", "Group=root", "RuntimeDirectory=paperboat-updated", "After=local-fs.target network-online.target", "Wants=network-online.target", "PAPERBOAT_RELEASE_ROOT=" + layout.ReleasesRoot} {
					if !strings.Contains(string(updaterDefinition), expected) {
						t.Fatalf("updater missing %q:\n%s", expected, updaterDefinition)
					}
				}
			} else {
				if !strings.HasSuffix(hostd.DefinitionPath(), "/Library/LaunchDaemons/"+HostdLabel+".plist") || !strings.HasSuffix(updater.DefinitionPath(), "/Library/LaunchDaemons/"+UpdaterLabel+".plist") {
					t.Fatalf("paths hostd=%q updater=%q", hostd.DefinitionPath(), updater.DefinitionPath())
				}
				body, err := hostd.render()
				if err != nil || !strings.Contains(string(body), "<string>alice</string>") || !strings.Contains(string(body), "<string>"+HostdLabel+"</string>") {
					t.Fatalf("hostd plist err=%v body=%s", err, body)
				}
				body, err = updater.render()
				if err != nil || !strings.Contains(string(body), "<string>root</string>") || !strings.Contains(string(body), "<string>"+UpdaterLabel+"</string>") {
					t.Fatalf("updater plist err=%v body=%s", err, body)
				}
			}
		})
	}
}

func TestSplitServiceDefinitionUpgradeDoesNotRestartStableSupervisor(t *testing.T) {
	layout := splitLayout(t, "linux")
	control := &controller{}
	installer, err := New(Config{
		Platform: "linux", Kind: HostdKind, ConfigRoot: t.TempDir(), Executable: layout.HostdBinary,
		User: "alice", Group: "staff", Arguments: []string{"serve"}, UpgradeMode: UpgradeReload, Controller: control,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := control.applied; len(got) != 1 || got[0] {
		t.Fatalf("stable hostd restart flags=%v", got)
	}
}

func TestHostdInstallerRejectsRootOwnership(t *testing.T) {
	_, err := NewHostdInstaller(ComponentConfig{Layout: splitLayout(t, "linux"), User: "root", Group: "root", UID: 0, Controller: &controller{}})
	if !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("root hostd err=%v", err)
	}
}

func TestComponentControllerUsesOnlySplitServiceNames(t *testing.T) {
	for _, test := range []struct {
		platform string
		kind     string
		want     string
	}{
		{platform: "linux", kind: HostdKind, want: "paperboat-hostd.service"},
		{platform: "linux", kind: UpdaterKind, want: "paperboat-updated.service"},
		{platform: "darwin", kind: HostdKind, want: HostdLabel},
		{platform: "darwin", kind: UpdaterKind, want: UpdaterLabel},
	} {
		t.Run(test.platform+"_"+test.kind, func(t *testing.T) {
			controller, err := ComponentController(test.platform, test.kind, 501, ExecRunner{})
			if err != nil {
				t.Fatal(err)
			}
			switch value := controller.(type) {
			case SystemdController:
				if value.Unit != test.want {
					t.Fatalf("unit=%q want=%q", value.Unit, test.want)
				}
			case LaunchdController:
				if value.Label != test.want || value.UserDomain {
					t.Fatalf("label=%q user_domain=%v", value.Label, value.UserDomain)
				}
			default:
				t.Fatalf("controller=%T", controller)
			}
		})
	}
	if _, err := ComponentController("windows", HostdKind, 501, ExecRunner{}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("windows controller err=%v", err)
	}
}
