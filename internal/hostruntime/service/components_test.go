package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func splitLayout(t *testing.T, platform string) Layout {
	t.Helper()
	if runtime.GOOS == "windows" && platform != "windows" {
		t.Skip("POSIX split-service filesystem semantics are not applicable on Windows")
	}
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
	if runtime.GOOS == "windows" {
		layout.HostdBinary += ".exe"
		layout.UpdaterBinary += ".exe"
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

func TestDefaultWindowsLayoutUsesCanonicalSeparators(t *testing.T) {
	layout, err := DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	if layout.ReleasesRoot != `C:\Program Files\Paperboat\releases` || layout.RuntimeCurrent != `C:\Program Files\Paperboat\releases\runtime-current\paperboat-runtime.exe` {
		t.Fatalf("non-canonical Windows layout: %+v", layout)
	}
	for _, value := range []string{layout.ReleasesRoot, layout.RuntimeCurrent, layout.RuntimeRollback, layout.CLICurrent} {
		if strings.Contains(value, `\\`) {
			t.Fatalf("layout path contains a duplicate separator: %q", value)
		}
	}
}

func TestWindowsImmutableReleasePathsRejectTraversal(t *testing.T) {
	layout, err := DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	release, err := layout.WindowsRelease("2026.08.23.1")
	if err != nil {
		t.Fatal(err)
	}
	if release.Hostd != `C:\Program Files\Paperboat\releases\versions\2026.08.23.1\paperboat-hostd.exe` || release.Updater != `C:\Program Files\Paperboat\releases\versions\2026.08.23.1\paperboat-updater.exe` {
		t.Fatalf("release=%+v", release)
	}
	if version, err := layout.WindowsVersionForExecutable(release.Updater); err != nil || version != "2026.08.23.1" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	for _, version := range []string{"../2026.08.23.1", "2026.8.23.1", "2026.08.23.01", "2026.08.23.1\\escape"} {
		if _, err := layout.WindowsRelease(version); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("version %q err=%v", version, err)
		}
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
			config := ComponentConfig{Layout: layout, User: "alice", Group: "staff", UID: 501, GID: 20, HostdTokenFile: filepath.Join(t.TempDir(), "hostd.token"), ReleaseRepository: "https://releases.paperboat.test", MachineID: "machine_1", HealthURL: "http://127.0.0.1:38080/healthz", Controller: control}
			hostd, err := NewHostdInstaller(config)
			if err != nil {
				t.Fatal(err)
			}
			updater, err := NewUpdaterInstaller(config)
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
				for _, expected := range []string{"User=root", "Group=root", "RuntimeDirectory=paperboat-updated", "After=local-fs.target network-online.target", "Wants=network-online.target", "PAPERBOAT_RELEASE_ROOT=" + layout.ReleasesRoot, "PAPERBOAT_RUNTIME_CURRENT=" + layout.RuntimeCurrent, "PAPERBOAT_CLI_CURRENT=" + layout.CLICurrent, "PAPERBOAT_UPDATED_SOCKET=" + updaterControlSocket(platform)} {
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

func TestHostdInstallerAcceptsOnlyExactRootEnrollment(t *testing.T) {
	if _, err := NewHostdInstaller(ComponentConfig{Layout: splitLayout(t, "linux"), User: "root", Group: "root", UID: 0, GID: 0, HostdTokenFile: "/tmp/token", Controller: &controller{}}); err != nil {
		t.Fatalf("root hostd err=%v", err)
	}
	for _, config := range []ComponentConfig{
		{Layout: splitLayout(t, "linux"), User: "alice", Group: "users", UID: 0, GID: 0, HostdTokenFile: "/tmp/token", Controller: &controller{}},
		{Layout: splitLayout(t, "linux"), User: "root", Group: "root", UID: 0, GID: 1000, HostdTokenFile: "/tmp/token", Controller: &controller{}},
		{Layout: splitLayout(t, "linux"), User: "root", Group: "users", UID: 0, GID: 0, HostdTokenFile: "/tmp/token", Controller: &controller{}},
		{Layout: splitLayout(t, "linux"), User: "root", Group: "users", UID: 1000, GID: 1000, HostdTokenFile: "/tmp/token", Controller: &controller{}},
	} {
		if _, err := NewHostdInstaller(config); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("invalid identity %+v err=%v", config, err)
		}
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
	if controller, err := ComponentController("windows", HostdKind, 501, ExecRunner{}); err != nil {
		t.Fatalf("windows controller err=%v", err)
	} else if _, ok := controller.(WindowsController); !ok {
		t.Fatalf("windows controller=%T", controller)
	}
}
