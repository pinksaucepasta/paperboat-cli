package service

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

type controller struct {
	applied   []bool
	removed   int
	applyErr  error
	removeErr error
}

func (c *controller) Apply(_ context.Context, _ string, upgrading bool) error {
	c.applied = append(c.applied, upgrading)
	return c.applyErr
}
func (c *controller) Remove(context.Context, string) error { c.removed++; return c.removeErr }

func executable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pb")
	if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSystemdDefinitionSignalsWorkerBeforeForceCleaningCgroup(t *testing.T) {
	body, err := renderSystemd(Config{Kind: WorkerKind, User: "paperboat", Group: "paperboat", Executable: "/usr/local/libexec/paperboat/pb"})
	if err != nil {
		t.Fatal(err)
	}
	definition := string(body)
	if !strings.Contains(definition, "TimeoutStopSec=60s\nKillMode=mixed\n") ||
		!strings.Contains(definition, "Type=notify\n") || !strings.Contains(definition, "WatchdogSec=30s\n") ||
		!strings.Contains(definition, "RuntimeDirectory=paperboat\n") || !strings.Contains(definition, "StateDirectoryMode=0700\n") ||
		!strings.Contains(definition, "CacheDirectoryMode=0750\n") {
		t.Fatalf("systemd shutdown policy missing:\n%s", definition)
	}
}

func TestSystemdDefinitionEscapesSpecifiersAndEnvironmentExpansion(t *testing.T) {
	body, err := renderSystemd(Config{Kind: WorkerKind, User: "paperboat", Group: "paperboat", Executable: "/opt/pb%stable", Arguments: []string{"$TOKEN"}, Environment: map[string]string{"VALUE": "$HOME%h"}})
	if err != nil {
		t.Fatal(err)
	}
	definition := string(body)
	if !strings.Contains(definition, `ExecStart="/opt/pb%%stable" "$$TOKEN"`) ||
		!strings.Contains(definition, `Environment="VALUE=$$HOME%%h"`) {
		t.Fatalf("unsafe systemd escaping:\n%s", definition)
	}
}

func TestPreviewSystemdDefinitionKeepsSourceTmpVisible(t *testing.T) {
	body, err := renderSystemd(Config{Kind: PreviewKind, Instance: "abc123", Executable: "/opt/pb", Arguments: []string{"__runtime-serve"}, Environment: map[string]string{"HOME": "/home/test"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "PrivateTmp=true") {
		t.Fatalf("preview worker must see user-selected /tmp sources:\n%s", body)
	}
	body, err = renderSystemd(Config{Kind: WorkerKind, User: "paperboat", Group: "paperboat", Executable: "/opt/pb", Arguments: []string{"run"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "PrivateTmp=true") {
		t.Fatalf("non-preview worker lost PrivateTmp:\n%s", body)
	}
}

func TestSystemdInstallUpgradeAndUninstallAreDeterministic(t *testing.T) {
	control := &controller{}
	installer, err := New(Config{Platform: "linux", ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run", "--state", "/var/lib/paperboat"}, Environment: map[string]string{"HOME": "/home/test", "PATH": "/usr/bin:/bin"}, Controller: control})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(installer.DefinitionPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "ExecStart=") || !strings.Contains(string(first), "NoNewPrivileges=false") || strings.Contains(string(first), "ProtectHome") {
		t.Fatalf("definition=%s", first)
	}
	info, _ := os.Stat(installer.DefinitionPath())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(installer.DefinitionPath())
	if string(first) != string(second) || len(control.applied) != 2 || control.applied[0] || !control.applied[1] {
		t.Fatalf("applied=%v", control.applied)
	}
	if err := installer.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(installer.DefinitionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("definition remains: %v", err)
	}
}

func TestServiceDefinitionsSafelyPreservePathsWithSpaces(t *testing.T) {
	control := &controller{}
	executable := executable(t)
	installer, err := New(Config{Platform: "linux", ConfigRoot: t.TempDir(), Executable: executable, User: "test", Group: "test", Arguments: []string{"run", "--state", "/home/test/Application Support/Paperboat"}, Environment: map[string]string{"HOME": "/home/test/Application Support"}, Controller: control})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	definition, err := os.ReadFile(installer.DefinitionPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), `Environment="HOME=/home/test/Application Support"`) || !strings.Contains(string(definition), `"/home/test/Application Support/Paperboat"`) {
		t.Fatalf("definition did not quote spaced values: %s", definition)
	}
}

func TestServiceDefinitionRejectsControlCharacters(t *testing.T) {
	_, err := New(Config{Platform: "linux", ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run\nExecStart=/tmp/other"}, Environment: map[string]string{"HOME": "/home/test"}, Controller: &controller{}})
	if !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("error=%v", err)
	}
}

func TestLaunchdDefinitionIsEscapedValidXML(t *testing.T) {
	root := t.TempDir()
	installer, err := New(Config{Platform: "darwin", ConfigRoot: root, Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run"}, Environment: map[string]string{"HOME": "/Users/test"}, Controller: &controller{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(installer.DefinitionPath())
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		if _, err := decoder.Token(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
	}
	if !strings.Contains(string(data), "<key>ProgramArguments</key>") || !strings.Contains(string(data), Label) {
		t.Fatalf("plist=%s", data)
	}
	if strings.Contains(string(data), "StandardOutPath") || !strings.Contains(string(data), "<key>UserName</key>") {
		t.Fatalf("plist must use unified logging and an explicit user: %s", data)
	}
}

func TestLaunchdDefinitionUsesTypedStructuredValues(t *testing.T) {
	config := Config{
		Kind: PreviewKind, Instance: "docs", Executable: "/Applications/Paperboat & Tools/pb",
		User: "test", Group: "staff", Arguments: []string{"preview", "<docs>"},
		Environment: map[string]string{"PAPERBOAT_VALUE": `a&b<"c">`},
	}
	body, err := renderLaunchd(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Label                string
		ProgramArguments     []string
		EnvironmentVariables map[string]string
		RunAtLoad            bool
		KeepAlive            struct{ SuccessfulExit bool }
		Umask                uint64
	}
	format, err := plist.Unmarshal(body, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if format != plist.XMLFormat || decoded.Label != previewLabel("docs") || !decoded.RunAtLoad ||
		decoded.KeepAlive.SuccessfulExit || decoded.Umask != 0o77 ||
		len(decoded.ProgramArguments) != 3 || decoded.ProgramArguments[0] != config.Executable ||
		decoded.ProgramArguments[2] != "<docs>" || decoded.EnvironmentVariables["PAPERBOAT_VALUE"] != `a&b<"c">` {
		t.Fatalf("decoded launchd definition=%+v format=%d", decoded, format)
	}
}

func TestHostServiceDefinitionsRunAsRootInBootDomain(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			root := t.TempDir()
			installer, err := New(Config{Platform: platform, Kind: HostKind, ConfigRoot: root, Executable: executable(t), User: "root", Group: "root", Arguments: []string{"--uid", "501", "--gid", "20"}, Controller: &controller{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(installer.DefinitionPath())
			if err != nil {
				t.Fatal(err)
			}
			definition := string(body)
			if platform == "linux" {
				if !strings.HasSuffix(installer.DefinitionPath(), "/etc/systemd/system/paperboat-runtime-privileged.service") || !strings.Contains(definition, "User=root\nGroup=root") || !strings.Contains(definition, "NoNewPrivileges=true") || !strings.Contains(definition, "WantedBy=multi-user.target") {
					t.Fatalf("path=%s definition=%s", installer.DefinitionPath(), definition)
				}
			} else if !strings.HasSuffix(installer.DefinitionPath(), "/Library/LaunchDaemons/"+HostLabel+".plist") || !strings.Contains(definition, "<string>"+HostLabel+"</string>") || !strings.Contains(definition, "<key>UserName</key>") {
				t.Fatalf("path=%s definition=%s", installer.DefinitionPath(), definition)
			}
		})
	}
}

func TestConfigServiceDefinitionsUsePerUserDomains(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			installer, err := New(Config{Platform: platform, Kind: ConfigKind, ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"__runtime-config"}, Controller: &controller{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(installer.DefinitionPath())
			if platform == "darwin" {
				if !strings.HasSuffix(installer.DefinitionPath(), "/Library/LaunchAgents/"+ConfigLabel+".plist") || !strings.Contains(string(body), "<string>"+ConfigLabel+"</string>") {
					t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
				}
			} else if !strings.HasSuffix(installer.DefinitionPath(), "/.config/systemd/user/paperboat-runtime-config.service") || !strings.Contains(string(body), "WantedBy=default.target") || strings.Contains(string(body), "User=test") {
				t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
			}
		})
	}
}

func TestLocalDaemonDefinitionsUsePerUserDomains(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			installer, err := New(Config{Platform: platform, Kind: DaemonKind, ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"__local-daemon"}, Controller: &controller{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(installer.DefinitionPath())
			definition := string(body)
			if platform == "darwin" {
				if !strings.HasSuffix(installer.DefinitionPath(), "/Library/LaunchAgents/"+DaemonLabel+".plist") || !strings.Contains(definition, "<string>"+DaemonLabel+"</string>") {
					t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
				}
			} else if !strings.HasSuffix(installer.DefinitionPath(), "/.config/systemd/user/paperboat-local-daemon.service") || !strings.Contains(definition, "Description=Paperboat local daemon") || !strings.Contains(definition, "WantedBy=default.target") || strings.Contains(definition, "User=test") {
				t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
			}
		})
	}
}

func TestAccountNamesAllowSafelyPlacedDots(t *testing.T) {
	for _, value := range []string{"pujan.pm", "first.last-1", "user_name"} {
		if !safeAccount(value) {
			t.Fatalf("safe account %q was rejected", value)
		}
	}
	for _, value := range []string{".user", "user.", "user..name", "user/name"} {
		if safeAccount(value) {
			t.Fatalf("unsafe account %q was accepted", value)
		}
	}
}

func TestPreviewServiceDefinitionsAreIsolatedAndCrashRestartOnly(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			installer, err := New(Config{Platform: platform, Kind: PreviewKind, Instance: "abc123", ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"__runtime-preview", "--name", "docs"}, Controller: &controller{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(installer.DefinitionPath())
			definition := string(body)
			if strings.Contains(installer.DefinitionPath(), "runtime-config") || strings.Contains(installer.DefinitionPath(), "runtime-host") {
				t.Fatalf("preview collided with singleton service: %s", installer.DefinitionPath())
			}
			if platform == "darwin" {
				if !strings.HasSuffix(installer.DefinitionPath(), "/Library/LaunchAgents/com.pinksaucepasta.paperboat.runtime-preview.abc123.plist") || !strings.Contains(definition, "<key>SuccessfulExit</key>") || !strings.Contains(definition, "<false") {
					t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
				}
			} else if !strings.HasSuffix(installer.DefinitionPath(), "/.config/systemd/user/paperboat-preview-abc123.service") || !strings.Contains(definition, "Restart=on-failure") || !strings.Contains(definition, "WantedBy=default.target") {
				t.Fatalf("path=%s body=%s", installer.DefinitionPath(), body)
			}
		})
	}
}

func TestControllerFailureIsNotReportedAsSuccess(t *testing.T) {
	control := &controller{applyErr: errors.New("manager failed")}
	installer, err := New(Config{Platform: "linux", ConfigRoot: t.TempDir(), Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run"}, Controller: control})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); !errors.Is(err, control.applyErr) {
		t.Fatalf("install err=%v", err)
	}
	if _, err := os.Stat(installer.DefinitionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed fresh definition remains: %v", err)
	}
	control.applyErr = nil
	if err := installer.Install(context.Background()); err != nil {
		t.Fatalf("install retry: %v", err)
	}
	if len(control.applied) != 2 || control.applied[0] || control.applied[1] {
		t.Fatalf("apply modes=%v", control.applied)
	}
	control.removeErr = errors.New("stop failed")
	if err := installer.Uninstall(context.Background()); !errors.Is(err, control.removeErr) {
		t.Fatalf("uninstall err=%v", err)
	}
	if _, err := os.Stat(installer.DefinitionPath()); err != nil {
		t.Fatalf("definition removed despite controller failure: %v", err)
	}
	control.removeErr = nil
	if err := installer.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(installer.DefinitionPath())
	if err != nil {
		t.Fatal(err)
	}
	control.applyErr = errors.New("upgrade failed")
	if err := installer.Install(context.Background()); !errors.Is(err, control.applyErr) {
		t.Fatalf("upgrade err=%v", err)
	}
	restored, err := os.ReadFile(installer.DefinitionPath())
	if err != nil || string(restored) != string(previous) {
		t.Fatalf("previous definition was not restored: err=%v", err)
	}
}

func TestDefinitionQuotesExecutablePathWithSpaces(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "pb")
	if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	installer, err := New(Config{Platform: "linux", ConfigRoot: t.TempDir(), Executable: path, User: "test", Group: "test", Arguments: []string{"run"}, Controller: &controller{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	definition, err := os.ReadFile(installer.DefinitionPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), `ExecStart="`+path+`" "run"`) {
		t.Fatalf("definition=%s", definition)
	}
}

func TestInstallDoesNotRewriteExistingConfigRootPermissions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	installer, err := New(Config{Platform: "linux", ConfigRoot: root, Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run"}, Controller: &controller{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestInstallSecuresExistingServiceDefinitionDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(directory, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o775); err != nil {
		t.Fatal(err)
	}
	installer, err := New(Config{Platform: "linux", ConfigRoot: root, Executable: executable(t), User: "test", Group: "test", Arguments: []string{"run"}, Controller: &controller{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("service definition directory mode = %o, want 755", got)
	}
}

type commandRunner struct {
	calls       [][]string
	errAt       int
	customError error
}

func (r *commandRunner) Run(_ context.Context, name string, args ...string) error {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if r.errAt == len(r.calls) {
		if r.customError != nil {
			return r.customError
		}
		return errors.New("command failed")
	}
	return nil
}

func TestNativeControllerCommandSequences(t *testing.T) {
	runner := &commandRunner{}
	systemd := SystemdController{Runner: runner}
	if err := systemd.Apply(context.Background(), "", false); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 || strings.Join(runner.calls[1], " ") != "systemctl enable --now paperboat-runtime-host.service" || strings.Join(runner.calls[2], " ") != "systemctl is-active --quiet paperboat-runtime-host.service" {
		t.Fatalf("calls=%v", runner.calls)
	}
	runner = &commandRunner{}
	systemd.Runner = runner
	if err := systemd.Apply(context.Background(), "", true); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 || strings.Join(runner.calls[2], " ") != "systemctl restart paperboat-runtime-host.service" || strings.Join(runner.calls[3], " ") != "systemctl is-active --quiet paperboat-runtime-host.service" {
		t.Fatalf("upgrade calls=%v", runner.calls)
	}
	runner = &commandRunner{}
	launchd := LaunchdController{Runner: runner, UID: 501}
	if err := launchd.Apply(context.Background(), "/tmp/helper.plist", true); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 || strings.Join(runner.calls[0], " ") != "launchctl bootout system/"+Label || strings.Join(runner.calls[3], " ") != "launchctl print system/"+Label {
		t.Fatalf("calls=%v", runner.calls)
	}
	runner = &commandRunner{errAt: 3}
	if err := (SystemdController{Runner: runner}).Apply(context.Background(), "", false); err == nil {
		t.Fatal("inactive systemd service reported success")
	}
	runner = &commandRunner{errAt: 3}
	if err := (LaunchdController{Runner: runner, UID: 501}).Apply(context.Background(), "/tmp/helper.plist", false); err == nil {
		t.Fatal("inactive launchd service reported success")
	}
}

func TestSystemdRemoveIgnoresOnlyAbsentUnitReset(t *testing.T) {
	definition := filepath.Join(t.TempDir(), "paperboat.service")
	if err := os.WriteFile(definition, []byte("unit"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &commandRunner{errAt: 3}
	runnerError := &CommandError{Tool: "systemctl", Cause: errors.New("exit status 1"), Output: "Failed to reset failed state of unit paperboat.service: Unit paperboat.service not loaded."}
	runner.customError = runnerError
	if err := (SystemdController{Runner: runner}).Remove(context.Background(), definition); err != nil {
		t.Fatalf("absent unit reset error=%v", err)
	}
	if _, err := os.Stat(definition); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("definition still exists: %v", err)
	}
	runner = &commandRunner{errAt: 3, customError: &CommandError{Tool: "systemctl", Cause: errors.New("exit status 1"), Output: "Access denied"}}
	if err := (SystemdController{Runner: runner}).Remove(context.Background(), filepath.Join(t.TempDir(), "missing.service")); err == nil {
		t.Fatal("non-absent reset failure was ignored")
	}
}

func TestLaunchdControllerHandlesBootstrapTransition(t *testing.T) {
	loadedAfterError := &commandRunner{errAt: 1}
	controller := LaunchdController{Runner: loadedAfterError, UID: 501}
	if err := controller.Apply(context.Background(), "/tmp/helper.plist", false); err != nil {
		t.Fatal(err)
	}
	if len(loadedAfterError.calls) != 4 || strings.Join(loadedAfterError.calls[1], " ") != "launchctl print system/"+Label {
		t.Fatalf("loaded-after-error calls=%v", loadedAfterError.calls)
	}

	reservedLabel := &launchdTransitionRunner{failures: 2}
	controller.Runner = reservedLabel
	if err := controller.Apply(context.Background(), "/tmp/helper.plist", false); err != nil {
		t.Fatal(err)
	}
	if len(reservedLabel.calls) != 5 || strings.Join(reservedLabel.calls[2], " ") != "launchctl bootstrap system /tmp/helper.plist" {
		t.Fatalf("reserved-label calls=%v", reservedLabel.calls)
	}
}

type launchdTransitionRunner struct {
	calls    [][]string
	failures int
}

func (r *launchdTransitionRunner) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(r.calls) <= r.failures {
		return errors.New("launchd transition in progress")
	}
	return nil
}

func TestExecRunnerReturnsBoundedNativeDiagnostics(t *testing.T) {
	err := (ExecRunner{}).Run(context.Background(), "/bin/sh", "-c", "printf native-diagnostic >&2; exit 7")
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Tool != "/bin/sh" || !strings.Contains(commandErr.Output, "native-diagnostic") {
		t.Fatalf("err=%v", err)
	}
	output := &boundedCommandOutput{limit: 8}
	data := []byte("0123456789abcdef")
	if written, err := output.Write(data); err != nil || written != len(data) || output.String() != "01234567" {
		t.Fatalf("written=%d output=%q err=%v", written, output.String(), err)
	}
}
