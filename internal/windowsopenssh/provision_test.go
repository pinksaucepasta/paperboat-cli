package windowsopenssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls []recordedCall
	errAt int
}

func (r *fakeRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	r.calls = append(r.calls, recordedCall{name: name, args: append([]string(nil), arguments...)})
	if strings.EqualFold(filepath.Base(name), "powershell.exe") && len(arguments) > 0 && strings.Contains(arguments[len(arguments)-1], "Convert-PaperboatFirewallRule") {
		return []byte(`{"captured_at":"2026-08-20T00:00:00Z","system_sshd":false,"profiles":[],"openssh_inbound":[]}`), nil
	}
	if r.errAt > 0 && len(r.calls) == r.errAt {
		return []byte("failed"), errors.New("command failed")
	}
	if len(arguments) == 1 && arguments[0] == "--version" {
		return []byte("v1.7.0"), nil
	}
	return nil, nil
}

func TestProvisionUsesExactPinnedPackageAndVerifiesEveryBinary(t *testing.T) {
	root := t.TempDir()
	install := filepath.Join(root, "OpenSSH")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh.exe", "sshd.exe", "scp.exe", "sftp.exe", "sftp-server.exe", "ssh-keygen.exe"} {
		if err := os.WriteFile(filepath.Join(install, name), []byte("pe"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{}
	result, err := Provision(context.Background(), Config{
		Platform: "windows", WingetPath: "winget.exe", InstallRoot: install,
		StateRoot: filepath.Join(root, "state"), ApprovedVersion: ApprovedVersion,
		ExpectedPublisher: "Microsoft", Port: 38222, Runner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCalls, installIndex := 8, 1
	if runtime.GOOS == "windows" {
		wantCalls, installIndex = 10, 2
	}
	if result.PackageID != PackageID || result.Version != ApprovedVersion || len(runner.calls) != wantCalls {
		t.Fatalf("unexpected result/calls: %#v %#v", result, runner.calls)
	}
	want := []string{"install", "--exact", "--id", PackageID, "--version", ApprovedVersion, "--source", "winget", "--scope", "machine", "--silent", "--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity"}
	if !reflect.DeepEqual(runner.calls[installIndex].args, want) {
		t.Fatalf("install arguments = %#v, want %#v", runner.calls[installIndex].args, want)
	}
}

func TestSupportedWingetVersion(t *testing.T) {
	for value, want := range map[string]bool{"v1.7.0": true, "1.12.350": true, "v1.6.9": false, "garbage": false} {
		if got := supportedWingetVersion(value); got != want {
			t.Fatalf("supportedWingetVersion(%q)=%t, want %t", value, got, want)
		}
	}
}

func TestWindowsSignatureScriptsImportSecurityModuleBySystemPath(t *testing.T) {
	runner := &fakeRunner{}
	_, _ = resolveWinget(context.Background(), runner)
	if len(runner.calls) != 1 {
		t.Fatalf("resolve calls = %d, want 1", len(runner.calls))
	}
	script := runner.calls[0].args[len(runner.calls[0].args)-1]
	for _, required := range []string{"$env:WINDIR", "Microsoft.PowerShell.Security.psd1", "Import-Module -Name $m -ErrorAction Stop", "Get-AuthenticodeSignature"} {
		if !strings.Contains(script, required) {
			t.Fatalf("resolve script missing %q: %s", required, script)
		}
	}
}

func TestProvisionDoesNotFallBackWhenWingetIsUnavailable(t *testing.T) {
	errAt := 1
	if runtime.GOOS == "windows" {
		errAt = 2
	}
	runner := &fakeRunner{errAt: errAt}
	root := t.TempDir()
	_, err := Provision(context.Background(), Config{Platform: "windows", WingetPath: "winget.exe", InstallRoot: filepath.Join(root, "OpenSSH"), StateRoot: filepath.Join(root, "state"), ApprovedVersion: ApprovedVersion, ExpectedPublisher: "Microsoft", Port: 38222, Runner: runner})
	if !errors.Is(err, ErrInstallerUnavailable) || len(runner.calls) != errAt {
		t.Fatalf("error/calls = %v/%d", err, len(runner.calls))
	}
}

func TestWriteServiceConfigIsLoopbackOnlyAndKeyOnly(t *testing.T) {
	root := t.TempDir()
	path, err := WriteServiceConfig(ServiceConfig{StateRoot: root, SSHDPath: filepath.Join(root, "sshd.exe"), SFTPPath: filepath.Join(root, "sftp-server.exe"), AuthorizedKeys: filepath.Join(root, "authorized_keys", "paperboat"), Port: 38222})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"ListenAddress 127.0.0.1", "ListenAddress ::1", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "AllowTcpForwarding no"} {
		if !strings.Contains(text, required) {
			t.Fatalf("config missing %q:\n%s", required, text)
		}
	}
}

func TestClassifyInventoryPreservesSystemSSHDAndClassifiesEveryDisposition(t *testing.T) {
	root := t.TempDir()
	config := Config{Platform: "windows", InstallRoot: filepath.Join(root, "OpenSSH"), StateRoot: filepath.Join(root, "state"), ApprovedVersion: ApprovedVersion, ExpectedPublisher: "Microsoft", Port: 38222, Runner: &fakeRunner{}}
	approved := BinaryRecord{Path: filepath.Join(config.InstallRoot, "sshd.exe"), Exists: true, Regular: true, SignatureValid: true, Publisher: "CN=Microsoft Corporation", Version: ApprovedVersion}
	cases := []struct {
		name   string
		record InventoryRecord
		want   InstallationClass
	}{
		{name: "missing", want: InstallationMissing},
		{name: "windows capability", record: InventoryRecord{CapabilityPresent: true, SystemService: ServiceRecord{Name: "sshd", Exists: true}}, want: InstallationWindowsCapability},
		{name: "approved winget alongside admin sshd", record: InventoryRecord{WingetRegistered: true, WingetVersion: ApprovedVersion, ProgramFilesSSHD: approved, SystemService: ServiceRecord{Name: "sshd", Exists: true, PathName: `C:\\Windows\\System32\\OpenSSH\\sshd.exe`}}, want: InstallationPaperboatApproved},
		{name: "different winget version", record: InventoryRecord{WingetRegistered: true, WingetVersion: "9.9.0.0", ProgramFilesSSHD: approved}, want: InstallationDifferentWinget},
		{name: "third party", record: InventoryRecord{ProgramFilesSSHD: approved}, want: InstallationThirdParty},
		{name: "untrusted binary", record: InventoryRecord{ProgramFilesSSHD: BinaryRecord{Path: approved.Path, Exists: true, Regular: true, Publisher: "CN=Unknown"}}, want: InstallationUntrusted},
		{name: "paperboat service ownership conflict", record: InventoryRecord{PaperboatService: ServiceRecord{Name: ServiceName, Exists: true, PathName: `C:\\admin\\sshd.exe -D -f C:\\admin\\sshd_config`}}, want: InstallationConflicting},
		{name: "winget registration without expected binary", record: InventoryRecord{WingetRegistered: true, WingetVersion: ApprovedVersion}, want: InstallationConflicting},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyInventory(test.record, config)
			if got.Class != test.want {
				t.Fatalf("class = %q, want %q", got.Class, test.want)
			}
			if got.SystemSSHDManaged != test.record.SystemService.Exists {
				t.Fatalf("system service ownership = %t, want %t", got.SystemSSHDManaged, test.record.SystemService.Exists)
			}
		})
	}
}

func TestClassifyInventoryRejectsWrongPEArchitecture(t *testing.T) {
	root := t.TempDir()
	config := Config{Platform: "windows", Architecture: "arm64", InstallRoot: filepath.Join(root, "OpenSSH"), StateRoot: filepath.Join(root, "state"), ApprovedVersion: ApprovedVersion, ExpectedPublisher: "Microsoft", Port: 38222, Runner: &fakeRunner{}}
	record := InventoryRecord{WingetRegistered: true, WingetVersion: ApprovedVersion, ProgramFilesSSHD: BinaryRecord{Path: filepath.Join(config.InstallRoot, "sshd.exe"), Exists: true, Regular: true, SignatureValid: true, Publisher: "CN=Microsoft Corporation", Version: ApprovedVersion, Architecture: "amd64"}}
	if got := ClassifyInventory(record, config).Class; got != InstallationUntrusted {
		t.Fatalf("class=%q", got)
	}
}

func TestValidateLoopbackHealthRequiresPaperboatOwnedDualStackListeners(t *testing.T) {
	root := t.TempDir()
	config := Config{Platform: "windows", InstallRoot: filepath.Join(root, "OpenSSH"), StateRoot: filepath.Join(root, "state"), ApprovedVersion: ApprovedVersion, ExpectedPublisher: "Microsoft", Port: 38222, Runner: &fakeRunner{}}
	result := Result{SSHDPath: filepath.Join(config.InstallRoot, "sshd.exe"), Port: config.Port}
	health := ServiceHealth{
		Service: ServiceRecord{Name: ServiceName, Exists: true, State: "Running", ProcessID: 41, PathName: `"` + result.SSHDPath + `" -D -f "` + filepath.Join(config.StateRoot, "sshd_config") + `"`},
		Listeners: []ListenerRecord{
			{Address: "127.0.0.1", Port: config.Port, ProcessID: 41, ExecutablePath: result.SSHDPath},
			{Address: "::1", Port: config.Port, ProcessID: 41, ExecutablePath: result.SSHDPath},
		},
	}
	if err := ValidateLoopbackHealth(health, config, result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ServiceHealth){
		func(value *ServiceHealth) { value.Listeners = value.Listeners[:1] },
		func(value *ServiceHealth) { value.Listeners[0].ProcessID = 99 },
		func(value *ServiceHealth) { value.Listeners[0].ExecutablePath = filepath.Join(root, "other.exe") },
		func(value *ServiceHealth) { value.Listeners[0].Address = "0.0.0.0" },
		func(value *ServiceHealth) {
			value.Service.PathName = `C:\\admin\\sshd.exe -D -f C:\\admin\\sshd_config`
		},
	} {
		candidate := health
		candidate.Listeners = append([]ListenerRecord(nil), health.Listeners...)
		mutate(&candidate)
		if err := ValidateLoopbackHealth(candidate, config, result); !errors.Is(err, ErrServiceUnhealthy) && !errors.Is(err, ErrServiceOwnership) {
			t.Fatalf("error = %v, want typed unhealthy or ownership error", err)
		}
	}
}
