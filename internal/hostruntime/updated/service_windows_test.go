//go:build windows

package updated

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func testWindowsUpdaterConfig(t *testing.T) WindowsConfig {
	t.Helper()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	return WindowsConfig{StateRoot: layout.UpdateStateRoot, RuntimeCurrent: layout.RuntimeCurrent, RuntimeRollback: layout.RuntimeRollback, RuntimeStaged: layout.RuntimeStaged, CLICurrent: layout.CLICurrent, CLIRollback: layout.CLIRollback, OwnerSID: "S-1-5-21-1-2-3-1001", MachineID: "machine", RepositoryURL: "https://get.pprbt.dev", TokenFile: hostinstall.WindowsHostdTokenPath(), InstallState: hostinstall.WindowsInstallConfigPath(), ControlSocket: `\\.\pipe\PaperboatUpdatedControl`, HostdSocket: layout.HostdSocket, HealthURL: "http://127.0.0.1:8080/healthz", ActiveVersion: "2026.08.23.1", Architecture: "amd64", SetupMode: "client"}
}

func TestWindowsUpdaterRejectsMutableTrustAndPathInputs(t *testing.T) {
	baseline := testWindowsUpdaterConfig(t)
	if !validWindowsConfig(baseline) {
		t.Fatal("valid fixed updater config rejected")
	}
	tests := []func(*WindowsConfig){
		func(c *WindowsConfig) { c.TokenFile = `C:\Temp\token` },
		func(c *WindowsConfig) { c.InstallState = `C:\Temp\state.json` },
		func(c *WindowsConfig) { c.StateRoot = `C:\Temp\updates` },
		func(c *WindowsConfig) { c.ControlSocket = `\\.\pipe\attacker` },
		func(c *WindowsConfig) { c.HealthURL = "http://10.0.0.1:8080/healthz" },
		func(c *WindowsConfig) { c.Architecture = "386" },
		func(c *WindowsConfig) { c.SetupMode = "both" },
	}
	for index, mutate := range tests {
		candidate := baseline
		mutate(&candidate)
		if validWindowsConfig(candidate) {
			t.Fatalf("mutable trust case %d accepted", index)
		}
	}
}

func TestPrivilegedWindowsServiceIdentityContract(t *testing.T) {
	config := mgr.Config{ServiceStartName: "LocalSystem", StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}
	if !validPrivilegedWindowsServiceConfig(config, mgr.StartAutomatic, mgr.ErrorNormal) {
		t.Fatal("valid LocalSystem service identity rejected")
	}
	config.ServiceStartName = "Paperboat"
	if validPrivilegedWindowsServiceConfig(config, mgr.StartAutomatic, mgr.ErrorNormal) {
		t.Fatal("mutable service account accepted")
	}
	config.ServiceStartName = "LocalSystem"
	config.SidType = windows.SERVICE_SID_TYPE_NONE
	if validPrivilegedWindowsServiceConfig(config, mgr.StartAutomatic, mgr.ErrorNormal) {
		t.Fatal("mutable service SID type accepted")
	}
}

func TestWindowsSSHCommandContractIsExact(t *testing.T) {
	valid := []string{"__windows-sshd-service", "--sshd", `C:\Program Files\OpenSSH\sshd.exe`, "--config", `C:\ProgramData\Paperboat\ssh\sshd_config`}
	if !validWindowsSSHArguments(valid) {
		t.Fatal("valid fixed PaperboatSshd command rejected")
	}
	mutated := append([]string(nil), valid...)
	mutated[2] = `C:\Temp\sshd.exe`
	if validWindowsSSHArguments(mutated) {
		t.Fatal("mutable sshd executable accepted")
	}
}

func TestWindowsActiveServiceTargetsAreExactRoleArtifacts(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := layout.WindowsRelease("2026.08.23.1")
	if err != nil {
		t.Fatal(err)
	}
	hostd := windowsServiceTarget{Executable: paths.Hostd}
	updater := windowsServiceTarget{Executable: paths.Updater}
	ssh := windowsServiceTarget{Executable: paths.Runtime}
	if !activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("exact role targets rejected")
	}
	hostd.Executable = paths.Runtime
	if activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("runtime artifact accepted as hostd")
	}
}
