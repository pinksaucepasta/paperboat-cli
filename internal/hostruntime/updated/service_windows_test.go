//go:build windows

package updated

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type noopWindowsActivationGate struct{}

func (noopWindowsActivationGate) Candidate(context.Context, workerupdate.GateRequest) error {
	return nil
}
func (noopWindowsActivationGate) Drain(context.Context, workerupdate.GateRequest) error  { return nil }
func (noopWindowsActivationGate) Active(context.Context, workerupdate.GateRequest) error { return nil }
func (noopWindowsActivationGate) Commit(context.Context, workerupdate.GateRequest) error {
	return nil
}
func (noopWindowsActivationGate) Rollback(context.Context, workerupdate.GateRequest) error {
	return nil
}

func TestWaitForWindowsUpdaterVersionWaitsForApplicationReadiness(t *testing.T) {
	calls := 0
	err := waitForWindowsUpdaterVersion(context.Background(), "2026.08.28.2", time.Second, time.Millisecond, func(context.Context) (ControlResponse, error) {
		calls++
		if calls < 3 {
			return ControlResponse{Version: "2026.08.28.1"}, nil
		}
		return ControlResponse{Version: "2026.08.28.2"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("status calls=%d want=3", calls)
	}
}

func TestWaitForWindowsUpdaterVersionReturnsExactMismatch(t *testing.T) {
	err := waitForWindowsUpdaterVersion(context.Background(), "2026.08.28.2", 5*time.Millisecond, time.Millisecond, func(context.Context) (ControlResponse, error) {
		return ControlResponse{Version: "2026.08.28.1"}, nil
	})
	if !errors.Is(err, errInvalidWindowsActivation) || !strings.Contains(err.Error(), `got "2026.08.28.1", want "2026.08.28.2"`) {
		t.Fatalf("error=%v", err)
	}
}

func testWindowsUpdaterConfig(t *testing.T) WindowsConfig {
	t.Helper()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	return WindowsConfig{StateRoot: layout.UpdateStateRoot, RuntimeStateRoot: `C:\Users\Pujan\AppData\Local\Paperboat\runtime`, Binary: layout.Binary, BinaryRollback: layout.BinaryRollback, BinaryStaged: layout.BinaryStaged, OwnerSID: "S-1-5-21-1-2-3-1001", MachineID: "machine", RepositoryURL: "https://get.pprbt.dev", TokenFile: hostinstall.WindowsHostdTokenPath(), InstallState: hostinstall.WindowsInstallConfigPath(), ControlSocket: `\\.\pipe\PaperboatUpdatedControl`, HostdSocket: layout.HostdSocket, HealthURL: "http://127.0.0.1:8080/healthz", ActiveVersion: "2026.08.23.1", Architecture: "amd64", SetupMode: "client", ActivationGate: noopWindowsActivationGate{}, CandidateStarter: func(context.Context, workerupdate.StartRequest) (workerupdate.Worker, error) {
		return nil, errors.New("candidate test stub")
	}}
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
		func(c *WindowsConfig) { c.RuntimeStateRoot = `C:\Temp\owner-state` },
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

func TestWindowsRecoveryPolicyIsServiceSpecific(t *testing.T) {
	standard := windowsRecoveryActionsForService(windowsHostdService)
	if !windowsRecoveryActionsMatch(standard, []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}) {
		t.Fatal("hostd/updater recovery policy changed")
	}
	if !windowsRecoveryActionsMatch(windowsRecoveryActionsForService(windowsUpdaterService), standard) {
		t.Fatal("PaperboatUpdated does not use the standard recovery policy")
	}
	ssh := windowsRecoveryActionsForService(windowsSSHService)
	if !windowsRecoveryActionsMatch(ssh, []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.NoAction}}) {
		t.Fatal("PaperboatSshd recovery policy changed")
	}
	if windowsRecoveryActionsMatch(standard, ssh) {
		t.Fatal("PaperboatSshd incorrectly shares the updater recovery policy")
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

func TestWindowsActiveServiceTargetsUseCanonicalBinary(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	hostd := windowsServiceTarget{Executable: layout.Binary}
	updater := windowsServiceTarget{Executable: layout.Binary}
	ssh := windowsServiceTarget{Executable: layout.Binary}
	if !activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("exact role targets rejected")
	}
	hostd.Executable = layout.BinaryRollback
	if activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("runtime artifact accepted as hostd")
	}
	hostd.Executable = layout.Binary
	updater.Executable = layout.BinaryRollback
	if !activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("intentional rollback artifact rejected as updater")
	}
	updater.Executable = `C:\Temp\pb.exe`
	if activeWindowsServiceTargetsMatch(layout, "2026.08.23.1", hostd, updater, ssh) {
		t.Fatal("mutable updater artifact accepted")
	}
}

func TestNormalizeWindowsRollbackTargetsRestartsUpdaterFromCanonicalPath(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	hostd := windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-hostd"}}
	updater := windowsServiceTarget{Executable: layout.BinaryRollback, Arguments: []string{"__runtime-updated"}, WasRunning: true}
	ssh := windowsServiceTarget{}
	_, normalized, _, err := normalizeWindowsRollbackTargets(hostd, updater, ssh)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Executable != layout.Binary || !normalized.WasRunning {
		t.Fatalf("normalized updater=%+v want canonical executable %q", normalized, layout.Binary)
	}
}

func TestWindowsActivationPathsAcceptRollbackUpdaterDuringRecovery(t *testing.T) {
	config := testWindowsUpdaterConfig(t)
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := canonicalWindowsRelease(layout, "2026.08.24.1")
	if err != nil {
		t.Fatal(err)
	}
	component := windowsActivationComponent{Path: paths.Runtime, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Length: 1}
	journal := windowsActivationJournal{
		Schema: windowsActivationJournalSchema, TransactionID: "0123456789abcdef0123456789abcdef",
		PreviousVersion: config.ActiveVersion, Version: "2026.08.24.1", Architecture: config.Architecture,
		Stage: windowsActivationStaged, Runtime: component, CLI: component, Hostd: component, Updater: component,
		PreviousBinary: windowsActivationComponent{Path: layout.Binary, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Length: 1},
		OldHostd:       windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-hostd"}},
		NewHostd:       windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-hostd"}},
		OldUpdater:     windowsServiceTarget{Executable: layout.BinaryRollback, Arguments: []string{"__runtime-updated"}},
		NewUpdater:     windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-updated"}},
	}
	if !validWindowsActivationPaths(config, journal) {
		t.Fatal("staged journal with rollback updater was rejected")
	}
	journal.OldUpdater.Executable = `C:\Temp\pb.exe`
	if validWindowsActivationPaths(config, journal) {
		t.Fatal("mutable updater executable was accepted")
	}
}
