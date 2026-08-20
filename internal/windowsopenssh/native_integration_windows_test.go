package windowsopenssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestNativeProvisionAndService is intentionally opt-in because it installs
// the pinned machine-wide OpenSSH package and creates PaperboatSshd. CI runs it
// only on the disposable native Windows qualification runner.
func TestNativeProvisionAndService(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_OPENSSH_NATIVE") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_OPENSSH_NATIVE=1 on the native qualification runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	config := DefaultConfig(nil)
	inventory, inventoryErr := Inventory(ctx, config)
	if inventoryErr != nil {
		t.Fatalf("inventory approved OpenSSH before setup: %v", inventoryErr)
	}
	t.Logf("OpenSSH inventory class=%s winget_version=%s program_files_version=%s", inventory.Class, inventory.Record.WingetVersion, inventory.Record.ProgramFilesSSHD.Version)
	result, err := Setup(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.PackageID != PackageID || result.Version != ApprovedVersion || result.Port != config.Port {
		t.Fatalf("unexpected setup result: %+v", result)
	}
	assertNativeServiceSID(t)
	health, err := CheckLoopbackHealth(ctx, config, result.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(health.Listeners) < 2 {
		t.Fatalf("expected IPv4 and IPv6 loopback listeners: %+v", health)
	}
	report, err := Qualify(ctx, config, result.Result)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Authenticated || !report.Exec || !report.ExitStatus || !report.PTY ||
		!report.SCPUpload || !report.SCPDownload || !report.SFTPUpload || !report.SFTPDownload ||
		!report.Restored || !report.TemporaryStateRemoved {
		t.Fatalf("incomplete native OpenSSH qualification report: %+v", report)
	}
}

// TestNativeRepairStoppedService proves that the production repair engine
// restores a Paperboat-owned service without touching the administrator sshd.
func TestNativeRepairStoppedService(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_OPENSSH_NATIVE") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_OPENSSH_NATIVE=1 on the native qualification runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	config := DefaultConfig(nil)
	setup, err := Setup(ctx, config)
	if err != nil {
		t.Fatalf("establish repair precondition: %v", err)
	}
	if output, err := config.Runner.Run(ctx, "sc.exe", "stop", ServiceName); err != nil {
		t.Fatalf("stop Paperboat-owned service: %v: %s", err, boundedOutput(output))
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, healthErr := CheckLoopbackHealth(ctx, config, setup.Result)
		if errors.Is(healthErr, ErrServiceUnhealthy) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stopped service remained healthy: %v", healthErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.WriteFile(setup.ConfigPath, []byte("this is deliberately invalid sshd configuration\n"), 0o600); err != nil {
		t.Fatalf("corrupt Paperboat-owned configuration: %v", err)
	}
	if err := ValidateServiceConfig(config.Runner, setup.SSHDPath, setup.ConfigPath); err == nil {
		t.Fatal("deliberately corrupt Paperboat configuration unexpectedly validated")
	}
	hostKey := filepath.Join(config.StateRoot, "hostkeys", "ssh_host_ed25519_key")
	if output, err := config.Runner.Run(ctx, "icacls.exe", hostKey, "/grant", "*S-1-1-0:R"); err != nil {
		t.Fatalf("weaken Paperboat host-key ACL: %v: %s", err, boundedOutput(output))
	}
	defer func() { _ = protectHostKeyFiles(hostKey, hostKey+".pub") }()
	if err := verifyHostKeyFiles(hostKey); err == nil {
		t.Fatal("deliberately weakened Paperboat host-key ACL unexpectedly validated")
	}
	repaired, err := Repair(ctx, config)
	if err != nil {
		t.Fatalf("repair stopped Paperboat service: %v", err)
	}
	if repaired.Inventory.Class != InstallationPaperboatApproved || len(repaired.Health.Listeners) < 2 {
		t.Fatalf("incomplete repair result: %+v", repaired)
	}
	assertNativeServiceSID(t)
	if err := verifyHostKeyFiles(hostKey, hostKey+".pub"); err != nil {
		t.Fatalf("repair did not restore protected host-key ACLs: %v", err)
	}
	qualified, err := Qualify(ctx, config, repaired.SetupResult.Result)
	if err != nil || !qualified.Authenticated || !qualified.Exec || !qualified.PTY || !qualified.SCPUpload || !qualified.SCPDownload || !qualified.SFTPUpload || !qualified.SFTPDownload {
		t.Fatalf("repaired service qualification failed: report=%+v error=%v", qualified, err)
	}
}

func assertNativeServiceSID(t *testing.T) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to SCM for service SID verification: %v", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		t.Fatalf("open %s for service SID verification: %v", ServiceName, err)
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		t.Fatalf("query %s service SID type: %v", ServiceName, err)
	}
	if config.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		t.Fatalf("%s service SID type = %d, want unrestricted", ServiceName, config.SidType)
	}
}

// TestNativeUninstallOwnership proves that uninstall removes only Paperboat's
// dedicated service and state, preserving the shared package and system sshd.
func TestNativeUninstallOwnership(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_OPENSSH_NATIVE") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_OPENSSH_NATIVE=1 on the native qualification runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	config := DefaultConfig(nil)
	setup, err := Setup(ctx, config)
	if err != nil {
		t.Fatalf("establish uninstall precondition: %v", err)
	}
	before, err := Inventory(ctx, config)
	if err != nil || before.Class != InstallationPaperboatApproved || !before.Record.PaperboatService.Exists {
		t.Fatalf("invalid uninstall inventory precondition: inventory=%+v error=%v", before, err)
	}
	restored := false
	defer func() {
		if restored {
			return
		}
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer restoreCancel()
		if _, restoreErr := Setup(restoreCtx, config); restoreErr != nil {
			t.Errorf("restore Paperboat OpenSSH after uninstall test: %v", restoreErr)
		}
	}()
	if err := RemovePaperboatState(ctx, config); err != nil {
		t.Fatalf("remove Paperboat-owned OpenSSH state: %v", err)
	}
	after, err := Inventory(ctx, config)
	if err != nil {
		t.Fatalf("inventory after Paperboat uninstall: %v", err)
	}
	if after.Class != InstallationPaperboatApproved || after.Record.PaperboatService.Exists || !after.Record.WingetRegistered || after.Record.WingetVersion != before.Record.WingetVersion || after.Record.ProgramFilesSSHD.Path != before.Record.ProgramFilesSSHD.Path || !after.Record.ProgramFilesSSHD.Exists {
		t.Fatalf("shared OpenSSH changed during Paperboat uninstall: before=%+v after=%+v", before, after)
	}
	if after.Record.SystemService.Exists != before.Record.SystemService.Exists || !strings.EqualFold(after.Record.SystemService.PathName, before.Record.SystemService.PathName) {
		t.Fatalf("administrator sshd changed during Paperboat uninstall: before=%+v after=%+v", before.Record.SystemService, after.Record.SystemService)
	}
	for _, path := range []string{setup.ConfigPath, filepath.Join(config.StateRoot, "hostkeys"), filepath.Join(config.StateRoot, "authorized_keys"), filepath.Join(config.StateRoot, "logs")} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("Paperboat-owned state remained after uninstall: %s: %v", path, statErr)
		}
	}
	recreated, err := Setup(ctx, config)
	if err != nil {
		t.Fatalf("restore Paperboat OpenSSH after uninstall: %v", err)
	}
	restored = true
	report, err := Qualify(ctx, config, recreated.Result)
	if err != nil || !report.Authenticated || !report.Exec || !report.PTY || !report.SCPUpload || !report.SCPDownload || !report.SFTPUpload || !report.SFTPDownload {
		t.Fatalf("restored service qualification failed: report=%+v error=%v", report, err)
	}
}

func TestNativeFirewallProfiles(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_OPENSSH_NATIVE") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_OPENSSH_NATIVE=1 on the native qualification runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := DefaultConfig(nil)
	setup, err := Setup(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckFirewallOwnership(ctx, config); err != nil {
		t.Fatalf("unsafe Paperboat firewall ownership: %v", err)
	}
	snapshot, err := snapshotFirewall(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	profiles := make(map[string]FirewallProfile, len(snapshot.Profiles))
	for _, profile := range snapshot.Profiles {
		profiles[strings.ToLower(profile.Name)] = profile
	}
	for _, name := range []string{"domain", "private", "public"} {
		profile, found := profiles[name]
		if !found || !profile.Enabled {
			t.Errorf("Windows Defender Firewall profile %s is absent or disabled: %+v", name, profile)
		}
	}
	for _, rule := range snapshot.OpenSSHInbound {
		if paperboatEndpointFirewallRule(rule, config.Port) {
			t.Errorf("enabled inbound firewall rule exposes Paperboat endpoint: %+v", rule)
		}
	}
	if _, err := CheckLoopbackHealth(ctx, config, setup.Result); err != nil {
		t.Fatalf("loopback-only service unhealthy across firewall profile inventory: %v", err)
	}
}

func TestNativeSCMCrashRecovery(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_OPENSSH_NATIVE") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_OPENSSH_NATIVE=1 on the native qualification runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := DefaultConfig(nil)
	setup, err := Setup(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	actions, err := service.RecoveryActions()
	if err != nil || len(actions) != len(paperboatServiceRecovery) {
		t.Fatalf("read SCM recovery actions: actions=%+v error=%v", actions, err)
	}
	for index := range actions {
		if actions[index] != paperboatServiceRecovery[index] {
			t.Fatalf("SCM recovery action %d=%+v, want %+v", index, actions[index], paperboatServiceRecovery[index])
		}
	}
	if enabled, err := service.RecoveryActionsOnNonCrashFailures(); err != nil || !enabled {
		t.Fatalf("SCM non-crash recovery disabled: enabled=%t error=%v", enabled, err)
	}
	before, err := service.Query()
	if err != nil || before.ProcessId == 0 {
		t.Fatalf("query PaperboatSshd before crash: status=%+v error=%v", before, err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, before.ProcessId)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.TerminateProcess(process, 99); err != nil {
		windows.CloseHandle(process)
		t.Fatal(err)
	}
	windows.CloseHandle(process)
	deadline := time.Now().Add(45 * time.Second)
	var afterPID uint32
	for time.Now().Before(deadline) {
		status, queryErr := service.Query()
		if queryErr == nil && status.ProcessId != 0 && status.ProcessId != before.ProcessId {
			afterPID = status.ProcessId
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if afterPID == 0 {
		t.Fatalf("SCM did not recover PaperboatSshd after terminating pid %d", before.ProcessId)
	}
	if _, err := CheckLoopbackHealth(ctx, config, setup.Result); err != nil {
		t.Fatalf("recovered PaperboatSshd is unhealthy: %v", err)
	}
	report, err := Qualify(ctx, config, setup.Result)
	if err != nil || !report.Authenticated || !report.Exec || !report.PTY || !report.SCPUpload || !report.SCPDownload || !report.SFTPUpload || !report.SFTPDownload {
		t.Fatalf("recovered service qualification failed: report=%+v error=%v", report, err)
	}
}
