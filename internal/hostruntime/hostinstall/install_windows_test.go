//go:build windows

package hostinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestFreshStandaloneInstallVerifiesBeforeCleanup(t *testing.T) {
	previousAdministrator := isAdministratorForStandaloneInstall
	previousVerify := verifyStandaloneReleaseForInstall
	previousPurge := purgeStandaloneInstall
	t.Cleanup(func() {
		isAdministratorForStandaloneInstall = previousAdministrator
		verifyStandaloneReleaseForInstall = previousVerify
		purgeStandaloneInstall = previousPurge
	})
	verificationCalled, recoveryCalled, purgeCalled := false, false, false
	want := errors.New("signed release rejected")
	isAdministratorForStandaloneInstall = func() bool { return true }
	verifyStandaloneReleaseForInstall = func(context.Context, string, bootstrap.ArtifactTarget) (releaseindex.Target, error) {
		verificationCalled = true
		return releaseindex.Target{}, want
	}
	purgeStandaloneInstall = func(context.Context) error {
		purgeCalled = true
		return nil
	}
	source := filepath.Join(t.TempDir(), "pb.exe")
	err := installStandaloneBinary(context.Background(), source, "2026.09.05.1", true, func() error {
		recoveryCalled = true
		return nil
	})
	if !verificationCalled || !errors.Is(err, want) || recoveryCalled || purgeCalled {
		t.Fatalf("verification=%t error=%v recovery=%t purge=%t", verificationCalled, err, recoveryCalled, purgeCalled)
	}
}

func TestStaleWindowsRuntimeProcessScriptIncludesEveryInstalledRuntimeRole(t *testing.T) {
	pattern := regexp.MustCompile(staleWindowsRuntimeProcessPattern)
	tests := []struct {
		name string
		line string
		want bool
	}{
		{name: "hostd", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __runtime-hostd`, want: true},
		{name: "worker", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __runtime-worker`, want: true},
		{name: "updated", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __runtime-updated`, want: true},
		{name: "local daemon supervisor", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __runtime-local-daemon`, want: true},
		{name: "local daemon worker", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __local-daemon --server https://api.pprbt.dev`, want: true},
		{name: "managed ssh", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __windows-sshd-service --sshd sshd.exe`, want: true},
		{name: "unrelated pb process", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" --version`, want: false},
		{name: "unrelated runtime command", line: `"C:\\Program Files\\Paperboat\\bin\\pb.exe" __runtime-client`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pattern.MatchString(test.line); got != test.want {
				t.Fatalf("pattern match=%t for %q, want %t", got, test.line, test.want)
			}
		})
	}
	if !strings.Contains(staleWindowsRuntimeProcessScript, staleWindowsRuntimeProcessPattern) {
		t.Fatal("stale runtime process script does not use the bounded runtime-role pattern")
	}
}

func TestWindowsSSHServiceSetFollowsHostClientTransition(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	previousRemoveService, previousRemoveState, previousSetup := removePaperboatSSHService, removePaperboatSSHState, setupPaperboatSSH
	t.Cleanup(func() {
		removePaperboatSSHService = previousRemoveService
		removePaperboatSSHState = previousRemoveState
		setupPaperboatSSH = previousSetup
	})
	var removedService, removedState []windowsopenssh.Config
	var installs []windowsopenssh.Config
	removePaperboatSSHService = func(_ context.Context, config windowsopenssh.Config) error {
		removedService = append(removedService, config)
		return nil
	}
	removePaperboatSSHState = func(_ context.Context, config windowsopenssh.Config) error {
		removedState = append(removedState, config)
		return nil
	}
	setupPaperboatSSH = func(_ context.Context, config windowsopenssh.Config) (windowsopenssh.SetupResult, error) {
		installs = append(installs, config)
		return windowsopenssh.SetupResult{}, nil
	}
	host := Request{SetupMode: "host", OwnerSID: "S-1-5-21-1-2-3-4"}
	if err := removeWindowsSSHBeforeActivation(context.Background(), host, layout); err != nil {
		t.Fatal(err)
	}
	if err := installWindowsSSHAfterActivation(context.Background(), host, layout); err != nil {
		t.Fatal(err)
	}
	client := Request{SetupMode: "client", OwnerSID: host.OwnerSID}
	if err := removeWindowsSSHBeforeActivation(context.Background(), client, layout); err != nil {
		t.Fatal(err)
	}
	if err := installWindowsSSHAfterActivation(context.Background(), client, layout); err != nil {
		t.Fatal(err)
	}
	if len(removedService) != 2 || len(removedState) != 1 || len(installs) != 1 {
		t.Fatalf("host/client SSH operations: remove service=%d remove state=%d install=%d", len(removedService), len(removedState), len(installs))
	}
	for _, config := range removedService {
		if config.ServiceExecutable != layout.Binary {
			t.Fatalf("SSH ownership executable: service=%q want=%q", config.ServiceExecutable, layout.Binary)
		}
	}
	if removedState[0].ServiceExecutable != layout.Binary {
		t.Fatalf("SSH state ownership executable=%q want=%q", removedState[0].ServiceExecutable, layout.Binary)
	}
	if installs[0].ServiceExecutable != layout.Binary || installs[0].InstallRoot != `C:\Program Files\OpenSSH` || installs[0].StateRoot != `C:\ProgramData\Paperboat\ssh` {
		t.Fatalf("host SSH install=%+v", installs[0])
	}
}

func TestWindowsHostRuntimeFailurePreservesManagedSSHState(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	previousRemoveService, previousRemoveState := removePaperboatSSHService, removePaperboatSSHState
	t.Cleanup(func() {
		removePaperboatSSHService = previousRemoveService
		removePaperboatSSHState = previousRemoveState
	})
	var serviceRemovals, stateRemovals []windowsopenssh.Config
	removePaperboatSSHService = func(_ context.Context, config windowsopenssh.Config) error {
		serviceRemovals = append(serviceRemovals, config)
		if _, err := os.ReadFile(filepath.Join(config.StateRoot, "hostkeys", "ssh_host_ed25519_key.pub")); err != nil {
			return err
		}
		return nil
	}
	removePaperboatSSHState = func(_ context.Context, config windowsopenssh.Config) error {
		stateRemovals = append(stateRemovals, config)
		return nil
	}
	host := Request{SetupMode: "host", OwnerSID: "S-1-5-21-1-2-3-4"}
	hostKeyPath := filepath.Join(windowsopenssh.DefaultConfig(nil).StateRoot, "hostkeys", "ssh_host_ed25519_key.pub")
	if err := os.MkdirAll(filepath.Dir(hostKeyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostKeyPath, []byte("ssh-ed25519 AAAA preserved\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupWindowsSSHAfterRuntimeFailure(context.Background(), host, layout); err != nil {
		t.Fatal(err)
	}
	if len(serviceRemovals) != 1 || len(stateRemovals) != 0 {
		t.Fatalf("host cleanup removed service=%d state=%d", len(serviceRemovals), len(stateRemovals))
	}
	client := Request{SetupMode: "client", OwnerSID: host.OwnerSID}
	if err := cleanupWindowsSSHAfterRuntimeFailure(context.Background(), client, layout); err != nil {
		t.Fatal(err)
	}
	if len(serviceRemovals) != 1 || len(stateRemovals) != 1 {
		t.Fatalf("client cleanup removed service=%d state=%d", len(serviceRemovals), len(stateRemovals))
	}
	if contents, err := os.ReadFile(hostKeyPath); err != nil || string(contents) != "ssh-ed25519 AAAA preserved\n" {
		t.Fatalf("host key after rollback=%q err=%v", contents, err)
	}
}

func TestWindowsRepairRequestCarriesPersistedReadinessEndpoint(t *testing.T) {
	request := windowsRepairRequest(WindowsRuntimeConfig{
		SetupMode: "host", OwnerSID: "S-1-5-21-1-2-3-4",
		StateRoot:     `C:\Users\Pujan\AppData\Local\Paperboat\runtime`,
		ListenAddress: "127.0.0.1:8080",
	})
	if request.SetupMode != "host" || request.OwnerSID != "S-1-5-21-1-2-3-4" || request.StateRoot == "" || request.HelperListenAddress != "127.0.0.1:8080" {
		t.Fatalf("repair request=%+v", request)
	}
}

func TestRunWindowsInstallPhaseReturnsNamedDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	finished := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWindowsInstallPhase(ctx, "stage verified Paperboat runtime", func() error {
			close(started)
			<-finished
			return nil
		})
	}()
	<-started
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) || err == nil || err.Error() != "stage verified Paperboat runtime: context canceled" {
		t.Fatalf("phase error = %v", err)
	}
	close(finished)
}

func TestPrepareWindowsLocalDaemonStateRepairsSiblingStateTree(t *testing.T) {
	if !isAdministrator() {
		t.Skip("requires an elevated Windows token")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	ownerSID := user.User.Sid.String()
	base := filepath.Join(t.TempDir(), "Paperboat")
	runtimeRoot := filepath.Join(base, "runtime")
	stateRoot := filepath.Join(base, "state")
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	staleLock := filepath.Join(stateRoot, "daemon.lock")
	if err := os.WriteFile(staleLock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	staleSID := "S-1-5-5-999-999"
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	rootHandle, err := openWindowsLocalDaemonStateRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsHandleOwnedDACL(rootHandle, administrators, windowssecurity.OwnerFullControlDirectoryDACL(staleSID)); err != nil {
		windows.CloseHandle(rootHandle)
		t.Fatalf("seed stale state-root owner and DACL: %v", err)
	}
	if err := windows.CloseHandle(rootHandle); err != nil {
		t.Fatal(err)
	}
	lockHandle, _, err := openWindowsRuntimeObject(staleLock, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsHandleOwnedDACL(lockHandle, administrators, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+staleSID+")"); err != nil {
		windows.CloseHandle(lockHandle)
		t.Fatalf("seed stale lock owner and DACL: %v", err)
	}
	if err := windows.CloseHandle(lockHandle); err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.OwnerMatchesSID(stateRoot, administrators) || !windowssecurity.OwnerMatchesSID(staleLock, administrators) {
		t.Fatal("fixture did not reproduce the Administrators-owned stale state")
	}
	if err := PrepareWindowsLocalDaemonState(runtimeRoot, ownerSID); err != nil {
		t.Fatalf("prepare LocalDaemon state: %v", err)
	}
	if !windowssecurity.OwnerMatchesSID(stateRoot, user.User.Sid) || !windowssecurity.ProtectedDACLMatches(stateRoot, windowsLocalDaemonStateRootDACL(ownerSID)) {
		t.Fatal("LocalDaemon state root was not rebound to the permanent enrolled SID")
	}
	if !windowssecurity.OwnerMatchesSID(staleLock, user.User.Sid) || !windowssecurity.ProtectedDACLMatches(staleLock, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+ownerSID+")") {
		t.Fatal("existing LocalDaemon state was not rebound to the permanent enrolled SID")
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "daemon.lock.owner.json.new"), []byte("owner"), 0o600); err != nil {
		t.Fatalf("write state after repair: %v", err)
	}
}
