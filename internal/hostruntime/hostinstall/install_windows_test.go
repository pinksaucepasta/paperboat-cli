//go:build windows

package hostinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

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
