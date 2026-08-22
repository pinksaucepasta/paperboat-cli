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
)

func TestWindowsCLIEntrypointUsesStableLauncherAtPublicPBPath(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	launcher, entrypoint := windowsCLIEntrypointPaths(layout)
	if launcher != `C:\Program Files\Paperboat\bin\pb-launcher.exe` || entrypoint != `C:\Program Files\Paperboat\bin\pb.exe` {
		t.Fatalf("launcher=%q entrypoint=%q", launcher, entrypoint)
	}
}

func TestReplaceWindowsCLIEntrypointReplacesStaleClientBinary(t *testing.T) {
	directory := t.TempDir()
	launcher := filepath.Join(directory, "pb-launcher.exe")
	entrypoint := filepath.Join(directory, "pb.exe")
	if err := os.WriteFile(launcher, []byte("stable launcher bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entrypoint, []byte("stale full CLI bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceWindowsCLIEntrypoint(entrypoint, launcher); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(entrypoint)
	if err != nil || string(got) != "stable launcher bytes" {
		t.Fatalf("entrypoint=%q err=%v", got, err)
	}
}

func TestWindowsSSHServiceSetFollowsHostClientTransition(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	previousRemoveService, previousRemoveState, previousInstall := removePaperboatSSHService, removePaperboatSSHState, installPaperboatSSH
	t.Cleanup(func() {
		removePaperboatSSHService = previousRemoveService
		removePaperboatSSHState = previousRemoveState
		installPaperboatSSH = previousInstall
	})
	var removedService, removedState []windowsopenssh.Config
	var installs []struct{ executable, sshd, config string }
	removePaperboatSSHService = func(_ context.Context, config windowsopenssh.Config) error {
		removedService = append(removedService, config)
		return nil
	}
	removePaperboatSSHState = func(_ context.Context, config windowsopenssh.Config) error {
		removedState = append(removedState, config)
		return nil
	}
	installPaperboatSSH = func(_ context.Context, executable, sshd, config string) error {
		installs = append(installs, struct{ executable, sshd, config string }{executable, sshd, config})
		return nil
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
		if config.ServiceExecutable != layout.RuntimeCurrent {
			t.Fatalf("SSH ownership executable: service=%q want=%q", config.ServiceExecutable, layout.RuntimeCurrent)
		}
	}
	if removedState[0].ServiceExecutable != layout.RuntimeCurrent {
		t.Fatalf("SSH state ownership executable=%q want=%q", removedState[0].ServiceExecutable, layout.RuntimeCurrent)
	}
	if installs[0].executable != layout.RuntimeCurrent || installs[0].sshd != `C:\Program Files\OpenSSH\sshd.exe` || installs[0].config != `C:\ProgramData\Paperboat\ssh\sshd_config` {
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
