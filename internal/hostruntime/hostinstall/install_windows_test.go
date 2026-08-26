//go:build windows

package hostinstall

import (
	"context"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
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
