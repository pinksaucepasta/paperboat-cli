//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
)

func runLocalDaemonService(_ context.Context, args []string, _ io.Writer, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("local daemon service does not accept arguments")
	}
	install, err := windowsRuntimeInstallConfig()
	if err != nil {
		return err
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	stateDirectory := filepath.Join(filepath.Dir(install.StateRoot), "state")
	if err := localdaemon.PrepareWindowsOwnerState(stateDirectory, install.OwnerSID); err != nil {
		recordWindowsServiceLaunchFailure("PaperboatLocalDaemon", err)
		return err
	}
	return service.RunWindowsService(service.ServiceEntryConfig{
		Name:        "PaperboatLocalDaemon",
		Executable:  layout.Binary,
		Arguments:   []string{"__local-daemon", "--server", install.ControlURL},
		EnrolledSID: install.OwnerSID,
		LaunchFailure: func(err error) {
			recordWindowsServiceLaunchFailure("PaperboatLocalDaemon", err)
		},
	})
}
