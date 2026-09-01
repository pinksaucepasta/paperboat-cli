//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
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

func executeLocalDaemonService(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := runLocalDaemonService(ctx, args, stdout, stderr); err != nil {
		writeError(stderr, err)
		return 1
	}
	return 0
}
