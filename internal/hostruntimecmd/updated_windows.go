//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
)

// runUpdated is the SCM entry point. It rejects arguments so the service can
// never turn the update boundary into a general command runner.
func runUpdated(ctx context.Context, args []string, _ io.Writer, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("updated does not accept arguments")
	}
	config, err := windowsRuntimeInstallConfig()
	if err != nil {
		return err
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	workerConfig := updated.WindowsConfig{StateRoot: layout.UpdateStateRoot, RuntimeCurrent: layout.RuntimeCurrent, RuntimeRollback: layout.RuntimeRollback, RuntimeStaged: layout.RuntimeStaged, CLICurrent: layout.CLICurrent, CLIRollback: layout.CLIRollback, OwnerSID: config.OwnerSID, MachineID: config.MachineID, RepositoryURL: config.ControlURL, TokenFile: config.TokenFile, InstallState: filepath.Join(hostinstall.WindowsProgramDataRoot(), "runtime-install.json"), Architecture: config.Artifact.Architecture}
	return service.RunWindowsSystemService("PaperboatUpdated", func(serviceCtx context.Context) error {
		return updated.RunWindows(serviceCtx, workerConfig)
	})
}
