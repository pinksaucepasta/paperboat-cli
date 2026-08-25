//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
	"os"
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
	workerConfig, err := windowsUpdatedConfig()
	if err != nil {
		return err
	}
	return service.RunWindowsSystemService("PaperboatUpdated", func(serviceCtx context.Context) error {
		return updated.RunWindows(serviceCtx, workerConfig)
	})
}

func runActivator(_ context.Context, args []string, _ io.Writer, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("activator does not accept arguments")
	}
	config, err := windowsUpdatedConfig()
	if err != nil {
		return err
	}
	return service.RunWindowsSystemService("PaperboatUpdateActivator", func(serviceCtx context.Context) error {
		return updated.RunWindowsActivator(serviceCtx, config)
	})
}

func windowsUpdatedConfig() (updated.WindowsConfig, error) {
	config, err := windowsRuntimeInstallConfig()
	if err != nil {
		return updated.WindowsConfig{}, err
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return updated.WindowsConfig{}, err
	}
	activeVersion := config.Artifact.Version
	if executable, executableErr := os.Executable(); executableErr == nil {
		if immutableVersion, versionErr := layout.WindowsVersionForExecutable(executable); versionErr == nil {
			activeVersion = immutableVersion
		}
	}
	return updated.WindowsConfig{StateRoot: layout.UpdateStateRoot, RuntimeCurrent: layout.RuntimeCurrent, RuntimeRollback: layout.RuntimeRollback, RuntimeStaged: layout.RuntimeStaged, CLICurrent: layout.CLICurrent, CLIRollback: layout.CLIRollback, OwnerSID: config.OwnerSID, MachineID: config.MachineID, RepositoryURL: config.Artifact.RepositoryURL, TokenFile: config.TokenFile, InstallState: filepath.Join(hostinstall.WindowsProgramDataRoot(), "runtime-install.json"), ControlSocket: `\\.\pipe\PaperboatUpdatedControl`, HostdSocket: layout.HostdSocket, HealthURL: "http://" + config.ListenAddress + "/healthz", ActiveVersion: activeVersion, Architecture: config.Artifact.Architecture, AutomaticActivation: true, SetupMode: config.SetupMode}, nil
}
