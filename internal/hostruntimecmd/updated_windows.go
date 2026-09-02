//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

// runUpdated is the SCM entry point. It rejects arguments so the service can
// never turn the update boundary into a general command runner.
func runUpdated(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) error {
	if len(args) != 0 {
		return errors.New("updated does not accept arguments")
	}
	workerConfig, err := windowsUpdatedConfig()
	if err != nil {
		recordWindowsServiceLaunchFailure("PaperboatUpdated", err)
		return err
	}
	err = service.RunWindowsSystemServiceWithReady("PaperboatUpdated", func(serviceCtx context.Context, ready func() error) error {
		return updated.RunWindowsWithReady(serviceCtx, workerConfig, ready)
	})
	if err != nil {
		recordWindowsServiceLaunchFailure("PaperboatUpdated", err)
		if stderr != nil {
			_, _ = io.WriteString(stderr, "PaperboatUpdated startup failed: "+err.Error()+"\n")
		}
	}
	return err
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
	result := windowsUpdatedConfigFor(config, layout, buildinfo.Version)
	token, err := readWindowsHostdTokenForSID(config.TokenFile, config.OwnerSID)
	if err != nil {
		return updated.WindowsConfig{}, err
	}
	client, err := hostdproto.NewClient(layout.HostdSocket, token, 31*time.Minute)
	clear(token)
	if err != nil {
		return updated.WindowsConfig{}, err
	}
	result.ActivationGate, err = workerupdate.NewDeploymentActivationGate(workerupdate.DeploymentActivationGateConfig{Provider: workerupdate.HostdDeploymentProvider{Client: client}})
	if err != nil {
		return updated.WindowsConfig{}, err
	}
	return result, nil
}

func windowsUpdatedConfigFor(config hostinstall.WindowsRuntimeConfig, layout service.Layout, runningVersion string) updated.WindowsConfig {
	// The running signed executable is the active updater during activation.
	// runtime-install.json deliberately remains on the previous version until
	// health verification commits the transaction, so using its version here
	// makes every candidate updater report the old version and forces rollback.
	tokenFile := config.TokenFile
	return updated.WindowsConfig{StateRoot: layout.UpdateStateRoot, RuntimeStateRoot: config.StateRoot, Binary: layout.Binary, BinaryRollback: layout.BinaryRollback, BinaryStaged: layout.BinaryStaged, OwnerSID: config.OwnerSID, MachineID: config.MachineID, RepositoryURL: config.Artifact.RepositoryURL, TokenFile: tokenFile, InstallState: filepath.Join(hostinstall.WindowsProgramDataRoot(), "runtime-install.json"), ControlSocket: `\\.\pipe\PaperboatUpdatedControl`, HostdSocket: layout.HostdSocket, HealthURL: "http://" + config.ListenAddress + "/healthz", ActiveVersion: runningVersion, Architecture: config.Artifact.Architecture, AutomaticActivation: true, SetupMode: config.SetupMode,
		CandidateStarter: func(ctx context.Context, request workerupdate.StartRequest) (workerupdate.Worker, error) {
			return startWindowsRuntimeWorkerForRelease(ctx, request.Executable, request.HostdEndpoint, tokenFile, request.WorkerID, request.Release.Version, request.Release.HostdAPIMin, request.Release.HostdAPIMax)
		},
	}
}
