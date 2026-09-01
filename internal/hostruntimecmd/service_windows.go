//go:build windows

package hostruntimecmd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
)

// runServiceCommand is the sole privileged command bridge used by the MSI,
// elevated setup engine, and repair flow. Every operation is idempotent and
// decodes the same bounded installation request before changing SCM state.
func runServiceCommand(ctx context.Context, args []string, stdin io.Reader, _, _ io.Writer) error {
	if len(args) > 0 && args[0] == elevation.BridgeCommand {
		return runServiceBridge(ctx, args[1:])
	}
	if len(args) != 1 {
		return errors.New("service requires install, commit, uninstall, uninstall-persisted, purge, repair, or stop")
	}
	switch args[0] {
	case "uninstall-persisted":
		if !elevation.IsCurrentProcessElevated() {
			return runElevatedServiceOperation(ctx, elevation.ActionUninstallPersist)
		}
		return uninstallPersistedWindowsRuntime(ctx)
	case "purge":
		if !elevation.IsCurrentProcessElevated() {
			return runElevatedServiceOperation(ctx, elevation.ActionPurge)
		}
		return hostinstall.Purge(ctx)
	case "repair":
		if !elevation.IsCurrentProcessElevated() {
			return runElevatedServiceOperation(ctx, elevation.ActionRepair)
		}
		return repairWindowsInstallation(ctx)
	case "stop":
		if !elevation.IsCurrentProcessElevated() {
			return runElevatedServiceOperation(ctx, elevation.ActionStop)
		}
		return hostinstall.Stop(ctx)
	case "install", "commit", "uninstall":
		request, err := hostinstall.Decode(stdin)
		if err != nil {
			return err
		}
		if !elevation.IsCurrentProcessElevated() {
			action := map[string]string{"install": elevation.ActionInstall, "commit": elevation.ActionCommit, "uninstall": elevation.ActionUninstall}[args[0]]
			return runElevatedServiceOperation(ctx, action, request)
		}
		switch args[0] {
		case "install":
			return hostinstall.Install(ctx, request)
		case "commit":
			return hostinstall.Commit(request)
		default:
			return uninstallWindowsRuntime(ctx, request)
		}
	default:
		return errors.New("service requires install, commit, uninstall, uninstall-persisted, purge, repair, or stop")
	}
}

func runElevatedServiceOperation(ctx context.Context, action string, payload ...any) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	var value any
	if len(payload) != 0 {
		value = payload[0]
	}
	return elevation.RunRuntimeService(ctx, executable, action, value)
}

func runServiceBridge(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("__runtime-service bridge", flag.ContinueOnError)
	requestPath := flags.String("request-file", "", "protected request file")
	resultPath := flags.String("result-file", "", "protected result file")
	cancelPath := flags.String("cancel-file", "", "protected cancellation marker")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *requestPath == "" || *resultPath == "" || *cancelPath == "" {
		return errors.New("service bridge requires request-file, result-file, and cancel-file")
	}
	return elevation.Execute(ctx, *requestPath, *resultPath, *cancelPath, dispatchElevatedOperation)
}

func dispatchElevatedOperation(ctx context.Context, request elevation.Request) error {
	switch request.Operation {
	case elevation.OperationRuntimeService:
		switch request.Action {
		case elevation.ActionUninstallPersist:
			return uninstallPersistedWindowsRuntime(ctx)
		case elevation.ActionPurge:
			return hostinstall.Purge(ctx)
		case elevation.ActionRepair:
			return repairWindowsInstallation(ctx)
		case elevation.ActionStop:
			return hostinstall.Stop(ctx)
		case elevation.ActionInstall, elevation.ActionInstallCommit, elevation.ActionCommit, elevation.ActionUninstall:
			installRequest, err := hostinstall.Decode(bytes.NewReader(request.Payload))
			if err != nil {
				return err
			}
			switch request.Action {
			case elevation.ActionInstall:
				return hostinstall.Install(ctx, installRequest)
			case elevation.ActionCommit:
				return hostinstall.Commit(installRequest)
			case elevation.ActionUninstall:
				return uninstallWindowsRuntime(ctx, installRequest)
			case elevation.ActionInstallCommit:
				if err := hostinstall.Install(ctx, installRequest); err != nil {
					return err
				}
				if err := hostinstall.Commit(installRequest); err != nil {
					return errors.Join(err, hostinstall.Uninstall(ctx, installRequest))
				}
				return nil
			}
		}
	case elevation.OperationOpenSSH:
		config := windowsopenssh.DefaultConfig(nil)
		config.OwnerSID = request.OwnerSID
		switch request.Action {
		case elevation.ActionOpenSSHSetup:
			_, err := windowsopenssh.Setup(ctx, config)
			return err
		case elevation.ActionOpenSSHRepair:
			_, err := windowsopenssh.Repair(ctx, config)
			return err
		case elevation.ActionOpenSSHRemove:
			return windowsopenssh.RemovePaperboatState(ctx, config)
		}
	}
	return errors.New("unsupported elevated Windows operation")
}

func repairWindowsInstallation(ctx context.Context) error {
	err := hostinstall.Repair(ctx)
	if errors.Is(err, hostinstall.ErrNotInstalled) {
		return nil
	}
	// hostinstall.Repair owns the complete role-scoped service contract. In
	// particular, Client repair removes PaperboatSshd while Host repair restores
	// it. A second unconditional OpenSSH repair here used to recreate the SSH
	// service on Client installations and contradicted that persisted role.
	return err
}

func uninstallPersistedWindowsRuntime(ctx context.Context) error {
	return hostinstall.UninstallPersisted(ctx)
}

func uninstallWindowsRuntime(ctx context.Context, request hostinstall.Request) error {
	return hostinstall.Uninstall(ctx, request)
}
