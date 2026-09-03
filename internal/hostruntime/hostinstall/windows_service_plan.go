package hostinstall

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

var standaloneVersionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)

type windowsRuntimeServiceDefinition struct {
	kind, executable string
	arguments        []string
}

// windowsServicePlanStep is the small lifecycle surface needed by the
// ordered Windows role plan. Keeping the sequencing/rollback policy separate
// from the native service implementation makes it deterministic to test and
// prevents a later role failure from leaving a service created by this exact
// attempt behind.
type windowsServicePlanStep interface {
	DefinitionPath() string
	Install(context.Context) error
	Start(context.Context) error
	Uninstall(context.Context) error
}

const windowsServicePlanRollbackTimeout = 45 * time.Second

func windowsServiceDeclarationPresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// executeWindowsServiceSteps applies one ordered role plan. The
// preexisting callback must report the native service-manager registration
// observed before the declaration is written. This is deliberately separate
// from declaration-file existence: a stale declaration with no SCM service is
// still created by this attempt and must be removed if a later step fails.
// The returned cleanup removes only registrations that did not exist before
// this call. On an install/start error, the same cleanup is run before the
// error is returned. Existing registrations are deliberately never
// uninstalled by a failed replacement.
func executeWindowsServiceSteps(
	ctx context.Context,
	definitions []windowsRuntimeServiceDefinition,
	makeStep func(windowsRuntimeServiceDefinition) (windowsServicePlanStep, error),
	preexisting func(context.Context, string) (bool, error),
	startAfterInstall bool,
) (func() error, error) {
	return executeWindowsServiceStepsWithHook(ctx, definitions, makeStep, preexisting, startAfterInstall, nil)
}

func executeWindowsServiceStepsWithHook(
	ctx context.Context,
	definitions []windowsRuntimeServiceDefinition,
	makeStep func(windowsRuntimeServiceDefinition) (windowsServicePlanStep, error),
	preexisting func(context.Context, string) (bool, error),
	startAfterInstall bool,
	afterStart func(int, windowsRuntimeServiceDefinition) error,
) (func() error, error) {
	if ctx == nil || makeStep == nil {
		return nil, service.ErrInvalidDefinition
	}
	if preexisting == nil {
		preexisting = func(_ context.Context, path string) (bool, error) {
			return windowsServiceDeclarationPresent(path)
		}
	}
	created := make([]windowsServicePlanStep, 0, len(definitions))
	rolledBack := false
	rollback := func() error {
		if rolledBack {
			return nil
		}
		rolledBack = true
		rollbackContext, cancel := context.WithTimeout(context.Background(), windowsServicePlanRollbackTimeout)
		defer cancel()
		var result error
		for index := len(created) - 1; index >= 0; index-- {
			if err := created[index].Uninstall(rollbackContext); err != nil {
				result = errors.Join(result, err)
			}
		}
		return result
	}
	for index, definition := range definitions {
		step, err := makeStep(definition)
		if err != nil {
			return nil, errors.Join(err, rollback())
		}
		if step == nil || step.DefinitionPath() == "" {
			return nil, errors.Join(service.ErrInvalidDefinition, rollback())
		}
		present, err := preexisting(ctx, step.DefinitionPath())
		if err != nil {
			return nil, errors.Join(err, rollback())
		}
		// Record ownership before Install. Native Enable can create an SCM
		// entry and then return an error while applying recovery/configuration;
		// waiting until Install succeeds would strand that partial registration.
		if !present {
			created = append(created, step)
		}
		if err := step.Install(ctx); err != nil {
			return nil, errors.Join(err, rollback())
		}
		if startAfterInstall {
			if err := step.Start(ctx); err != nil {
				return nil, errors.Join(err, rollback())
			}
			if afterStart != nil {
				if err := afterStart(index, definition); err != nil {
					return nil, errors.Join(err, rollback())
				}
			}
		}
	}
	return rollback, nil
}

func windowsRuntimeServiceDefinitions(layout service.Layout) []windowsRuntimeServiceDefinition {
	return []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind, executable: layout.Binary, arguments: []string{"__runtime-hostd"}},
		{kind: service.DaemonKind, executable: layout.Binary, arguments: []string{"__runtime-local-daemon"}},
		{kind: service.UpdaterKind, executable: layout.Binary, arguments: []string{"__runtime-updated"}},
	}
}

// executeWindowsServiceInstallPlan is the ordering boundary for a Windows
// role transition. Hostd performs a managed-SSH loopback reconciliation during
// startup, so host-mode recovery must not restore/start Hostd until Paperboat's
// dedicated OpenSSH service is installed and healthy. Keeping recovery in this
// plan also covers a crash journal whose rollback would otherwise start Hostd
// before the SSH callback runs.
func executeWindowsServiceInstallPlan(setupMode string, installSSH, recoverRuntime, installRuntime, cleanupSSH func() error) error {
	if installSSH == nil || recoverRuntime == nil || installRuntime == nil || cleanupSSH == nil {
		return ErrInvalidRequest
	}
	switch setupMode {
	case "host":
		// Hostd validates the managed SSH loopback endpoint as it starts. The
		// service SID used by the host-key ACL is deterministic, so OpenSSH can
		// be installed before Hostd is first registered.
		if err := installSSH(); err != nil {
			return err
		}
		if err := recoverRuntime(); err != nil {
			return errors.Join(err, cleanupSSH())
		}
		if err := installRuntime(); err != nil {
			return errors.Join(err, cleanupSSH())
		}
		return nil
	case "client":
		if err := recoverRuntime(); err != nil {
			return err
		}
		if err := installRuntime(); err != nil {
			return err
		}
		return cleanupSSH()
	default:
		return ErrInvalidRequest
	}
}

// executeWindowsServiceRepairPlan is the bounded repair ordering boundary.
// Host-mode repair keeps the managed-SSH service installed from the first
// phase through lifecycle repair. Removing it between recovery and repair
// creates a Windows SCM deletion race and lets Hostd start without its
// required loopback authority. Cleanup is reserved for a failed phase after
// the SSH prerequisite has been established.
func executeWindowsServiceRepairPlan(setupMode string, installSSH, recoverRuntime, repairRuntime, repairServices, cleanupSSH func() error) error {
	if installSSH == nil || recoverRuntime == nil || repairRuntime == nil || repairServices == nil || cleanupSSH == nil {
		return ErrInvalidRequest
	}
	switch setupMode {
	case "host":
		if err := installSSH(); err != nil {
			return err
		}
		if err := recoverRuntime(); err != nil {
			return errors.Join(err, cleanupSSH())
		}
		if err := repairRuntime(); err != nil {
			return errors.Join(err, cleanupSSH())
		}
		if err := repairServices(); err != nil {
			return errors.Join(err, cleanupSSH())
		}
		return nil
	case "client":
		if err := recoverRuntime(); err != nil {
			return err
		}
		if err := repairRuntime(); err != nil {
			return err
		}
		if err := repairServices(); err != nil {
			return err
		}
		return cleanupSSH()
	default:
		return ErrInvalidRequest
	}
}

func windowsActivatorExecutableOwned(layout service.Layout, executable string) bool {
	prefix := strings.TrimRight(layout.ReleasesRoot, `\`) + `\versions\`
	if len(executable) <= len(prefix) || !strings.EqualFold(executable[:len(prefix)], prefix) {
		return false
	}
	parts := strings.Split(executable[len(prefix):], `\`)
	return len(parts) == 2 && standaloneVersionPattern.MatchString(parts[0]) && strings.EqualFold(parts[1], "pb.exe")
}

func windowsActivatorServiceOwned(layout service.Layout, executable string, arguments []string, account string) bool {
	return windowsActivatorExecutableOwned(layout, executable) && len(arguments) == 1 && arguments[0] == "__runtime-activate" && strings.EqualFold(strings.TrimSpace(account), "LocalSystem")
}
