package hostinstall

import (
	"errors"
	"regexp"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

var standaloneVersionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)

type windowsRuntimeServiceDefinition struct {
	kind, executable string
	arguments        []string
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
