package hostinstall

import (
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
		{kind: service.UpdaterKind, executable: layout.Binary, arguments: []string{"__runtime-updated"}},
	}
}

func executeWindowsServiceInstallPlan(setupMode string, installSSH, installRuntime, cleanupSSH func() error) error {
	switch setupMode {
	case "host":
		// PaperboatHostd must be registered before OpenSSH host-key ACLs are
		// applied. Windows resolves NT SERVICE\PaperboatHostd only after SCM has
		// created the service with its unrestricted service SID.
		if err := installRuntime(); err != nil {
			return err
		}
		return installSSH()
	case "client":
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
