package service

import (
	"path/filepath"
	"strconv"
	"strings"
)

// ComponentConfig identifies the enrolled user that owns live workloads. The
// install root and all binaries come from Layout, so callers cannot redirect a
// privileged service to a user-controlled executable.
type ComponentConfig struct {
	Layout            Layout
	User              string
	Group             string
	UID               int
	GID               int
	HostdTokenFile    string
	ReleaseRepository string
	MachineID         string
	HealthURL         string
	Environment       map[string]string
	Controller        Controller
}

// ComponentController returns the one service-manager controller permitted for
// a split component. Keeping the unit and launchd label here prevents callers
// from accidentally registering hostd or the updater under a legacy runtime
// service name.
func ComponentController(platform, kind string, enrolledUID int, runner Runner) (Controller, error) {
	if runner == nil || enrolledUID < 0 {
		return nil, ErrInvalidDefinition
	}
	switch platform {
	case "linux":
		switch kind {
		case HostdKind:
			return SystemdController{Runner: runner, Unit: "paperboat-hostd.service"}, nil
		case UpdaterKind:
			return SystemdController{Runner: runner, Unit: "paperboat-updated.service"}, nil
		}
	case "darwin":
		switch kind {
		case HostdKind:
			return LaunchdController{Runner: runner, UID: enrolledUID, Label: HostdLabel}, nil
		case UpdaterKind:
			return LaunchdController{Runner: runner, UID: enrolledUID, Label: UpdaterLabel}, nil
		}
	case "windows":
		switch kind {
		case HostdKind, UpdaterKind:
			return WindowsController{}, nil
		}
	default:
		return nil, ErrUnsupportedPlatform
	}
	return nil, ErrInvalidDefinition
}

// NewHostdInstaller defines the durable, unprivileged host supervisor. It is
// intentionally a system service on Linux and a LaunchDaemon that drops to the
// enrolled account on macOS: it must outlive individual terminal clients, but
// must never run live user workloads as root.
func NewHostdInstaller(config ComponentConfig) (*Installer, error) {
	if err := config.Layout.Validate(); err != nil || config.User == "root" || config.UID <= 0 || !filepath.IsAbs(config.HostdTokenFile) {
		return nil, ErrInvalidDefinition
	}
	environment := copyEnvironment(config.Environment)
	environment["PAPERBOAT_HOSTD_SOCKET"] = config.Layout.HostdSocket
	environment["PAPERBOAT_RUNTIME_CURRENT"] = config.Layout.RuntimeCurrent
	environment["PAPERBOAT_RUNTIME_ROLLBACK"] = config.Layout.RuntimeRollback
	environment["PAPERBOAT_HOSTD_TOKEN_FILE"] = config.HostdTokenFile
	return New(Config{
		Platform: config.Layout.Platform, Kind: HostdKind, ConfigRoot: "/", Executable: config.Layout.HostdBinary,
		User: config.User, Group: config.Group, Arguments: []string{"serve"}, Environment: environment,
		UpgradeMode: UpgradeReload, Controller: config.Controller,
	})
}

// NewUpdaterInstaller defines the small privileged service that is allowed to
// stage and activate signed artifacts. It never receives a shell command or
// arbitrary path from a caller.
func NewUpdaterInstaller(config ComponentConfig) (*Installer, error) {
	if err := config.Layout.Validate(); err != nil || config.UID <= 0 || config.GID < 0 || !filepath.IsAbs(config.HostdTokenFile) || strings.TrimSpace(config.ReleaseRepository) == "" || strings.TrimSpace(config.MachineID) == "" || strings.TrimSpace(config.HealthURL) == "" {
		return nil, ErrInvalidDefinition
	}
	group := "root"
	if config.Layout.Platform == "darwin" {
		group = "wheel"
	}
	environment := copyEnvironment(config.Environment)
	environment["PAPERBOAT_UPDATE_STATE_ROOT"] = config.Layout.UpdateStateRoot
	environment["PAPERBOAT_RELEASE_ROOT"] = config.Layout.ReleasesRoot
	environment["PAPERBOAT_HOSTD_BINARY"] = config.Layout.HostdBinary
	environment["PAPERBOAT_UPDATER_BINARY"] = config.Layout.UpdaterBinary
	environment["PAPERBOAT_LAUNCHER_BINARY"] = config.Layout.Launcher
	environment["PAPERBOAT_RUNTIME_CURRENT"] = config.Layout.RuntimeCurrent
	environment["PAPERBOAT_RUNTIME_ROLLBACK"] = config.Layout.RuntimeRollback
	environment["PAPERBOAT_RUNTIME_STAGED"] = config.Layout.RuntimeStaged
	environment["PAPERBOAT_CLI_CURRENT"] = config.Layout.CLICurrent
	environment["PAPERBOAT_CLI_ROLLBACK"] = config.Layout.CLIRollback
	environment["PAPERBOAT_HOSTD_SOCKET"] = config.Layout.HostdSocket
	environment["PAPERBOAT_HOSTD_TOKEN_FILE"] = config.HostdTokenFile
	environment["PAPERBOAT_RELEASE_REPOSITORY"] = config.ReleaseRepository
	environment["PAPERBOAT_MACHINE_ID"] = config.MachineID
	environment["PAPERBOAT_UPDATE_HEALTH_URL"] = config.HealthURL
	environment["PAPERBOAT_ENROLLED_UID"] = strconv.Itoa(config.UID)
	environment["PAPERBOAT_ENROLLED_GID"] = strconv.Itoa(config.GID)
	environment["PAPERBOAT_UPDATED_SOCKET"] = updaterControlSocket(config.Layout.Platform)
	return New(Config{
		Platform: config.Layout.Platform, Kind: UpdaterKind, ConfigRoot: "/", Executable: config.Layout.UpdaterBinary,
		User: "root", Group: group, Arguments: []string{"serve"}, Environment: environment,
		UpgradeMode: UpgradeReload, Controller: config.Controller,
	})
}

func updaterControlSocket(platform string) string {
	if platform == "darwin" {
		return "/var/run/paperboat-updated/control.sock"
	}
	return "/run/paperboat-updated/control.sock"
}

func copyEnvironment(values map[string]string) map[string]string {
	result := make(map[string]string, len(values)+3)
	for key, value := range values {
		if strings.TrimSpace(key) != "" {
			result[key] = value
		}
	}
	return result
}
