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
	Layout               Layout
	User                 string
	Group                string
	UID                  int
	GID                  int
	HostdTokenFile       string
	ReleaseRepository    string
	MachineID            string
	HealthURL            string
	Environment          map[string]string
	EncryptedCredentials map[string]string
	Controller           Controller
}

// ComponentController returns the one service-manager controller permitted for
// a service role. Both roles invoke the same installed pb executable.
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

// NewHostdInstaller defines the durable host supervisor. It is intentionally a
// system service on Linux and a LaunchDaemon that drops to the enrolled account
// on macOS. Explicit root enrollments remain root for compatibility; an
// ordinary enrolled account can never be widened to root here.
func NewHostdInstaller(config ComponentConfig) (*Installer, error) {
	return newHostdInstaller(config, false)
}

// NewHostdInstallerPending is used by privileged installation recovery before
// the first binary slot exists. It permits only that fixed path to be absent;
// all identity, declaration, and environment validation remains unchanged.
func NewHostdInstallerPending(config ComponentConfig) (*Installer, error) {
	return newHostdInstaller(config, true)
}

func newHostdInstaller(config ComponentConfig, allowMissingExecutable bool) (*Installer, error) {
	if err := config.Layout.Validate(); err != nil || !validEnrolledIdentity(config.User, config.Group, config.UID, config.GID) || !filepath.IsAbs(config.HostdTokenFile) {
		return nil, ErrInvalidDefinition
	}
	environment := copyEnvironment(config.Environment)
	binary := config.Layout.Binary
	environment["PAPERBOAT_BINARY"] = binary
	// hostd starts the fenced runtime worker from the active slot. Keep this
	// explicit in the service definition so the supervisor never falls back to
	// an ambient or caller-controlled executable path.
	environment["PAPERBOAT_RUNTIME_CURRENT"] = binary
	environment["PAPERBOAT_BINARY_ROLLBACK"] = config.Layout.BinaryRollback
	environment["PAPERBOAT_BINARY_STAGED"] = config.Layout.BinaryStaged
	environment["PAPERBOAT_HOSTD_SOCKET"] = config.Layout.HostdSocket
	environment["PAPERBOAT_HOSTD_TOKEN_FILE"] = config.HostdTokenFile
	serviceConfig := Config{
		Platform: config.Layout.Platform, Kind: HostdKind, ConfigRoot: "/", Executable: binary,
		User: config.User, Group: config.Group, Arguments: []string{"__runtime-hostd"}, Environment: environment,
		EncryptedCredentials: config.EncryptedCredentials,
		UpgradeMode:          UpgradeReload, Controller: config.Controller,
	}
	if allowMissingExecutable {
		return newInstaller(serviceConfig, true)
	}
	return New(serviceConfig)
}

// NewUpdaterInstaller defines the small privileged service that is allowed to
// stage and activate signed artifacts. It never receives a shell command or
// arbitrary path from a caller.
func NewUpdaterInstaller(config ComponentConfig) (*Installer, error) {
	return newUpdaterInstaller(config, false)
}

// NewUpdaterInstallerPending is the pre-stage companion to
// NewHostdInstallerPending. Ordinary updater construction remains strict.
func NewUpdaterInstallerPending(config ComponentConfig) (*Installer, error) {
	return newUpdaterInstaller(config, true)
}

func newUpdaterInstaller(config ComponentConfig, allowMissingExecutable bool) (*Installer, error) {
	if err := config.Layout.Validate(); err != nil || !validEnrolledIdentity(config.User, config.Group, config.UID, config.GID) || !filepath.IsAbs(config.HostdTokenFile) || strings.TrimSpace(config.ReleaseRepository) == "" || strings.TrimSpace(config.MachineID) == "" || strings.TrimSpace(config.HealthURL) == "" {
		return nil, ErrInvalidDefinition
	}
	group := "root"
	if config.Layout.Platform == "darwin" {
		group = "wheel"
	}
	environment := copyEnvironment(config.Environment)
	binary := config.Layout.Binary
	environment["PAPERBOAT_BINARY"] = binary
	environment["PAPERBOAT_BINARY_ROLLBACK"] = config.Layout.BinaryRollback
	environment["PAPERBOAT_BINARY_STAGED"] = config.Layout.BinaryStaged
	environment["PAPERBOAT_UPDATE_STATE_ROOT"] = config.Layout.UpdateStateRoot
	environment["PAPERBOAT_RELEASE_ROOT"] = config.Layout.ReleasesRoot
	environment["PAPERBOAT_HOSTD_SOCKET"] = config.Layout.HostdSocket
	environment["PAPERBOAT_HOSTD_TOKEN_FILE"] = config.HostdTokenFile
	environment["PAPERBOAT_RELEASE_REPOSITORY"] = config.ReleaseRepository
	environment["PAPERBOAT_MACHINE_ID"] = config.MachineID
	environment["PAPERBOAT_UPDATE_HEALTH_URL"] = config.HealthURL
	environment["PAPERBOAT_ENROLLED_UID"] = strconv.Itoa(config.UID)
	environment["PAPERBOAT_ENROLLED_GID"] = strconv.Itoa(config.GID)
	environment["PAPERBOAT_UPDATED_SOCKET"] = updaterControlSocket(config.Layout.Platform)
	serviceConfig := Config{
		Platform: config.Layout.Platform, Kind: UpdaterKind, ConfigRoot: "/", Executable: binary,
		User: "root", Group: group, Arguments: []string{"__runtime-updated"}, Environment: environment,
		UpgradeMode: UpgradeReload, Controller: config.Controller,
	}
	if allowMissingExecutable {
		return newInstaller(serviceConfig, true)
	}
	return New(serviceConfig)
}

func validEnrolledIdentity(user, group string, uid, gid int) bool {
	if uid == 0 || gid == 0 {
		return user == "root" && (group == "root" || group == "wheel") && uid == 0 && gid == 0
	}
	return user != "" && user != "root" && group != "" && group != "root" && group != "wheel" && uid > 0 && gid > 0
}

func updaterControlSocket(platform string) string {
	if platform == "windows" {
		return `\\.\pipe\PaperboatUpdated`
	}
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
