package service

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/coreos/go-systemd/v22/unit"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"howett.net/plist"
)

const (
	// Legacy labels remain for existing monolithic installations. New automatic
	// update installations use HostdKind and UpdaterKind below.
	Label         = "com.pinksaucepasta.paperboat.runtime-host"
	HostLabel     = "com.pinksaucepasta.paperboat.runtime-privileged"
	ConfigLabel   = "com.pinksaucepasta.paperboat.runtime-config"
	DaemonLabel   = "com.pinksaucepasta.paperboat.local-daemon"
	HostdLabel    = "com.pinksaucepasta.paperboat.hostd"
	UpdaterLabel  = "com.pinksaucepasta.paperboat.updated"
	WorkerKind    = "worker"
	HostKind      = "host"
	ConfigKind    = "config"
	DaemonKind    = "daemon"
	PreviewKind   = "preview"
	HostdKind     = "hostd"
	UpdaterKind   = "updater"
	UpgradeReload = "reload_only"
)

var (
	ErrInvalidDefinition   = errors.New("invalid service definition")
	ErrUnsupportedPlatform = errors.New("unsupported service platform")
)

type Controller interface {
	Apply(context.Context, string, bool) error
	Remove(context.Context, string) error
}
type Config struct {
	Platform    string
	Kind        string
	Instance    string
	ConfigRoot  string
	Executable  string
	User        string
	Group       string
	Arguments   []string
	Environment map[string]string
	// UpgradeMode controls only service-definition activation. The stable hostd
	// service must not be restarted merely because its definition is rewritten:
	// ordinary releases replace a child runtime under hostd ownership instead.
	// The empty value preserves the legacy restart-on-upgrade behavior.
	UpgradeMode string
	Controller  Controller
}
type Installer struct {
	config         Config
	definitionPath string
}

func New(config Config) (*Installer, error) {
	if config.Kind == "" {
		config.Kind = WorkerKind
	}
	if config.Controller == nil || !filepath.IsAbs(config.ConfigRoot) || !filepath.IsAbs(config.Executable) || len(config.Arguments) == 0 || !safeAccount(config.User) || !safeAccount(config.Group) {
		return nil, ErrInvalidDefinition
	}
	if config.Platform == "windows" {
		if err := safeExecutableWindows(config.Executable); err != nil {
			return nil, err
		}
	} else if err := safeExecutable(config.Executable); err != nil {
		return nil, err
	}
	if !safeValues([]string{config.Executable}) {
		return nil, ErrInvalidDefinition
	}
	if !safeValues(config.Arguments) || !safeEnvironment(config.Environment) || config.UpgradeMode != "" && config.UpgradeMode != UpgradeReload {
		return nil, ErrInvalidDefinition
	}
	var path string
	switch config.Platform {
	case "darwin":
		label := Label
		if config.Kind == HostKind {
			label = HostLabel
		} else if config.Kind == HostdKind {
			label = HostdLabel
		} else if config.Kind == UpdaterKind {
			label = UpdaterLabel
		} else if config.Kind == ConfigKind {
			label = ConfigLabel
		} else if config.Kind == DaemonKind {
			label = DaemonLabel
		} else if config.Kind == PreviewKind && safeInstance(config.Instance) {
			label = previewLabel(config.Instance)
		} else if config.Kind != WorkerKind {
			return nil, ErrInvalidDefinition
		}
		directory := "LaunchDaemons"
		if config.Kind == ConfigKind || config.Kind == DaemonKind || config.Kind == PreviewKind {
			directory = "LaunchAgents"
		}
		path = filepath.Join(config.ConfigRoot, "Library", directory, label+".plist")
	case "linux":
		unit := "paperboat-runtime-host.service"
		if config.Kind == HostKind {
			unit = "paperboat-runtime-privileged.service"
		} else if config.Kind == HostdKind {
			unit = "paperboat-hostd.service"
		} else if config.Kind == UpdaterKind {
			unit = "paperboat-updated.service"
		} else if config.Kind == ConfigKind {
			path = filepath.Join(config.ConfigRoot, ".config", "systemd", "user", "paperboat-runtime-config.service")
		} else if config.Kind == DaemonKind {
			path = filepath.Join(config.ConfigRoot, ".config", "systemd", "user", "paperboat-local-daemon.service")
		} else if config.Kind == PreviewKind && safeInstance(config.Instance) {
			path = filepath.Join(config.ConfigRoot, ".config", "systemd", "user", "paperboat-preview-"+config.Instance+".service")
		} else if config.Kind != WorkerKind && config.Kind != HostdKind && config.Kind != UpdaterKind {
			return nil, ErrInvalidDefinition
		}
		if path == "" {
			path = filepath.Join(config.ConfigRoot, "etc", "systemd", "system", unit)
		}
	case "windows":
		if !safeWindowsServiceKind(config.Kind, config.Instance) {
			return nil, ErrInvalidDefinition
		}
		// The SCM owns the executable registration. This file is a durable,
		// root-owned declaration used to recover and audit the exact service
		// arguments without asking the SCM to accept arbitrary input later.
		path = filepath.Join(`C:\ProgramData\Paperboat\services`, windowsServiceName(config.Kind, config.Instance)+`.json`)
	default:
		return nil, ErrUnsupportedPlatform
	}
	return &Installer{config: config, definitionPath: path}, nil
}

func (i *Installer) Install(ctx context.Context) error {
	if err := ensureRoot(i.config.ConfigRoot); err != nil {
		return err
	}
	definition, err := i.render()
	if err != nil {
		return err
	}
	info, statErr := os.Lstat(i.definitionPath)
	upgrading := statErr == nil
	if statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return ErrInvalidDefinition
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	var previous []byte
	if upgrading {
		previous, err = os.ReadFile(i.definitionPath)
		if err != nil {
			return err
		}
	}
	if err := atomicWrite(i.definitionPath, definition, 0o600); err != nil {
		return err
	}
	// A stable hostd cannot be reloaded through launchd without restarting it,
	// and a systemd daemon-reload is unnecessary until the next boot for this
	// deliberately static definition. Keep the process and every workload it
	// owns untouched. Initial installation still starts it below.
	if upgrading && i.config.UpgradeMode == UpgradeReload {
		return nil
	}
	activateUpgrade := upgrading && i.config.UpgradeMode != UpgradeReload
	if err := i.config.Controller.Apply(ctx, i.definitionPath, activateUpgrade); err != nil {
		rollbackErr := i.rollback(ctx, previous, upgrading)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func (i *Installer) rollback(ctx context.Context, previous []byte, upgrading bool) error {
	if !upgrading {
		managerErr := i.config.Controller.Remove(ctx, i.definitionPath)
		removeErr := os.Remove(i.definitionPath)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return errors.Join(managerErr, removeErr, syncDirectory(filepath.Dir(i.definitionPath)))
	}
	if err := atomicWrite(i.definitionPath, previous, 0o600); err != nil {
		return err
	}
	return i.config.Controller.Apply(ctx, i.definitionPath, i.config.UpgradeMode != UpgradeReload)
}
func (i *Installer) Uninstall(ctx context.Context) error {
	if err := i.config.Controller.Remove(ctx, i.definitionPath); err != nil {
		return err
	}
	if err := os.Remove(i.definitionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(i.definitionPath))
}
func (i *Installer) DefinitionPath() string { return i.definitionPath }

func previewLabel(instance string) string {
	return "com.pinksaucepasta.paperboat.runtime-preview." + instance
}

func (i *Installer) render() ([]byte, error) {
	if i.config.Platform == "darwin" {
		return renderLaunchd(i.config)
	}
	if i.config.Platform == "windows" {
		return renderWindowsService(i.config)
	}
	return renderSystemd(i.config)
}

func renderLaunchd(config Config) ([]byte, error) {
	label := Label
	if config.Kind == HostKind {
		label = HostLabel
	} else if config.Kind == HostdKind {
		label = HostdLabel
	} else if config.Kind == UpdaterKind {
		label = UpdaterLabel
	} else if config.Kind == ConfigKind {
		label = ConfigLabel
	} else if config.Kind == DaemonKind {
		label = DaemonLabel
	} else if config.Kind == PreviewKind {
		label = previewLabel(config.Instance)
	}
	var keepAlive any = true
	if config.Kind == PreviewKind {
		keepAlive = struct {
			SuccessfulExit bool `plist:"SuccessfulExit"`
		}{SuccessfulExit: false}
	}
	definition := struct {
		Label                string            `plist:"Label"`
		ProcessType          string            `plist:"ProcessType"`
		UserName             string            `plist:"UserName"`
		GroupName            string            `plist:"GroupName"`
		ProgramArguments     []string          `plist:"ProgramArguments"`
		EnvironmentVariables map[string]string `plist:"EnvironmentVariables"`
		RunAtLoad            bool              `plist:"RunAtLoad"`
		KeepAlive            any               `plist:"KeepAlive"`
		Umask                uint64            `plist:"Umask"`
	}{
		Label: label, ProcessType: "Background", UserName: config.User, GroupName: config.Group,
		ProgramArguments:     append([]string{config.Executable}, config.Arguments...),
		EnvironmentVariables: config.Environment, RunAtLoad: true, KeepAlive: keepAlive, Umask: 0o77,
	}
	return plist.MarshalIndent(definition, plist.XMLFormat, "  ")
}

func renderSystemd(config Config) ([]byte, error) {
	description := "Paperboat host runtime"
	if config.Kind == HostKind {
		description = "Paperboat host service"
	} else if config.Kind == HostdKind {
		description = "Paperboat stable host supervisor"
	} else if config.Kind == UpdaterKind {
		description = "Paperboat signed update service"
	} else if config.Kind == ConfigKind {
		description = "Paperboat config sync"
	} else if config.Kind == DaemonKind {
		description = "Paperboat local daemon"
	} else if config.Kind == PreviewKind {
		description = "Paperboat preview " + config.Instance
	}
	after := "local-fs.target"
	if config.Kind == UpdaterKind {
		after = "local-fs.target network-online.target"
	}
	options := []*unit.UnitOption{
		unit.NewUnitOption("Unit", "Description", description),
		unit.NewUnitOption("Unit", "After", after),
		unit.NewUnitOption("Unit", "StartLimitIntervalSec", "0"),
	}
	if config.Kind == UpdaterKind {
		options = append(options, unit.NewUnitOption("Unit", "Wants", "network-online.target"))
	}
	systemService := config.Kind == WorkerKind || config.Kind == HostKind || config.Kind == HostdKind || config.Kind == UpdaterKind
	notify := systemService
	serviceType := "simple"
	if notify {
		serviceType = "notify"
	}
	options = append(options, unit.NewUnitOption("Service", "Type", serviceType))
	if config.Kind != ConfigKind && config.Kind != DaemonKind && config.Kind != PreviewKind {
		options = append(options,
			unit.NewUnitOption("Service", "User", config.User),
			unit.NewUnitOption("Service", "Group", config.Group),
		)
	}
	var command strings.Builder
	command.WriteString(systemdEscape(config.Executable))
	for _, argument := range config.Arguments {
		command.WriteByte(' ')
		command.WriteString(systemdEscape(argument))
	}
	options = append(options, unit.NewUnitOption("Service", "ExecStart", command.String()))
	for _, key := range sortedKeys(config.Environment) {
		options = append(options, unit.NewUnitOption("Service", "Environment", systemdEscape(key+"="+config.Environment[key])))
	}
	restart := "always"
	if config.Kind == PreviewKind {
		restart = "on-failure"
	}
	options = append(options,
		unit.NewUnitOption("Service", "Restart", restart),
		unit.NewUnitOption("Service", "RestartSec", "5s"),
		unit.NewUnitOption("Service", "TimeoutStopSec", "60s"),
		unit.NewUnitOption("Service", "KillMode", "mixed"),
		unit.NewUnitOption("Service", "UMask", "0077"),
	)
	if notify {
		options = append(options,
			unit.NewUnitOption("Service", "NotifyAccess", "main"),
			unit.NewUnitOption("Service", "WatchdogSec", "30s"),
		)
	}
	if systemService {
		directory := systemDirectoryName(config.Kind)
		options = append(options,
			unit.NewUnitOption("Service", "RuntimeDirectory", directory),
			unit.NewUnitOption("Service", "RuntimeDirectoryMode", "0755"),
			unit.NewUnitOption("Service", "StateDirectory", directory),
			unit.NewUnitOption("Service", "StateDirectoryMode", "0700"),
			unit.NewUnitOption("Service", "CacheDirectory", directory),
			unit.NewUnitOption("Service", "CacheDirectoryMode", "0750"),
		)
	}
	noNewPrivileges := "false"
	if config.Kind == HostKind || config.Kind == HostdKind || config.Kind == UpdaterKind {
		noNewPrivileges = "true"
	}
	options = append(options, unit.NewUnitOption("Service", "NoNewPrivileges", noNewPrivileges))
	// Detached serve workers must access the user-selected source path. A private
	// /tmp namespace hides valid sources such as /tmp/site from the worker.
	if config.Kind != PreviewKind {
		options = append(options, unit.NewUnitOption("Service", "PrivateTmp", "true"))
	}
	wantedBy := "multi-user.target"
	if config.Kind == ConfigKind || config.Kind == DaemonKind || config.Kind == PreviewKind {
		wantedBy = "default.target"
	}
	options = append(options, unit.NewUnitOption("Install", "WantedBy", wantedBy))
	return io.ReadAll(unit.Serialize(options))
}

func systemDirectoryName(kind string) string {
	switch kind {
	case HostdKind:
		return "paperboat-hostd"
	case UpdaterKind:
		return "paperboat-updated"
	default:
		return "paperboat"
	}
}

func systemdEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, `%`, `%%`)
	value = strings.ReplaceAll(value, `$`, `$$`)
	return `"` + value + `"`
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		return err
	}
	info, err = os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		return ErrInvalidDefinition
	}
	return atomicfile.Write(path, data, atomicfile.Options{Mode: mode, OwnerUID: -1, OwnerGID: -1})
}
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func safeExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidDefinition
	}
	return nil
}
func safeValues(values []string) bool {
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}
func safeEnvironment(environment map[string]string) bool {
	for key, value := range environment {
		if !safeEnvironmentKey(key) || !safeValues([]string{value}) {
			return false
		}
	}
	return true
}

func safeEnvironmentKey(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func safeAccount(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if !(char == '_' || char == '-' || index > 0 && index < len(value)-1 && char == '.' && value[index-1] != '.' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
func safeInstance(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || index > 0 && char == '-') {
			return false
		}
	}
	return true
}
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func ensureRoot(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	return nil
}
