//go:build darwin || linux

package localdaemon

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

type serviceConfig struct {
	Platform    string
	Home        string
	Executable  string
	ConfigPath  string
	ServerURL   string
	Username    string
	Group       string
	UID         int
	Environment map[string]string
	Runner      hostservice.Runner
}

func InstallCurrentUserService(ctx context.Context, executable, configPath, serverURL string) error {
	config, err := currentUserServiceConfig(executable)
	if err != nil {
		return err
	}
	config.ConfigPath, config.ServerURL = configPath, serverURL
	return installService(ctx, config)
}

func RemoveCurrentUserService(ctx context.Context, executable string) error {
	config, err := currentUserServiceConfig(executable)
	if err != nil {
		return err
	}
	installer, err := newServiceInstaller(config)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(installer.DefinitionPath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return installer.Uninstall(ctx)
}

func currentUserServiceConfig(executable string) (serviceConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return serviceConfig{}, err
	}
	account, err := user.Current()
	if err != nil {
		return serviceConfig{}, err
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return serviceConfig{}, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return serviceConfig{}, err
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return serviceConfig{}, err
	}
	environment := map[string]string{"HOME": home}
	for _, key := range []string{"XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" && filepath.IsAbs(value) {
			environment[key] = filepath.Clean(value)
		}
	}
	return serviceConfig{
		Platform: runtime.GOOS, Home: home, Executable: resolvedExecutable,
		Username: account.Username, Group: group.Name, UID: uid,
		Environment: environment, Runner: hostservice.ExecRunner{},
	}, nil
}

func installService(ctx context.Context, config serviceConfig) error {
	if ctx == nil || !filepath.IsAbs(config.Home) || !filepath.IsAbs(config.Executable) || config.Username == "" || config.Group == "" || config.UID < 0 || config.Runner == nil || config.ConfigPath != "" && !filepath.IsAbs(config.ConfigPath) {
		return ErrInvalidInventoryConfig
	}
	installer, err := newServiceInstaller(config)
	if err != nil {
		return err
	}
	if err := installer.Install(ctx); err != nil {
		return errors.Join(errors.New("install Paperboat local daemon service"), err)
	}
	return nil
}

func newServiceInstaller(config serviceConfig) (*hostservice.Installer, error) {
	if !filepath.IsAbs(config.Home) || !filepath.IsAbs(config.Executable) || config.Username == "" || config.Group == "" || config.UID < 0 || config.Runner == nil || config.ConfigPath != "" && !filepath.IsAbs(config.ConfigPath) {
		return nil, ErrInvalidInventoryConfig
	}
	arguments := []string{"__local-daemon"}
	if config.ConfigPath != "" {
		arguments = append(arguments, "--config", filepath.Clean(config.ConfigPath))
	}
	if strings.TrimSpace(config.ServerURL) != "" {
		arguments = append(arguments, "--server", strings.TrimSpace(config.ServerURL))
	}
	var controller hostservice.Controller
	switch config.Platform {
	case "darwin":
		controller = hostservice.LaunchdController{Runner: config.Runner, UID: config.UID, Label: hostservice.DaemonLabel, UserDomain: true}
	case "linux":
		controller = hostservice.SystemdController{Runner: config.Runner, Unit: "paperboat-local-daemon.service", User: true}
	default:
		return nil, hostservice.ErrUnsupportedPlatform
	}
	return hostservice.New(hostservice.Config{
		Platform: config.Platform, Kind: hostservice.DaemonKind, ConfigRoot: config.Home,
		Executable: config.Executable, User: config.Username, Group: config.Group,
		Arguments: arguments, Environment: config.Environment, Controller: controller,
	})
}
