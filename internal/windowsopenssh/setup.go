package windowsopenssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

type SetupResult struct {
	Result
	CreatedHostKey bool
}

func Setup(ctx context.Context, config Config) (SetupResult, error) {
	inventory, err := Inventory(ctx, config)
	if err != nil {
		return SetupResult{}, err
	}
	var result Result
	if inventory.Class == InstallationPaperboatApproved {
		result, err = verifyInstalledResult(ctx, config)
	} else {
		result, err = Provision(ctx, config)
	}
	if err != nil {
		return SetupResult{}, err
	}
	return setupFromResult(ctx, config, result)
}

func setupFromResult(ctx context.Context, config Config, result Result) (SetupResult, error) {
	authorizedRoot := filepath.Join(config.StateRoot, "authorized_keys")
	if err := os.MkdirAll(authorizedRoot, 0o700); err != nil {
		return SetupResult{}, err
	}
	authorized := filepath.Join(authorizedRoot, "paperboat")
	if _, err := os.Lstat(authorized); errors.Is(err, os.ErrNotExist) {
		if err := atomicfile.Write(authorized, nil, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
			return SetupResult{}, err
		}
	} else if err != nil {
		return SetupResult{}, err
	}
	configPath, err := WriteServiceConfig(ServiceConfig{StateRoot: config.StateRoot, SSHDPath: result.SSHDPath, SFTPPath: result.SFTPPath, AuthorizedKeys: authorized, Port: result.Port})
	if err != nil {
		return SetupResult{}, err
	}
	hostKey := filepath.Join(config.StateRoot, "hostkeys", "ssh_host_ed25519_key")
	created := false
	if _, err := os.Lstat(hostKey); errors.Is(err, os.ErrNotExist) {
		keygen := filepath.Join(config.InstallRoot, "ssh-keygen.exe")
		if err := verifyBinary(ctx, config, keygen); err != nil {
			return SetupResult{}, err
		}
		keyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		output, keyErr := config.Runner.Run(keyCtx, keygen, "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
		cancel()
		if keyErr != nil {
			return SetupResult{}, errors.Join(ErrInstallFailed, errors.New(boundedOutput(output)))
		}
		created = true
	} else if err != nil {
		return SetupResult{}, err
	}
	if err := protectHostKeyFiles(hostKey); err != nil {
		return SetupResult{}, err
	}
	if err := protectHostPublicKeyFile(hostKey+".pub", config.OwnerSID); err != nil {
		return SetupResult{}, err
	}
	if err := ValidateServiceConfig(config.Runner, result.SSHDPath, configPath); err != nil {
		return SetupResult{}, err
	}
	serviceExecutable, err := paperboatServiceExecutable(config.ServiceExecutable)
	if err != nil {
		return SetupResult{}, err
	}
	if err := InstallService(ctx, serviceExecutable, result.SSHDPath, configPath); err != nil {
		return SetupResult{}, err
	}
	result.ConfigPath = configPath
	healthCtx, cancelHealth := context.WithTimeout(ctx, 15*time.Second)
	defer cancelHealth()
	if _, err := CheckLoopbackHealth(healthCtx, config, result); err != nil {
		return SetupResult{}, err
	}
	if err := RepairFirewallOwnership(ctx, config); err != nil {
		return SetupResult{}, err
	}
	return SetupResult{Result: result, CreatedHostKey: created}, nil
}

func paperboatServiceExecutable(configured string) (string, error) {
	path := configured
	if path == "" {
		path = os.Getenv("PAPERBOAT_SERVICE_EXECUTABLE")
	}
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(ErrServiceOwnership, err)
	}
	return filepath.Clean(path), nil
}
