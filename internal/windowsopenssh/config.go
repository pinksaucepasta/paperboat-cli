package windowsopenssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

type ServiceConfig struct {
	StateRoot      string
	SSHDPath       string
	SFTPPath       string
	AuthorizedKeys string
	Port           uint16
}

func WriteServiceConfig(config ServiceConfig) (string, error) {
	if !filepath.IsAbs(config.StateRoot) || !filepath.IsAbs(config.SSHDPath) || !filepath.IsAbs(config.SFTPPath) ||
		!filepath.IsAbs(config.AuthorizedKeys) || config.Port == 0 || strings.ContainsAny(config.StateRoot+config.SSHDPath+config.SFTPPath+config.AuthorizedKeys, "\"\r\n\x00") {
		return "", ErrInvalidConfig
	}
	if err := os.MkdirAll(filepath.Join(config.StateRoot, "hostkeys"), 0o700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(config.StateRoot, "logs"), 0o700); err != nil {
		return "", err
	}
	quote := func(value string) string { return `"` + value + `"` }
	lines := []string{
		"# Managed by Paperboat. Manual changes are replaced.",
		"Port " + strconv.Itoa(int(config.Port)),
		"ListenAddress 127.0.0.1",
		"ListenAddress ::1",
		"Protocol 2",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"PermitEmptyPasswords no",
		"PubkeyAuthentication yes",
		"AuthorizedKeysFile " + quote(config.AuthorizedKeys),
		"HostKey " + quote(filepath.Join(config.StateRoot, "hostkeys", "ssh_host_ed25519_key")),
		"AllowAgentForwarding no",
		"AllowTcpForwarding no",
		"GatewayPorts no",
		"PermitTunnel no",
		"X11Forwarding no",
		"Subsystem sftp " + quote(config.SFTPPath),
		"LogLevel VERBOSE",
	}
	path := filepath.Join(config.StateRoot, "sshd_config")
	if err := atomicfile.Write(path, []byte(strings.Join(lines, "\n")+"\n"), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return "", err
	}
	return path, nil
}

func ValidateServiceConfig(runner Runner, sshdPath, configPath string) error {
	if runner == nil || !filepath.IsAbs(sshdPath) || !filepath.IsAbs(configPath) {
		return ErrInvalidConfig
	}
	validationCtx, cancel := context.WithTimeout(contextBackground(), 15*time.Second)
	defer cancel()
	output, err := runner.Run(validationCtx, sshdPath, "-t", "-f", configPath)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, boundedOutput(output))
	}
	return nil
}

var contextBackground = func() context.Context { return context.Background() }
