package windowsopenssh

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

type ListenerRecord struct {
	Address         string `json:"address"`
	Port            uint16 `json:"port"`
	ProcessID       uint32 `json:"process_id"`
	ParentProcessID uint32 `json:"parent_process_id"`
	ExecutablePath  string `json:"executable_path"`
}

type ServiceHealth struct {
	Service   ServiceRecord    `json:"service"`
	Listeners []ListenerRecord `json:"listeners"`
}

// CheckLoopbackHealth is read-only. It establishes only that the Paperboat-owned
// service is running and is the process listening on both loopback families.
func CheckLoopbackHealth(ctx context.Context, config Config, result Result) (ServiceHealth, error) {
	if err := validate(config); err != nil {
		return ServiceHealth{}, err
	}
	if result.Port != config.Port || !sameCleanPath(result.SSHDPath, filepath.Join(config.InstallRoot, "sshd.exe")) {
		return ServiceHealth{}, ErrInvalidConfig
	}
	if config.Platform != "windows" {
		return ServiceHealth{}, ErrInstallerUnavailable
	}
	health, err := collectLoopbackHealth(ctx, config, result)
	if err != nil {
		return ServiceHealth{}, err
	}
	if err := ValidateLoopbackHealth(health, config, result); err != nil {
		return ServiceHealth{}, err
	}
	return health, nil
}

func ValidateLoopbackHealth(health ServiceHealth, config Config, result Result) error {
	if !health.Service.Exists || !strings.EqualFold(health.Service.Name, ServiceName) || !strings.EqualFold(health.Service.State, "running") || health.Service.ProcessID == 0 {
		return ErrServiceUnhealthy
	}
	if !strings.Contains(strings.ToLower(health.Service.PathName), strings.ToLower(filepath.Clean(result.SSHDPath))) {
		return ErrServiceOwnership
	}
	seen := map[string]bool{}
	for _, listener := range health.Listeners {
		if listener.Port != result.Port {
			continue
		}
		if listener.ProcessID != health.Service.ProcessID && listener.ParentProcessID != health.Service.ProcessID {
			return ErrServiceOwnership
		}
		if !sameCleanPath(listener.ExecutablePath, result.SSHDPath) {
			return ErrServiceOwnership
		}
		if listener.Address == "127.0.0.1" || listener.Address == "::1" {
			seen[listener.Address] = true
			continue
		}
		return fmt.Errorf("%w: PaperboatSshd listener %q is not loopback", ErrServiceUnhealthy, listener.Address)
	}
	if !seen["127.0.0.1"] || !seen["::1"] {
		return fmt.Errorf("%w: PaperboatSshd must own 127.0.0.1:%d and [::1]:%d", ErrServiceUnhealthy, result.Port, result.Port)
	}
	return nil
}

func sameCleanPath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
