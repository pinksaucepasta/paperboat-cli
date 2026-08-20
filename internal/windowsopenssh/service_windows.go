//go:build windows

package windowsopenssh

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var paperboatServiceRecovery = []mgr.RecoveryAction{
	{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	{Type: mgr.NoAction, Delay: 0},
}

func InstallService(ctx context.Context, serviceExecutable, sshdPath, configPath string) error {
	if ctx == nil || !filepath.IsAbs(serviceExecutable) || !filepath.IsAbs(sshdPath) || !filepath.IsAbs(configPath) {
		return ErrInvalidConfig
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	arguments := []string{"__windows-sshd-service", "--sshd", sshdPath, "--config", configPath}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(ServiceName, serviceExecutable, mgr.Config{
			DisplayName: "Paperboat OpenSSH Server", Description: "Loopback-only OpenSSH endpoint managed by Paperboat",
			StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem",
			SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
		}, arguments...)
	} else if err == nil {
		current, configErr := service.Config()
		if configErr != nil {
			service.Close()
			return configErr
		}
		expectedCommand := windows.EscapeArg(serviceExecutable) + " __windows-sshd-service --sshd " + windows.EscapeArg(sshdPath) + " --config " + windows.EscapeArg(configPath)
		if !sameServiceCommand(current.BinaryPathName, serviceExecutable, sshdPath, configPath) && !sameLegacyServiceCommand(current.BinaryPathName, sshdPath, configPath) {
			service.Close()
			return ErrServiceOwnership
		}
		current.BinaryPathName = expectedCommand
		current.StartType = mgr.StartAutomatic
		current.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
		err = service.UpdateConfig(current)
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.SetRecoveryActions(paperboatServiceRecovery, 24*60*60); err != nil {
		return err
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		status, queryErr := service.Query()
		if queryErr != nil {
			return queryErr
		}
		if status.State == svc.Running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return context.DeadlineExceeded
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func sameServiceCommand(command, serviceExecutable, sshdPath, configPath string) bool {
	command = strings.ToLower(command)
	return strings.Contains(command, strings.ToLower(filepath.Clean(serviceExecutable))) && strings.Contains(command, " __windows-sshd-service ") && strings.Contains(command, strings.ToLower(filepath.Clean(sshdPath))) && strings.Contains(command, strings.ToLower(filepath.Clean(configPath)))
}

func sameLegacyServiceCommand(command, sshdPath, configPath string) bool {
	command = strings.ToLower(command)
	return strings.Contains(command, strings.ToLower(filepath.Clean(sshdPath))) && strings.Contains(command, " -d -f ") && strings.Contains(command, strings.ToLower(filepath.Clean(configPath)))
}

// RemoveServiceOwned stops and deletes only a PaperboatSshd registration whose
// command still points at Paperboat's dedicated binaries and state. A service
// merely named PaperboatSshd is never sufficient ownership evidence.
func RemoveServiceOwned(ctx context.Context, config Config) error {
	if err := validate(config); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	current, err := service.Config()
	if err != nil {
		return err
	}
	serviceExecutable, err := paperboatServiceExecutable()
	if err != nil {
		return err
	}
	if !sameOwnedServiceCommand(current.BinaryPathName, serviceExecutable, config) {
		return ErrServiceOwnership
	}
	_, _ = service.Control(svc.Stop)
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return service.Delete()
}

func sameOwnedServiceCommand(command, serviceExecutable string, config Config) bool {
	sshdPath := filepath.Join(config.InstallRoot, "sshd.exe")
	configPath := filepath.Join(config.StateRoot, "sshd_config")
	return sameServiceCommand(command, serviceExecutable, sshdPath, configPath) || sameLegacyServiceCommand(command, sshdPath, configPath)
}
