//go:build windows

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsServiceDefinition struct {
	Schema      string            `json:"schema"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Executable  string            `json:"executable"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"environment,omitempty"`
	Account     string            `json:"account"`
}

func windowsServiceName(kind, instance string) string {
	switch kind {
	case HostdKind:
		return "PaperboatHostd"
	case UpdaterKind:
		return "PaperboatUpdated"
	case HostKind:
		return "PaperboatHost"
	case ConfigKind:
		return "PaperboatRuntimeConfig"
	case DaemonKind:
		return "PaperboatLocalDaemon"
	case PreviewKind:
		return "PaperboatPreview-" + instance
	default:
		return "PaperboatRuntime"
	}
}

func safeWindowsServiceKind(kind, instance string) bool {
	if kind == PreviewKind {
		return safeInstance(instance)
	}
	return kind == WorkerKind || kind == HostKind || kind == HostdKind || kind == UpdaterKind || kind == ConfigKind || kind == DaemonKind
}

func safeExecutableWindows(path string) error {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return ErrInvalidDefinition
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidDefinition
	}
	return nil
}

func renderWindowsService(config Config) ([]byte, error) {
	name := windowsServiceName(config.Kind, config.Instance)
	if !safeWindowsServiceKind(config.Kind, config.Instance) || name == "" {
		return nil, ErrInvalidDefinition
	}
	description := "Paperboat host runtime"
	if config.Kind == HostdKind {
		description = "Paperboat stable host supervisor"
	} else if config.Kind == UpdaterKind {
		description = "Paperboat signed update service"
	}
	definition := windowsServiceDefinition{
		Schema: "paperboat.windows-service/v1", Name: name,
		DisplayName: name, Description: description, Executable: config.Executable,
		Arguments: append([]string(nil), config.Arguments...), Environment: copyEnvironment(config.Environment),
		Account: config.User,
	}
	return json.MarshalIndent(definition, "", "  ")
}

// WindowsController registers services directly with the Service Control
// Manager. The declaration is parsed strictly from the file written by the
// installer; callers cannot pass an arbitrary executable through Apply.
type WindowsController struct{}

func (WindowsController) Apply(ctx context.Context, definitionPath string, upgrading bool) error {
	definition, err := readWindowsServiceDefinition(definitionPath)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(definition.Name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(definition.Name, definition.Executable, mgr.Config{
			DisplayName: definition.DisplayName, Description: definition.Description,
			StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
			// LocalSystem is deliberate for the privileged service boundary.
			// hostd obtains the enrolled interactive token before creating a
			// user workload, so workloads never run as SYSTEM.
			ServiceStartName: "LocalSystem",
		}, definition.Arguments...)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		current, configErr := service.Config()
		if configErr != nil {
			return configErr
		}
		current.BinaryPathName = windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
		current.DisplayName = definition.DisplayName
		current.Description = definition.Description
		current.StartType = mgr.StartAutomatic
		if err := service.UpdateConfig(current); err != nil {
			return err
		}
		if upgrading {
			_ = stopWindowsService(ctx, service)
		}
	}
	defer service.Close()
	if definition.Name == "PaperboatHostd" {
		// The hostd service is only a privileged token bridge. If the enrolled
		// owner has logged off or the child fails, SCM retries the bridge with
		// bounded backoff instead of leaving a LocalSystem workload behind.
		if err := service.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
			{Type: mgr.ServiceRestart, Delay: time.Minute},
		}, 24*60*60); err != nil {
			return err
		}
		if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			return err
		}
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) && !errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		return err
	}
	// SCM can return ERROR_SERVICE_REQUEST_TIMEOUT while the service process is
	// already registered and still completing its bounded startup. Querying the
	// authoritative state avoids reporting a failed install when SCM transitions
	// the same process to Running moments later.
	return waitWindowsService(ctx, service, svc.Running)
}

func (WindowsController) Remove(ctx context.Context, definitionPath string) error {
	definition, err := readWindowsServiceDefinition(definitionPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if definition.Name == "" {
		return nil
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, err := manager.OpenService(definition.Name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return nil
	}
	if err != nil {
		manager.Disconnect()
		return err
	}
	if err := stopWindowsService(ctx, service); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		service.Close()
		manager.Disconnect()
		return err
	}
	if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		service.Close()
		manager.Disconnect()
		return err
	}
	if err := service.Close(); err != nil {
		manager.Disconnect()
		return err
	}
	manager.Disconnect()
	// Closing the last service handle is what lets SCM finalize a pending
	// deletion. Give SCM that window before polling so the poll itself does not
	// continuously reopen and pin the marked-for-delete service.
	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
	}
	for {
		probeManager, connectErr := mgr.Connect()
		if connectErr != nil {
			return connectErr
		}
		probe, openErr := probeManager.OpenService(definition.Name)
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			probeManager.Disconnect()
			return nil
		}
		if openErr != nil {
			probeManager.Disconnect()
			return openErr
		}
		_ = probe.Close()
		probeManager.Disconnect()
		timer = time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func readWindowsServiceDefinition(path string) (windowsServiceDefinition, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".json" {
		return windowsServiceDefinition{}, ErrInvalidDefinition
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return windowsServiceDefinition{}, err
	}
	if len(body) > 64<<10 {
		return windowsServiceDefinition{}, ErrInvalidDefinition
	}
	var definition windowsServiceDefinition
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&definition) != nil || definition.Schema != "paperboat.windows-service/v1" || definition.Name == "" || safeExecutableWindows(definition.Executable) != nil || len(definition.Arguments) == 0 || !safeValues(definition.Arguments) || !safeEnvironment(definition.Environment) {
		return windowsServiceDefinition{}, ErrInvalidDefinition
	}
	return definition, nil
}

func stopWindowsService(ctx context.Context, service *mgr.Service) error {
	_, err := service.Control(svc.Stop)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return waitWindowsService(ctx, service, svc.Stopped)
}

func waitWindowsService(ctx context.Context, service *mgr.Service, want svc.State) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

var _ Controller = WindowsController{}

func (d windowsServiceDefinition) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.Executable)
}
