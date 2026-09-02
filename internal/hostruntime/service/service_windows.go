//go:build windows

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsServiceDefinitionRoot   = `C:\ProgramData\Paperboat\services`
	windowsServiceDeleteTimeout    = 30 * time.Second
	windowsServiceDeleteDelay      = 500 * time.Millisecond
	windowsServiceOperationTimeout = 30 * time.Second
	// Instances are an internal qualification/test seam. Empty instances keep
	// the one fixed service name used by a normal installation; a non-empty
	// instance gets a bounded role-prefixed name so an acceptance run cannot
	// collide with an existing Paperboat service by accident.
	windowsServiceInstanceMax = 64
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
	base := windowsServiceBaseNameForKind(kind)
	if base == "" || instance == "" {
		return base
	}
	return base + "-" + instance
}

func windowsServiceBaseNameForKind(kind string) string {
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
	case WorkerKind:
		return "PaperboatRuntime"
	default:
		return ""
	}
}

func safeWindowsServiceKind(kind, instance string) bool {
	if windowsServiceBaseNameForKind(kind) == "" {
		return false
	}
	if instance == "" {
		return true
	}
	if len(instance) > windowsServiceInstanceMax || instance != strings.TrimSpace(instance) {
		return false
	}
	for _, character := range instance {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func windowsServiceNameFromDefinitionPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".json" {
		return "", ErrInvalidDefinition
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if windowsServiceBaseNameFromName(name) == "" {
		return "", ErrInvalidDefinition
	}
	return name, nil
}

// windowsServiceBaseNameFromName accepts the fixed production names and the
// same names with one bounded instance suffix. It deliberately does not
// accept arbitrary SCM names, even when they happen to live under the
// Paperboat declaration directory.
func windowsServiceBaseNameFromName(name string) string {
	for _, base := range []string{
		"PaperboatHostd", "PaperboatUpdated", "PaperboatHost",
		"PaperboatRuntimeConfig", "PaperboatLocalDaemon", "PaperboatRuntime",
	} {
		if strings.EqualFold(name, base) {
			return base
		}
		prefix := base + "-"
		if len(name) > len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
			instance := name[len(prefix):]
			if safeWindowsServiceKind(windowsServiceKindForBaseName(base), instance) {
				return base
			}
		}
	}
	return ""
}

func windowsServiceKindForBaseName(base string) string {
	switch base {
	case "PaperboatHostd":
		return HostdKind
	case "PaperboatUpdated":
		return UpdaterKind
	case "PaperboatHost":
		return HostKind
	case "PaperboatRuntimeConfig":
		return ConfigKind
	case "PaperboatLocalDaemon":
		return DaemonKind
	default:
		return WorkerKind
	}
}

var windowsServiceProbe = probeWindowsService

func probeWindowsService(name string) (owned bool, resultErr error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := service.Close(); err != nil {
		return true, err
	}
	return true, nil
}

func validateWindowsDirectoryNoReparse(path string) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidDefinition
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrInvalidDefinition, err)
	}
	return nil
}

func validateWindowsAncestorDirectories(path string, allowMissingTail bool) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidDefinition
	}
	current := filepath.Dir(filepath.Clean(path))
	for {
		err := validateWindowsDirectoryNoReparse(current)
		if errors.Is(err, os.ErrNotExist) && allowMissingTail {
			parent := filepath.Dir(current)
			if parent == current {
				return nil
			}
			current = parent
			continue
		}
		if err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateWindowsRegularFileNoReparse(path string, allowMissing bool) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidDefinition
	}
	if err := validateWindowsAncestorDirectories(path, allowMissing); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrInvalidDefinition, err)
		}
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrInvalidDefinition, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrInvalidDefinition, err)
	}
	return nil
}

func safeExecutableWindows(path string) error {
	return validateWindowsExecutable(path, false)
}

func validateWindowsExecutable(path string, allowMissing bool) error {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return ErrInvalidDefinition
	}
	return validateWindowsRegularFileNoReparse(path, allowMissing)
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
	} else if config.Kind == DaemonKind {
		description = "Paperboat local daemon"
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

func windowsNativeOperationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrLifecycleInvalid
	}
	operationCtx, cancel := context.WithTimeout(ctx, windowsServiceOperationTimeout)
	return operationCtx, cancel, nil
}

// Inspect reports the SCM registration and process state for the exact
// declaration path. A registered service without its declaration is returned
// as native state so NativeTransactionalComponent can fail closed with an
// uncertain outcome instead of treating the orphan as absent.
func (WindowsController) Inspect(ctx context.Context, definitionPath string) (NativeControllerStatus, error) {
	operationCtx, cancel, err := windowsNativeOperationContext(ctx)
	if err != nil {
		return NativeControllerStatus{}, err
	}
	defer cancel()
	_ = operationCtx
	name, err := windowsServiceNameFromDefinitionPath(definitionPath)
	if err != nil {
		return NativeControllerStatus{}, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return NativeControllerStatus{}, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return NativeControllerStatus{}, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return NativeControllerStatus{Registered: true}, nil
	}
	if err != nil {
		return NativeControllerStatus{}, err
	}
	defer service.Close()
	// Read and validate the declaration only after SCM proves the service
	// exists. On a genuinely clean machine the declaration directory itself is
	// absent, which is an ordinary empty state rather than an invalid path.
	definition, definitionErr := readWindowsServiceDefinitionForRemoval(definitionPath)
	if definitionErr != nil {
		return NativeControllerStatus{}, definitionErr
	}
	config, err := service.Config()
	if err != nil {
		return NativeControllerStatus{}, err
	}
	if !windowsServiceConfigurationOwnsDefinition(config, definition) {
		return NativeControllerStatus{}, ErrInvalidDefinition
	}
	status, err := service.Query()
	if err != nil {
		return NativeControllerStatus{}, err
	}
	running := status.State == svc.Running
	return NativeControllerStatus{
		Registered: true,
		Enabled:    config.StartType == mgr.StartAutomatic,
		Running:    running,
		Ready:      running,
	}, nil
}

// Enable registers or updates the exact declaration as an automatic
// LocalSystem service but does not start it. Separating enablement from Start
// lets LifecycleManager journal and roll back each phase independently.
func (WindowsController) Enable(ctx context.Context, definitionPath string) (resultErr error) {
	operationCtx, cancel, err := windowsNativeOperationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	definition, err := readWindowsServiceDefinition(definitionPath)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(definition.Name)
	existing := err == nil
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(definition.Name, definition.Executable, windowsServiceManagerConfig(definition), definition.Arguments...)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, service.Close()) }()
	if existing {
		config, configErr := service.Config()
		if configErr != nil {
			return configErr
		}
		updated, err := windowsServiceConfigForDefinition(config, definition)
		if err != nil {
			return err
		}
		if err := service.UpdateConfig(updated); err != nil {
			return err
		}
	}
	if err := configureWindowsServiceRecovery(service, definition.Name); err != nil {
		return err
	}
	// A successful Enable must have an automatic start declaration. Querying it
	// before returning catches SCM accepting an incomplete UpdateConfig.
	config, err := service.Config()
	if err != nil {
		return err
	}
	if config.StartType != mgr.StartAutomatic || !windowsServiceConfigurationOwnsDefinition(config, definition) {
		return ErrInvalidDefinition
	}
	_ = operationCtx // keeps all future SCM calls on the bounded operation context contract.
	return nil
}

// windowsServiceConfigForDefinition is the owned transition boundary used by
// lifecycle rollback. An SCM entry may still contain the just-failed new
// declaration, so exact equality with the old declaration is not sufficient.
// A transition is accepted only for the fixed Paperboat executable, expected
// role argument, LocalSystem account, and service SID policy; a same-name
// foreign registration cannot be adopted.
func windowsServiceConfigForDefinition(current mgr.Config, definition windowsServiceDefinition) (mgr.Config, error) {
	if !windowsServiceConfigurationOwnsDefinition(current, definition) && !windowsServiceConfigurationTrustedForTransition(current, definition) {
		return mgr.Config{}, ErrInvalidDefinition
	}
	current.BinaryPathName = windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
	current.DisplayName = definition.DisplayName
	current.Description = definition.Description
	current.StartType = mgr.StartAutomatic
	current.ErrorControl = mgr.ErrorNormal
	current.ServiceStartName = "LocalSystem"
	if windowsServiceUsesSID(definition.Name) {
		current.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	}
	return current, nil
}

func windowsServiceConfigurationTrustedForTransition(config mgr.Config, definition windowsServiceDefinition) bool {
	if !isWindowsSystemAccount(config.ServiceStartName) || !windowsServiceUsesSID(definition.Name) || config.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		return false
	}
	arguments, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(arguments) != 2 {
		return false
	}
	layout, err := DefaultLayout("windows")
	if err != nil || !exactWindowsPath(filepath.Clean(arguments[0]), layout.Binary) {
		return false
	}
	wantArgument := windowsServiceRoleArgument(definition.Name)
	return wantArgument != "" && arguments[1] == wantArgument
}

func windowsServiceRoleArgument(name string) string {
	base := windowsServiceBaseNameFromName(name)
	return map[string]string{
		"PaperboatHostd":         "__runtime-hostd",
		"PaperboatUpdated":       "__runtime-updated",
		"PaperboatLocalDaemon":   "__runtime-local-daemon",
		"PaperboatHost":          "__runtime-host-service",
		"PaperboatRuntimeConfig": "__runtime-config",
	}[base]
}

func (WindowsController) Disable(ctx context.Context, definitionPath string) (resultErr error) {
	operationCtx, cancel, err := windowsNativeOperationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	name, err := windowsServiceNameFromDefinitionPath(definitionPath)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, service.Close()) }()
	definition, err := readWindowsServiceDefinitionForRemoval(definitionPath)
	if err != nil {
		return err
	}
	config, err := service.Config()
	if err != nil {
		return err
	}
	updated, err := windowsServiceConfigForDefinition(config, definition)
	if err != nil {
		return err
	}
	updated.StartType = mgr.StartDisabled
	if err := service.UpdateConfig(updated); err != nil {
		return err
	}
	if operationCtx.Err() != nil {
		return operationCtx.Err()
	}
	return nil
}

func (WindowsController) Start(ctx context.Context, definitionPath string) error {
	operationCtx, cancel, err := windowsNativeOperationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
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
	if err != nil {
		return err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return err
	}
	if !windowsServiceConfigurationOwnsDefinition(config, definition) || config.StartType == mgr.StartDisabled {
		return ErrInvalidDefinition
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) && !errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		return err
	}
	return waitWindowsService(operationCtx, service, svc.Running)
}

func (WindowsController) Stop(ctx context.Context, definitionPath string) error {
	operationCtx, cancel, err := windowsNativeOperationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	name, err := windowsServiceNameFromDefinitionPath(definitionPath)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	definition, err := readWindowsServiceDefinitionForRemoval(definitionPath)
	if err != nil {
		return err
	}
	config, err := service.Config()
	if err != nil {
		return err
	}
	if !windowsServiceConfigurationOwnsDefinition(config, definition) {
		return ErrInvalidDefinition
	}
	return stopWindowsService(operationCtx, service)
}

func windowsServiceManagerConfig(definition windowsServiceDefinition) mgr.Config {
	config := mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:   mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
		DisplayName: definition.DisplayName, Description: definition.Description,
		ServiceStartName: "LocalSystem",
	}
	if windowsServiceUsesSID(definition.Name) {
		config.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	}
	return config
}

func windowsServiceUsesSID(name string) bool {
	base := windowsServiceBaseNameFromName(name)
	return base == "PaperboatHostd" || base == "PaperboatUpdated" || base == "PaperboatLocalDaemon"
}

func configureWindowsServiceRecovery(service *mgr.Service, name string) error {
	if service == nil {
		return ErrInvalidDefinition
	}
	if !windowsServiceUsesSID(name) {
		return nil
	}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60); err != nil {
		return err
	}
	return service.SetRecoveryActionsOnNonCrashFailures(true)
}

func (WindowsController) Apply(ctx context.Context, definitionPath string, upgrading bool) (resultErr error) {
	definition, err := readWindowsServiceDefinition(definitionPath)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithTimeout(ctx, windowsServiceOperationTimeout)
	defer cancel()
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() {
		if disconnectErr := manager.Disconnect(); disconnectErr != nil {
			resultErr = errors.Join(resultErr, disconnectErr)
		}
	}()
	service, err := manager.OpenService(definition.Name)
	existing := err == nil
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		config := mgr.Config{
			DisplayName: definition.DisplayName, Description: definition.Description,
			StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
			// LocalSystem is deliberate for the privileged service boundary.
			// hostd obtains the enrolled interactive token before creating a
			// user workload, so workloads never run as SYSTEM.
			ServiceStartName: "LocalSystem",
		}
		if windowsServiceUsesSID(definition.Name) {
			config.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
		}
		service, err = manager.CreateService(definition.Name, definition.Executable, config, definition.Arguments...)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer func() {
		if closeErr := service.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	if existing {
		current, configErr := service.Config()
		if configErr != nil {
			return configErr
		}
		// Never adopt a same-name registration until its current SCM
		// declaration proves Paperboat ownership. This path is used by the
		// standalone Installer.Install compatibility boundary, so the same
		// collision refusal as Enable is required here too.
		current, err = windowsServiceConfigForDefinition(current, definition)
		if err != nil {
			return err
		}
		if err := service.UpdateConfig(current); err != nil {
			return err
		}
		if upgrading {
			if err := stopWindowsService(operationCtx, service); err != nil {
				return err
			}
		}
	}
	if windowsServiceUsesSID(definition.Name) {
		// Owner-scoped workloads run behind a privileged token bridge. If the
		// enrolled owner logs off or the child fails, SCM retries the bridge with
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
	if windowsServiceUsesSID(definition.Name) {
		installed, configErr := service.Config()
		wantPath := windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
		validIdentity := configErr == nil && strings.EqualFold(installed.BinaryPathName, wantPath) && strings.EqualFold(installed.ServiceStartName, "LocalSystem") && installed.StartType == mgr.StartAutomatic && installed.ErrorControl == mgr.ErrorNormal
		validIdentity = validIdentity && installed.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED
		if !validIdentity {
			return errors.Join(ErrInvalidDefinition, configErr)
		}
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) && !errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		return err
	}
	// SCM can return ERROR_SERVICE_REQUEST_TIMEOUT while the service process is
	// already registered and still completing its bounded startup. Querying the
	// authoritative state avoids reporting a failed install when SCM transitions
	// the same process to Running moments later.
	return waitWindowsService(operationCtx, service, svc.Running)
}

func (WindowsController) Remove(ctx context.Context, definitionPath string) (resultErr error) {
	definition, err := readWindowsServiceDefinitionForRemoval(definitionPath)
	if errors.Is(err, os.ErrNotExist) {
		name, nameErr := windowsServiceNameFromDefinitionPath(definitionPath)
		if nameErr != nil {
			return nameErr
		}
		exists, probeErr := windowsServiceProbe(name)
		if probeErr != nil {
			return probeErr
		}
		if exists {
			return fmt.Errorf("%w: registered service %q has no declaration", ErrInvalidDefinition, name)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deleteCtx, cancel := context.WithTimeout(ctx, windowsServiceDeleteTimeout)
	defer cancel()
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() {
		if manager != nil {
			resultErr = errors.Join(resultErr, manager.Disconnect())
		}
	}()
	service, err := manager.OpenService(definition.Name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		var serviceCloseErr error
		if service != nil {
			serviceCloseErr = service.Close()
		}
		disconnectErr := manager.Disconnect()
		manager = nil
		return errors.Join(serviceCloseErr, disconnectErr, waitWindowsServiceDeletion(deleteCtx, definition.Name))
	}
	if err != nil {
		return err
	}
	defer func() {
		if service != nil {
			resultErr = errors.Join(resultErr, service.Close())
		}
	}()
	config, configErr := service.Config()
	if configErr != nil {
		return configErr
	}
	if !windowsServiceConfigurationOwnsDefinition(config, definition) {
		return ErrInvalidDefinition
	}
	if err := stopWindowsService(deleteCtx, service); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	if err := service.Close(); err != nil {
		return err
	}
	service = nil
	disconnectErr := manager.Disconnect()
	manager = nil
	return errors.Join(disconnectErr, waitWindowsServiceDeletion(deleteCtx, definition.Name))
}

func readWindowsServiceDefinition(path string) (windowsServiceDefinition, error) {
	return readWindowsServiceDefinitionWithExecutablePolicy(path, false)
}

func readWindowsServiceDefinitionForRemoval(path string) (windowsServiceDefinition, error) {
	return readWindowsServiceDefinitionWithExecutablePolicy(path, true)
}

func readWindowsServiceDefinitionWithExecutablePolicy(path string, allowMissingExecutable bool) (windowsServiceDefinition, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".json" {
		return windowsServiceDefinition{}, ErrInvalidDefinition
	}
	if err := validateWindowsRegularFileNoReparse(path, false); err != nil {
		return windowsServiceDefinition{}, err
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
	expectedName, nameErr := windowsServiceNameFromDefinitionPath(path)
	decodeErr := decoder.Decode(&definition)
	var extra any
	trailingErr := decoder.Decode(&extra)
	executableErr := validateWindowsExecutable(definition.Executable, allowMissingExecutable)
	if decodeErr != nil || trailingErr != io.EOF || nameErr != nil || !strings.EqualFold(definition.Name, expectedName) || definition.Schema != "paperboat.windows-service/v1" || definition.Name == "" || executableErr != nil || len(definition.Arguments) == 0 || !safeValues(definition.Arguments) || !safeEnvironment(definition.Environment) {
		return windowsServiceDefinition{}, ErrInvalidDefinition
	}
	return definition, nil
}

func windowsServiceConfigurationOwnsDefinition(config mgr.Config, definition windowsServiceDefinition) bool {
	wantPath := windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
	return strings.EqualFold(config.BinaryPathName, wantPath) && isWindowsSystemAccount(config.ServiceStartName)
}

func isWindowsSystemAccount(value string) bool {
	value = strings.TrimSpace(value)
	return strings.EqualFold(value, "SYSTEM") || strings.EqualFold(value, "LocalSystem") || strings.EqualFold(value, `NT AUTHORITY\SYSTEM`)
}

func waitWindowsServiceDeletion(ctx context.Context, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return pollWindowsServiceDeletion(ctx, windowsServiceDeleteTimeout, windowsServiceDeleteDelay, func() (resultErr error) {
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
		service, err := manager.OpenService(name)
		if err != nil {
			return err
		}
		return service.Close()
	})
}

func pollWindowsServiceDeletion(ctx context.Context, timeout, delay time.Duration, probe func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 || delay <= 0 || probe == nil {
		return ErrInvalidDefinition
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	wait := func(duration time.Duration) error {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-deadlineCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return deadlineCtx.Err()
		case <-timer.C:
			return nil
		}
	}
	if err := wait(delay); err != nil {
		return err
	}
	for {
		err := probe()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
		if err := wait(delay); err != nil {
			return err
		}
	}
}

func exactWindowsPath(left, right string) bool {
	return filepath.IsAbs(left) && filepath.IsAbs(right) && filepath.Clean(left) == left && filepath.Clean(right) == right && strings.EqualFold(left, right)
}

func stopWindowsService(ctx context.Context, service *mgr.Service) error {
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithTimeout(ctx, windowsServiceOperationTimeout)
	defer cancel()
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if status.State != svc.StopPending {
			_, controlErr := service.Control(svc.Stop)
			if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) &&
				!errors.Is(controlErr, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) &&
				!errors.Is(controlErr, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
				return controlErr
			}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-operationCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return operationCtx.Err()
		case <-timer.C:
		}
	}
}

func waitWindowsService(ctx context.Context, service *mgr.Service, want svc.State) error {
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithTimeout(ctx, windowsServiceOperationTimeout)
	defer cancel()
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
		case <-operationCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return operationCtx.Err()
		case <-timer.C:
		}
	}
}

var (
	_ Controller                = WindowsController{}
	_ NativeLifecycleController = WindowsController{}
)

func (d windowsServiceDefinition) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.Executable)
}
