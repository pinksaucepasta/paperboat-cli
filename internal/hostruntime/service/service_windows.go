//go:build windows

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// WindowsPreviewServiceArtifact is the ownership inventory used by preview
// cleanup. A service without its declaration is deliberately not considered
// owned: callers must surface that residue instead of deleting an ambiguous
// SCM entry.
type WindowsPreviewServiceArtifact struct {
	Name       string
	HasService bool
	// ServiceTerminal is true only when SCM reports durable successful
	// completion, or when the registration is already marked for deletion.
	// Callers must not reconcile a descriptor-less service while this is false.
	ServiceTerminal bool
	HasDeclaration  bool
	DeclarationRoot string
	// DeclarationModifiedAt lets reconciliation preserve a just-created SCM
	// registration during the descriptor publication/startup window.
	DeclarationModifiedAt time.Time
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

func isWindowsPreviewServiceName(name string) bool {
	const prefix = "PaperboatPreview-"
	return strings.HasPrefix(name, prefix) && safeInstance(strings.TrimPrefix(name, prefix))
}

func windowsServiceNameFromDefinitionPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".json" {
		return "", ErrInvalidDefinition
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	switch name {
	case "PaperboatHostd", "PaperboatUpdated", "PaperboatHost", "PaperboatRuntimeConfig", "PaperboatLocalDaemon", "PaperboatRuntime":
		return name, nil
	default:
		if isWindowsPreviewServiceName(name) {
			return name, nil
		}
		return "", ErrInvalidDefinition
	}
}

var windowsServiceProbe = probeWindowsService

var windowsServiceList = listWindowsServices

var windowsPreviewServiceTerminalProbe = probeWindowsPreviewServiceTerminal

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

func listWindowsServices() (result []string, resultErr error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	names, err := manager.ListServices()
	if err != nil {
		return nil, err
	}
	result = make([]string, 0)
	for _, name := range names {
		if isWindowsPreviewServiceName(name) {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result, nil
}

func probeWindowsPreviewServiceTerminal(name string) (exists bool, terminal bool, resultErr error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, true, nil
	}
	if err != nil {
		return false, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, service.Close()) }()
	status, err := service.Query()
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, true, nil
	}
	if err != nil {
		return true, false, err
	}
	return true, windowsPreviewServiceStatusTerminal(status), nil
}

func windowsPreviewServiceStatusTerminal(status svc.Status) bool {
	return status.State == svc.Stopped && status.Win32ExitCode == 0 && status.ServiceSpecificExitCode == 0
}

func validateWindowsPreviewDeclarationEntry(entry os.DirEntry) error {
	if !entry.IsDir() {
		return nil
	}
	name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
	if strings.EqualFold(filepath.Ext(entry.Name()), ".json") && isWindowsPreviewServiceName(name) {
		return fmt.Errorf("preview declaration %s is a directory: %w", entry.Name(), ErrInvalidDefinition)
	}
	return nil
}

// ListWindowsPreviewServiceArtifacts inventories both SCM services and
// declarations. It is intentionally fail-closed for malformed declarations;
// an uninstall caller must not silently skip a state it cannot validate.
func ListWindowsPreviewServiceArtifacts() ([]WindowsPreviewServiceArtifact, error) {
	serviceNames, err := windowsServiceList()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]WindowsPreviewServiceArtifact, len(serviceNames))
	for _, name := range serviceNames {
		exists, terminal, err := windowsPreviewServiceTerminalProbe(name)
		if err != nil {
			return nil, fmt.Errorf("query preview service %s status: %w", name, err)
		}
		if exists {
			byName[name] = WindowsPreviewServiceArtifact{Name: name, HasService: true, ServiceTerminal: terminal}
		}
	}
	entries, err := readWindowsServiceDefinitionEntries()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := validateWindowsPreviewDeclarationEntry(entry); err != nil {
			return nil, err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if !isWindowsPreviewServiceName(name) {
			continue
		}
		path := filepath.Join(windowsServiceDefinitionRoot, entry.Name())
		definition, err := readWindowsServiceDefinitionForRemoval(path)
		if err != nil {
			return nil, fmt.Errorf("validate preview declaration %s: %w", entry.Name(), err)
		}
		stateRoot, ok := windowsPreviewStateRoot(definition.Arguments)
		if !ok {
			return nil, fmt.Errorf("validate preview declaration %s: %w", entry.Name(), ErrInvalidDefinition)
		}
		if err := validateWindowsPreviewDefinition(path, name, stateRoot, definition); err != nil {
			return nil, fmt.Errorf("validate preview declaration %s: %w", entry.Name(), err)
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat preview declaration %s: %w", entry.Name(), err)
		}
		artifact := byName[name]
		artifact.Name = name
		artifact.HasDeclaration = true
		artifact.DeclarationRoot = stateRoot
		artifact.DeclarationModifiedAt = info.ModTime().UTC()
		byName[name] = artifact
	}
	result := make([]WindowsPreviewServiceArtifact, 0, len(byName))
	for _, artifact := range byName {
		result = append(result, artifact)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func readWindowsServiceDefinitionEntries() ([]os.DirEntry, error) {
	info, err := os.Lstat(windowsServiceDefinitionRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidDefinition
	}
	if err := validateWindowsDirectoryNoReparse(windowsServiceDefinitionRoot); err != nil {
		return nil, err
	}
	return os.ReadDir(windowsServiceDefinitionRoot)
}

func windowsPreviewStateRoot(args []string) (string, bool) {
	var root string
	count := 0
	for index, arg := range args {
		if arg != "--state-root" {
			continue
		}
		count++
		if count != 1 || index+1 >= len(args) || args[index+1] == "" {
			return "", false
		}
		root = args[index+1]
	}
	return root, count == 1
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

func (WindowsController) Apply(ctx context.Context, definitionPath string, upgrading bool) (resultErr error) {
	definition, err := readWindowsServiceDefinition(definitionPath)
	if err != nil {
		return err
	}
	if isWindowsPreviewServiceName(definition.Name) {
		stateRoot, ok := windowsPreviewStateRoot(definition.Arguments)
		if !ok {
			return ErrInvalidDefinition
		}
		if err := validateWindowsPreviewDefinition(definitionPath, definition.Name, stateRoot, definition); err != nil {
			return err
		}
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
		if definition.Name == "PaperboatHostd" || definition.Name == "PaperboatUpdated" || definition.Name == "PaperboatLocalDaemon" {
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
		current.BinaryPathName = windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
		current.DisplayName = definition.DisplayName
		current.Description = definition.Description
		current.StartType = mgr.StartAutomatic
		current.ErrorControl = mgr.ErrorNormal
		current.ServiceStartName = "LocalSystem"
		if definition.Name == "PaperboatHostd" || definition.Name == "PaperboatUpdated" || definition.Name == "PaperboatLocalDaemon" {
			current.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
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
	if definition.Name == "PaperboatHostd" || definition.Name == "PaperboatUpdated" || definition.Name == "PaperboatLocalDaemon" || isWindowsPreviewServiceName(definition.Name) {
		// Owner-scoped workloads run behind a privileged token bridge. If the
		// enrolled owner logs off or the child fails, SCM retries the bridge with
		// bounded backoff instead of leaving a LocalSystem workload behind or
		// permanently losing a durable preview.
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
	if definition.Name == "PaperboatHostd" || definition.Name == "PaperboatUpdated" || definition.Name == "PaperboatLocalDaemon" {
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
	if isWindowsPreviewServiceName(definition.Name) {
		stateRoot, ok := windowsPreviewStateRoot(definition.Arguments)
		if !ok || validateWindowsPreviewDefinition(definitionPath, definition.Name, stateRoot, definition) != nil {
			return ErrInvalidDefinition
		}
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

func exactWindowsPath(left, right string) bool {
	return filepath.IsAbs(left) && filepath.IsAbs(right) && filepath.Clean(left) == left && filepath.Clean(right) == right && strings.EqualFold(left, right)
}

func windowsPreviewInstanceFromName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:8])
}

func validateWindowsPreviewArguments(args []string, serviceName, stateRoot, definitionPath string) error {
	if len(args) < 10 || !safeValues(args) || !isWindowsPreviewServiceName(serviceName) || !validWindowsStateRoot(stateRoot) {
		return ErrInvalidDefinition
	}
	command := args[0]
	if command != "__runtime-preview" && command != "__runtime-private-preview" && command != "__runtime-serve" {
		return ErrInvalidDefinition
	}
	if args[1] != "--state-root" || !exactWindowsPath(args[2], stateRoot) || args[3] != "--name" || args[4] == "" || args[5] != "--descriptor" || args[7] != "--service-definition" {
		return ErrInvalidDefinition
	}
	instance := windowsPreviewInstanceFromName(args[4])
	if !strings.EqualFold(serviceName, "PaperboatPreview-"+instance) {
		return ErrInvalidDefinition
	}
	expectedDescriptor := filepath.Join(stateRoot, "previews", "active", instance+".json")
	if !exactWindowsPath(args[6], expectedDescriptor) || !exactWindowsPath(args[8], definitionPath) {
		return ErrInvalidDefinition
	}
	index := 9
	if command == "__runtime-preview" {
		if index+2 > len(args) || args[index] != "--port" {
			return ErrInvalidDefinition
		}
		port, err := strconv.ParseUint(args[index+1], 10, 16)
		if err != nil || port == 0 {
			return ErrInvalidDefinition
		}
		index += 2
	}
	if index >= len(args) {
		return ErrInvalidDefinition
	}
	switch args[index] {
	case "--indefinite":
		index++
	case "--expires-at":
		if index+2 > len(args) || args[index+1] == "" {
			return ErrInvalidDefinition
		}
		expires, err := time.Parse(time.RFC3339Nano, args[index+1])
		if err != nil || expires.UTC().Format(time.RFC3339Nano) != args[index+1] {
			return ErrInvalidDefinition
		}
		index += 2
	default:
		return ErrInvalidDefinition
	}
	if index != len(args) {
		return ErrInvalidDefinition
	}
	return nil
}

func validateWindowsPreviewDeclarationRoot() error {
	info, err := os.Lstat(windowsServiceDefinitionRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	return validateWindowsDirectoryNoReparse(windowsServiceDefinitionRoot)
}

func validateWindowsPreviewDefinition(path, serviceName, stateRoot string, definition windowsServiceDefinition) error {
	if !isWindowsPreviewServiceName(serviceName) || !validWindowsStateRoot(stateRoot) || !exactWindowsPath(path, filepath.Join(windowsServiceDefinitionRoot, serviceName+".json")) || !strings.EqualFold(definition.Name, serviceName) || !isWindowsSystemAccount(definition.Account) {
		return ErrInvalidDefinition
	}
	layout, err := DefaultLayout("windows")
	if err != nil || !exactWindowsPath(definition.Executable, layout.Binary) {
		return errors.Join(ErrInvalidDefinition, err)
	}
	if err := validateWindowsExecutable(definition.Executable, true); err != nil {
		return err
	}
	return validateWindowsPreviewArguments(definition.Arguments, serviceName, stateRoot, path)
}

// ValidateWindowsPreviewServiceOwnership proves that a declaration and its
// SCM registration both describe the exact Paperboat preview service. It does
// not mutate either object and is used as the preflight phase for bulk cleanup.
func ValidateWindowsPreviewServiceOwnership(ctx context.Context, name, stateRoot string) (resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx
	if !isWindowsPreviewServiceName(name) || !validWindowsStateRoot(stateRoot) {
		return ErrInvalidDefinition
	}
	if err := validateWindowsPreviewDeclarationRoot(); err != nil {
		return err
	}
	definitionPath := filepath.Join(windowsServiceDefinitionRoot, name+".json")
	definition, err := readWindowsServiceDefinitionForRemoval(definitionPath)
	if errors.Is(err, os.ErrNotExist) {
		exists, probeErr := windowsServiceProbe(name)
		if probeErr != nil {
			return probeErr
		}
		if exists {
			return ErrInvalidDefinition
		}
		return nil
	}
	if err != nil {
		return err
	}
	declaredRoot, ok := windowsPreviewStateRoot(definition.Arguments)
	if !ok || !sameWindowsServicePath(declaredRoot, stateRoot) {
		return ErrInvalidDefinition
	}
	if err := validateWindowsPreviewDefinition(definitionPath, name, stateRoot, definition); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() {
		if manager != nil {
			resultErr = errors.Join(resultErr, manager.Disconnect())
		}
	}()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		disconnectErr := manager.Disconnect()
		manager = nil
		return errors.Join(disconnectErr, waitWindowsServiceDeletion(ctx, name))
	}
	if err != nil {
		return err
	}
	config, configErr := service.Config()
	closeErr := service.Close()
	if configErr != nil || closeErr != nil {
		return errors.Join(configErr, closeErr)
	}
	if !windowsServiceConfigurationOwnsDefinition(config, definition) {
		return ErrInvalidDefinition
	}
	return nil
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

// RemoveWindowsPreviewService removes one preview only after its declaration
// and SCM command both prove ownership of the supplied runtime state root.
// Missing executables are allowed during this removal-only validation because
// the declaration and SCM command remain the ownership evidence.
func RemoveWindowsPreviewService(ctx context.Context, name, stateRoot string) error {
	if !isWindowsPreviewServiceName(name) || !validWindowsStateRoot(stateRoot) {
		return ErrInvalidDefinition
	}
	if err := ValidateWindowsPreviewServiceOwnership(ctx, name, stateRoot); err != nil {
		return err
	}
	definitionPath := filepath.Join(windowsServiceDefinitionRoot, name+".json")
	if err := (WindowsController{}).Remove(ctx, definitionPath); err != nil {
		return err
	}
	// The service removal and declaration deletion are separate mutations. The
	// declaration may have been replaced while SCM was deleting the service,
	// so prove the exact production declaration again immediately before the
	// file removal instead of relying on the earlier preflight.
	if err := ValidateWindowsPreviewServiceOwnership(ctx, name, stateRoot); err != nil {
		return err
	}
	if _, err := readOwnedWindowsPreviewDefinitionForRemoval(definitionPath, name, stateRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(definitionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(windowsServiceDefinitionRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncServiceDirectory(windowsServiceDefinitionRoot)
}

func readOwnedWindowsPreviewDefinitionForRemoval(path, name, stateRoot string) (windowsServiceDefinition, error) {
	definition, err := readWindowsServiceDefinitionForRemoval(path)
	if err != nil {
		return windowsServiceDefinition{}, err
	}
	if err := validateWindowsPreviewDefinition(path, name, stateRoot, definition); err != nil {
		return windowsServiceDefinition{}, err
	}
	return definition, nil
}

func validWindowsStateRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.VolumeName(path) != ""
}

func sameWindowsServicePath(left, right string) bool {
	return validWindowsStateRoot(left) && validWindowsStateRoot(right) && strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
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

var _ Controller = WindowsController{}

func (d windowsServiceDefinition) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.Executable)
}
