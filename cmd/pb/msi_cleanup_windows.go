//go:build windows

package main

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

	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	msiPaperboatOpenSSHRegistryPath = `SOFTWARE\Paperboat\OpenSSH`
	msiPaperboatServicePrefix       = "PaperboatPreview-"
	msiPaperboatServiceSchema       = "paperboat.windows-service/v1"
	msiPaperboatPreviewCommand      = "__runtime-preview"
	msiPaperboatServeCommand        = "__runtime-serve"
	msiPaperboatPrivatePreview      = "__runtime-private-preview"
)

var errMSIServiceOwnership = errors.New("paperboat_msi_service_ownership_conflict")

type msiCleanupPaths struct {
	InstallRoot      string
	BinaryRoot       string
	StateRoot        string
	ServiceRoot      string
	OpenSSHRoot      string
	OpenSSHStateRoot string
}

type msiWindowsServiceDefinition struct {
	Schema      string            `json:"schema"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Executable  string            `json:"executable"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"environment,omitempty"`
	Account     string            `json:"account"`
}

type msiPreviewDescriptor struct {
	Schema            string `json:"schema"`
	Name              string `json:"name"`
	ServiceDefinition string `json:"service_definition"`
}

// msiCleanupCommand is intentionally hidden. It is called only by the
// deferred MSI action while pb.exe is still installed and before RemoveFiles.
func msiCleanupCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "__msi-cleanup",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 1 || args[0] != "--full-uninstall" {
				return fmt.Errorf("__msi-cleanup requires exactly --full-uninstall")
			}
			ctx, cancel := context.WithTimeout(command.Context(), 5*time.Minute)
			defer cancel()
			return runMSIFullUninstallCleanup(ctx, command.ErrOrStderr())
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runMSIFullUninstallCleanup(ctx context.Context, output io.Writer) error {
	paths, err := msiCleanupPathsForCurrentInstall()
	if err != nil {
		return err
	}

	if err := removePaperboatPreviewServices(ctx, paths, output); err != nil {
		return fmt.Errorf("remove Paperboat dynamic services: %w", err)
	}
	if err := removePaperboatOpenSSHState(ctx, paths, output); err != nil {
		return fmt.Errorf("remove Paperboat OpenSSH state: %w", err)
	}
	return nil
}

func msiCleanupPathsForCurrentInstall() (msiCleanupPaths, error) {
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if !filepath.IsAbs(programFiles) || !filepath.IsAbs(programData) {
		return msiCleanupPaths{}, errors.New("Paperboat MSI cleanup could not resolve ProgramFiles and ProgramData")
	}
	installRoot := filepath.Join(programFiles, "Paperboat")
	stateRoot := filepath.Join(programData, "Paperboat")
	return msiCleanupPaths{
		InstallRoot:      installRoot,
		BinaryRoot:       filepath.Join(installRoot, "bin"),
		StateRoot:        stateRoot,
		ServiceRoot:      filepath.Join(stateRoot, "services"),
		OpenSSHRoot:      filepath.Join(programFiles, "OpenSSH"),
		OpenSSHStateRoot: filepath.Join(stateRoot, "ssh"),
	}, nil
}

func removePaperboatPreviewServices(ctx context.Context, paths msiCleanupPaths, output io.Writer) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	names, err := manager.ListServices()
	if err != nil {
		return err
	}
	for _, name := range names {
		if !isPaperboatPreviewServiceName(name) {
			continue
		}
		service, openErr := manager.OpenService(name)
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if openErr != nil {
			return fmt.Errorf("open %s: %w", name, openErr)
		}
		config, configErr := service.Config()
		if configErr != nil {
			_ = service.Close()
			return fmt.Errorf("read %s configuration: %w", name, configErr)
		}

		definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
		definition, definitionExists, definitionErr := readMSIServiceDefinition(definitionPath)
		if definitionErr != nil && !errors.Is(definitionErr, os.ErrNotExist) {
			writeMSICleanupEvent(output, "preserving %s because its Paperboat ownership declaration is invalid", name)
			_ = service.Close()
			continue
		}

		owned := false
		if definitionExists {
			owned = ownedPaperboatPreviewDefinition(definitionPath, definition, name, paths) && ownedSCMConfiguration(config, definition, paths)
		} else {
			owned = ownedPaperboatPreviewSCMConfiguration(name, config, paths)
		}
		if !owned {
			writeMSICleanupEvent(output, "preserving %s because SCM ownership could not be proven", name)
			_ = service.Close()
			continue
		}

		if err := removeSCMService(ctx, manager, service, name); err != nil {
			return err
		}
		writeMSICleanupEvent(output, "removed Paperboat dynamic service %s", name)
	}

	if err := removeOwnedPreviewDescriptors(paths, output); err != nil {
		return err
	}
	return removeOwnedPreviewDefinitions(ctx, manager, paths, output)
}

func removeOwnedPreviewDefinitions(ctx context.Context, manager *mgr.Mgr, paths msiCleanupPaths, output io.Writer) error {
	entries, err := os.ReadDir(paths.ServiceRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateMSIDirectory(paths.ServiceRoot); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if !isPaperboatPreviewServiceName(name) {
			continue
		}
		path := filepath.Join(paths.ServiceRoot, entry.Name())
		definition, exists, readErr := readMSIServiceDefinition(path)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			writeMSICleanupEvent(output, "preserving dynamic declaration %s because it is invalid", entry.Name())
			continue
		}
		if !exists || !ownedPaperboatPreviewDefinition(path, definition, name, paths) {
			continue
		}
		service, openErr := manager.OpenService(name)
		if openErr == nil {
			_ = service.Close()
			return fmt.Errorf("owned dynamic service %s still exists after cleanup", name)
		}
		if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) && !errors.Is(openErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("verify removal of %s: %w", name, openErr)
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove dynamic service declaration %s: %w", entry.Name(), removeErr)
		}
		writeMSICleanupEvent(output, "removed Paperboat dynamic service declaration %s", entry.Name())
	}
	return nil
}

func removeOwnedPreviewDescriptors(paths msiCleanupPaths, output io.Writer) error {
	activeRoot := filepath.Join(paths.StateRoot, "previews", "active")
	entries, err := os.ReadDir(activeRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateMSIDirectory(activeRoot); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(activeRoot, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return statErr
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil || len(body) > 64<<10 {
			continue
		}
		var descriptor msiPreviewDescriptor
		if json.Unmarshal(body, &descriptor) != nil || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name == "" {
			continue
		}
		definitionName := strings.TrimSuffix(filepath.Base(descriptor.ServiceDefinition), filepath.Ext(descriptor.ServiceDefinition))
		definitionPath := filepath.Join(paths.ServiceRoot, definitionName+".json")
		if !isPaperboatPreviewServiceName(definitionName) || !sameWindowsPath(descriptor.ServiceDefinition, definitionPath) {
			continue
		}
		definition, definitionExists, definitionErr := readMSIServiceDefinition(definitionPath)
		if definitionExists && (definitionErr != nil || !ownedPaperboatPreviewDefinition(definitionPath, definition, definitionName, paths)) {
			continue
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove preview descriptor %s: %w", entry.Name(), removeErr)
		}
		writeMSICleanupEvent(output, "removed Paperboat preview descriptor %s", entry.Name())
	}
	return nil
}

func readMSIServiceDefinition(path string) (msiWindowsServiceDefinition, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return msiWindowsServiceDefinition{}, false, os.ErrNotExist
	}
	if err != nil {
		return msiWindowsServiceDefinition{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return msiWindowsServiceDefinition{}, true, errMSIServiceOwnership
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return msiWindowsServiceDefinition{}, true, err
	}
	if len(body) > 64<<10 {
		return msiWindowsServiceDefinition{}, true, errMSIServiceOwnership
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var definition msiWindowsServiceDefinition
	if err := decoder.Decode(&definition); err != nil {
		return msiWindowsServiceDefinition{}, true, errMSIServiceOwnership
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return msiWindowsServiceDefinition{}, true, errMSIServiceOwnership
	}
	return definition, true, nil
}

func ownedPaperboatPreviewDefinition(path string, definition msiWindowsServiceDefinition, name string, paths msiCleanupPaths) bool {
	return sameWindowsPath(path, filepath.Join(paths.ServiceRoot, name+".json")) &&
		definition.Schema == msiPaperboatServiceSchema &&
		strings.EqualFold(definition.Name, name) &&
		isSystemAccount(definition.Account) &&
		allowedPaperboatServiceExecutable(definition.Executable, paths) &&
		validPaperboatPreviewArguments(definition.Arguments, path)
}

func ownedSCMConfiguration(config mgr.Config, definition msiWindowsServiceDefinition, paths msiCleanupPaths) bool {
	if !isSystemAccount(config.ServiceStartName) || !allowedPaperboatServiceExecutable(definition.Executable, paths) {
		return false
	}
	executable, args, err := decomposeWindowsServiceCommand(config.BinaryPathName)
	if err != nil || !sameWindowsPath(executable, definition.Executable) {
		return false
	}
	// Older Paperboat Windows service definitions lost their arguments when
	// updated in SCM. A valid declaration remains authoritative for uninstall,
	// but any arguments still present must agree exactly with that declaration.
	return len(args) == 0 || sameStringSlice(args, definition.Arguments)
}

func ownedPaperboatPreviewSCMConfiguration(name string, config mgr.Config, paths msiCleanupPaths) bool {
	if !isSystemAccount(config.ServiceStartName) {
		return false
	}
	executable, args, err := decomposeWindowsServiceCommand(config.BinaryPathName)
	if err != nil || !allowedPaperboatServiceExecutable(executable, paths) {
		return false
	}
	return validPaperboatPreviewArguments(args, filepath.Join(paths.ServiceRoot, name+".json"))
}

func validPaperboatPreviewArguments(args []string, definitionPath string) bool {
	if len(args) == 0 || (args[0] != msiPaperboatPreviewCommand && args[0] != msiPaperboatServeCommand && args[0] != msiPaperboatPrivatePreview) {
		return false
	}
	count := 0
	for index, arg := range args {
		if arg != "--service-definition" {
			continue
		}
		count++
		if index+1 >= len(args) || !sameWindowsPath(args[index+1], definitionPath) {
			return false
		}
	}
	return count == 1
}

func decomposeWindowsServiceCommand(command string) (string, []string, error) {
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || len(args) == 0 {
		return "", nil, errMSIServiceOwnership
	}
	return args[0], args[1:], nil
}

func allowedPaperboatServiceExecutable(path string, paths msiCleanupPaths) bool {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	if base != "pb.exe" && base != "paperboat-runtime.exe" && base != "paperboat-hostd.exe" && base != "paperboat-updater.exe" {
		return false
	}
	if !underWindowsPath(path, paths.BinaryRoot) &&
		!underWindowsPath(path, filepath.Join(paths.StateRoot, "updates", "current")) &&
		!underWindowsPath(path, filepath.Join(paths.StateRoot, "updates", "rollback")) {
		return false
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return attrErr == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func removeSCMService(ctx context.Context, manager *mgr.Mgr, service *mgr.Service, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := stopMSIService(ctx, service); err != nil {
		_ = service.Close()
		return fmt.Errorf("stop %s: %w", name, err)
	}
	if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		_ = service.Close()
		return fmt.Errorf("delete %s: %w", name, err)
	}
	if err := service.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		probe, err := manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("wait for %s removal: %w", name, err)
		}
		if probe != nil {
			_ = probe.Close()
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return fmt.Errorf("wait for %s removal: timeout", name)
		case <-timer.C:
		}
	}
}

func stopMSIService(ctx context.Context, service *mgr.Service) error {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
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
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return errors.New("service stop timeout")
		case <-timer.C:
		}
	}
}

func removePaperboatOpenSSHState(ctx context.Context, paths msiCleanupPaths, output io.Writer) error {
	owned, err := paperboatOpenSSHMarkerOwned()
	if err != nil {
		return err
	}
	if !owned {
		writeMSICleanupEvent(output, "preserving PaperboatSshd and OpenSSH state because MSI ownership is not proven")
		return nil
	}
	config := windowsopenssh.DefaultConfig(nil)
	config.InstallRoot = paths.OpenSSHRoot
	config.StateRoot = paths.OpenSSHStateRoot
	if err := windowsopenssh.RemovePaperboatState(ctx, config); err != nil {
		if errors.Is(err, windowsopenssh.ErrServiceOwnership) {
			writeMSICleanupEvent(output, "preserving PaperboatSshd and OpenSSH state because service ownership changed")
			return nil
		}
		return err
	}
	writeMSICleanupEvent(output, "removed Paperboat-owned PaperboatSshd state; shared OpenSSH package preserved")
	return nil
}

func paperboatOpenSSHMarkerOwned() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, msiPaperboatOpenSSHRegistryPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	required := map[string]string{
		"PackageId":              windowsopenssh.PackageID,
		"Service":                windowsopenssh.ServiceName,
		"Provisioner":            "Paperboat host setup",
		"CapabilityInstallation": "never",
		"ExistingSystemSshd":     "preserve",
	}
	for name, expected := range required {
		value, _, valueErr := key.GetStringValue(name)
		if valueErr != nil || value != expected {
			return false, nil
		}
	}
	if stateRoot, _, valueErr := key.GetStringValue("StateRoot"); valueErr == nil {
		programData := strings.TrimSpace(os.Getenv("ProgramData"))
		if !sameWindowsPath(stateRoot, filepath.Join(programData, "Paperboat", "ssh")) {
			return false, nil
		}
	} else if valueErr != registry.ErrNotExist {
		return false, valueErr
	}
	return true, nil
}

func isPaperboatPreviewServiceName(name string) bool {
	if !strings.HasPrefix(name, msiPaperboatServicePrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, msiPaperboatServicePrefix)
	if len(suffix) != 16 {
		return false
	}
	for _, char := range suffix {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func isSystemAccount(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "SYSTEM") || strings.EqualFold(strings.TrimSpace(value), "LocalSystem") || strings.EqualFold(strings.TrimSpace(value), `NT AUTHORITY\SYSTEM`)
}

func sameWindowsPath(left, right string) bool {
	return filepath.IsAbs(left) && filepath.IsAbs(right) && strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func underWindowsPath(path, root string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(root) {
		return false
	}
	path = strings.TrimRight(filepath.Clean(path), `\`)
	root = strings.TrimRight(filepath.Clean(root), `\`)
	if strings.EqualFold(path, root) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(root)+`\`)
}

func validateMSIDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errMSIServiceOwnership
	}
	attributes, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errMSIServiceOwnership, attrErr)
	}
	return nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func writeMSICleanupEvent(output io.Writer, format string, args ...any) {
	if output == nil {
		return
	}
	_, _ = fmt.Fprintf(output, "paperboat-msi-cleanup: "+format+"\n", args...)
}
