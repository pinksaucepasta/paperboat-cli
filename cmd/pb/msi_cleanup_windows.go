//go:build windows

package main

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
	"strconv"
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

var (
	errMSIServiceOwnership = errors.New("paperboat_msi_service_ownership_conflict")
	errMSIPreviewOwnership = errors.New("paperboat_msi_preview_ownership_conflict")
	errMSIRuntimeResidue   = errors.New("paperboat_msi_runtime_residue")

	msiGetFileAttributes     = windows.GetFileAttributes
	msiServiceAbsenceTimeout = 30 * time.Second
	msiServicePollInterval   = 100 * time.Millisecond
)

type msiCleanupPaths struct {
	InstallRoot      string
	BinaryRoot       string
	RuntimeCurrent   string
	RuntimeRollback  string
	RuntimeStaged    string
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
	return runMSIFullUninstallCleanupWithPaths(ctx, paths, output)
}

func runMSIFullUninstallCleanupWithPaths(ctx context.Context, paths msiCleanupPaths, output io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Runtime slot ownership must be proved before any SCM, declaration, or
	// descriptor mutation. This also makes a missing runtime executable safe:
	// its exact slot and all existing ancestors are still validated.
	if err := preflightMSIRuntimeSlots(paths); err != nil {
		return fmt.Errorf("preflight Paperboat runtime slots: %w", err)
	}
	if err := removePaperboatPreviewServices(ctx, paths, output); err != nil {
		return fmt.Errorf("remove Paperboat dynamic services: %w", err)
	}
	if err := removePaperboatOpenSSHState(ctx, paths, output); err != nil {
		return fmt.Errorf("remove Paperboat OpenSSH state: %w", err)
	}
	if err := removePaperboatRuntimeSlots(ctx, paths, output); err != nil {
		return fmt.Errorf("remove Paperboat runtime slots: %w", err)
	}
	return nil
}

func removePaperboatRuntimeSlots(ctx context.Context, paths msiCleanupPaths, output io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := preflightMSIRuntimeSlots(paths); err != nil {
		return err
	}
	for _, slot := range []struct {
		name string
		path string
	}{
		{name: "runtime-current", path: paths.RuntimeCurrent},
		{name: "runtime-rollback", path: paths.RuntimeRollback},
		{name: "runtime-staged", path: paths.RuntimeStaged},
	} {
		if slot.path == "" {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		removed, err := removeOwnedPaperboatRuntimeSlot(slot.path, paths.InstallRoot)
		if err != nil {
			return fmt.Errorf("remove %s: %w", slot.name, err)
		}
		if removed {
			writeMSICleanupEvent(output, "removed Paperboat runtime slot %s", slot.name)
		}
	}
	return nil
}

func removeOwnedPaperboatRuntimeSlot(path, installRoot string) (bool, error) {
	slotDirectory, releasesDirectory, err := exactMSIRuntimeSlotDirectories(path, installRoot)
	if err != nil {
		return false, err
	}

	for _, directory := range []string{installRoot, releasesDirectory, slotDirectory} {
		exists, validateErr := validateExistingMSIDirectory(directory)
		if validateErr != nil {
			return false, validateErr
		}
		if !exists {
			return false, nil
		}
	}

	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return removeEmptyMSIRuntimeDirectories(slotDirectory, releasesDirectory)
	}
	if statErr != nil {
		return false, statErr
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errMSIServiceOwnership
	}
	attributes, attrErr := msiGetFileAttributes(windows.StringToUTF16Ptr(path))
	if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, errors.Join(errMSIServiceOwnership, attrErr)
	}
	if err := validateMSIRuntimeSlotContents(slotDirectory, filepath.Base(slotDirectory)); err != nil {
		return false, err
	}

	// Revalidate the exact file and every ancestor immediately before deletion.
	// The preflight above protects the mutation plan; this final check protects
	// the planned path from a replacement between preflight and Remove.
	stillOwned, finalErr := revalidateMSIRuntimeSlotBeforeDelete(path, installRoot)
	if finalErr != nil {
		return false, finalErr
	}
	if !stillOwned {
		return removeEmptyMSIRuntimeDirectories(slotDirectory, releasesDirectory)
	}
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return false, removeErr
	}
	_, removeErr := removeEmptyMSIRuntimeDirectories(slotDirectory, releasesDirectory)
	if removeErr != nil {
		return false, removeErr
	}
	return true, nil
}

func revalidateMSIRuntimeSlotBeforeDelete(path, installRoot string) (bool, error) {
	slotDirectory, releasesDirectory, err := exactMSIRuntimeSlotDirectories(path, installRoot)
	if err != nil {
		return false, err
	}
	for _, directory := range []string{installRoot, releasesDirectory, slotDirectory} {
		exists, validateErr := validateExistingMSIDirectory(directory)
		if validateErr != nil {
			return false, validateErr
		}
		if !exists {
			return false, nil
		}
	}
	exists, validateErr := validateMSIRegularFile(path, false)
	if errors.Is(validateErr, os.ErrNotExist) {
		return false, nil
	}
	if validateErr != nil {
		return false, validateErr
	}
	if !exists {
		return false, nil
	}
	if err := validateMSIRuntimeSlotContents(slotDirectory, filepath.Base(slotDirectory)); err != nil {
		return false, err
	}
	return true, nil
}

func exactMSIRuntimeSlotDirectories(path, installRoot string) (slotDirectory, releasesDirectory string, err error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(installRoot) {
		return "", "", errMSIServiceOwnership
	}
	releasesDirectory = filepath.Join(installRoot, "releases")
	for _, slotName := range []string{"runtime-current", "runtime-rollback", "runtime-staged"} {
		expected := filepath.Join(releasesDirectory, slotName, "paperboat-runtime.exe")
		if sameWindowsPath(path, expected) {
			slotDirectory := filepath.Dir(expected)
			if !underWindowsPath(releasesDirectory, installRoot) || !underWindowsPath(slotDirectory, installRoot) {
				return "", "", errMSIServiceOwnership
			}
			return slotDirectory, releasesDirectory, nil
		}
	}
	return "", "", errMSIServiceOwnership
}

func validateExistingMSIDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return true, errMSIServiceOwnership
	}
	return true, validateMSIDirectory(path)
}

func preflightMSIRuntimeSlots(paths msiCleanupPaths) error {
	for _, slot := range []struct {
		name string
		path string
	}{
		{name: "runtime-current", path: paths.RuntimeCurrent},
		{name: "runtime-rollback", path: paths.RuntimeRollback},
		{name: "runtime-staged", path: paths.RuntimeStaged},
	} {
		if slot.path == "" {
			continue
		}
		slotDirectory, releasesDirectory, err := exactMSIRuntimeSlotDirectories(slot.path, paths.InstallRoot)
		if err != nil {
			return fmt.Errorf("validate %s path: %w", slot.name, err)
		}
		for _, directory := range []string{paths.InstallRoot, releasesDirectory, slotDirectory} {
			exists, validateErr := validateExistingMSIDirectory(directory)
			if validateErr != nil {
				return fmt.Errorf("validate %s ancestor %s: %w", slot.name, directory, validateErr)
			}
			if !exists {
				break
			}
		}
		if _, err := validateMSIRegularFile(slot.path, true); err != nil {
			return fmt.Errorf("validate %s executable: %w", slot.name, err)
		}
		exists, validateErr := validateExistingMSIDirectory(slotDirectory)
		if validateErr != nil {
			return fmt.Errorf("revalidate %s slot: %w", slot.name, validateErr)
		}
		if exists {
			if err := validateMSIRuntimeSlotContents(slotDirectory, slot.name); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateMSIRegularFile(path string, allowMissing bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if allowMissing {
			return false, nil
		}
		return false, os.ErrNotExist
	}
	if err != nil {
		return true, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return true, errMSIServiceOwnership
	}
	attributes, attrErr := msiGetFileAttributes(windows.StringToUTF16Ptr(path))
	if attrErr != nil {
		return true, errors.Join(errMSIServiceOwnership, attrErr)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return true, errMSIServiceOwnership
	}
	return true, nil
}

func validateMSIRuntimeSlotContents(slotDirectory, slotName string) error {
	entries, err := os.ReadDir(slotDirectory)
	if err != nil {
		return fmt.Errorf("scan %s slot: %w", slotName, err)
	}
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), "paperboat-runtime.exe") {
			return errors.Join(errMSIRuntimeResidue, errMSIServiceOwnership,
				fmt.Errorf("preserve %s because slot contains unexpected entry %s", slotName, entry.Name()))
		}
	}
	return nil
}

func removeEmptyMSIRuntimeDirectories(slotDirectory, releasesDirectory string) (bool, error) {
	if exists, err := validateExistingMSIDirectory(slotDirectory); err != nil {
		return false, err
	} else if !exists {
		return false, nil
	}
	if err := validateMSIRuntimeSlotContents(slotDirectory, filepath.Base(slotDirectory)); err != nil {
		return false, err
	}
	removedSlot := false
	if err := os.Remove(slotDirectory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
			return false, errors.Join(errMSIRuntimeResidue, errMSIServiceOwnership)
		}
		return false, err
	}
	removedSlot = true

	if exists, err := validateExistingMSIDirectory(releasesDirectory); err != nil {
		return removedSlot, err
	} else if !exists {
		return removedSlot, nil
	}
	if err := os.Remove(releasesDirectory); err != nil && !errors.Is(err, os.ErrNotExist) &&
		!errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
		return removedSlot, err
	}
	return removedSlot, nil
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
		RuntimeCurrent:   filepath.Join(installRoot, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback:  filepath.Join(installRoot, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:    filepath.Join(installRoot, "releases", "runtime-staged", "paperboat-runtime.exe"),
		StateRoot:        stateRoot,
		ServiceRoot:      filepath.Join(stateRoot, "services"),
		OpenSSHRoot:      filepath.Join(programFiles, "OpenSSH"),
		OpenSSHStateRoot: filepath.Join(stateRoot, "ssh"),
	}, nil
}

type msiPreviewServiceCandidate struct {
	name    string
	service *mgr.Service
}

type msiPreviewCleanupFile struct {
	name string
	path string
}

type msiPreviewCleanupPlan struct {
	services     []msiPreviewServiceCandidate
	declarations []msiPreviewCleanupFile
	descriptors  []msiPreviewCleanupFile
}

func msiPreviewOwnershipConflict(format string, args ...any) error {
	return errors.Join(errMSIPreviewOwnership, fmt.Errorf(format, args...))
}

func closeMSIPreviewServiceCandidates(candidates []msiPreviewServiceCandidate) error {
	var result error
	for index := range candidates {
		if candidates[index].service != nil {
			result = errors.Join(result, candidates[index].service.Close())
			candidates[index].service = nil
		}
	}
	return result
}

func removePaperboatPreviewServices(ctx context.Context, paths msiCleanupPaths, output io.Writer) (resultErr error) {
	if err := preflightMSIRuntimeSlots(paths); err != nil {
		return fmt.Errorf("preflight Paperboat runtime slots: %w", err)
	}
	manager, err := mgr.Connect()
	if err != nil {
		return msiPreviewOwnershipConflict("connect SCM while proving Paperboat preview ownership: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()

	plan, err := preflightPaperboatPreviewCleanup(manager, paths, output)
	if err != nil {
		return err
	}
	for index := range plan.services {
		candidate := &plan.services[index]
		if err := validateMSIPreviewServiceOwnership(candidate.service, candidate.name, paths); err != nil {
			return errors.Join(err, closeMSIPreviewServiceCandidates(plan.services[index:]))
		}
		if err := removeSCMService(ctx, manager, candidate.service, candidate.name); err != nil {
			closeErr := closeMSIPreviewServiceCandidates(plan.services[index+1:])
			candidate.service = nil
			return errors.Join(err, closeErr)
		}
		candidate.service = nil
		writeMSICleanupEvent(output, "removed Paperboat dynamic service %s", candidate.name)
	}
	if err := verifyPlannedPreviewDefinitionsRemovedWithContext(ctx, manager, plan.declarations); err != nil {
		return err
	}
	if err := removePlannedPreviewDescriptorsWithPaths(ctx, manager, plan.descriptors, paths, output); err != nil {
		return err
	}
	return removePlannedPreviewDefinitionFilesWithPaths(ctx, manager, plan.declarations, paths, output)
}

func preflightPaperboatPreviewCleanup(manager *mgr.Mgr, paths msiCleanupPaths, output io.Writer) (msiPreviewCleanupPlan, error) {
	plan := msiPreviewCleanupPlan{}
	fail := func(err error) (msiPreviewCleanupPlan, error) {
		return msiPreviewCleanupPlan{}, errors.Join(err, closeMSIPreviewServiceCandidates(plan.services))
	}

	names, err := manager.ListServices()
	if err != nil {
		return fail(msiPreviewOwnershipConflict("list Paperboat preview services while proving ownership: %w", err))
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
			return fail(msiPreviewOwnershipConflict("open %s while proving ownership: %w", name, openErr))
		}
		if ownershipErr := validateMSIPreviewServiceOwnership(service, name, paths); ownershipErr != nil {
			writeMSICleanupEvent(output, "preserving %s because its Paperboat ownership declaration is invalid", name)
			return fail(errors.Join(ownershipErr, service.Close()))
		}
		plan.services = append(plan.services, msiPreviewServiceCandidate{name: name, service: service})
	}

	declarations, err := scanOwnedPreviewDefinitions(paths, output)
	if err != nil {
		return fail(err)
	}
	plan.declarations = declarations
	descriptors, err := scanOwnedPreviewDescriptors(paths)
	if err != nil {
		return fail(err)
	}
	plan.descriptors = descriptors
	return plan, nil
}

func validateMSIPreviewServiceOwnership(service *mgr.Service, name string, paths msiCleanupPaths) error {
	config, configErr := service.Config()
	if configErr != nil {
		return msiPreviewOwnershipConflict("read %s configuration while proving ownership: %w", name, configErr)
	}
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	definition, definitionExists, definitionErr := readMSIServiceDefinition(definitionPath)
	if definitionErr != nil && !errors.Is(definitionErr, os.ErrNotExist) {
		return msiPreviewOwnershipConflict("preserve %s because its Paperboat ownership declaration is invalid: %w", name, definitionErr)
	}
	owned := false
	if definitionExists {
		owned = ownedPaperboatPreviewDefinition(definitionPath, definition, name, paths) && ownedSCMConfiguration(config, definition, paths)
	} else {
		owned = ownedPaperboatPreviewSCMConfiguration(name, config, paths)
	}
	if !owned {
		return msiPreviewOwnershipConflict("preserve %s because SCM ownership could not be proven", name)
	}
	return nil
}

func scanOwnedPreviewDefinitions(paths msiCleanupPaths, output io.Writer) ([]msiPreviewCleanupFile, error) {
	exists, err := validateExistingMSIDirectory(paths.ServiceRoot)
	if errors.Is(err, os.ErrNotExist) || !exists {
		return nil, nil
	}
	if err != nil {
		return nil, msiPreviewOwnershipConflict("validate Paperboat service declaration root: %w", err)
	}
	entries, err := os.ReadDir(paths.ServiceRoot)
	if err != nil {
		return nil, msiPreviewOwnershipConflict("scan Paperboat service declarations while proving ownership: %w", err)
	}
	var files []msiPreviewCleanupFile
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if !isPaperboatPreviewServiceName(name) {
			continue
		}
		path := filepath.Join(paths.ServiceRoot, entry.Name())
		exists, ownershipErr := validateOwnedMSIServiceDefinition(path, name, paths)
		if ownershipErr != nil {
			writeMSICleanupEvent(output, "preserving dynamic declaration %s because it is invalid", entry.Name())
			return nil, msiPreviewOwnershipConflict("preserve dynamic declaration %s because it is invalid: %w", entry.Name(), ownershipErr)
		}
		if !exists {
			return nil, msiPreviewOwnershipConflict("preserve dynamic declaration %s because ownership could not be proven", entry.Name())
		}
		files = append(files, msiPreviewCleanupFile{name: entry.Name(), path: path})
	}
	return files, nil
}

func validateOwnedMSIServiceDefinition(path, name string, paths msiCleanupPaths) (bool, error) {
	rootExists, rootErr := validateExistingMSIDirectory(filepath.Dir(path))
	if rootErr != nil {
		return true, rootErr
	}
	if !rootExists {
		return false, nil
	}
	definition, exists, err := readMSIServiceDefinition(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if !exists || !ownedPaperboatPreviewDefinition(path, definition, name, paths) {
		return exists, errMSIPreviewOwnership
	}
	return true, nil
}

func validateOwnedMSIPreviewDescriptor(path string, paths msiCleanupPaths) (bool, error) {
	rootExists, rootErr := validateExistingMSIDirectory(filepath.Dir(path))
	if rootErr != nil {
		return true, rootErr
	}
	if !rootExists {
		return false, nil
	}
	exists, err := validateMSIRegularFile(path, true)
	if err != nil || !exists {
		return exists, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return true, err
	}
	if len(body) > 64<<10 {
		return true, errMSIPreviewOwnership
	}
	logicalName, definitionName, definitionPath, descriptorErr := parseOwnedMSIPreviewDescriptor(body, paths)
	if descriptorErr != nil {
		return true, errMSIPreviewOwnership
	}
	expectedDescriptor := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json")
	if !sameWindowsPath(path, expectedDescriptor) {
		return true, errMSIPreviewOwnership
	}
	definition, definitionExists, definitionErr := readMSIServiceDefinition(definitionPath)
	if definitionErr != nil {
		return true, definitionErr
	}
	logicalDefinitionName, logicalNameOK := paperboatPreviewLogicalName(definition.Arguments)
	if !definitionExists || !logicalNameOK || logicalDefinitionName != logicalName || !ownedPaperboatPreviewDefinition(definitionPath, definition, definitionName, paths) {
		return true, errMSIPreviewOwnership
	}
	return true, nil
}

func parseOwnedMSIPreviewDescriptor(body []byte, paths msiCleanupPaths) (string, string, string, error) {
	if len(body) > 64<<10 {
		return "", "", "", errMSIPreviewOwnership
	}
	var descriptor msiPreviewDescriptor
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&descriptor) != nil {
		return "", "", "", errMSIPreviewOwnership
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name == "" {
		return "", "", "", errMSIPreviewOwnership
	}
	definitionName := strings.TrimSuffix(filepath.Base(descriptor.ServiceDefinition), filepath.Ext(descriptor.ServiceDefinition))
	definitionPath := filepath.Join(paths.ServiceRoot, definitionName+".json")
	if !isPaperboatPreviewServiceName(definitionName) || !sameWindowsPath(descriptor.ServiceDefinition, definitionPath) {
		return "", "", "", errMSIPreviewOwnership
	}
	return descriptor.Name, definitionName, definitionPath, nil
}

func scanOwnedPreviewDescriptors(paths msiCleanupPaths) ([]msiPreviewCleanupFile, error) {
	activeRoot := filepath.Join(paths.StateRoot, "previews", "active")
	exists, err := validateExistingMSIDirectory(activeRoot)
	if errors.Is(err, os.ErrNotExist) || !exists {
		return nil, nil
	}
	if err != nil {
		return nil, msiPreviewOwnershipConflict("validate Paperboat preview descriptor root: %w", err)
	}
	entries, err := os.ReadDir(activeRoot)
	if err != nil {
		return nil, msiPreviewOwnershipConflict("scan Paperboat preview descriptors while proving ownership: %w", err)
	}
	var files []msiPreviewCleanupFile
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(activeRoot, entry.Name())
		exists, ownershipErr := validateOwnedMSIPreviewDescriptor(path, paths)
		if ownershipErr != nil {
			return nil, msiPreviewOwnershipConflict("preserve preview descriptor %s because its ownership declaration is invalid: %w", entry.Name(), ownershipErr)
		}
		if !exists {
			return nil, msiPreviewOwnershipConflict("preserve preview descriptor %s because it disappeared while ownership was being proven", entry.Name())
		}
		files = append(files, msiPreviewCleanupFile{name: entry.Name(), path: path})
	}
	return files, nil
}

func removePlannedPreviewDescriptorsWithPaths(ctx context.Context, manager *mgr.Mgr, files []msiPreviewCleanupFile, paths msiCleanupPaths, output io.Writer) error {
	for _, file := range files {
		exists, validateErr := validateOwnedMSIPreviewDescriptor(file.path, paths)
		if validateErr != nil {
			return msiPreviewOwnershipConflict("preserve preview descriptor %s because ownership changed before removal: %w", file.name, validateErr)
		}
		if !exists {
			writeMSICleanupEvent(output, "preview descriptor %s was already absent", file.name)
			continue
		}
		body, readErr := os.ReadFile(file.path)
		if readErr != nil {
			return msiPreviewOwnershipConflict("preserve preview descriptor %s because it changed before removal: %w", file.name, readErr)
		}
		serviceName, _, _, parseErr := parseOwnedMSIPreviewDescriptor(body, paths)
		if parseErr != nil {
			return msiPreviewOwnershipConflict("preserve preview descriptor %s because its service ownership changed before removal: %w", file.name, parseErr)
		}
		if err := waitForMSIServiceAbsence(ctx, manager, serviceName); err != nil {
			return err
		}
		exists, validateErr = validateOwnedMSIPreviewDescriptor(file.path, paths)
		if validateErr != nil {
			return msiPreviewOwnershipConflict("preserve preview descriptor %s because ownership changed before removal", file.name)
		}
		if !exists {
			writeMSICleanupEvent(output, "preview descriptor %s was already absent", file.name)
			continue
		}
		if removeErr := os.Remove(file.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove preview descriptor %s: %w", file.name, removeErr)
		}
		writeMSICleanupEvent(output, "removed Paperboat preview descriptor %s", file.name)
	}
	return nil
}

func verifyPlannedPreviewDefinitionsRemovedWithContext(ctx context.Context, manager *mgr.Mgr, files []msiPreviewCleanupFile) error {
	for _, file := range files {
		name := strings.TrimSuffix(file.name, filepath.Ext(file.name))
		if err := waitForMSIServiceAbsence(ctx, manager, name); err != nil {
			return err
		}
	}
	return nil
}

func removePlannedPreviewDefinitionFilesWithPaths(ctx context.Context, manager *mgr.Mgr, files []msiPreviewCleanupFile, paths msiCleanupPaths, output io.Writer) error {
	for _, file := range files {
		name := strings.TrimSuffix(file.name, filepath.Ext(file.name))
		if err := waitForMSIServiceAbsence(ctx, manager, name); err != nil {
			return err
		}
		exists, validateErr := validateOwnedMSIServiceDefinition(file.path, name, paths)
		if validateErr != nil {
			return msiPreviewOwnershipConflict("preserve dynamic service declaration %s because ownership changed before removal: %w", file.name, validateErr)
		}
		if !exists {
			writeMSICleanupEvent(output, "dynamic service declaration %s was already absent", file.name)
			continue
		}
		if removeErr := os.Remove(file.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove dynamic service declaration %s: %w", file.name, removeErr)
		}
		writeMSICleanupEvent(output, "removed Paperboat dynamic service declaration %s", file.name)
	}
	return nil
}

func readMSIServiceDefinition(path string) (msiWindowsServiceDefinition, bool, error) {
	exists, err := validateMSIRegularFile(path, true)
	if errors.Is(err, os.ErrNotExist) || !exists {
		return msiWindowsServiceDefinition{}, false, os.ErrNotExist
	}
	if err != nil {
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
		validPaperboatPreviewArguments(definition.Arguments, name, path, paths)
}

func ownedSCMConfiguration(config mgr.Config, definition msiWindowsServiceDefinition, paths msiCleanupPaths) bool {
	if !isSystemAccount(config.ServiceStartName) || !allowedPaperboatServiceExecutable(definition.Executable, paths) {
		return false
	}
	executable, args, err := decomposeWindowsServiceCommand(config.BinaryPathName)
	if err != nil || !sameWindowsPath(executable, definition.Executable) {
		return false
	}
	return sameStringSlice(args, definition.Arguments)
}

func ownedPaperboatPreviewSCMConfiguration(name string, config mgr.Config, paths msiCleanupPaths) bool {
	if !isSystemAccount(config.ServiceStartName) {
		return false
	}
	executable, args, err := decomposeWindowsServiceCommand(config.BinaryPathName)
	if err != nil || !allowedPaperboatServiceExecutable(executable, paths) {
		return false
	}
	return validPaperboatPreviewArguments(args, name, filepath.Join(paths.ServiceRoot, name+".json"), paths)
}

func validPaperboatPreviewArguments(args []string, serviceName, definitionPath string, paths msiCleanupPaths) bool {
	if len(args) < 10 || !isPaperboatPreviewServiceName(serviceName) || (args[0] != msiPaperboatPreviewCommand && args[0] != msiPaperboatServeCommand && args[0] != msiPaperboatPrivatePreview) {
		return false
	}
	if args[1] != "--state-root" || !sameWindowsPath(args[2], paths.StateRoot) || args[3] != "--name" || args[4] == "" || args[5] != "--descriptor" || args[7] != "--service-definition" || !sameWindowsPath(args[8], definitionPath) {
		return false
	}
	if !strings.EqualFold(serviceName, msiPaperboatServicePrefix+msiPreviewInstance(args[4])) {
		return false
	}
	expectedDescriptor := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(args[4])+".json")
	if !sameWindowsPath(args[6], expectedDescriptor) {
		return false
	}
	index := 9
	if args[0] == msiPaperboatPreviewCommand {
		if index+2 > len(args) || args[index] != "--port" {
			return false
		}
		port, err := strconv.ParseUint(args[index+1], 10, 16)
		if err != nil || port == 0 {
			return false
		}
		index += 2
	}
	if index >= len(args) {
		return false
	}
	switch args[index] {
	case "--indefinite":
		index++
	case "--expires-at":
		if index+2 > len(args) || args[index+1] == "" {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, args[index+1]); err != nil {
			return false
		}
		index += 2
	default:
		return false
	}
	return index == len(args)
}

func paperboatPreviewLogicalName(args []string) (string, bool) {
	if len(args) < 5 || args[3] != "--name" || args[4] == "" {
		return "", false
	}
	return args[4], true
}

func msiPreviewInstance(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:8])
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
	if !strings.EqualFold(filepath.Base(path), "paperboat-runtime.exe") || !sameWindowsPath(path, paths.RuntimeCurrent) {
		return false
	}
	exists, err := validateMSIRegularFile(path, true)
	if errors.Is(err, os.ErrNotExist) || !exists {
		return true
	}
	return err == nil
}

func removeSCMService(ctx context.Context, manager *mgr.Mgr, service *mgr.Service, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if stopErr := stopMSIService(ctx, service); stopErr != nil {
		return fmt.Errorf("stop %s: %w", name, errors.Join(stopErr, service.Close()))
	}
	if deleteErr := service.Delete(); deleteErr != nil && !errors.Is(deleteErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete %s: %w", name, errors.Join(deleteErr, service.Close()))
	}
	if err := service.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return waitForMSIServiceAbsence(ctx, manager, name)
}

func waitForMSIServiceAbsence(ctx context.Context, manager *mgr.Mgr, name string) error {
	return waitForMSIServiceAbsenceWithProbe(ctx, name, func() error {
		probe, err := manager.OpenService(name)
		if probe != nil {
			err = errors.Join(err, probe.Close())
		}
		return err
	})
}

func waitForMSIServiceAbsenceWithProbe(ctx context.Context, name string, probe func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	boundedCtx, cancel := context.WithTimeout(ctx, msiServiceAbsenceTimeout)
	defer cancel()
	for {
		err := probe()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return msiPreviewOwnershipConflict("verify removal of %s: %w", name, err)
		}
		timer := time.NewTimer(msiServicePollInterval)
		select {
		case <-boundedCtx.Done():
			timer.Stop()
			if errors.Is(boundedCtx.Err(), context.DeadlineExceeded) {
				return msiPreviewOwnershipConflict("wait for %s removal: timeout", name)
			}
			return boundedCtx.Err()
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

func paperboatOpenSSHMarkerOwned() (owned bool, resultErr error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, msiPaperboatOpenSSHRegistryPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, key.Close()) }()
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
	return filepath.IsAbs(left) && filepath.IsAbs(right) && filepath.Clean(left) == left && filepath.Clean(right) == right && strings.EqualFold(left, right)
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
	attributes, attrErr := msiGetFileAttributes(windows.StringToUTF16Ptr(path))
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
