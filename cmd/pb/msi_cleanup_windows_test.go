//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestMSIPreviewOwnershipRequiresExactPaperboatDeclaration(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:    root,
		BinaryRoot:     filepath.Join(root, "bin"),
		RuntimeCurrent: filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		StateRoot:      filepath.Join(root, "state"),
		ServiceRoot:    filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(paths.ServiceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := paths.RuntimeCurrent
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	logicalName := "fixture"
	name := msiPaperboatServicePrefix + msiPreviewInstance(logicalName)
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: executable,
		Arguments: []string{
			msiPaperboatPreviewCommand,
			"--state-root", paths.StateRoot,
			"--name", logicalName,
			"--descriptor", descriptorPath,
			"--service-definition", definitionPath,
			"--port", "38123",
			"--indefinite",
		},
		Account: "SYSTEM",
	}
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(definitionPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := readMSIServiceDefinition(definitionPath)
	if err != nil || !exists || !ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths) {
		t.Fatalf("owned definition exists=%t err=%v definition=%+v", exists, err, loaded)
	}

	loaded.Arguments[loadedArgumentIndex(loaded.Arguments, "--service-definition")+1] = filepath.Join(paths.ServiceRoot, "PaperboatPreview-ffffffffffffffff.json")
	if ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths) {
		t.Fatal("definition with a different service declaration path was accepted")
	}
	loaded, _, err = readMSIServiceDefinition(definitionPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Arguments[loadedArgumentIndex(loaded.Arguments, "--name")+1] = "foreign"
	if ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths) {
		t.Fatal("definition whose logical name is not hash-bound to the service was accepted")
	}
}

func TestMSIPreviewOwnershipRejectsLookalikeNamesAndExecutables(t *testing.T) {
	for _, name := range []string{"PaperboatPreview-0123456789abcde", "PaperboatPreview-0123456789abcdef0", "PaperboatPreview-0123456789ABCDEf"} {
		if isPaperboatPreviewServiceName(name) {
			t.Fatalf("lookalike service name accepted: %s", name)
		}
	}
	paths := msiCleanupPaths{BinaryRoot: `C:\Program Files\Paperboat\bin`, StateRoot: `C:\ProgramData\Paperboat`, ServiceRoot: `C:\ProgramData\Paperboat\services`}
	if allowedPaperboatServiceExecutable(`C:\Program Files\PaperboatEvil\bin\pb.exe`, paths) {
		t.Fatal("lookalike executable root accepted")
	}
}

func TestMSIPreviewCleanupRecognizesRuntimeCurrentOnly(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:    root,
		BinaryRoot:     filepath.Join(root, "bin"),
		RuntimeCurrent: filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		StateRoot:      filepath.Join(root, "state"),
		ServiceRoot:    filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RuntimeCurrent, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}

	if !allowedPaperboatServiceExecutable(paths.RuntimeCurrent, paths) {
		t.Fatal("production runtime-current executable was not recognized as owned")
	}
	if !ownedMSIPreviewTestDefinition(t, paths, paths.RuntimeCurrent) {
		t.Fatal("production runtime-current service declaration was not recognized as owned")
	}
	for _, legacy := range []string{
		filepath.Join(paths.BinaryRoot, "pb.exe"),
		filepath.Join(paths.StateRoot, "updates", "current", "paperboat-runtime.exe"),
		filepath.Join(paths.StateRoot, "updates", "rollback", "paperboat-runtime.exe"),
	} {
		if allowedPaperboatServiceExecutable(legacy, paths) {
			t.Fatalf("legacy preview executable path was accepted: %s", legacy)
		}
	}

	foreign := filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	if allowedPaperboatServiceExecutable(foreign, paths) {
		t.Fatal("foreign runtime release slot was accepted")
	}
	if ownedMSIPreviewTestDefinition(t, paths, foreign) {
		t.Fatal("foreign runtime release declaration would be removed")
	}

	malformed := filepath.Join(root, "releases", "runtime-current", "not-paperboat-runtime.exe")
	if err := os.WriteFile(malformed, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	if allowedPaperboatServiceExecutable(malformed, paths) {
		t.Fatal("malformed runtime-current executable name was accepted")
	}
	if ownedMSIPreviewTestDefinition(t, paths, malformed) {
		t.Fatal("malformed runtime-current declaration would be removed")
	}

	directory := filepath.Join(root, "releases", "runtime-current", "paperboat-hostd.exe")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if allowedPaperboatServiceExecutable(directory, paths) {
		t.Fatal("non-regular runtime-current executable was accepted")
	}
}

func TestMSIPreviewOwnershipRejectsMismatchedSCMAccountAndArgs(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:    root,
		RuntimeCurrent: filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		StateRoot:      filepath.Join(root, "state"),
		ServiceRoot:    filepath.Join(root, "state", "services"),
	}
	logicalName := "fixture"
	name := msiPaperboatServicePrefix + msiPreviewInstance(logicalName)
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: paths.RuntimeCurrent,
		Arguments:  []string{msiPaperboatPreviewCommand, "--state-root", paths.StateRoot, "--name", logicalName, "--descriptor", filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json"), "--service-definition", definitionPath, "--port", "38123", "--indefinite"},
		Account:    "SYSTEM",
	}
	validCommand := windows.EscapeArg(paths.RuntimeCurrent) + " " + strings.Join(quoteWindowsTestArgs(definition.Arguments), " ")
	valid := mgr.Config{ServiceStartName: "LocalSystem", BinaryPathName: validCommand}
	if !ownedSCMConfiguration(valid, definition, paths) {
		t.Fatal("matching SCM configuration was not recognized as owned")
	}
	accountMismatch := valid
	accountMismatch.ServiceStartName = "NT AUTHORITY\\LocalService"
	if ownedSCMConfiguration(accountMismatch, definition, paths) {
		t.Fatal("mismatched SCM account was accepted")
	}
	argsMismatch := valid
	argsMismatch.BinaryPathName = windows.EscapeArg(paths.RuntimeCurrent) + " " + msiPaperboatPreviewCommand + " --unexpected-definition " + windows.EscapeArg(definitionPath)
	if ownedSCMConfiguration(argsMismatch, definition, paths) {
		t.Fatal("mismatched SCM arguments were accepted")
	}
}

func TestMSIRuntimeSlotCleanupRejectsNonEmptySlotResidue(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
	}
	for _, path := range []string{paths.RuntimeCurrent, paths.RuntimeRollback, paths.RuntimeStaged} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	foreign := filepath.Join(filepath.Dir(paths.RuntimeCurrent), "foreign.exe")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removePaperboatRuntimeSlots(nil, paths, nil); !errors.Is(err, errMSIRuntimeResidue) {
		t.Fatalf("runtime residue cleanup err=%v, want typed residue failure", err)
	}
	for _, path := range []string{paths.RuntimeCurrent, paths.RuntimeRollback, paths.RuntimeStaged} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("runtime slot was mutated at %s: %v", path, err)
		}
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign file was removed with runtime slot: %v", err)
	}

	malformed := filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe")
	if err := os.MkdirAll(malformed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removePaperboatRuntimeSlots(nil, msiCleanupPaths{RuntimeCurrent: malformed}, nil); !errors.Is(err, errMSIServiceOwnership) {
		t.Fatalf("malformed runtime slot cleanup err=%v, want ownership failure", err)
	}
	if info, err := os.Lstat(malformed); err != nil || !info.IsDir() {
		t.Fatalf("malformed runtime slot was not preserved: info=%v err=%v", info, err)
	}
}

func TestMSIRuntimeSlotCleanupRemovesMissingFileEmptySlotDirectory(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}

	removed, err := removeOwnedPaperboatRuntimeSlot(paths.RuntimeCurrent, paths.InstallRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("empty runtime-current slot directory was not removed")
	}
	if _, err := os.Lstat(filepath.Dir(paths.RuntimeCurrent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty runtime-current slot directory remains: %v", err)
	}
}

func TestMSIRuntimeSlotFinalValidationRejectsReparseReplacement(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:    root,
		RuntimeCurrent: filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RuntimeCurrent, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := msiGetFileAttributes
	t.Cleanup(func() { msiGetFileAttributes = previous })
	msiGetFileAttributes = func(path *uint16) (uint32, error) {
		if strings.EqualFold(windows.UTF16PtrToString(path), paths.RuntimeCurrent) {
			return windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
		}
		return previous(path)
	}
	if owned, err := revalidateMSIRuntimeSlotBeforeDelete(paths.RuntimeCurrent, paths.InstallRoot); !errors.Is(err, errMSIServiceOwnership) || owned {
		t.Fatalf("final runtime validation = (%t, %v), want false and ownership error", owned, err)
	}
}

func ownedMSIPreviewTestDefinition(t *testing.T, paths msiCleanupPaths, executable string) bool {
	t.Helper()
	if err := os.MkdirAll(paths.ServiceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	logicalName := "fixture"
	name := msiPaperboatServicePrefix + msiPreviewInstance(logicalName)
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: executable,
		Arguments: []string{
			msiPaperboatPreviewCommand,
			"--state-root", paths.StateRoot,
			"--name", logicalName,
			"--descriptor", filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json"),
			"--service-definition", definitionPath,
			"--port", "38123",
			"--indefinite",
		},
		Account: "SYSTEM",
	}
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(definitionPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(definitionPath)
	loaded, exists, err := readMSIServiceDefinition(definitionPath)
	return err == nil && exists && ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths)
}

func loadedArgumentIndex(args []string, value string) int {
	for index, arg := range args {
		if arg == value {
			return index
		}
	}
	return -1
}

func quoteWindowsTestArgs(args []string) []string {
	quoted := make([]string, len(args))
	for index, arg := range args {
		quoted[index] = windows.EscapeArg(arg)
	}
	return quoted
}

func TestWaitForMSIServiceAbsencePollsMarkedForDeleteUntilAbsent(t *testing.T) {
	previousInterval := msiServicePollInterval
	msiServicePollInterval = time.Millisecond
	t.Cleanup(func() { msiServicePollInterval = previousInterval })
	responses := []error{
		windows.ERROR_SERVICE_MARKED_FOR_DELETE,
		windows.ERROR_SERVICE_MARKED_FOR_DELETE,
		windows.ERROR_SERVICE_DOES_NOT_EXIST,
	}
	probes := 0
	err := waitForMSIServiceAbsenceWithProbe(context.Background(), "PaperboatPreview-0123456789abcdef", func() error {
		probes++
		return responses[min(probes-1, len(responses)-1)]
	})
	if err != nil {
		t.Fatalf("wait returned error: %v", err)
	}
	if probes != len(responses) {
		t.Fatalf("probe count=%d, want %d", probes, len(responses))
	}
}

func TestWaitForMSIServiceAbsenceBoundsBackgroundContext(t *testing.T) {
	previousTimeout := msiServiceAbsenceTimeout
	previousInterval := msiServicePollInterval
	msiServiceAbsenceTimeout = 5 * time.Millisecond
	msiServicePollInterval = time.Millisecond
	t.Cleanup(func() {
		msiServiceAbsenceTimeout = previousTimeout
		msiServicePollInterval = previousInterval
	})
	err := waitForMSIServiceAbsenceWithProbe(nil, "PaperboatPreview-0123456789abcdef", func() error {
		return windows.ERROR_SERVICE_MARKED_FOR_DELETE
	})
	if !errors.Is(err, errMSIPreviewOwnership) {
		t.Fatalf("wait error=%v, want bounded ownership failure", err)
	}
}

func TestMSIServiceDefinitionRejectsReparseAttribute(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "PaperboatPreview-0123456789abcdef.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.windows-service/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := msiGetFileAttributes
	msiGetFileAttributes = func(*uint16) (uint32, error) {
		return windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
	}
	t.Cleanup(func() { msiGetFileAttributes = previous })
	_, exists, err := readMSIServiceDefinition(path)
	if !exists || !errors.Is(err, errMSIServiceOwnership) {
		t.Fatalf("reparse declaration exists=%t err=%v, want ownership failure", exists, err)
	}
}

func TestMSIPreviewDescriptorRejectsReparseAttribute(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "descriptor.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.preview-runtime/v1","name":"fixture"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := msiGetFileAttributes
	msiGetFileAttributes = func(*uint16) (uint32, error) {
		return windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
	}
	t.Cleanup(func() { msiGetFileAttributes = previous })
	exists, err := validateOwnedMSIPreviewDescriptor(path, msiCleanupPaths{StateRoot: root})
	if !exists || !errors.Is(err, errMSIServiceOwnership) {
		t.Fatalf("reparse descriptor exists=%t err=%v, want ownership failure", exists, err)
	}
}

func TestMSIPreviewDescriptorRequiresHashBoundPathAndStrictJSON(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{StateRoot: root, ServiceRoot: filepath.Join(root, "services")}
	logicalName := "fixture"
	serviceName := msiPaperboatServicePrefix + msiPreviewInstance(logicalName)
	definitionPath := filepath.Join(paths.ServiceRoot, serviceName+".json")
	valid := msiPreviewDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              logicalName,
		BindAddress:       "127.0.0.1",
		Port:              38123,
		ServiceGeneration: 1787503345680,
		Indefinite:        true,
		ServiceDefinition: definitionPath,
	}
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(paths.StateRoot, "previews", "active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(active, "wrong.json")
	if err := os.WriteFile(wrongPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if exists, err := validateOwnedMSIPreviewDescriptor(wrongPath, paths); !exists || !errors.Is(err, errMSIPreviewOwnership) {
		t.Fatalf("wrong descriptor path exists=%t err=%v, want ownership failure", exists, err)
	}
	validPath := filepath.Join(active, msiPreviewInstance(logicalName)+".json")
	unknown := strings.TrimSuffix(string(body), "}") + `,"unexpected":true}`
	if err := os.WriteFile(validPath, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if exists, err := validateOwnedMSIPreviewDescriptor(validPath, paths); !exists || !errors.Is(err, errMSIPreviewOwnership) {
		t.Fatalf("unknown descriptor field exists=%t err=%v, want ownership failure", exists, err)
	}
	if err := os.WriteFile(validPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	logical, definition, resolved, err := parseOwnedMSIPreviewDescriptor(body, paths)
	if err != nil {
		t.Fatalf("parse full production descriptor: %v", err)
	}
	if logical != logicalName || definition != serviceName || !sameWindowsPath(resolved, definitionPath) {
		t.Fatalf("parsed descriptor=(%q,%q,%q), want (%q,%q,%q)", logical, definition, resolved, logicalName, serviceName, definitionPath)
	}
}

func TestMSIServiceDefinitionRejectsUnknownAndTrailingJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "PaperboatPreview-0123456789abcdef.json")
	valid := `{"schema":"paperboat.windows-service/v1","name":"PaperboatPreview-0123456789abcdef","display_name":"preview","description":"preview","executable":"C:\\Paperboat\\releases\\runtime-current\\paperboat-runtime.exe","arguments":["__runtime-preview","--service-definition","C:\\Paperboat\\services\\PaperboatPreview-0123456789abcdef.json"],"account":"SYSTEM"}`
	for name, body := range map[string]string{
		"unknown":  strings.TrimSuffix(valid, "}") + `,"unexpected":true}`,
		"trailing": valid + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, exists, err := readMSIServiceDefinition(path)
			if !exists || !errors.Is(err, errMSIServiceOwnership) {
				t.Fatalf("exists=%t err=%v, want strict ownership failure", exists, err)
			}
		})
	}
}
