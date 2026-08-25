//go:build windows

package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func writeWindowsRemovalTestDefinition(t *testing.T, root, name, executable string, arguments []string) string {
	t.Helper()
	path := filepath.Join(root, name+".json")
	body, err := json.Marshal(windowsServiceDefinition{
		Schema: "paperboat.windows-service/v1", Name: name, DisplayName: name,
		Description: "test", Executable: executable, Arguments: arguments, Account: "SYSTEM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindowsControllerRemoveMissingPreviewDeclarationFailsWhenServiceExists(t *testing.T) {
	previousProbe := windowsServiceProbe
	t.Cleanup(func() { windowsServiceProbe = previousProbe })

	const name = "PaperboatPreview-0123456789abcdef"
	var probedName string
	windowsServiceProbe = func(name string) (bool, error) {
		probedName = name
		return true, nil
	}
	definitionPath := filepath.Join(t.TempDir(), name+".json")

	err := (WindowsController{}).Remove(context.Background(), definitionPath)
	if !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("Remove error = %v, want invalid-definition error", err)
	}
	if probedName != name {
		t.Fatalf("probed service = %q, want %q", probedName, name)
	}
}

func TestWindowsControllerRemoveMissingDeclarationIsIdempotentWhenServiceIsAbsent(t *testing.T) {
	previousProbe := windowsServiceProbe
	t.Cleanup(func() { windowsServiceProbe = previousProbe })

	const name = "PaperboatPreview-0123456789abcdef"
	windowsServiceProbe = func(string) (bool, error) { return false, nil }
	definitionPath := filepath.Join(t.TempDir(), name+".json")

	if err := (WindowsController{}).Remove(context.Background(), definitionPath); err != nil {
		t.Fatalf("Remove error = %v, want nil", err)
	}
}

func TestWindowsPreviewDeclarationDirectoryFailsClosed(t *testing.T) {
	root := t.TempDir()
	name := "PaperboatPreview-0123456789abcdef"
	path := filepath.Join(root, name+".json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsPreviewDeclarationEntry(entries[0]); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("preview declaration directory error = %v, want invalid-definition", err)
	}
}

func TestWindowsRemovalAcceptsMissingRuntimeCurrentFromRealDeclaration(t *testing.T) {
	root := t.TempDir()
	const name = "PaperboatPreview-0123456789abcdef"
	executable := filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe")
	stateRoot := filepath.Join(root, "state")
	path := writeWindowsRemovalTestDefinition(t, root, name, executable, []string{
		"__runtime-preview", "--state-root", stateRoot, "--name", "docs",
	})
	if _, err := os.Stat(executable); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime-current fixture unexpectedly exists: %v", err)
	}
	for _, directory := range []string{filepath.Join(root, "releases"), filepath.Join(root, "releases", "runtime-current")} {
		if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing runtime ancestor %q unexpectedly exists: %v", directory, err)
		}
	}
	if _, err := readWindowsServiceDefinition(path); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("normal definition read error = %v, want invalid-definition", err)
	}
	definition, err := readWindowsServiceDefinitionForRemoval(path)
	if err != nil {
		t.Fatalf("removal definition read error = %v", err)
	}
	if definition.Executable != executable || definition.Name != name {
		t.Fatalf("removal definition = %+v, want executable %q and name %q", definition, executable, name)
	}
	if state, ok := windowsPreviewStateRoot(definition.Arguments); !ok || state != stateRoot {
		t.Fatalf("state root = %q, %v; want %q, true", state, ok, stateRoot)
	}
}

func TestWindowsRemovalOwnershipUsesSCMCommandAndAccount(t *testing.T) {
	root := t.TempDir()
	const name = "PaperboatPreview-0123456789abcdef"
	executable := filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe")
	arguments := []string{"__runtime-preview", "--state-root", filepath.Join(root, "state")}
	path := writeWindowsRemovalTestDefinition(t, root, name, executable, arguments)
	definition, err := readWindowsServiceDefinitionForRemoval(path)
	if err != nil {
		t.Fatal(err)
	}
	want := windows.ComposeCommandLine(append([]string{executable}, arguments...))
	if !windowsServiceConfigurationOwnsDefinition(mgr.Config{BinaryPathName: want, ServiceStartName: "LocalSystem"}, definition) {
		t.Fatal("matching SCM command/account was rejected")
	}
	for _, config := range []mgr.Config{
		{BinaryPathName: windows.ComposeCommandLine([]string{filepath.Join(root, "other.exe")}), ServiceStartName: "LocalSystem"},
		{BinaryPathName: want, ServiceStartName: "Administrator"},
	} {
		if windowsServiceConfigurationOwnsDefinition(config, definition) {
			t.Fatalf("foreign SCM configuration was accepted: %+v", config)
		}
	}
}

func TestWindowsRemovalRejectsTrailingJSON(t *testing.T) {
	root := t.TempDir()
	const name = "PaperboatPreview-0123456789abcdef"
	path := writeWindowsRemovalTestDefinition(t, root, name, filepath.Join(root, "runtime-current.exe"), []string{"__runtime-preview"})
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte(`
{"schema":"paperboat.windows-service/v1"}`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWindowsServiceDefinitionForRemoval(path); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("trailing JSON read error = %v, want invalid-definition", err)
	}
}

func TestWindowsPreviewDeclarationOwnershipIsExact(t *testing.T) {
	const stateRoot = `C:\ProgramData\Paperboat\state`
	const logicalName = "docs"
	serviceName := "PaperboatPreview-" + windowsPreviewInstanceFromName(logicalName)
	definitionPath := filepath.Join(windowsServiceDefinitionRoot, serviceName+".json")
	args := []string{
		"__runtime-preview", "--state-root", stateRoot, "--name", logicalName,
		"--descriptor", filepath.Join(stateRoot, "previews", "active", windowsPreviewInstanceFromName(logicalName)+".json"),
		"--service-definition", definitionPath, "--port", "3000", "--indefinite",
	}
	layout, err := DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	definition := windowsServiceDefinition{
		Schema: "paperboat.windows-service/v1", Name: serviceName, Executable: layout.RuntimeCurrent,
		Arguments: args, Account: "SYSTEM",
	}
	if err := validateWindowsPreviewDefinition(definitionPath, serviceName, stateRoot, definition); err != nil {
		t.Fatalf("valid preview declaration rejected: %v", err)
	}
	for _, mutate := range []func(*windowsServiceDefinition){
		func(d *windowsServiceDefinition) { d.Account = "Administrator" },
		func(d *windowsServiceDefinition) { d.Executable = layout.RuntimeRollback },
		func(d *windowsServiceDefinition) { d.Arguments = append([]string{}, args[:len(args)-1]...) },
		func(d *windowsServiceDefinition) {
			d.Arguments = append([]string{}, args...)
			d.Arguments[6] = filepath.Join(stateRoot, "previews", "active", "foreign.json")
		},
	} {
		candidate := definition
		candidate.Arguments = append([]string(nil), definition.Arguments...)
		mutate(&candidate)
		if err := validateWindowsPreviewDefinition(definitionPath, serviceName, stateRoot, candidate); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("foreign preview declaration accepted: definition=%+v error=%v", candidate, err)
		}
	}
}

func TestWindowsPreviewServiceTerminalStatusRequiresSuccessfulStop(t *testing.T) {
	tests := []struct {
		name   string
		status svc.Status
		want   bool
	}{
		{name: "stopped successfully", status: svc.Status{State: svc.Stopped}, want: true},
		{name: "start pending", status: svc.Status{State: svc.StartPending}},
		{name: "running", status: svc.Status{State: svc.Running}},
		{name: "stop pending", status: svc.Status{State: svc.StopPending}},
		{name: "win32 failure", status: svc.Status{State: svc.Stopped, Win32ExitCode: 1}},
		{name: "service failure", status: svc.Status{State: svc.Stopped, ServiceSpecificExitCode: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := windowsPreviewServiceStatusTerminal(test.status); got != test.want {
				t.Fatalf("terminal = %v, want %v for %+v", got, test.want, test.status)
			}
		})
	}
}

func TestPollWindowsServiceDeletionWaitsThroughMarkedForDelete(t *testing.T) {
	calls := 0
	err := pollWindowsServiceDeletion(context.Background(), 100*time.Millisecond, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return windows.ERROR_SERVICE_MARKED_FOR_DELETE
		}
		return windows.ERROR_SERVICE_DOES_NOT_EXIST
	})
	if err != nil {
		t.Fatalf("poll error = %v", err)
	}
	if calls != 3 {
		t.Fatalf("probe calls = %d, want 3", calls)
	}
}

func TestPollWindowsServiceDeletionBoundsBackgroundContext(t *testing.T) {
	calls := 0
	started := time.Now()
	err := pollWindowsServiceDeletion(context.Background(), 12*time.Millisecond, time.Millisecond, func() error {
		calls++
		return windows.ERROR_SERVICE_MARKED_FOR_DELETE
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("poll error = %v, want deadline exceeded", err)
	}
	if calls == 0 || time.Since(started) > time.Second {
		t.Fatalf("bounded poll calls=%d elapsed=%s", calls, time.Since(started))
	}
}
