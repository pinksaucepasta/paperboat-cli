//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsServiceInstanceNamesAreBoundedAndRoleScoped(t *testing.T) {
	const instance = "trk34-a1b2_c3"
	for _, test := range []struct {
		kind string
		base string
	}{
		{kind: HostdKind, base: "PaperboatHostd"},
		{kind: UpdaterKind, base: "PaperboatUpdated"},
		{kind: HostKind, base: "PaperboatHost"},
		{kind: ConfigKind, base: "PaperboatRuntimeConfig"},
		{kind: DaemonKind, base: "PaperboatLocalDaemon"},
		{kind: WorkerKind, base: "PaperboatRuntime"},
	} {
		name := windowsServiceName(test.kind, instance)
		want := test.base + "-" + instance
		if name != want {
			t.Fatalf("windowsServiceName(%q, %q)=%q, want %q", test.kind, instance, name, want)
		}
		path := filepath.Join(windowsServiceDefinitionRoot, name+".json")
		parsed, err := windowsServiceNameFromDefinitionPath(path)
		if err != nil || parsed != name {
			t.Fatalf("windowsServiceNameFromDefinitionPath(%q)=%q, %v; want %q", path, parsed, err, name)
		}
	}
	if got := windowsServiceName(HostdKind, ""); got != "PaperboatHostd" {
		t.Fatalf("empty instance changed production service name: %q", got)
	}
	for _, instance := range []string{" leading", "trailing ", "bad\\name", "bad/name", strings.Repeat("x", windowsServiceInstanceMax+1)} {
		if safeWindowsServiceKind(HostdKind, instance) {
			t.Fatalf("unsafe instance accepted: %q", instance)
		}
	}
	for _, path := range []string{
		filepath.Join(windowsServiceDefinitionRoot, "PaperboatHostd-.json"),
		filepath.Join(windowsServiceDefinitionRoot, "PaperboatHostd-foreign.name.json"),
		filepath.Join(windowsServiceDefinitionRoot, "Foreign-"+instance+".json"),
	} {
		if _, err := windowsServiceNameFromDefinitionPath(path); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("foreign/empty service path accepted: %q err=%v", path, err)
		}
	}
}

func TestNativeWindowsRebootMetadataValidationIsFailClosed(t *testing.T) {
	instance := "trk34-reboot-00112233445566778899"
	root := `C:\ProgramData\paperboat-trk34-123456`
	suffix := strings.TrimPrefix(instance, "trk34-reboot-")
	metadata := nativeWindowsRebootMetadata{
		Schema:                  nativeWindowsRebootMetadataSchema,
		Instance:                instance,
		OwnerSID:                "S-1-5-21-1-2-3-4",
		ExecutableRoot:          root,
		Executable:              filepath.Join(root, "service.test.exe"),
		ConfigRoot:              filepath.Join(root, "config"),
		StateRoot:               filepath.Join(root, "lifecycle"),
		HostdName:               windowsServiceName(HostdKind, instance),
		UpdaterName:             windowsServiceName(UpdaterKind, instance),
		HostdDefinition:         filepath.Join(windowsServiceDefinitionRoot, windowsServiceName(HostdKind, instance)+".json"),
		UpdaterDefinition:       filepath.Join(windowsServiceDefinitionRoot, windowsServiceName(UpdaterKind, instance)+".json"),
		HostdDefinitionSHA256:   strings.Repeat("a", 64),
		UpdaterDefinitionSHA256: strings.Repeat("b", 64),
		HostdHealth:             "127.0.0.1:12345",
		UpdaterHealth:           "127.0.0.1:12346",
		HostdWorkloadFailure:    filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-hostd-workload.failure.txt"),
		UpdaterWorkloadFailure:  filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-updater-workload.failure.txt"),
	}
	// The shape validator receives the platform temp root implicitly but touches
	// neither SCM nor the filesystem.
	if err := validateNativeWindowsRebootMetadataShape(metadata, metadata.metadataPath(), `C:\ProgramData`); err != nil {
		t.Fatalf("valid reboot metadata rejected: %v", err)
	}
	mutations := []func(*nativeWindowsRebootMetadata){
		func(candidate *nativeWindowsRebootMetadata) { candidate.Schema = "foreign" },
		func(candidate *nativeWindowsRebootMetadata) { candidate.Instance = "trk34-reboot-" },
		func(candidate *nativeWindowsRebootMetadata) {
			candidate.Executable = filepath.Join(candidate.ExecutableRoot, "foreign.exe")
		},
		func(candidate *nativeWindowsRebootMetadata) { candidate.HostdName = "PaperboatHostd-foreign" },
		func(candidate *nativeWindowsRebootMetadata) { candidate.HostdDefinitionSHA256 = "short" },
		func(candidate *nativeWindowsRebootMetadata) { candidate.HostdHealth = "192.0.2.1:12345" },
		func(candidate *nativeWindowsRebootMetadata) {
			candidate.HostdWorkloadFailure = filepath.Join(`C:\Users\tester`, filepath.Base(candidate.HostdWorkloadFailure))
		},
		func(candidate *nativeWindowsRebootMetadata) { candidate.OwnerSID = "not-a-sid" },
	}
	for index, mutate := range mutations {
		candidate := metadata
		mutate(&candidate)
		if err := validateNativeWindowsRebootMetadataShape(candidate, candidate.metadataPath(), `C:\ProgramData`); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("metadata mutation %d accepted: %v", index, err)
		}
	}
}

func TestWindowsServiceConfigTransitionRestoresOwnedDeclaration(t *testing.T) {
	layout, err := DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	old := windowsServiceDefinition{
		Schema: "paperboat.windows-service/v1", Name: "PaperboatHostd",
		DisplayName: "old hostd", Description: "old declaration",
		Executable: layout.Binary, Arguments: []string{"__runtime-hostd", "--restored"}, Account: "SYSTEM",
	}
	current := mgr.Config{
		BinaryPathName:   windows.ComposeCommandLine([]string{layout.Binary, "__runtime-hostd"}),
		ServiceStartName: "LocalSystem", StartType: mgr.StartAutomatic,
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	updated, err := windowsServiceConfigForDefinition(current, old)
	if err != nil {
		t.Fatalf("owned transition rejected: %v", err)
	}
	wantPath := windows.ComposeCommandLine([]string{layout.Binary, "__runtime-hostd", "--restored"})
	if updated.BinaryPathName != wantPath || updated.DisplayName != old.DisplayName || updated.Description != old.Description || updated.StartType != mgr.StartAutomatic || !isWindowsSystemAccount(updated.ServiceStartName) {
		t.Fatalf("restored config=%+v want path=%q and old metadata", updated, wantPath)
	}
	for _, foreign := range []mgr.Config{
		{BinaryPathName: windows.ComposeCommandLine([]string{`C:\Foreign\pb.exe`, "__runtime-hostd"}), ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED},
		{BinaryPathName: windows.ComposeCommandLine([]string{layout.Binary, "__runtime-hostd"}), ServiceStartName: "Administrator", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED},
		{BinaryPathName: windows.ComposeCommandLine([]string{layout.Binary, "__runtime-hostd"}), ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_NONE},
	} {
		if _, err := windowsServiceConfigForDefinition(foreign, old); !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("foreign transition accepted: config=%+v err=%v", foreign, err)
		}
	}
}

func TestPendingWindowsInstallerAllowsRecoveryBeforeBinaryPublication(t *testing.T) {
	layout, err := DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Platform: "windows", Kind: HostdKind, ConfigRoot: `C:\ProgramData\Paperboat`,
		Executable: layout.Binary, User: "Paperboat", Group: "Paperboat",
		Arguments: []string{"__runtime-hostd"}, Controller: WindowsController{},
	}
	if _, err := New(config); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("ordinary Windows installer accepted missing runtime: %v", err)
	}
	if _, err := NewPending(config); err != nil {
		t.Fatalf("pending Windows installer rejected recovery boundary: %v", err)
	}
}

func TestWindowsControllerInspectChecksSCMBeforeMissingDeclaration(t *testing.T) {
	source, err := os.ReadFile("service_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	open := strings.Index(text, "manager.OpenService(name)")
	read := strings.Index(text, "readWindowsServiceDefinitionForRemoval(definitionPath)")
	if open < 0 || read < 0 || open >= read {
		t.Fatal("Windows inspection must prove SCM registration before requiring the declaration tree")
	}
}

func TestWindowsServiceEntryRejectsMissingContext(t *testing.T) {
	if err := (WindowsController{}).Apply(context.Background(), `C:\ProgramData\Paperboat\missing.json`, false); err == nil {
		t.Fatal("missing service definition unexpectedly accepted")
	}
}
