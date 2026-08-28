package hostinstall

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestWindowsRuntimeServicesUseCanonicalBinary(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	definitions := windowsRuntimeServiceDefinitions(layout)
	if len(definitions) != 3 {
		t.Fatalf("definitions=%+v", definitions)
	}
	if definitions[0].kind != service.HostdKind || definitions[1].kind != service.DaemonKind || definitions[2].kind != service.UpdaterKind {
		t.Fatalf("service order=%+v", definitions)
	}
	for _, definition := range definitions {
		if definition.executable != layout.Binary {
			t.Fatalf("service %q executable=%q want=%q", definition.kind, definition.executable, layout.Binary)
		}
	}
	if !reflect.DeepEqual(definitions[0].arguments, []string{"__runtime-hostd"}) || !reflect.DeepEqual(definitions[1].arguments, []string{"__runtime-local-daemon"}) || !reflect.DeepEqual(definitions[2].arguments, []string{"__runtime-updated"}) {
		t.Fatalf("definitions=%+v", definitions)
	}
}

func TestWindowsHostServicesInstallSSHBeforeStartingRuntime(t *testing.T) {
	var events []string
	err := executeWindowsServiceInstallPlan("host", func() error {
		events = append(events, "ssh")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"ssh", "runtime"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsHostServicesCleanSSHWhenRuntimeFails(t *testing.T) {
	var events []string
	runtimeFailure := errors.New("runtime failed")
	err := executeWindowsServiceInstallPlan("host", func() error {
		events = append(events, "ssh")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return runtimeFailure
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if !errors.Is(err, runtimeFailure) || !reflect.DeepEqual(events, []string{"ssh", "runtime", "cleanup-ssh"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsClientServicesCleanSSHAfterRuntimeStarts(t *testing.T) {
	var events []string
	err := executeWindowsServiceInstallPlan("client", func() error {
		events = append(events, "unexpected-ssh-install")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"runtime", "cleanup-ssh"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsActivatorOwnershipAcceptsOnlyVersionedReleaseBinary(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	valid := layout.ReleasesRoot + `\versions\2026.08.28.1\pb.exe`
	if !windowsActivatorServiceOwned(layout, valid, []string{"__runtime-activate"}, "LocalSystem") {
		t.Fatalf("owned activator target rejected: %q", valid)
	}
	for _, invalid := range []string{layout.Binary, layout.BinaryRollback, layout.ReleasesRoot + `\versions\..\pb.exe`, layout.ReleasesRoot + `\versions\2026.08.28.1\other.exe`} {
		if windowsActivatorExecutableOwned(layout, invalid) {
			t.Fatalf("unowned activator target accepted: %q", invalid)
		}
	}
	if windowsActivatorServiceOwned(layout, valid, []string{"__runtime-updated"}, "LocalSystem") || windowsActivatorServiceOwned(layout, valid, []string{"__runtime-activate"}, "User") {
		t.Fatal("unowned activator service command accepted")
	}
}
