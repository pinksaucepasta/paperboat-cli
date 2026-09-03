package hostinstall

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

type fakeWindowsServicePlanStep struct {
	path         string
	events       *[]string
	installErr   error
	startErr     error
	uninstallErr error
}

func (step *fakeWindowsServicePlanStep) DefinitionPath() string { return step.path }

func (step *fakeWindowsServicePlanStep) Install(context.Context) error {
	*step.events = append(*step.events, "install:"+step.path)
	return step.installErr
}

func (step *fakeWindowsServicePlanStep) Start(context.Context) error {
	*step.events = append(*step.events, "start:"+step.path)
	return step.startErr
}

func (step *fakeWindowsServicePlanStep) Uninstall(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("rollback context was not live")
	}
	*step.events = append(*step.events, "uninstall:"+step.path)
	return step.uninstallErr
}

func TestWindowsServiceStepsInstallInDependencyOrderAndRollbackOnlyNewDeclarations(t *testing.T) {
	definitions := []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind, executable: `C:\Paperboat\pb.exe`},
		{kind: service.DaemonKind, executable: `C:\Paperboat\pb.exe`},
		{kind: service.UpdaterKind, executable: `C:\Paperboat\pb.exe`},
	}
	present := map[string]bool{"daemon": true}
	var events []string
	updaterFailure := errors.New("updated service failed")
	makeStep := func(definition windowsRuntimeServiceDefinition) (windowsServicePlanStep, error) {
		return &fakeWindowsServicePlanStep{path: definition.kind, events: &events, installErr: map[string]error{service.UpdaterKind: updaterFailure}[definition.kind]}, nil
	}
	declarationPresent := func(_ context.Context, path string) (bool, error) { return present[path], nil }
	_, err := executeWindowsServiceSteps(context.Background(), definitions, makeStep, declarationPresent, false)
	if !errors.Is(err, updaterFailure) {
		t.Fatalf("install err=%v want updater failure", err)
	}
	want := []string{"install:hostd", "install:daemon", "install:updater", "uninstall:updater", "uninstall:hostd"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
}

func TestWindowsServiceStepsTreatStaleDeclarationAsNewWhenSCMIsAbsent(t *testing.T) {
	definitions := []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind},
		{kind: service.DaemonKind},
	}
	// The hostd declaration is left behind by an interrupted install, but SCM
	// has no matching registration. The native registration snapshot, not the
	// declaration file, must determine rollback ownership.
	declarations := map[string]bool{service.HostdKind: true}
	registered := map[string]bool{}
	inspected := map[string]bool{}
	var events []string
	installFailure := errors.New("daemon service failed")
	makeStep := func(definition windowsRuntimeServiceDefinition) (windowsServicePlanStep, error) {
		return &fakeWindowsServicePlanStep{
			path:       definition.kind,
			events:     &events,
			installErr: map[string]error{service.DaemonKind: installFailure}[definition.kind],
		}, nil
	}
	preexisting := func(_ context.Context, path string) (bool, error) {
		inspected[path] = true
		return registered[path], nil
	}
	_, err := executeWindowsServiceSteps(context.Background(), definitions, makeStep, preexisting, false)
	if !errors.Is(err, installFailure) {
		t.Fatalf("install err=%v want daemon failure", err)
	}
	want := []string{"install:hostd", "install:daemon", "uninstall:daemon", "uninstall:hostd"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
	if !declarations[service.HostdKind] || registered[service.HostdKind] || !inspected[service.HostdKind] {
		t.Fatalf("stale declaration fixture was not inspected: declarations=%v registered=%v inspected=%v", declarations, registered, inspected)
	}
}

func TestWindowsServiceStepsCleanupAfterPostInstallReadinessFailure(t *testing.T) {
	definitions := []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind},
		{kind: service.DaemonKind},
	}
	var events []string
	makeStep := func(definition windowsRuntimeServiceDefinition) (windowsServicePlanStep, error) {
		return &fakeWindowsServicePlanStep{path: definition.kind, events: &events}, nil
	}
	// The daemon was registered before this attempt. A post-install readiness
	// failure must remove only the hostd registration created by this attempt.
	preexisting := func(_ context.Context, path string) (bool, error) {
		return path == service.DaemonKind, nil
	}
	cleanup, err := executeWindowsServiceSteps(context.Background(), definitions, makeStep, preexisting, false)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the caller's local-daemon readiness failure by invoking the
	// returned cleanup before handing the failure back to its caller.
	if err := cleanup(); err != nil {
		t.Fatalf("post-install cleanup err=%v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("idempotent cleanup err=%v", err)
	}
	want := []string{"install:hostd", "install:daemon", "uninstall:hostd"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
}

func TestWindowsServiceStepsReadinessHookRunsBeforeUpdater(t *testing.T) {
	definitions := []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind},
		{kind: service.DaemonKind},
		{kind: service.UpdaterKind},
	}
	var events []string
	makeStep := func(definition windowsRuntimeServiceDefinition) (windowsServicePlanStep, error) {
		return &fakeWindowsServicePlanStep{path: definition.kind, events: &events}, nil
	}
	_, err := executeWindowsServiceStepsWithHook(
		context.Background(), definitions, makeStep,
		func(context.Context, string) (bool, error) { return false, nil }, true,
		func(_ int, definition windowsRuntimeServiceDefinition) error {
			if definition.kind == service.DaemonKind {
				events = append(events, "ready:"+definition.kind)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"install:hostd", "start:hostd",
		"install:daemon", "start:daemon", "ready:daemon",
		"install:updater", "start:updater",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
}

func TestWindowsServiceStepsStartFailureRollsBackInReverseOrderWithLiveContext(t *testing.T) {
	definitions := []windowsRuntimeServiceDefinition{
		{kind: service.HostdKind},
		{kind: service.DaemonKind},
		{kind: service.UpdaterKind},
	}
	var events []string
	startFailure := errors.New("local daemon was not ready")
	makeStep := func(definition windowsRuntimeServiceDefinition) (windowsServicePlanStep, error) {
		return &fakeWindowsServicePlanStep{path: definition.kind, events: &events, startErr: map[string]error{service.DaemonKind: startFailure}[definition.kind]}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cleanup, err := executeWindowsServiceSteps(ctx, definitions, makeStep, func(context.Context, string) (bool, error) { return false, nil }, true)
	if !errors.Is(err, startFailure) {
		t.Fatalf("start err=%v want daemon failure", err)
	}
	want := []string{"install:hostd", "start:hostd", "install:daemon", "start:daemon", "uninstall:daemon", "uninstall:hostd"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
	if cleanup != nil {
		t.Fatal("failed service plan returned cleanup handle")
	}
	cancel()
}

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
		events = append(events, "recover")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"ssh", "recover", "runtime"}) {
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
		events = append(events, "recover")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return runtimeFailure
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if !errors.Is(err, runtimeFailure) || !reflect.DeepEqual(events, []string{"ssh", "recover", "runtime", "cleanup-ssh"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsClientServicesCleanSSHAfterRuntimeStarts(t *testing.T) {
	var events []string
	err := executeWindowsServiceInstallPlan("client", func() error {
		events = append(events, "unexpected-ssh-install")
		return nil
	}, func() error {
		events = append(events, "recover")
		return nil
	}, func() error {
		events = append(events, "runtime")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"recover", "runtime", "cleanup-ssh"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsHostServicesCleanSSHWhenRuntimeRecoveryFails(t *testing.T) {
	var events []string
	recoveryFailure := errors.New("recovery failed")
	err := executeWindowsServiceInstallPlan("host", func() error {
		events = append(events, "ssh")
		return nil
	}, func() error {
		events = append(events, "recover")
		return recoveryFailure
	}, func() error {
		events = append(events, "runtime")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if !errors.Is(err, recoveryFailure) || !reflect.DeepEqual(events, []string{"ssh", "recover", "cleanup-ssh"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsRepairPlanKeepsSSHUntilFinalLifecycleRepair(t *testing.T) {
	var events []string
	err := executeWindowsServiceRepairPlan("host", func() error {
		events = append(events, "ssh")
		return nil
	}, func() error {
		events = append(events, "recover")
		return nil
	}, func() error {
		events = append(events, "binary-config")
		return nil
	}, func() error {
		events = append(events, "lifecycle-repair")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"ssh", "recover", "binary-config", "lifecycle-repair"}) {
		t.Fatalf("events=%q err=%v", events, err)
	}
}

func TestWindowsRepairPlanCleansSSHOnlyAfterARepairPhaseFails(t *testing.T) {
	for _, test := range []struct {
		name       string
		failureAt  string
		wantEvents []string
	}{
		{name: "recovery", failureAt: "recover", wantEvents: []string{"ssh", "recover", "cleanup-ssh"}},
		{name: "binary-config", failureAt: "binary-config", wantEvents: []string{"ssh", "recover", "binary-config", "cleanup-ssh"}},
		{name: "lifecycle", failureAt: "lifecycle-repair", wantEvents: []string{"ssh", "recover", "binary-config", "lifecycle-repair", "cleanup-ssh"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			failure := errors.New(test.failureAt + " failed")
			phase := func(name string) func() error {
				return func() error {
					events = append(events, name)
					if name == test.failureAt {
						return failure
					}
					return nil
				}
			}
			err := executeWindowsServiceRepairPlan("host", phase("ssh"), phase("recover"), phase("binary-config"), phase("lifecycle-repair"), phase("cleanup-ssh"))
			if !errors.Is(err, failure) || !reflect.DeepEqual(events, test.wantEvents) {
				t.Fatalf("events=%q err=%v", events, err)
			}
		})
	}
}

func TestWindowsClientRepairPlanRepairsBeforeSSHCleanup(t *testing.T) {
	var events []string
	err := executeWindowsServiceRepairPlan("client", func() error {
		events = append(events, "unexpected-ssh")
		return nil
	}, func() error {
		events = append(events, "recover")
		return nil
	}, func() error {
		events = append(events, "binary-config")
		return nil
	}, func() error {
		events = append(events, "lifecycle-repair")
		return nil
	}, func() error {
		events = append(events, "cleanup-ssh")
		return nil
	})
	if err != nil || !reflect.DeepEqual(events, []string{"recover", "binary-config", "lifecycle-repair", "cleanup-ssh"}) {
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
