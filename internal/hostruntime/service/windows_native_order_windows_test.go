//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestNativeWindowsComponentsCanStageAllRolesBeforeReadiness protects the
// Windows install boundary from probing hostd while LocalDaemon is still
// absent. NativeTransactionalComponent.Install is declaration-only; callers
// must prepare every role, start every role, and only then run application
// readiness probes.
func TestNativeWindowsComponentsCanStageAllRolesBeforeReadiness(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	roles := []struct {
		kind     string
		argument string
	}{
		{kind: HostdKind, argument: "__runtime-hostd"},
		{kind: DaemonKind, argument: "__runtime-local-daemon"},
		{kind: UpdaterKind, argument: "__runtime-updated"},
	}
	controls := make(map[string]*fakeNativeController, len(roles))
	components := make([]*NativeTransactionalComponent, 0, len(roles))
	for _, role := range roles {
		control := &fakeNativeController{}
		controls[role.kind] = control
		installer, err := New(Config{
			Platform: "windows", Kind: role.kind, ConfigRoot: root, Executable: executable,
			User: "SYSTEM", Group: "SYSTEM", Arguments: []string{role.argument}, Controller: control,
		})
		if err != nil {
			t.Fatalf("new %s installer: %v", role.kind, err)
		}
		// Keep this unit test isolated from the machine-wide production
		// declaration directory. The Windows render/controller rules remain
		// identical because the native boundary is injected below.
		installer.definitionPath = filepath.Join(root, role.kind+".json")
		component, err := NewNativeTransactionalComponent(NativeTransactionalComponentConfig{
			Installer: installer, Controller: control,
			Probe: func(context.Context) error {
				if !controls[DaemonKind].snapshot().Running {
					return errors.New("local daemon is not running")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("new %s component: %v", role.kind, err)
		}
		components = append(components, component)
	}

	// Preparation must not start any role. This is the crucial distinction from
	// Installer.Install, whose standalone compatibility behavior starts a fresh
	// Windows service as part of Apply.
	for _, component := range components {
		if err := component.Install(context.Background()); err != nil {
			t.Fatalf("prepare %s: %v", component.ID(), err)
		}
	}
	for _, role := range roles {
		if got := controls[role.kind].start; got != 0 {
			t.Fatalf("prepare %s started its service %d time(s)", role.kind, got)
		}
	}

	for _, component := range components {
		if err := component.Start(context.Background()); err != nil {
			t.Fatalf("start %s: %v", component.ID(), err)
		}
	}
	for _, component := range components {
		if err := component.CheckReadiness(context.Background()); err != nil {
			t.Fatalf("readiness %s after all roles started: %v", component.ID(), err)
		}
	}
}
