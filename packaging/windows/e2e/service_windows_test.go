//go:build windows && paperboat_native_e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestNativeSCMHostdAndUpdaterLifecycle(t *testing.T) {
	fixture := requiredFixture(t)
	for _, test := range []struct {
		kind string
		name string
	}{
		{kind: service.HostdKind, name: "PaperboatHostd"},
		{kind: service.UpdaterKind, name: "PaperboatUpdated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertServiceAbsent(t, test.name)
			configRoot := t.TempDir()
			marker := filepath.Join(configRoot, "service-events.log")
			installer, err := service.New(service.Config{
				Platform:   "windows",
				Kind:       test.kind,
				ConfigRoot: configRoot,
				Executable: fixture,
				User:       "SYSTEM",
				Group:      "Administrators",
				Arguments:  []string{"--service-name", test.name, "--marker", marker},
				Controller: service.WindowsController{},
			})
			if err != nil {
				t.Fatalf("construct installer: %v", err)
			}
			if _, err := os.Stat(installer.DefinitionPath()); err == nil {
				t.Fatalf("service definition already exists: %s", installer.DefinitionPath())
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("inspect service definition: %v", err)
			}
			installed := true
			t.Cleanup(func() {
				if installed {
					_ = installer.Uninstall(context.Background())
					_ = waitServiceAbsent(test.name, 15*time.Second)
				}
			})

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := installer.Install(ctx); err != nil {
				t.Fatalf("install %s: %v", test.name, err)
			}
			installed = true
			assertServiceConfiguration(t, test.name, fixture, mgr.StartAutomatic)
			assertServiceRunning(t, test.name)

			// Reapplying the declaration exercises UpdateConfig. Windows stores
			// executable and arguments in one BinaryPathName string, so upgrades
			// must retain every fixed argument.
			if err := installer.Install(ctx); err != nil {
				t.Fatalf("upgrade %s declaration: %v", test.name, err)
			}
			assertServiceConfiguration(t, test.name, fixture, mgr.StartAutomatic)
			assertServiceArguments(t, test.name, "--service-name", test.name, "--marker", marker)

			// Restart through SCM, the boundary used after logout, reboot, or
			// service recovery. The declaration and fixed arguments must remain
			// attached to the same service instance.
			restartService(t, test.name)
			assertServiceConfiguration(t, test.name, fixture, mgr.StartAutomatic)

			if err := installer.Uninstall(ctx); err != nil {
				t.Fatalf("uninstall %s: %v", test.name, err)
			}
			installed = false
			if err := waitServiceAbsent(test.name, 15*time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(installer.DefinitionPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("service definition after uninstall: %v", err)
			}
		})
	}
}

func assertServiceArguments(t *testing.T, name string, want ...string) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to SCM: %v", err)
	}
	defer manager.Disconnect()
	handle, err := manager.OpenService(name)
	if err != nil {
		t.Fatalf("open service %s: %v", name, err)
	}
	defer handle.Close()
	config, err := handle.Config()
	if err != nil {
		t.Fatalf("query service %s configuration: %v", name, err)
	}
	arguments, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil {
		t.Fatalf("parse service %s command line: %v", name, err)
	}
	if len(arguments) != len(want)+1 {
		t.Fatalf("service %s arguments=%q want=%q", name, arguments, want)
	}
	for index := range want {
		if arguments[index+1] != want[index] {
			t.Fatalf("service %s arguments=%q want=%q", name, arguments[1:], want)
		}
	}
}

func TestNativeDurablePreviewServiceLifecycle(t *testing.T) {
	fixture := requiredFixture(t)
	root := t.TempDir()
	// Include the process identity and timestamp so a terminated qualification
	// process can never collide with a stale service from an earlier run.
	name := fmt.Sprintf("e2e-preview-%d-%d", os.Getpid(), time.Now().UnixNano())
	serviceName := previewServiceName(name)
	assertServiceAbsent(t, serviceName)

	expires := time.Now().UTC().Add(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	descriptor, err := hostruntime.InstallPreviewService(ctx, fixture, root, name, 32123, &expires, false)
	if err != nil {
		t.Fatalf("install durable preview service: %v", err)
	}
	t.Cleanup(func() {
		_ = hostruntime.RemovePreviewService(context.Background(), root, name)
		_ = removeServiceIfPresent(serviceName)
		_ = waitServiceAbsent(serviceName, 15*time.Second)
	})
	if descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name != name || descriptor.Port != 32123 || descriptor.Indefinite || descriptor.ExpiresAt == nil || descriptor.ServiceDefinition == "" {
		t.Fatalf("unexpected preview descriptor: %+v", descriptor)
	}
	assertServiceConfiguration(t, serviceName, fixture, mgr.StartAutomatic)
	assertServiceRunning(t, serviceName)

	// Reconciliation before expiry must be a no-op.
	if err := hostruntime.ReconcileExpiredPreviewServices(ctx, root, expires.Add(-time.Second)); err != nil {
		t.Fatalf("reconcile before expiry: %v", err)
	}
	assertServiceRunning(t, serviceName)

	// An explicit SCM stop/start proves durable services survive the same
	// restart boundary used by recovery and reconnect flows.
	restartService(t, serviceName)

	if err := hostruntime.ReconcileExpiredPreviewServices(ctx, root, expires.Add(time.Second)); err != nil {
		t.Fatalf("reconcile after expiry: %v", err)
	}
	if err := waitServiceAbsent(serviceName, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(previewDescriptorPath(root, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview descriptor after expiry: %v", err)
	}
	// Removal after expiry is intentionally idempotent.
	if err := hostruntime.RemovePreviewService(ctx, root, name); err != nil {
		t.Fatalf("idempotent preview uninstall: %v", err)
	}
}

func requiredFixture(t *testing.T) string {
	t.Helper()
	path := os.Getenv("PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE")
	if path == "" {
		t.Fatal("PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE is required")
	}
	path, err := filepath.Abs(path)
	if err != nil || !strings.EqualFold(filepath.Ext(path), ".exe") {
		t.Fatalf("fixture must be an absolute .exe: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("fixture is not a regular file: %q: %v", path, err)
	}
	return path
}

func assertServiceAbsent(t *testing.T, name string) {
	t.Helper()
	if err := waitServiceAbsent(name, 0); err != nil {
		t.Fatal(err)
	}
}

func assertServiceConfiguration(t *testing.T, name, fixture string, startType uint32) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to SCM: %v", err)
	}
	defer manager.Disconnect()
	svcHandle, err := manager.OpenService(name)
	if err != nil {
		t.Fatalf("open service %s: %v", name, err)
	}
	defer svcHandle.Close()
	config, err := svcHandle.Config()
	if err != nil {
		t.Fatalf("query service %s configuration: %v", name, err)
	}
	if config.StartType != startType {
		t.Fatalf("service %s start type=%d want=%d", name, config.StartType, startType)
	}
	if !strings.EqualFold(config.ServiceStartName, "LocalSystem") {
		t.Fatalf("service %s account=%q want LocalSystem", name, config.ServiceStartName)
	}
	if !strings.Contains(strings.ToLower(config.BinaryPathName), strings.ToLower(fixture)) {
		t.Fatalf("service %s binary path=%q does not contain fixture %q", name, config.BinaryPathName, fixture)
	}
}

func assertServiceRunning(t *testing.T, name string) {
	t.Helper()
	if err := waitServiceState(name, svc.Running, 30*time.Second); err != nil {
		t.Fatal(err)
	}
}

func restartService(t *testing.T, name string) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to SCM for restart: %v", err)
	}
	defer manager.Disconnect()
	svcHandle, err := manager.OpenService(name)
	if err != nil {
		t.Fatalf("open service %s for restart: %v", name, err)
	}
	if _, err := svcHandle.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		svcHandle.Close()
		t.Fatalf("stop service %s: %v", name, err)
	}
	if err := waitServiceState(name, svc.Stopped, 30*time.Second); err != nil {
		svcHandle.Close()
		t.Fatal(err)
	}
	if err := svcHandle.Start(); err != nil {
		svcHandle.Close()
		t.Fatalf("start service %s: %v", name, err)
	}
	if err := waitServiceState(name, svc.Running, 30*time.Second); err != nil {
		svcHandle.Close()
		t.Fatal(err)
	}
	if err := svcHandle.Close(); err != nil {
		t.Fatalf("close service %s: %v", name, err)
	}
}

func waitServiceAbsent(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		svcHandle, err := manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			manager.Disconnect()
			return nil
		}
		if err != nil {
			manager.Disconnect()
			return err
		}
		_ = svcHandle.Close()
		manager.Disconnect()
		if timeout == 0 || time.Now().After(deadline) {
			return errors.New("service " + name + " already exists")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func removeServiceIfPresent(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	svcHandle, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return nil
	}
	if err != nil {
		manager.Disconnect()
		return err
	}
	status, queryErr := svcHandle.Query()
	if queryErr == nil && status.State != svc.Stopped {
		_, _ = svcHandle.Control(svc.Stop)
	}
	if queryErr == nil && status.State != svc.Stopped {
		_ = waitServiceState(name, svc.Stopped, 15*time.Second)
	}
	deleteErr := svcHandle.Delete()
	if errors.Is(deleteErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		deleteErr = nil
	}
	_ = svcHandle.Close()
	manager.Disconnect()
	return deleteErr
}

func waitServiceState(name string, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		svcHandle, err := manager.OpenService(name)
		if err != nil {
			manager.Disconnect()
			return err
		}
		status, queryErr := svcHandle.Query()
		_ = svcHandle.Close()
		manager.Disconnect()
		if queryErr != nil {
			return queryErr
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service %s state=%d want=%d", name, status.State, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func previewServiceName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "PaperboatPreview-" + hex.EncodeToString(sum[:8])
}

func previewDescriptorPath(root, name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(root, "previews", "active", hex.EncodeToString(sum[:8])+".json")
}
