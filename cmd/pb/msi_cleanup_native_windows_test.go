//go:build windows && paperboat_native_e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestNativeMSIPreviewCleanup exercises the SCM and declaration removal path
// against the exact executable path registered by the elevated preview broker.
// It is opt-in because creating and deleting machine services requires an
// elevated Windows test process.
func TestNativeMSIPreviewCleanup(t *testing.T) {
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("connect SCM: ", err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })

	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		BinaryRoot:      filepath.Join(root, "bin"),
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
		StateRoot:       filepath.Join(root, "state"),
		ServiceRoot:     filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RuntimeCurrent, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}

	currentLogicalName := nativeMSIPreviewLogicalName(1)
	currentName := nativeMSIPreviewName(1)
	definitionPath := filepath.Join(paths.ServiceRoot, currentName+".json")
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(currentLogicalName)+".json")
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		nativeMSIPreviewRemoveFixture(t, manager, paths, currentName, cleanupCtx)
	})
	if err := nativeMSIPreviewFixture(t, manager, paths, currentName, currentLogicalName, paths.RuntimeCurrent); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(descriptorPath), 0o700); err != nil {
		t.Fatal(err)
	}
	descriptorBody, err := json.Marshal(msiPreviewDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              currentLogicalName,
		ServiceDefinition: definitionPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, descriptorBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := removePaperboatPreviewServices(cleanupCtx, paths, io.Discard); err != nil {
		t.Fatal("remove preview services: ", err)
	}
	if err := removePaperboatRuntimeSlots(cleanupCtx, paths, io.Discard); err != nil {
		t.Fatal("remove runtime slots: ", err)
	}

	assertNativeMSIPreviewAbsent(t, manager, currentName)
	if _, err := os.Stat(filepath.Join(paths.ServiceRoot, currentName+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legitimate runtime-current declaration was not removed: %v", err)
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legitimate preview descriptor was not removed: %v", err)
	}
	if _, err := os.Stat(paths.RuntimeCurrent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legitimate runtime-current executable was not removed: %v", err)
	}
}

func TestNativeMSIPreviewMissingRuntimeCurrent(t *testing.T) {
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("connect SCM: ", err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })

	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
		StateRoot:       filepath.Join(root, "state"),
		ServiceRoot:     filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	logicalName := nativeMSIPreviewLogicalName(2)
	name := nativeMSIPreviewName(2)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		nativeMSIPreviewRemoveFixture(t, manager, paths, name, cleanupCtx)
	})
	if err := nativeMSIPreviewFixture(t, manager, paths, name, logicalName, paths.RuntimeCurrent); err != nil {
		t.Fatal(err)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runMSIFullUninstallCleanupWithPaths(cleanupCtx, paths, io.Discard); err != nil {
		t.Fatal("cleanup with missing runtime-current: ", err)
	}
	assertNativeMSIPreviewAbsent(t, manager, name)
	if _, err := os.Stat(filepath.Join(paths.ServiceRoot, name+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-runtime declaration was not removed: %v", err)
	}
}

func TestNativeMSIPreviewOwnershipConflictPreservesRuntimeState(t *testing.T) {
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("connect SCM: ", err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })

	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		BinaryRoot:      filepath.Join(root, "bin"),
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
		StateRoot:       filepath.Join(root, "state"),
		ServiceRoot:     filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RuntimeCurrent, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}

	logicalName := nativeMSIPreviewLogicalName(4)
	name := nativeMSIPreviewName(4)
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json")
	if err := nativeMSIPreviewMismatchedFixture(t, manager, paths, name, logicalName, paths.RuntimeCurrent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		nativeMSIPreviewRemoveFixture(t, manager, paths, name, cleanupCtx)
		_ = os.Remove(descriptorPath)
	})
	if err := os.MkdirAll(filepath.Dir(descriptorPath), 0o700); err != nil {
		t.Fatal(err)
	}
	descriptorBody, err := json.Marshal(msiPreviewDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              logicalName,
		ServiceDefinition: definitionPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, descriptorBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cleanupErr := runMSIFullUninstallCleanupWithPaths(cleanupCtx, paths, io.Discard)
	if !errors.Is(cleanupErr, errMSIPreviewOwnership) {
		t.Fatalf("cleanup err=%v, want typed preview ownership failure", cleanupErr)
	}
	assertNativeMSIPreviewPresent(t, manager, name)
	for _, path := range []string{definitionPath, descriptorPath, paths.RuntimeCurrent} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("ownership-conflict state %s was not preserved: %v", path, err)
		}
	}
}

func TestNativeMSIPreviewDescriptorConflictPreservesOwnedService(t *testing.T) {
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("connect SCM: ", err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })

	root := t.TempDir()
	paths := msiCleanupPaths{
		InstallRoot:     root,
		BinaryRoot:      filepath.Join(root, "bin"),
		RuntimeCurrent:  filepath.Join(root, "releases", "runtime-current", "paperboat-runtime.exe"),
		RuntimeRollback: filepath.Join(root, "releases", "runtime-rollback", "paperboat-runtime.exe"),
		RuntimeStaged:   filepath.Join(root, "releases", "runtime-staged", "paperboat-runtime.exe"),
		StateRoot:       filepath.Join(root, "state"),
		ServiceRoot:     filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.RuntimeCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RuntimeCurrent, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}

	ownedLogicalName := nativeMSIPreviewLogicalName(5)
	foreignLogicalName := nativeMSIPreviewLogicalName(6)
	ownedName := nativeMSIPreviewName(5)
	foreignName := nativeMSIPreviewName(6)
	if err := nativeMSIPreviewFixture(t, manager, paths, ownedName, ownedLogicalName, paths.RuntimeCurrent); err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(foreignLogicalName)+".json")
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		nativeMSIPreviewRemoveFixture(t, manager, paths, ownedName, cleanupCtx)
		_ = os.Remove(descriptorPath)
	})
	if err := os.MkdirAll(filepath.Dir(descriptorPath), 0o700); err != nil {
		t.Fatal(err)
	}
	foreignDefinition := filepath.Join(paths.ServiceRoot, foreignName+".json")
	descriptorBody, err := json.Marshal(msiPreviewDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              foreignLogicalName,
		ServiceDefinition: foreignDefinition,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, descriptorBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cleanupErr := runMSIFullUninstallCleanupWithPaths(cleanupCtx, paths, io.Discard)
	if !errors.Is(cleanupErr, errMSIPreviewOwnership) {
		t.Fatalf("cleanup err=%v, want typed preview ownership failure", cleanupErr)
	}
	assertNativeMSIPreviewPresent(t, manager, ownedName)
	for _, path := range []string{filepath.Join(paths.ServiceRoot, ownedName+".json"), descriptorPath, paths.RuntimeCurrent} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("state %s was not preserved after descriptor conflict: %v", path, err)
		}
	}
}

func nativeMSIPreviewLogicalName(index uint64) string {
	return fmt.Sprintf("native-msi-preview-%d", index)
}

func nativeMSIPreviewName(index uint64) string {
	return msiPaperboatServicePrefix + msiPreviewInstance(nativeMSIPreviewLogicalName(index))
}

func nativeMSIPreviewFixture(t *testing.T, manager *mgr.Mgr, paths msiCleanupPaths, name, logicalName, executable string) error {
	t.Helper()
	if err := os.MkdirAll(paths.ServiceRoot, 0o700); err != nil {
		return err
	}
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: executable,
		Arguments:  []string{msiPaperboatPreviewCommand, "--state-root", paths.StateRoot, "--name", logicalName, "--descriptor", descriptorPath, "--service-definition", definitionPath, "--port", "38123", "--indefinite"},
		Account:    "SYSTEM",
	}
	body, err := json.Marshal(definition)
	if err != nil {
		return err
	}
	if err := os.WriteFile(definitionPath, body, 0o600); err != nil {
		return err
	}
	service, err := manager.CreateService(name, executable, mgr.Config{
		DisplayName:      name,
		Description:      "Paperboat MSI cleanup qualification fixture",
		StartType:        mgr.StartManual,
		ServiceStartName: "LocalSystem",
	}, definition.Arguments...)
	if err != nil {
		_ = os.Remove(definitionPath)
		return err
	}
	return service.Close()
}

func nativeMSIPreviewMismatchedFixture(t *testing.T, manager *mgr.Mgr, paths msiCleanupPaths, name, logicalName, executable string) error {
	t.Helper()
	if err := os.MkdirAll(paths.ServiceRoot, 0o700); err != nil {
		return err
	}
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	descriptorPath := filepath.Join(paths.StateRoot, "previews", "active", msiPreviewInstance(logicalName)+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: executable,
		Arguments:  []string{msiPaperboatPreviewCommand, "--state-root", paths.StateRoot, "--name", logicalName, "--descriptor", descriptorPath, "--service-definition", definitionPath, "--port", "38123", "--indefinite"},
		Account:    "SYSTEM",
	}
	body, err := json.Marshal(definition)
	if err != nil {
		return err
	}
	if err := os.WriteFile(definitionPath, body, 0o600); err != nil {
		return err
	}
	service, err := manager.CreateService(name, executable, mgr.Config{
		DisplayName:      name,
		Description:      "Paperboat MSI cleanup ownership-conflict fixture",
		StartType:        mgr.StartManual,
		ServiceStartName: "NT AUTHORITY\\LocalService",
	}, msiPaperboatPreviewCommand, "--unexpected-definition", definitionPath)
	if err != nil {
		_ = os.Remove(definitionPath)
		return err
	}
	return service.Close()
}

func nativeMSIPreviewRemoveFixture(t *testing.T, manager *mgr.Mgr, paths msiCleanupPaths, name string, ctx context.Context) {
	t.Helper()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_ = os.Remove(filepath.Join(paths.ServiceRoot, name+".json"))
		return
	}
	if err != nil {
		t.Errorf("open cleanup fixture %s: %v", name, err)
		return
	}
	if err := removeSCMService(ctx, manager, service, name); err != nil {
		t.Errorf("remove cleanup fixture %s: %v", name, err)
	}
	if err := os.Remove(filepath.Join(paths.ServiceRoot, name+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove cleanup declaration %s: %v", name, err)
	}
}

func assertNativeMSIPreviewAbsent(t *testing.T, manager *mgr.Mgr, name string) {
	t.Helper()
	service, err := manager.OpenService(name)
	if service != nil {
		_ = service.Close()
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatalf("service %s still exists after cleanup: %v", name, err)
	}
}

func assertNativeMSIPreviewPresent(t *testing.T, manager *mgr.Mgr, name string) {
	t.Helper()
	service, err := manager.OpenService(name)
	if err != nil {
		t.Fatalf("preserved service %s was removed: %v", name, err)
	}
	_ = service.Close()
}
