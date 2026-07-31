//go:build darwin || linux

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExpiredPreviewDescriptorCleansWithoutExtendingLifetime(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	expires := time.Now().UTC().Add(-time.Minute)
	serviceDefinition, _, err := previewServiceDefinition(root, "docs", runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(serviceDefinition), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serviceDefinition, []byte("unit"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(root, "previews", "active", "preview.json")
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "docs", Port: 3000, ExpiresAt: &expires, ServiceDefinition: serviceDefinition}
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		t.Fatal(err)
	}
	runner := &recordingPreviewRunner{}
	err = RunProductionPreviewWorker(context.Background(), ProductionPreviewWorkerConfig{ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "docs", Port: 3000, ExpiresAt: &expires, DescriptorPath: descriptorPath, ServiceDefinition: serviceDefinition, ServiceRunner: runner})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{descriptorPath, serviceDefinition} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path remains %s: %v", path, err)
		}
	}
	joined := strings.Join(runner.calls, "\n")
	if runtime.GOOS == "linux" && (!strings.Contains(joined, "systemctl --user disable paperboat-preview-") || !strings.Contains(joined, "systemctl --user daemon-reload")) {
		t.Fatalf("retirement calls=%v", runner.calls)
	}
	if runtime.GOOS == "darwin" && !strings.Contains(joined, "launchctl bootout gui/") {
		t.Fatalf("retirement calls=%v", runner.calls)
	}
}

func TestPreviewDescriptorMismatchCannotDeleteNamedPath(t *testing.T) {
	root := t.TempDir()
	expires := time.Now().UTC().Add(-time.Minute)
	protected := filepath.Join(root, "protected")
	if err := os.WriteFile(protected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(root, "previews", "active", "preview.json")
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "docs", Port: 3000, ExpiresAt: &expires, ServiceDefinition: protected}
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		t.Fatal(err)
	}
	err := RunProductionPreviewWorker(context.Background(), ProductionPreviewWorkerConfig{ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "docs", Port: 3000, ExpiresAt: &expires, DescriptorPath: descriptorPath, ServiceDefinition: protected})
	if !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("protected path changed: %v", err)
	}
}

type recordingPreviewRunner struct{ calls []string }

func (r *recordingPreviewRunner) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return nil
}

func TestCoordinatorPreviewRecoveryOwnsChildrenAndContinuesPastBadDescriptors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a Unix process")
	}
	root := t.TempDir()
	executable := filepath.Join(root, "preview-runner")
	script := "#!/bin/sh\ntrap 'exit 0' INT TERM\nprintf '%s' \"$$\" > \"$PAPERBOAT_TEST_PID_FILE\"\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_TEST_PID_FILE", filepath.Join(root, "child.pid"))
	activePath := filepath.Join(root, "previews", "active", "active.json")
	if err := writePreviewRuntimeDescriptor(activePath, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "docs", Port: 3000, Indefinite: true}); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Minute)
	expiredPath := filepath.Join(root, "previews", "active", "expired.json")
	if err := writePreviewRuntimeDescriptor(expiredPath, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "old", Port: 3001, ExpiresAt: &expired}); err != nil {
		t.Fatal(err)
	}
	corruptPath := filepath.Join(root, "previews", "active", "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &CoordinatorPreviewManager{Executable: executable, StateRoot: root}
	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("corrupt descriptor was not reported")
	}
	waitForPreviewChildren(t, manager, 1)
	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("corrupt descriptor was not reported on repeat scan")
	}
	waitForPreviewChildren(t, manager, 1)
	if _, err := os.Stat(expiredPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired descriptor remains: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	waitForPreviewChildren(t, manager, 0)
}

func waitForPreviewChildren(t *testing.T, manager *CoordinatorPreviewManager, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		got := len(manager.children)
		manager.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("preview child count did not reach %d", want)
}
