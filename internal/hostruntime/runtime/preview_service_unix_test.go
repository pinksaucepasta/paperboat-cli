//go:build darwin || linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestPrivatePreviewDescriptorPublishesOnlyLoopbackReadiness(t *testing.T) {
	root := t.TempDir()
	name := "remote-docs"
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(root, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	expires := time.Now().UTC().Add(time.Hour)
	remote := &PrivatePreviewRuntimeDescriptor{MachineID: "machine_1", MachineName: "Studio", EnvironmentID: "env_1", MachineGeneration: 4, TargetPort: 3000}
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, BindAddress: "127.0.0.1", ServiceGeneration: 5, ExpiresAt: &expires, ServiceDefinition: filepath.Join(root, "service"), PrivateRemote: remote}
	if err := writePreviewRuntimeDescriptor(path, descriptor); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadPrivatePreviewService(root, name)
	if err != nil || loaded != *remote {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err := MarkPrivatePreviewServiceReady(root, name, "http://127.0.0.1:4567"); err != nil {
		t.Fatal(err)
	}
	ready, err := readPreviewRuntimeDescriptor(path)
	if err != nil || ready.Port != 4567 || ready.Record == nil || ready.Record.URL != "http://127.0.0.1:4567" || ready.Record.TargetPort != 3000 || ready.Record.State != "ready" {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	for _, invalid := range []string{"http://0.0.0.0:4567", "https://127.0.0.1:4567", "http://127.0.0.1:4567/path"} {
		if err := MarkPrivatePreviewServiceReady(root, name, invalid); !errors.Is(err, ErrProductionInvalid) {
			t.Fatalf("url=%q err=%v", invalid, err)
		}
	}
	if err := BeginPrivatePreviewService(root, name); err != nil {
		t.Fatal(err)
	}
	restarting, err := readPreviewRuntimeDescriptor(path)
	if err != nil || restarting.Port != 0 || restarting.Record != nil {
		t.Fatalf("restarting=%+v err=%v", restarting, err)
	}
}

func TestPrivatePreviewPolicyCapFailsWithListStopRecovery(t *testing.T) {
	root := t.TempDir()
	expires := time.Now().UTC().Add(time.Hour)
	existing := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "existing", BindAddress: "127.0.0.1", ServiceGeneration: 1, ExpiresAt: &expires, ServiceDefinition: filepath.Join(root, "existing.service"), PrivateRemote: &PrivatePreviewRuntimeDescriptor{MachineID: "machine_1", MachineName: "Studio", EnvironmentID: "env_1", MachineGeneration: 1, TargetPort: 3000}}
	if err := writePreviewRuntimeDescriptor(filepath.Join(root, "previews", "active", "existing.json"), existing); err != nil {
		t.Fatal(err)
	}
	_, err := InstallPrivatePreviewService(context.Background(), filepath.Join(root, "pb"), root, "second", PrivatePreviewRuntimeDescriptor{MachineID: "machine_2", MachineName: "Office", EnvironmentID: "env_2", MachineGeneration: 1, TargetPort: 4000}, &expires, false, 1)
	if !errors.Is(err, ErrPreviewAlreadyActive) || !strings.Contains(err.Error(), "pb preview revoke") {
		t.Fatalf("err=%v", err)
	}
}

func TestPrivatePreviewInstallLockHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	release, err := acquirePreviewInstallLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquirePreviewInstallLock(ctx, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitPreviewServiceReadyReportsMissingWorkerImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err := WaitPreviewServiceReady(ctx, t.TempDir(), "missing-preview")
	if !errors.Is(err, ErrPreviewServiceMissing) {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("missing worker took %s to report", elapsed)
	}
}

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
	if runtime.GOOS == "linux" && (strings.Contains(joined, "disable --now") || !strings.Contains(joined, "systemctl --user daemon-reload") || !strings.Contains(joined, "systemctl --user reset-failed")) {
		t.Fatalf("retirement calls=%v", runner.calls)
	}
	if runtime.GOOS == "darwin" && strings.Contains(joined, "launchctl bootout gui/") {
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

type scriptedPreviewRunner struct {
	calls []string
	run   func(string) error
}

type outputPreviewRunner struct {
	recordingPreviewRunner
	output string
}

func (r *outputPreviewRunner) Output(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return r.output, nil
}

func (r *scriptedPreviewRunner) Run(_ context.Context, name string, args ...string) error {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if r.run != nil {
		return r.run(call)
	}
	return nil
}

func TestReconcileExpiredPreviewServiceWithMissingUnitAndDefinition(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	expires := time.Now().UTC().Add(-time.Minute)
	definition, _, err := previewServiceDefinition(root, "stale", runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "previews", "active", "stale.json")
	if err := writePreviewRuntimeDescriptor(path, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "stale", Port: 3000, ExpiresAt: &expires, ServiceDefinition: definition}); err != nil {
		t.Fatal(err)
	}
	runner := &scriptedPreviewRunner{run: func(call string) error {
		if runtime.GOOS == "linux" && strings.Contains(call, "disable --now") {
			return &hostservice.CommandError{Tool: "systemctl", Cause: errors.New("exit status 1"), Output: "Failed to disable unit: Unit paperboat-preview.service does not exist"}
		}
		if runtime.GOOS == "linux" && strings.Contains(call, "reset-failed") {
			return &hostservice.CommandError{Tool: "systemctl", Cause: errors.New("exit status 1"), Output: "Unit paperboat-preview.service not loaded"}
		}
		if runtime.GOOS == "darwin" && strings.Contains(call, "bootout") {
			return errors.New("No such process")
		}
		return nil
	}}
	if err := reconcileExpiredPreviewServices(context.Background(), root, time.Now().UTC(), runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale descriptor remains: %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	if runtime.GOOS == "linux" && strings.Contains(joined, "reset-failed paperboat-preview-*.service") {
		t.Fatalf("unexpected retirement calls: %v", runner.calls)
	}
}

func TestResetFailedPreviewServicesEnumeratesExactUnits(t *testing.T) {
	runner := &outputPreviewRunner{output: "● paperboat-preview-0123456789abcdef.service loaded failed failed\n" +
		"paperboat-preview-fedcba9876543210.service loaded failed failed\n" +
		"paperboat-preview-bad;touch.service loaded failed failed\n" +
		"other.service loaded failed failed\n"}
	if err := resetFailedPreviewServices(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, unit := range []string{"paperboat-preview-0123456789abcdef.service", "paperboat-preview-fedcba9876543210.service"} {
		if !strings.Contains(joined, "reset-failed "+unit) {
			t.Fatalf("unit was not reset: %s calls=%v", unit, runner.calls)
		}
	}
	if strings.Contains(joined, "bad;touch") || strings.Contains(joined, "reset-failed other.service") {
		t.Fatalf("unsafe or foreign unit was reset: %v", runner.calls)
	}
}

func TestWaitPreviewServiceReadyReportsFailedWorkerImmediately(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	expires := time.Now().UTC().Add(time.Hour)
	definition, _, err := previewServiceDefinition(root, "failed", runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(definition), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(definition, []byte("service"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "previews", "active", previewServiceInstance("failed")+".json")
	if err := writePreviewRuntimeDescriptor(path, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "failed", Port: 3000, ExpiresAt: &expires, ServiceDefinition: definition}); err != nil {
		t.Fatal(err)
	}
	runner := &scriptedPreviewRunner{run: func(call string) error {
		if strings.Contains(call, "is-active") {
			return errors.New("inactive")
		}
		if strings.Contains(call, "is-failed") {
			return nil
		}
		if runtime.GOOS == "darwin" && strings.Contains(call, "launchctl print") {
			return errors.New("worker exited")
		}
		return nil
	}}
	started := time.Now()
	_, err = waitPreviewServiceReady(context.Background(), root, "failed", runner)
	if !errors.Is(err, ErrPreviewServiceFailed) {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("failed worker took %s to report", elapsed)
	}
}

func TestRemoveAllPreviewServicesRetiresOnlyDurableEntries(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	expires := time.Now().UTC().Add(time.Hour)
	for _, name := range []string{"docs", "report"} {
		definition, _, err := previewServiceDefinition(root, name, runtime.GOOS)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(definition), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(definition, []byte("service"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "previews", "active", name+".json")
		if err := writePreviewRuntimeDescriptor(path, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, Port: 3000, ExpiresAt: &expires, ServiceDefinition: definition}); err != nil {
			t.Fatal(err)
		}
	}
	coordinatorPath := filepath.Join(root, "previews", "active", "coordinator.json")
	if err := writePreviewRuntimeDescriptor(coordinatorPath, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "local", Port: 3001, ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	runner := &recordingPreviewRunner{}
	if err := removeAllPreviewServices(context.Background(), root, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) == 0 {
		t.Fatal("durable services were not retired")
	}
	for _, name := range []string{"docs", "report"} {
		if _, err := os.Stat(filepath.Join(root, "previews", "active", name+".json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("durable descriptor %s remains: %v", name, err)
		}
	}
	if _, err := os.Stat(coordinatorPath); err != nil {
		t.Fatalf("coordinator descriptor was removed: %v", err)
	}
}

type failingPreviewRunner struct{}

func (*failingPreviewRunner) Run(context.Context, string, ...string) error {
	return errors.New("service control failed")
}

func TestRemoveAllPreviewServicesRetainsDescriptorWhenStopFails(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	expires := time.Now().UTC().Add(time.Hour)
	definition, _, err := previewServiceDefinition(root, "docs", runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "previews", "active", "docs.json")
	if err := writePreviewRuntimeDescriptor(path, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: "docs", Port: 3000, ExpiresAt: &expires, ServiceDefinition: definition}); err != nil {
		t.Fatal(err)
	}
	if err := removeAllPreviewServices(context.Background(), root, &failingPreviewRunner{}); err == nil {
		t.Fatal("service stop failure was hidden")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("descriptor was not retained for retry: %v", err)
	}
}

func TestCoordinatorPreviewRecoveryOwnsChildrenAndContinuesPastBadDescriptors(t *testing.T) {
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

func TestReadPreviewReadySkipsBoundedProcessLogs(t *testing.T) {
	record, err := readPreviewReady(strings.NewReader("frp connecting\n" + `{"preview_key":"p-test","url":"https://preview.example.test"}` + "\n"))
	if err != nil || record.PreviewKey != "p-test" || record.URL != "https://preview.example.test" {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	if _, err := readPreviewReady(strings.NewReader("only logs\n")); err == nil {
		t.Fatal("log-only output was accepted")
	}
}
