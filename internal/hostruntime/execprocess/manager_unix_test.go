//go:build darwin || linux

package execprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
)

func testManager(t *testing.T, root string, configure func(*Config)) *Manager {
	t.Helper()
	config := Config{WorkspaceRoot: root, BaseEnvironment: []string{"PATH=/usr/bin:/bin", "LANG=C"}, MaximumActive: 4, ReplayBytes: 64 << 10, ChunkBytes: 1024, CancelGrace: 20 * time.Millisecond}
	if configure != nil {
		configure(&config)
	}
	manager, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func collect(t *testing.T, execution *Execution) []Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var events []Event
	for sequence := uint64(1); ; sequence++ {
		event, err := execution.Next(ctx, sequence)
		if errors.Is(err, io.EOF) {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
}

func TestExactArgvCWDEnvironmentAndSeparateStreams(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{OperationID: "operation_exact", Argv: []string{"/bin/sh", "-c", `printf '%s|%s' "$PWD" "$VALUE"; printf error >&2; exit 7`}, CWD: root, Environment: map[string]string{"VALUE": "a b"}}
	execution, replay, err := manager.Start(context.Background(), request)
	if err != nil || replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	snapshot, err := execution.Wait(context.Background())
	if err != nil || snapshot.State != StateExited || snapshot.Result == nil || snapshot.Result.Code != 7 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	events := collect(t, execution)
	var stdout, stderr strings.Builder
	for _, event := range events {
		if event.Stream == "stdout" {
			stdout.Write(event.Data)
		}
		if event.Stream == "stderr" {
			stderr.Write(event.Data)
		}
	}
	if stdout.String() != resolvedRoot+"|a b" || stderr.String() != "error" {
		t.Fatalf("stdout=%q stderr=%q events=%#v", stdout.String(), stderr.String(), events)
	}
}

func TestManagedEnvironmentIsResolvedForEachNewProcess(t *testing.T) {
	root := t.TempDir()
	value := "first"
	manager := testManager(t, root, func(config *Config) {
		config.ManagedEnvironment = func() ([]string, error) {
			return []string{"INJECTED=" + value, "OVERRIDE=managed"}, nil
		}
	})
	run := func(operationID string, override map[string]string) string {
		t.Helper()
		execution, _, err := manager.Start(context.Background(), Request{OperationID: operationID, Argv: []string{"/bin/sh", "-c", `printf '%s|%s' "$INJECTED" "$OVERRIDE"`}, CWD: root, Environment: override})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := execution.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		var output strings.Builder
		for _, event := range collect(t, execution) {
			if event.Stream == "stdout" {
				output.Write(event.Data)
			}
		}
		return output.String()
	}
	if got := run("operation_managed_first", nil); got != "first|managed" {
		t.Fatalf("first environment=%q", got)
	}
	value = "second"
	if got := run("operation_managed_second", map[string]string{"override": "request"}); got != "second|request" {
		t.Fatalf("second environment=%q", got)
	}
}

func TestRequestRejectsCaseFoldedEnvironmentDuplicates(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	_, _, err := manager.Start(context.Background(), Request{OperationID: "operation_duplicate_environment", Argv: []string{"/bin/true"}, CWD: root, Environment: map[string]string{"Token": "one", "TOKEN": "two"}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v", err)
	}
}

func TestManagedEnvironmentFailureFailsClosed(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, func(config *Config) {
		config.ManagedEnvironment = func() ([]string, error) { return nil, errors.New("secret detail") }
	})
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_managed_unavailable", Argv: []string{"/bin/true"}, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := execution.Wait(context.Background())
	if err != nil || snapshot.State != StateFailed || snapshot.ErrorCode != "environment_unavailable" || strings.Contains(snapshot.ErrorCode, "secret detail") {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestPipeProcessPreservesSymlinkInvocationName(t *testing.T) {
	root := t.TempDir()
	command := filepath.Join(root, "sh")
	if err := os.Symlink("/bin/sh", command); err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, root, nil)
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_symlink_argv0", Argv: []string{command, "-c", `printf %s "$0"`}, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := execution.Wait(context.Background())
	if err != nil || snapshot.Result == nil || snapshot.Result.Code != 0 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	var stdout strings.Builder
	for _, event := range collect(t, execution) {
		if event.Stream == "stdout" {
			stdout.Write(event.Data)
		}
	}
	if stdout.String() != command {
		t.Fatalf("stdout=%q, want invocation %q", stdout.String(), command)
	}
}

func TestImmediateExitPublishesAllOutputBeforeTerminalState(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	for index := range 100 {
		execution, _, err := manager.Start(context.Background(), Request{OperationID: fmt.Sprintf("operation_drain_%d", index), Argv: []string{"/bin/sh", "-c", `printf out; printf err >&2`}, CWD: root})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := execution.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		events := collect(t, execution)
		var stdout, stderr strings.Builder
		for _, event := range events {
			if event.Stream == "stdout" {
				stdout.Write(event.Data)
			}
			if event.Stream == "stderr" {
				stderr.Write(event.Data)
			}
		}
		if stdout.String() != "out" || stderr.String() != "err" {
			t.Fatalf("iteration=%d stdout=%q stderr=%q events=%#v", index, stdout.String(), stderr.String(), events)
		}
	}
}

func TestOperationRetryDoesNotStartSecondProcessAndConflictFails(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "marker")
	manager := testManager(t, root, nil)
	request := Request{OperationID: "operation_retry", Argv: []string{"/bin/sh", "-c", `printf x >> "$1"`, "sh", marker}, CWD: root}
	first, replay, err := manager.Start(context.Background(), request)
	if err != nil || replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	second, replay, err := manager.Start(context.Background(), request)
	if err != nil || !replay || first != second {
		t.Fatalf("same=%v replay=%v err=%v", first == second, replay, err)
	}
	if _, err := first.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "x" {
		t.Fatalf("marker=%q err=%v", data, err)
	}
	request.Argv = []string{"/bin/echo", "different"}
	if _, _, err := manager.Start(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict err=%v", err)
	}
}

func TestTimeoutTerminatesProcessGroupAndReportsCanceled(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_timeout", Argv: []string{"/bin/sh", "-c", `trap '' TERM; while :; do sleep 1; done`}, CWD: root, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snapshot, err := execution.Wait(ctx)
	if err != nil || snapshot.State != StateCanceled || snapshot.ErrorCode != "exec_timeout" || snapshot.Result == nil {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestImmediateCancellationCannotLeaveStartingProcessRunning(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "late-marker")
	manager := testManager(t, root, nil)
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_cancel_start", Argv: []string{"/bin/sh", "-c", `sleep 0.2; printf late > "$1"`, "sh", marker}, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := execution.Cancel(cancelCtx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	snapshot, err := execution.Wait(context.Background())
	if err != nil || snapshot.State != StateCanceled {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled process published marker: %v", err)
	}
}

func TestPTYMergesOutputAndReportsExit(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_pty", Argv: []string{"/bin/sh", "-c", `printf out; printf err >&2; exit 9`}, CWD: root, PTY: true, Dimensions: pty.Dimensions{Columns: 80, Rows: 24}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := execution.Wait(context.Background())
	if err != nil || snapshot.Result == nil || snapshot.Result.Code != 9 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	events := collect(t, execution)
	var output strings.Builder
	for _, event := range events {
		if event.Stream == "pty" {
			output.Write(event.Data)
		}
		if event.Stream == "stdout" || event.Stream == "stderr" {
			t.Fatalf("PTY emitted split stream: %#v", event)
		}
	}
	if !strings.Contains(output.String(), "out") || !strings.Contains(output.String(), "err") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestReplayBoundRejectsEvictedSequence(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, func(config *Config) { config.ReplayBytes = 64 << 10; config.ChunkBytes = 1024 })
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_replay", Argv: []string{"/bin/sh", "-c", `head -c 131072 /dev/zero`}, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execution.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := execution.Next(context.Background(), 1); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestLiveReaderBackpressuresInsteadOfEvictingUnreadOutput(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, func(config *Config) { config.ReplayBytes = 64 << 10; config.ChunkBytes = 1024 })
	execution, _, err := manager.Start(context.Background(), Request{OperationID: "operation_live_backpressure", Argv: []string{"/bin/sh", "-c", `head -c 262144 /dev/zero`}, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := execution.OpenReader(1)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var bytesRead int
	for {
		event, release, nextErr := reader.Next(context.Background())
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		bytesRead += len(event.Data)
		release()
		if terminalState(event.State) {
			break
		}
	}
	if bytesRead != 262144 {
		t.Fatalf("bytes=%d", bytesRead)
	}
}

func TestValidationRejectsEscapedCWDInvalidEnvironmentAndImplicitDimensions(t *testing.T) {
	root := t.TempDir()
	manager := testManager(t, root, nil)
	requests := []Request{
		{OperationID: "operation_bad_cwd", Argv: []string{"/bin/true"}, CWD: filepath.Dir(root)},
		{OperationID: "operation_bad_env", Argv: []string{"/bin/true"}, CWD: root, Environment: map[string]string{"BAD-KEY": "x"}},
		{OperationID: "operation_bad_size", Argv: []string{"/bin/true"}, CWD: root, Dimensions: pty.Dimensions{Columns: 80, Rows: 24}},
	}
	for _, request := range requests {
		if _, _, err := manager.Start(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("request=%#v err=%v", request, err)
		}
	}
}

func TestPersistentCompletedOperationReplaysWithoutRerun(t *testing.T) {
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	config := Config{WorkspaceRoot: root, BaseEnvironment: []string{"PATH=/usr/bin:/bin"}, MaximumActive: 2, MaximumOperations: 16, ReplayBytes: 64 << 10, Store: durable}
	first, err := NewPersistent(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "marker")
	request := Request{OperationID: "operation_persisted", Argv: []string{"/bin/sh", "-c", `printf x >> "$1"; exit 6`, "sh", marker}, CWD: root}
	execution, replay, err := first.Start(context.Background(), request)
	if err != nil || replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	if snapshot, err := execution.Wait(context.Background()); err != nil || snapshot.Result == nil || snapshot.Result.Code != 6 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	second, err := NewPersistent(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	recovered, replay, err := second.Start(context.Background(), request)
	if err != nil || !replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	snapshot := recovered.Snapshot()
	if snapshot.State != StateExited || snapshot.Result == nil || snapshot.Result.Code != 6 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "x" {
		t.Fatalf("marker=%q err=%v", data, err)
	}
}

func TestPersistentPendingOperationBecomesRestartFailure(t *testing.T) {
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	config := Config{WorkspaceRoot: root, BaseEnvironment: []string{"PATH=/usr/bin:/bin"}, MaximumActive: 2, MaximumOperations: 16, ReplayBytes: 64 << 10, Store: durable}
	validator := testManager(t, root, nil)
	request := Request{OperationID: "operation_pending", Argv: []string{"/bin/true"}, CWD: root}
	_, hash, err := validator.validate(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, inserted, err := durable.ReserveOperation(context.Background(), persistencePrefix+request.OperationID, hash[:], time.Now().UTC().Add(time.Hour)); err != nil || !inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	manager, err := NewPersistent(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	execution, replay, err := manager.Start(context.Background(), request)
	if err != nil || !replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	snapshot := execution.Snapshot()
	if snapshot.State != StateFailed || snapshot.ErrorCode != "exec_start_uncertain" || snapshot.Result == nil {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	records, err := durable.OperationsWithPrefix(context.Background(), persistencePrefix, time.Now().UTC(), 16)
	if err != nil || len(records) != 1 || records[0].State != "completed" || records[0].ErrorCode != "exec_start_uncertain" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
}
