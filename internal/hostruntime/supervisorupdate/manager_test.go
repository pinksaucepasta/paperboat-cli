package supervisorupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

type testFetcher struct{ content map[string][]byte }

func (f testFetcher) FetchComponent(_ context.Context, release workerupdate.Release, component string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.content[component])), nil
}

type testWorkloads struct{ snapshots []WorkloadSnapshot }

func (w *testWorkloads) Snapshot(context.Context) (WorkloadSnapshot, error) {
	if len(w.snapshots) == 0 {
		return WorkloadSnapshot{Generation: 1}, nil
	}
	result := w.snapshots[0]
	w.snapshots = w.snapshots[1:]
	return result, nil
}

type testVerifier struct{}

func (testVerifier) Verify(context.Context, string, string, string) error { return nil }

type testActivator struct{ err error }

func (a *testActivator) Activate(context.Context) error { return a.err }
func (a *testActivator) Rollback(context.Context) error { return nil }

func TestProtectedWorkloadStagesWithoutActivation(t *testing.T) {
	root, old, next, active, candidate := testFixture(t)
	workloads := &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 7, Protected: 2}}}
	manager := newTestManager(t, root, active, old, next, workloads, nil)
	result, err := manager.Check(context.Background(), func(context.Context) (workerupdate.Release, bool, error) { return candidate, true, nil })
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !result.MaintenanceRequired || result.StagedVersion != candidate.Version || result.Applied {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got, _ := os.ReadFile(manager.config.Paths.HostdCurrent); !bytes.Equal(got, old) {
		t.Fatal("protected workload allowed current hostd replacement")
	}
	if !regularMatches(manager.config.Paths.HostdStaged, candidate.Hostd) {
		t.Fatal("candidate hostd was not staged")
	}
}

func TestNoProtectedWorkloadActivatesAllSupervisorSlots(t *testing.T) {
	root, old, next, active, candidate := testFixture(t)
	workloads := &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 3}}}
	manager := newTestManager(t, root, active, old, next, workloads, nil)
	result, err := manager.Check(context.Background(), func(context.Context) (workerupdate.Release, bool, error) { return candidate, true, nil })
	if err != nil || !result.Applied {
		t.Fatalf("check result=%+v err=%v", result, err)
	}
	for name, path := range map[string]string{"hostd": manager.config.Paths.HostdCurrent, "updater": manager.config.Paths.UpdaterCurrent, "launcher": manager.config.Paths.LauncherCurrent} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, next) {
			t.Fatalf("%s current was not activated: err=%v", name, readErr)
		}
	}
	if !regularMatches(manager.config.Paths.HostdRollback, active.Hostd) {
		t.Fatal("previous hostd was not retained as rollback")
	}
}

func TestApprovalRejectsStaleWorkloadGeneration(t *testing.T) {
	root, old, next, active, candidate := testFixture(t)
	workloads := &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 9, Protected: 1}, {Generation: 10, Protected: 1}}}
	manager := newTestManager(t, root, active, old, next, workloads, nil)
	_, err := manager.Approve(context.Background(), candidate.Version, func(context.Context) (workerupdate.Release, bool, error) { return candidate, true, nil })
	if !errors.Is(err, ErrStaleWorkloads) {
		t.Fatalf("expected stale workload rejection, got %v", err)
	}
	if got, _ := os.ReadFile(manager.config.Paths.HostdCurrent); !bytes.Equal(got, old) {
		t.Fatal("stale approval replaced current hostd")
	}
}

func TestApprovalRequiresExactRelease(t *testing.T) {
	root, old, next, active, candidate := testFixture(t)
	manager := newTestManager(t, root, active, old, next, &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 1, Protected: 1}}}, nil)
	_, err := manager.Approve(context.Background(), "2026.08.18.999", func(context.Context) (workerupdate.Release, bool, error) { return candidate, true, nil })
	if !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("expected exact release rejection, got %v", err)
	}
}

func TestRecoveryCommitsFullyRotatedSupervisor(t *testing.T) {
	root, _, next, active, candidate := testFixture(t)
	failing := &testActivator{err: errors.New("service restart interrupted")}
	manager := newTestManager(t, root, active, validELF(0x11), next, &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 1}}}, failing)
	_, err := manager.Check(context.Background(), func(context.Context) (workerupdate.Release, bool, error) { return candidate, true, nil })
	if !errors.Is(err, ErrActivationUncertain) {
		t.Fatalf("expected uncertain activation, got %v", err)
	}
	recovered := newTestManager(t, root, candidate, validELF(0x11), next, &testWorkloads{snapshots: []WorkloadSnapshot{{Generation: 1}}}, nil)
	if err := recovered.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := recovered.ActiveVersion(); got != candidate.Version {
		t.Fatalf("active version after recovery=%s", got)
	}
}

func testFixture(t *testing.T) (string, []byte, []byte, workerupdate.Release, workerupdate.Release) {
	t.Helper()
	root := t.TempDir()
	old := validELF(0x11)
	next := validELF(0x22)
	active := workerupdate.Release{Version: "2026.08.18.1", Platform: runtime.GOOS, Architecture: runtime.GOARCH, Hostd: target(old), Updater: target(old), Launcher: target(old)}
	candidate := workerupdate.Release{Version: "2026.08.18.2", Platform: runtime.GOOS, Architecture: runtime.GOARCH, Hostd: target(next), Updater: target(next), Launcher: target(next)}
	paths := []string{filepath.Join(root, "hostd"), filepath.Join(root, "updater"), filepath.Join(root, "launcher")}
	for _, path := range paths {
		if err := os.WriteFile(path, old, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root, old, next, active, candidate
}

func newTestManager(t *testing.T, root string, active workerupdate.Release, old, next []byte, workloads *testWorkloads, activator *testActivator) *Manager {
	t.Helper()
	paths := Paths{
		StatePath:    filepath.Join(root, "journal.json"),
		HostdCurrent: filepath.Join(root, "hostd"), HostdRollback: filepath.Join(root, "rollback-hostd"), HostdStaged: filepath.Join(root, "staged-hostd"),
		UpdaterCurrent: filepath.Join(root, "updater"), UpdaterRollback: filepath.Join(root, "rollback-updater"), UpdaterStaged: filepath.Join(root, "staged-updater"),
		LauncherCurrent: filepath.Join(root, "launcher"), LauncherRollback: filepath.Join(root, "rollback-launcher"), LauncherStaged: filepath.Join(root, "staged-launcher"),
	}
	if err := prepareSupervisorUpdateTestRoot(root); err != nil {
		t.Fatal(err)
	}
	fetcher := testFetcher{content: map[string][]byte{"hostd": next, "updater": next, "launcher": next}}
	var activation Activator
	if activator != nil {
		activation = activator
	}
	manager, err := New(Config{Paths: paths, Active: active, Fetcher: fetcher, Workloads: workloads, NativeVerifier: testVerifier{}, Activator: activation, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func validELF(marker byte) []byte {
	value := make([]byte, 64)
	if runtime.GOOS == "windows" {
		value = make([]byte, 128)
		copy(value[:2], "MZ")
		binary.LittleEndian.PutUint32(value[0x3c:0x40], 64)
		copy(value[64:68], "PE\x00\x00")
		machine := uint16(0x8664)
		if runtime.GOARCH == "arm64" {
			machine = 0xaa64
		}
		binary.LittleEndian.PutUint16(value[68:70], machine)
		binary.LittleEndian.PutUint16(value[84:86], 0x20b)
		value[len(value)-1] = marker
		return value
	}
	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint32(value[:4], 0xfeedfacf)
		cpu := uint32(0x01000007)
		if runtime.GOARCH == "arm64" {
			cpu = 0x0100000c
		}
		binary.LittleEndian.PutUint32(value[4:8], cpu)
	} else {
		copy(value, "\x7fELF")
		value[4], value[5] = 2, 1
		machine := uint16(62)
		if runtime.GOARCH == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(value[18:20], machine)
	}
	value[len(value)-1] = marker
	return value
}

func target(content []byte) workerupdate.ComponentTarget {
	digest := sha256.Sum256(content)
	return workerupdate.ComponentTarget{SHA256: fmtHex(digest[:]), Length: int64(len(content)), Platform: runtime.GOOS, Architecture: runtime.GOARCH}
}

func fmtHex(value []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for i, value := range value {
		result[i*2], result[i*2+1] = hex[value>>4], hex[value&15]
	}
	return string(result)
}
