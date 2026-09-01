//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func TestValidRuntimeIdentitySupportsOnlyExactPairs(t *testing.T) {
	for _, test := range []struct {
		uid, gid int
		want     bool
	}{
		{uid: 1000, gid: 1000, want: true},
		{uid: 0, gid: 0, want: true},
		{uid: 0, gid: 1000},
		{uid: 1000, gid: 0},
		{uid: -1, gid: -1},
	} {
		if got := validRuntimeIdentity(test.uid, test.gid); got != test.want {
			t.Fatalf("validRuntimeIdentity(%d, %d)=%v want %v", test.uid, test.gid, got, test.want)
		}
	}
}

type recordingUpdaterRunner struct {
	started chan struct{}
	stopped chan struct{}
}

func (r *recordingUpdaterRunner) Run(ctx context.Context, ready func() error) error {
	close(r.started)
	if err := ready(); err != nil {
		return err
	}
	<-ctx.Done()
	close(r.stopped)
	return ctx.Err()
}

type recordingProcessNotifier struct {
	mu               sync.Mutex
	events           []string
	watchdogInterval time.Duration
	watchdogSeen     chan struct{}
	watchdogErr      error
}

func (n *recordingProcessNotifier) Ready() error {
	n.record("ready")
	return nil
}

func (n *recordingProcessNotifier) Degraded(_ string) error {
	n.record("degraded")
	return nil
}

func (n *recordingProcessNotifier) Stopping() error {
	n.record("stopping")
	return nil
}

func (n *recordingProcessNotifier) WatchdogInterval() time.Duration { return n.watchdogInterval }

func (n *recordingProcessNotifier) Watchdog() error {
	n.record("watchdog")
	select {
	case n.watchdogSeen <- struct{}{}:
	default:
	}
	return n.watchdogErr
}

func (n *recordingProcessNotifier) record(event string) {
	n.mu.Lock()
	n.events = append(n.events, event)
	n.mu.Unlock()
}

func (n *recordingProcessNotifier) snapshot() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.events...)
}

func TestRunNotifiedUpdaterSendsReadyWatchdogAndStopping(t *testing.T) {
	runner := &recordingUpdaterRunner{started: make(chan struct{}), stopped: make(chan struct{})}
	notifier := &recordingProcessNotifier{watchdogInterval: time.Millisecond, watchdogSeen: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runNotifiedUpdater(ctx, runner, notifier) }()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("updater did not start")
	}
	select {
	case <-notifier.watchdogSeen:
	case <-time.After(time.Second):
		t.Fatal("watchdog notification was not sent")
	}
	cancel()
	select {
	case <-runner.stopped:
	case <-time.After(time.Second):
		t.Fatal("updater did not stop after cancellation")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	events := notifier.snapshot()
	if len(events) < 3 || events[0] != "ready" || events[len(events)-1] != "stopping" {
		t.Fatalf("notification events=%v", events)
	}
}

func TestRunNotifiedUpdaterStopsAfterWatchdogFailure(t *testing.T) {
	watchdogErr := errors.New("watchdog socket failed")
	runner := &recordingUpdaterRunner{started: make(chan struct{}), stopped: make(chan struct{})}
	notifier := &recordingProcessNotifier{watchdogInterval: time.Millisecond, watchdogSeen: make(chan struct{}, 1), watchdogErr: watchdogErr}
	if err := runNotifiedUpdater(context.Background(), runner, notifier); !errors.Is(err, watchdogErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	select {
	case <-runner.stopped:
	case <-time.After(time.Second):
		t.Fatal("updater did not stop after watchdog failure")
	}
	events := notifier.snapshot()
	if len(events) < 4 || events[0] != "ready" || events[len(events)-1] != "stopping" {
		t.Fatalf("notification events=%v", events)
	}
	if events[len(events)-2] != "degraded" {
		t.Fatalf("notification events=%v", events)
	}
}

func TestResolveUpdatedActiveRecoversVerifiedMonitoringCandidate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	version := "2026.08.27.55"
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-monitor", Stage: updateflow.StageMonitoring,
		ActiveVersion: "2026.08.27.52", CandidateVersion: version,
		CandidateDigest: strings.Repeat("a", 64), CandidateLength: 1024, StagedPath: filepath.Join(root, "pb"),
		HostdAPIMin: 1, HostdAPIMax: 1, RuntimeAPIMin: 1, RuntimeAPIMax: 1,
		WorkerID: "runtime-2026.08.27.55", WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: time.Now().Add(-time.Minute).UTC(), HealthDeadline: time.Now().Add(time.Minute).UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	active, err := resolveUpdatedActive(context.Background(), path, version, func(context.Context, string) (workerupdate.Release, error) {
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != version || active.Platform != runtime.GOOS || active.Architecture != runtime.GOARCH {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}

func TestResolveUpdatedActiveDoesNotBypassSignedRevocation(t *testing.T) {
	called := false
	_, err := resolveUpdatedActive(context.Background(), filepath.Join(t.TempDir(), "transaction.json"), "2026.08.27.55", func(context.Context, string) (workerupdate.Release, error) {
		called = true
		return workerupdate.Release{}, workerupdate.ErrReleaseRevoked
	})
	if !called || !errors.Is(err, workerupdate.ErrReleaseRevoked) {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestResolveUpdatedActiveUsesPersistedPreviousReleaseForRollback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-current", Stage: updateflow.StageMonitoring,
		ActiveVersion: "2026.08.27.55", ActiveDigest: strings.Repeat("a", 64), ActiveLength: 900,
		ActiveHostdAPIMin: 1, ActiveHostdAPIMax: 1, ActiveRuntimeAPIMin: 1, ActiveRuntimeAPIMax: 1,
		CandidateVersion: "2026.08.27.56", CandidateDigest: strings.Repeat("b", 64), CandidateLength: 1024,
		StagedPath: filepath.Join(root, "pb"), HostdAPIMin: 1, HostdAPIMax: 1, RuntimeAPIMin: 1, RuntimeAPIMax: 1,
		WorkerID: "runtime-2026.08.27.56", WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: time.Now().Add(-time.Minute).UTC(), HealthDeadline: time.Now().Add(time.Minute).UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	var checked []string
	active, err := resolveUpdatedActive(context.Background(), path, journal.CandidateVersion, func(_ context.Context, version string) (workerupdate.Release, error) {
		checked = append(checked, version)
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != journal.ActiveVersion || strings.Join(checked, ",") != journal.CandidateVersion+","+journal.ActiveVersion {
		t.Fatalf("active=%+v checked=%v err=%v", active, checked, err)
	}
}

func TestResolveUpdatedActiveAfterCurrentIndexAdvancesWithoutTransaction(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	version := "2026.08.27.57"
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-seed", Stage: updateflow.StageIdle,
		ActiveVersion: version, ActiveDigest: strings.Repeat("a", 64), ActiveLength: 900,
		ActiveHostdAPIMin: 1, ActiveHostdAPIMax: 1, ActiveRuntimeAPIMin: 1, ActiveRuntimeAPIMax: 1,
		BootID: "hostd", StageUpdatedAt: time.Now().UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	active, err := resolveUpdatedActive(context.Background(), path, version, func(context.Context, string) (workerupdate.Release, error) {
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != version || active.SHA256 != journal.ActiveDigest {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}
