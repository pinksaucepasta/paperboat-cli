//go:build darwin || linux

package workerupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

func TestTRK35UpdateJournalClockBoundaryIsInclusive(t *testing.T) {
	fixture := newFixture(t)
	const timestamp = "2026-09-01T12:00:00Z"
	now, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.config.Now = func() time.Time { return now }
	base := fixture.manager.newJournal()
	if !base.StageUpdatedAt.Equal(now) {
		t.Fatalf("new journal timestamp=%s want=%s", base.StageUpdatedAt, now)
	}
	if next, err := base.Transition(updateflow.StageChecking, now); err != nil || !next.StageUpdatedAt.Equal(now) {
		t.Fatalf("equal timestamp transition=%+v err=%v", next, err)
	}
	if _, err := base.Transition(updateflow.StageChecking, now.Add(-time.Nanosecond)); !errors.Is(err, updateflow.ErrInvalidTransition) {
		t.Fatalf("clock rollback transition error=%v", err)
	}
}

func TestTRK35CorruptJournalBlocksRecoveryWithoutTouchingRuntime(t *testing.T) {
	fixture := newFixture(t)
	currentBefore, err := os.ReadFile(fixture.paths.current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.paths.staged, []byte("candidate remains quarantined"), 0o700); err != nil {
		t.Fatal(err)
	}
	truncated := []byte(`{"schema":"paperboat.worker-update/v1","transaction_id":"txn-corrupt","stage":"cutover"`)
	if err := os.WriteFile(fixture.paths.journal, truncated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.TransactionState(); !errors.Is(err, updateflow.ErrInvalidJournal) {
		t.Fatalf("TransactionState error=%v, want invalid journal", err)
	}
	if err := fixture.manager.Recover(context.Background()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("corrupt journal recovery error=%v, want ErrBlocked", err)
	}
	currentAfter, err := os.ReadFile(fixture.paths.current)
	if err != nil || !bytes.Equal(currentAfter, currentBefore) {
		t.Fatalf("corrupt journal changed active runtime err=%v equal=%v", err, bytes.Equal(currentAfter, currentBefore))
	}
	if _, err := os.Stat(fixture.paths.staged); err != nil {
		t.Fatalf("corrupt journal removed staged evidence: %v", err)
	}
	if fixture.manager.ActiveVersion() != fixture.active.Version {
		t.Fatalf("corrupt journal changed active version=%q", fixture.manager.ActiveVersion())
	}
}

func TestTRK35CutoverCrashRecoveryIsIdempotentAtFixedClock(t *testing.T) {
	fixture := newFixture(t)
	now := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	fixture.manager.config.Now = func() time.Time { return now }
	gate := &scriptedGate{}
	fixture.manager.config.Gate = gate
	fixture.starter.activateError = errors.New("activation response lost")
	if _, err := fixture.manager.Activate(context.Background(), fixture.candidate); !errors.Is(err, fixture.starter.activateError) {
		t.Fatalf("cutover crash error=%v", err)
	}
	crashed, err := updateflow.Load(fixture.paths.journal)
	if err != nil || crashed.Stage != updateflow.StageCutover || crashed.WorkerEpoch == 0 {
		t.Fatalf("crashed journal=%+v err=%v", crashed, err)
	}

	fixture.starter.activateError = nil
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatalf("first crash recovery error=%v", err)
	}
	commits := gate.commit
	if fixture.manager.ActiveVersion() != fixture.candidate.Version || commits != 1 {
		t.Fatalf("first recovery active=%q commits=%d", fixture.manager.ActiveVersion(), commits)
	}
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatalf("idempotent crash recovery error=%v", err)
	}
	if fixture.manager.ActiveVersion() != fixture.candidate.Version || fixture.starter.starts != 1 || gate.commit != commits {
		t.Fatalf("recovery replay changed transaction active=%q starts=%d commits=%d want commits=%d", fixture.manager.ActiveVersion(), fixture.starter.starts, gate.commit, commits)
	}
	final, err := updateflow.Load(fixture.paths.journal)
	if err != nil || final.Stage != updateflow.StageIdle || final.ActiveVersion != fixture.candidate.Version || final.LastFailure != updateflow.FailureNone {
		t.Fatalf("final recovery journal=%+v err=%v", final, err)
	}
}

func TestTRK35QuarantineSurvivesRestartAndAllowsOnlyNewerRelease(t *testing.T) {
	fixture := newFixture(t)
	now := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	fixture.manager.config.Now = func() time.Time { return now }
	gate := &scriptedGate{candidateErr: errors.New("candidate rejected")}
	fixture.manager.config.Gate = gate
	if _, err := fixture.manager.Activate(context.Background(), fixture.candidate); !errors.Is(err, ErrActivationGate) {
		t.Fatalf("candidate failure error=%v", err)
	}
	quarantined, err := fixture.manager.TransactionState()
	if err != nil || !quarantined.Quarantined || quarantined.Stage != updateflow.StageIdle || quarantined.CandidateVersion != fixture.candidate.Version {
		t.Fatalf("quarantine state=%+v err=%v", quarantined, err)
	}

	restarted, err := New(fixture.manager.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Activate(context.Background(), fixture.candidate); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("exact quarantined retry error=%v", err)
	}
	restarted.config.Gate = &scriptedGate{}
	newer := release("2026.08.18.3", fixture.fetcher.body)
	result, err := restarted.Activate(context.Background(), newer)
	if err != nil || !result.Updated || restarted.ActiveVersion() != newer.Version {
		t.Fatalf("newer release result=%+v err=%v active=%q", result, err, restarted.ActiveVersion())
	}
}
