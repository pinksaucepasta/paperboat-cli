//go:build linux || darwin

package updateflow

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validJournal(root string, stage Stage) Journal {
	return Journal{Schema: SchemaV1, TransactionID: "txn_1", Stage: stage,
		ActiveVersion: "2026.08.18.3", RollbackVersion: "2026.08.17.1",
		CandidateVersion: "2026.08.19.1", CandidateDigest: strings.Repeat("a", 64),
		CandidateLength: 1024, CandidateCLIDigest: strings.Repeat("b", 64), CandidateCLILength: 1024, StagedPath: filepath.Join(root, "runtime.staged"),
		HostdAPIMin: 1, HostdAPIMax: 2, WorkerID: "runtime_4", WorkerEpoch: 4, BootID: "boot_1",
		StageUpdatedAt: time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)}
}

func TestJournalTransitionAndCrashRecovery(t *testing.T) {
	root := t.TempDir()
	j := validJournal(root, StageStaged)
	j.WorkerEpoch = 0
	steps := []struct {
		stage    Stage
		recovery RecoveryAction
	}{
		{StageCandidateStarted, RecoveryDiscardCandidate}, {StageCandidateReady, RecoveryDiscardCandidate},
		{StageCutover, RecoveryQueryHostd}, {StageMonitoring, RecoveryContinueMonitor},
		{StageCommitted, RecoveryFinalizeCleanup},
	}
	for index, step := range steps {
		if step.stage == StageCutover {
			j.WorkerEpoch = 4
		}
		var err error
		j, err = j.Transition(step.stage, j.StageUpdatedAt.Add(time.Duration(index+1)*time.Second))
		if err != nil {
			t.Fatalf("transition to %s: %v", step.stage, err)
		}
		if got := j.Recovery(); got != step.recovery {
			t.Fatalf("stage=%s recovery=%s", step.stage, got)
		}
	}
	if j.HealthDeadline.IsZero() {
		t.Fatal("monitoring deadline was not established")
	}
}

func TestJournalRejectsSkippedCutover(t *testing.T) {
	j := validJournal(t.TempDir(), StageCandidateReady)
	if _, err := j.Transition(StageMonitoring, j.StageUpdatedAt.Add(time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error=%v", err)
	}
}

func TestJournalRoundTripAndRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "journal.json")
	j := validJournal(root, StageMonitoring)
	if err := Write(path, j, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Stage != StageMonitoring {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.worker-update/v1","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("error=%v", err)
	}
}

func TestContradictoryJournalFailsClosed(t *testing.T) {
	j := validJournal(t.TempDir(), StageCutover)
	j.WorkerEpoch = 0
	if got := j.Recovery(); got != RecoveryRequired {
		t.Fatalf("recovery=%s", got)
	}
}
