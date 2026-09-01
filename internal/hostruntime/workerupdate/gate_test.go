//go:build darwin || linux

package workerupdate

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

type scriptedGate struct {
	mu                                                        sync.Mutex
	candidateErr, drainErr, activeErr, commitErr, rollbackErr error
	candidate, drain, active, commit, rollback                int
}

func (g *scriptedGate) Candidate(context.Context, GateRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.candidate++
	return g.candidateErr
}
func (g *scriptedGate) Drain(ctx context.Context, _ GateRequest) error {
	g.mu.Lock()
	g.drain++
	err := g.drainErr
	g.mu.Unlock()
	if errors.Is(err, context.DeadlineExceeded) {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}
func (g *scriptedGate) Active(context.Context, GateRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active++
	return g.activeErr
}
func (g *scriptedGate) Commit(context.Context, GateRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.commit++
	return g.commitErr
}
func (g *scriptedGate) Rollback(context.Context, GateRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rollback++
	return g.rollbackErr
}

func TestCandidateCanaryFailureQuarantinesWithoutCutover(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{candidateErr: errors.New("edge route canary failed")}
	fixture.manager.config.Gate = gate
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrActivationGate) || fixture.hostd.activations != 0 || gate.candidate != 1 || gate.drain != 0 {
		t.Fatalf("error=%v activations=%d gate=%+v", err, fixture.hostd.activations, gate)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureCanary || journal.CandidateVersion != fixture.candidate.Version {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
	if _, err := fixture.manager.Activate(context.Background(), fixture.candidate); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantined retry error=%v", err)
	}
}

func TestDrainDeadlineQuarantinesBeforeActivation(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{drainErr: context.DeadlineExceeded}
	fixture.manager.config.Gate = gate
	fixture.manager.config.DrainTimeout = time.Millisecond
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, context.DeadlineExceeded) || fixture.hostd.activations != 0 || gate.drain != 1 || gate.rollback != 1 {
		t.Fatalf("error=%v activations=%d gate=%+v", err, fixture.hostd.activations, gate)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureDrain || journal.CandidateVersion != fixture.candidate.Version {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
}

func TestPartialDrainErrorBlocksWhenOldPathCannotBeRestored(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{drainErr: errors.New("drain response lost"), rollbackErr: errors.New("old route remains drained")}
	fixture.manager.config.Gate = gate
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrBlocked) || gate.drain != 1 || gate.rollback != 1 || fixture.hostd.activations != 0 {
		t.Fatalf("error=%v activations=%d gate=%+v", err, fixture.hostd.activations, gate)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageBlocked || journal.LastFailure != updateflow.FailureDrain {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
}

func TestRecoverInterruptedDrainRevalidatesOldActiveBeforeDiscard(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{}
	fixture.manager.config.Gate = gate
	if err := os.WriteFile(fixture.paths.staged, []byte("candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	journal := withRelease(fixture.manager.newJournal(), fixture.candidate, fixture.paths.staged)
	var err error
	for _, stage := range []updateflow.Stage{updateflow.StageChecking, updateflow.StageStaged, updateflow.StageCandidateStarted, updateflow.StageCandidateValidating, updateflow.StageCandidateReady, updateflow.StageDraining} {
		journal, err = fixture.manager.transition(journal, stage)
		if err != nil {
			t.Fatal(err)
		}
	}
	journal.WorkerID, journal.WorkerEpoch = workerID(fixture.candidate.Version), 2
	if err := fixture.manager.write(journal); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gate.rollback != 1 {
		t.Fatalf("rollback calls=%d", gate.rollback)
	}
	recovered, err := updateflow.Load(fixture.paths.journal)
	if err != nil || recovered.Stage != updateflow.StageIdle || recovered.LastFailure != updateflow.FailureDrain {
		t.Fatalf("journal=%+v err=%v", recovered, err)
	}
	if _, err := os.Stat(fixture.paths.staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged candidate retained: %v", err)
	}
}

func TestRecoverCutoverWithOldActiveUndrainsBeforeCleanup(t *testing.T) {
	for _, rollbackFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "blocked"}[rollbackFailure], func(t *testing.T) {
			fixture := newFixture(t)
			gate := &scriptedGate{}
			if rollbackFailure {
				gate.rollbackErr = errors.New("old route not restored")
			}
			fixture.manager.config.Gate = gate
			if err := os.WriteFile(fixture.paths.staged, []byte("candidate"), 0o700); err != nil {
				t.Fatal(err)
			}
			journal := withRelease(fixture.manager.newJournal(), fixture.candidate, fixture.paths.staged)
			var err error
			for _, stage := range []updateflow.Stage{updateflow.StageChecking, updateflow.StageStaged, updateflow.StageCandidateStarted, updateflow.StageCandidateValidating, updateflow.StageCandidateReady, updateflow.StageDraining, updateflow.StageCutover} {
				journal, err = fixture.manager.transition(journal, stage)
				if err != nil {
					t.Fatal(err)
				}
			}
			journal.WorkerID, journal.WorkerEpoch = workerID(fixture.candidate.Version), 2
			if err := fixture.manager.write(journal); err != nil {
				t.Fatal(err)
			}
			err = fixture.manager.Recover(context.Background())
			if rollbackFailure && !errors.Is(err, ErrBlocked) || !rollbackFailure && err != nil {
				t.Fatalf("recover error=%v", err)
			}
			if gate.rollback != 1 {
				t.Fatalf("rollback calls=%d", gate.rollback)
			}
			recovered, loadErr := updateflow.Load(fixture.paths.journal)
			want := updateflow.StageIdle
			if rollbackFailure {
				want = updateflow.StageBlocked
			}
			if loadErr != nil || recovered.Stage != want {
				t.Fatalf("journal=%+v err=%v", recovered, loadErr)
			}
		})
	}
}

func TestPostPromoteJournalFailureRestoresStorageAndUndrains(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{}
	fixture.manager.config.Gate = gate
	fixture.manager.config.WriteJournal = func(path string, journal updateflow.Journal, uid, gid int) error {
		if journal.Stage == updateflow.StageCutover && journal.StagedPath == fixture.paths.current {
			return errors.New("journal fsync failed after promotion")
		}
		return updateflow.Write(path, journal, uid, gid)
	}
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if err == nil || gate.drain != 1 || gate.rollback != 1 || fixture.hostd.activations != 0 {
		t.Fatalf("error=%v activations=%d gate=%+v", err, fixture.hostd.activations, gate)
	}
	body, readErr := os.ReadFile(fixture.paths.current)
	if readErr != nil || len(body) != int(fixture.active.Length) {
		t.Fatalf("active slot not restored: bytes=%d err=%v", len(body), readErr)
	}
}

func TestStabilityCanaryFailureRollsBackAndRevalidates(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{activeErr: errors.New("edge path unavailable")}
	fixture.manager.config.Gate = gate
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrActivationGate) || fixture.hostd.activations != 2 || gate.candidate != 1 || gate.drain != 1 || gate.active != 1 || gate.rollback != 1 {
		t.Fatalf("error=%v activations=%d gate=%+v", err, fixture.hostd.activations, gate)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureHealth || journal.CandidateVersion != fixture.candidate.Version {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
}

func TestCommitFailureRemainsDurableAndRecoveryRetriesBeforeCleanup(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{commitErr: errors.New("hostd commit unavailable")}
	fixture.manager.config.Gate = gate
	result, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrActivationGate) || result.Updated || gate.commit != 1 || fixture.manager.ActiveVersion() != fixture.active.Version {
		t.Fatalf("result=%+v error=%v commit=%d active=%s", result, err, gate.commit, fixture.manager.ActiveVersion())
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageCommitted {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
	gate.commitErr = nil
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gate.commit != 2 || fixture.manager.ActiveVersion() != fixture.candidate.Version {
		t.Fatalf("commit=%d active=%s", gate.commit, fixture.manager.ActiveVersion())
	}
	journal, loadErr = updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
}

func TestRollbackRevalidationFailureLeavesDurableBlockedState(t *testing.T) {
	fixture := newFixture(t)
	gate := &scriptedGate{activeErr: errors.New("candidate unavailable"), rollbackErr: errors.New("restored path unavailable")}
	fixture.manager.config.Gate = gate
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrBlocked) || gate.rollback != 1 {
		t.Fatalf("error=%v gate=%+v", err, gate)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageBlocked || journal.LastFailure != updateflow.FailureRollback {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
}
