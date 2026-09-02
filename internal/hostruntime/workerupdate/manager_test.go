//go:build darwin || linux

package workerupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

func TestWorkerUpdateCutsOverWithoutRestartingHostd(t *testing.T) {
	fixture := newFixture(t)
	result, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.Version != fixture.candidate.Version {
		t.Fatalf("result=%+v", result)
	}
	if fixture.hostd.activations != 1 || fixture.hostd.active.WorkerID != workerID(fixture.candidate.Version) {
		t.Fatalf("hostd=%+v", fixture.hostd)
	}
	if fixture.starter.starts != 1 || fixture.starter.requests[0].Executable != fixture.paths.staged || fixture.starter.requests[0].UID <= 0 || !fixture.starter.requests[0].MutationsDisabled {
		t.Fatalf("start requests=%+v", fixture.starter.requests)
	}
	if _, err := os.Stat(fixture.paths.staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged runtime remains after commit: %v", err)
	}
	if !regularMatches(fixture.paths.current, fixture.candidate.Length, fixture.candidate.SHA256) || !regularMatches(fixture.paths.rollback, fixture.active.Length, fixture.active.SHA256) {
		t.Fatal("active/rollback runtime retention is incorrect")
	}
	if info, err := os.Stat(fixture.paths.current); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("active runtime is not executable: info=%v err=%v", info, err)
	}
	journal, err := updateflow.Load(fixture.paths.journal)
	if err != nil || journal.Stage != updateflow.StageIdle || journal.ActiveVersion != fixture.candidate.Version {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	recovered, err := ActiveReleaseFromJournal(fixture.paths.journal, fixture.candidate.Version)
	if err != nil || !sameReleaseTargets(recovered, fixture.candidate) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
}

func TestActiveVersionRemainsReadableDuringHealthHold(t *testing.T) {
	fixture := newFixture(t)
	health := &blockingHealth{entered: make(chan struct{}, 1), release: make(chan struct{})}
	fixture.manager.config.Health = health
	updateDone := make(chan error, 1)
	released := false
	defer func() {
		if !released {
			close(health.release)
		}
	}()
	go func() {
		_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
		updateDone <- err
	}()
	select {
	case <-health.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("update did not enter its health hold")
	}
	version := make(chan string, 1)
	go func() { version <- fixture.manager.ActiveVersion() }()
	select {
	case got := <-version:
		if got != fixture.active.Version {
			t.Fatalf("active version during hold = %q, want %q", got, fixture.active.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("active version blocked behind the update transaction")
	}
	close(health.release)
	released = true
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
}

func TestWorkerUpdateSeedsSignedActiveStateBeforeFirstUpdate(t *testing.T) {
	fixture := newFixture(t)
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, err := updateflow.Load(fixture.paths.journal)
	if err != nil || journal.Stage != updateflow.StageIdle || journal.ActiveVersion != fixture.active.Version || journal.ActiveDigest != fixture.active.SHA256 {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	recovered, err := RecoveryReleaseFromJournal(fixture.paths.journal, fixture.active.Version)
	if err != nil || !sameReleaseTargets(recovered, fixture.active) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
}

func TestNewerNativePackageSupersedesBlockedPreCutoverWorkerTransaction(t *testing.T) {
	fixture := newFixture(t)
	now := time.Now().UTC()
	journal := withRelease(withActiveRelease(updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-blocked-package-upgrade", Stage: updateflow.StageBlocked,
		BootID: "hostd", StageUpdatedAt: now, LastFailure: updateflow.FailureDrain,
	}, fixture.active), fixture.candidate, fixture.paths.staged)
	if err := os.WriteFile(fixture.paths.staged, fixture.fetcher.body, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := updateflow.Write(fixture.paths.journal, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	packaged := release("2026.08.18.3", fixture.fetcher.body)
	fixture.manager.active = packaged
	fixture.manager.activeVersion.Store(packaged.Version)
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := updateflow.Load(fixture.paths.journal)
	if err != nil || recovered.Stage != updateflow.StageIdle || recovered.ActiveVersion != packaged.Version || recovered.ActiveDigest != packaged.SHA256 {
		t.Fatalf("journal=%+v err=%v", recovered, err)
	}
	if _, err := os.Stat(fixture.paths.staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded staged candidate remains: %v", err)
	}
}

func TestNewerNativePackageSupersedesIdleOlderJournal(t *testing.T) {
	fixture := newFixture(t)
	journal := withActiveRelease(updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-idle-package-upgrade", Stage: updateflow.StageIdle,
		BootID: "hostd", StageUpdatedAt: time.Now().UTC(),
	}, fixture.active)
	if err := updateflow.Write(fixture.paths.journal, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	packaged := release("2026.08.18.3", fixture.fetcher.body)
	fixture.manager.active = packaged
	fixture.manager.activeVersion.Store(packaged.Version)
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := updateflow.Load(fixture.paths.journal)
	if err != nil || recovered.Stage != updateflow.StageIdle || recovered.ActiveVersion != packaged.Version || recovered.ActiveDigest != packaged.SHA256 {
		t.Fatalf("journal=%+v err=%v", recovered, err)
	}
}

func TestOlderExecutableCannotSupersedeBlockedWorkerTransaction(t *testing.T) {
	fixture := newFixture(t)
	now := time.Now().UTC()
	newer := release("2026.08.18.4", fixture.fetcher.body)
	journal := withRelease(withActiveRelease(updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-blocked-no-downgrade", Stage: updateflow.StageBlocked,
		BootID: "hostd", StageUpdatedAt: now, LastFailure: updateflow.FailureDrain,
	}, newer), fixture.candidate, fixture.paths.staged)
	if err := updateflow.Write(fixture.paths.journal, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Recover(context.Background()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("recover error=%v, want blocked", err)
	}
	persisted, err := updateflow.Load(fixture.paths.journal)
	if err != nil || persisted.TransactionID != journal.TransactionID || persisted.Stage != updateflow.StageBlocked {
		t.Fatalf("journal=%+v err=%v", persisted, err)
	}
}

func TestActiveReleaseFromLegacyMonitoringJournalUsesVerifiedCandidate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	candidate := release("2026.08.27.55", []byte("signed package"))
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-legacy", Stage: updateflow.StageMonitoring,
		ActiveVersion: "2026.08.27.52", CandidateVersion: candidate.Version,
		CandidateDigest: candidate.SHA256, CandidateLength: candidate.Length,
		StagedPath: filepath.Join(root, "pb"), HostdAPIMin: candidate.HostdAPIMin, HostdAPIMax: candidate.HostdAPIMax,
		RuntimeAPIMin: candidate.RuntimeAPIMin, RuntimeAPIMax: candidate.RuntimeAPIMax,
		WorkerID: "runtime-2026.08.27.55", WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: time.Now().Add(-time.Minute).UTC(), HealthDeadline: time.Now().Add(time.Minute).UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	recovered, err := ActiveReleaseFromJournal(path, candidate.Version)
	if err != nil || !sameReleaseTargets(recovered, candidate) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if _, err := ActiveReleaseFromJournal(path, journal.ActiveVersion); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("legacy active release error=%v", err)
	}
}

func TestRecoverLegacyPromotedCandidateCommitsHealthyTransaction(t *testing.T) {
	fixture := newFixture(t)
	now := time.Now().UTC()
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-legacy", Stage: updateflow.StageMonitoring,
		ActiveVersion: fixture.active.Version, CandidateVersion: fixture.candidate.Version,
		CandidateDigest: fixture.candidate.SHA256, CandidateLength: fixture.candidate.Length,
		StagedPath: fixture.paths.current, HostdAPIMin: fixture.candidate.HostdAPIMin, HostdAPIMax: fixture.candidate.HostdAPIMax,
		RuntimeAPIMin: fixture.candidate.RuntimeAPIMin, RuntimeAPIMax: fixture.candidate.RuntimeAPIMax,
		WorkerID: workerID(fixture.candidate.Version), WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: now.Add(-2 * time.Minute), HealthDeadline: now.Add(-time.Minute),
	}
	if err := updateflow.Write(fixture.paths.journal, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	fixture.manager.active = fixture.candidate
	fixture.hostd.active = hostdproto.Status{State: hostdproto.StateActive, WorkerID: workerID(fixture.candidate.Version), APIVersion: 1, Epoch: 2, LastHeartbeatUnixMilli: now.UnixMilli()}
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	committed, err := updateflow.Load(fixture.paths.journal)
	if err != nil || committed.Stage != updateflow.StageIdle || committed.ActiveVersion != fixture.candidate.Version || committed.ActiveDigest != fixture.candidate.SHA256 {
		t.Fatalf("journal=%+v err=%v", committed, err)
	}
}

func TestRuntimeStagingPatternPreservesDarwinPackageSuffix(t *testing.T) {
	if got := runtimeStagingPattern("darwin"); got != ".paperboat-runtime-*.pkg" {
		t.Fatalf("darwin staging pattern = %q", got)
	}
	if got := runtimeStagingPattern("linux"); got != ".paperboat-runtime-*" {
		t.Fatalf("linux staging pattern = %q", got)
	}
}

func TestDarwinInstalledExecutableIsRunnableByWorker(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "installed-pb")
	destination := filepath.Join(root, "releases", "pb.staged")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("signed executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stageInstalledDarwinExecutable(source, destination, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("staged Darwin executable mode=%#o, want executable", info.Mode().Perm())
	}
}

func TestOneHundredWorkerUpdatesKeepOneHostdAndBoundedRetention(t *testing.T) {
	fixture := newFixture(t)
	hostd := fixture.hostd
	for generation := 2; generation <= 101; generation++ {
		candidate := release(fmt.Sprintf("2026.08.18.%d", generation), fixture.fetcher.body)
		result, err := fixture.manager.Activate(context.Background(), candidate)
		if err != nil || !result.Updated || result.Version != candidate.Version {
			t.Fatalf("generation %d: result=%+v err=%v", generation, result, err)
		}
		if fixture.hostd != hostd {
			t.Fatalf("generation %d replaced the stable hostd", generation)
		}
		entries, err := retainedFiles(fixture.paths)
		if err != nil {
			t.Fatalf("generation %d: %v", generation, err)
		}
		if entries != 2 {
			t.Fatalf("generation %d retained %d artifacts, want one runtime current+rollback", generation, entries)
		}
	}
	if fixture.hostd.activations != 100 || fixture.starter.starts != 100 {
		t.Fatalf("activations=%d starts=%d", fixture.hostd.activations, fixture.starter.starts)
	}
}

func retainedFiles(paths fixturePaths) (int, error) {
	count := 0
	for _, directory := range []string{filepath.Dir(paths.current), filepath.Dir(paths.rollback), filepath.Dir(paths.staged)} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return 0, err
		}
		count += len(entries)
	}
	return count, nil
}

func TestWorkerUpdateRollsBackWithoutRestartingHostd(t *testing.T) {
	fixture := newFixture(t)
	fixture.health.err = errors.New("relay unavailable")
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if err == nil || err.Error() != "relay unavailable" {
		t.Fatalf("error=%v", err)
	}
	if fixture.hostd.activations != 2 || fixture.hostd.active.WorkerID != workerID(fixture.active.Version) {
		t.Fatalf("hostd=%+v", fixture.hostd)
	}
	if fixture.starter.starts != 2 {
		t.Fatalf("starts=%d", fixture.starter.starts)
	}
	if !regularMatches(fixture.paths.current, fixture.active.Length, fixture.active.SHA256) || !regularMatches(fixture.paths.staged, fixture.candidate.Length, fixture.candidate.SHA256) {
		t.Fatal("rollback did not retain old active and quarantine candidate")
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureHealth || journal.CandidateVersion != fixture.candidate.Version {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
	if _, err := fixture.manager.Activate(context.Background(), fixture.candidate); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("same candidate err=%v, want quarantine", err)
	}
}

func TestWorkerUpdateLeavesUncertainCutoverForRecovery(t *testing.T) {
	fixture := newFixture(t)
	fixture.starter.activateError = errors.New("activation response lost")
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if err == nil || err.Error() != "activation response lost" {
		t.Fatalf("error=%v", err)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageCutover {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
	// The fake hostd did activate the candidate before its response was lost.
	fixture.starter.activateError = nil
	if err := fixture.manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.manager.ActiveVersion() != fixture.candidate.Version || fixture.hostd.active.WorkerID != workerID(fixture.candidate.Version) {
		t.Fatalf("version=%s hostd=%+v", fixture.manager.ActiveVersion(), fixture.hostd)
	}
}

func TestWorkerUpdateRejectsTamperedArtifactBeforeCandidateStart(t *testing.T) {
	fixture := newFixture(t)
	fixture.fetcher.body = []byte("tampered")
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("error=%v", err)
	}
	if fixture.starter.starts != 0 || fixture.hostd.activations != 0 {
		t.Fatalf("candidate started after failed verification: starts=%d activations=%d", fixture.starter.starts, fixture.hostd.activations)
	}
	journal, loadErr := updateflow.Load(fixture.paths.journal)
	if loadErr != nil || journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureVerification || journal.ActiveVersion != fixture.active.Version {
		t.Fatalf("journal=%+v err=%v", journal, loadErr)
	}
	if recoverErr := fixture.manager.Recover(context.Background()); recoverErr != nil {
		t.Fatalf("failed verification stranded restart recovery: %v", recoverErr)
	}
}

func TestWorkerUpdateRejectsNativeSignatureBeforeCandidateStart(t *testing.T) {
	fixture := newFixture(t)
	calls := 0
	fixture.manager.config.NativeVerifier = nativeVerifierFunc(func(_ context.Context, path, platform, architecture string) error {
		calls++
		if filepath.Dir(path) != filepath.Dir(fixture.paths.staged) || filepath.Base(path) == filepath.Base(fixture.paths.staged) || platform != runtime.GOOS || architecture != runtime.GOARCH {
			t.Fatalf("native verification input path=%q platform=%q architecture=%q", path, platform, architecture)
		}
		return errors.New("native signature rejected")
	})
	_, err := fixture.manager.Activate(context.Background(), fixture.candidate)
	if !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("error=%v", err)
	}
	if calls != 1 || fixture.starter.starts != 0 || fixture.hostd.activations != 0 {
		t.Fatalf("calls=%d starts=%d activations=%d", calls, fixture.starter.starts, fixture.hostd.activations)
	}
}

func TestWorkerUpdateRejectsUnsignedCompatibilityRange(t *testing.T) {
	fixture := newFixture(t)
	invalid := fixture.candidate
	invalid.HostdAPIMin, invalid.HostdAPIMax = 0, 0
	_, err := fixture.manager.Activate(context.Background(), invalid)
	if !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("error=%v", err)
	}
	if fixture.starter.starts != 0 {
		t.Fatalf("candidate started with an invalid API range")
	}
}

func TestSchedulerAdapterOnlyRunsSafeManagerTransaction(t *testing.T) {
	fixture := newFixture(t)
	scheduler, err := fixture.manager.MandatoryScheduler(func(context.Context) (Release, bool, error) {
		return fixture.candidate, true, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scheduler.CheckNow(context.Background())
	if err != nil || !result.Updated || fixture.hostd.activations != 1 {
		t.Fatalf("result=%+v err=%v activations=%d", result, err, fixture.hostd.activations)
	}
}

type fixturePaths struct{ root, current, rollback, staged, journal string }
type fixture struct {
	manager           *Manager
	paths             fixturePaths
	active, candidate Release
	fetcher           *fakeFetcher
	starter           *fakeStarter
	hostd             *fakeHostd
	health            *fakeHealth
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"current", "rollback", "staged", "state", "installed"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	paths := fixturePaths{root: root, current: filepath.Join(root, "current", "pb"), rollback: filepath.Join(root, "rollback", "pb"), staged: filepath.Join(root, "staged", "pb"), journal: filepath.Join(root, "state", "journal.json")}
	if err := os.WriteFile(paths.current, body, 0o700); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(root, "installed", "pb")
	if err := os.WriteFile(installed, body, 0o700); err != nil {
		t.Fatal(err)
	}
	active := release("2026.08.18.1", body)
	candidate := release("2026.08.18.2", body)
	hostd := &fakeHostd{active: hostdproto.Status{State: hostdproto.StateActive, WorkerID: workerID(active.Version), APIVersion: 1, Epoch: 1}}
	starter := &fakeStarter{hostd: hostd}
	health := &fakeHealth{}
	fetcher := &fakeFetcher{body: body}
	workerUID := os.Geteuid()
	if workerUID == 0 {
		workerUID = 1
	}
	manager, err := New(Config{StatePath: paths.journal, Binary: paths.current, BinaryRollback: paths.rollback, BinaryStaged: paths.staged, Active: active, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), WorkerUID: workerUID, WorkerGID: os.Getegid(), HostdEndpoint: "private-hostd", Capability: bytes.Repeat([]byte{1}, 32), Fetcher: fetcher, Starter: starter, Hostd: hostd, Health: health, Gate: fakeActivationGate{}, NativeVerifier: nativeVerifierFunc(func(context.Context, string, string, string) error { return nil }), InstallPackage: func(context.Context, string) (string, error) { return installed, nil }, MonitorWindow: time.Millisecond, HealthInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{manager: manager, paths: paths, active: active, candidate: candidate, fetcher: fetcher, starter: starter, hostd: hostd, health: health}
}

func release(version string, body []byte) Release {
	sum := sha256.Sum256(body)
	return Release{Version: version, SHA256: hex.EncodeToString(sum[:]), Length: int64(len(body)), Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2}
}

func TestValidWorkerIdentitySupportsExactRootEnrollment(t *testing.T) {
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
		if got := validWorkerIdentity(test.uid, test.gid); got != test.want {
			t.Fatalf("validWorkerIdentity(%d, %d)=%v want %v", test.uid, test.gid, got, test.want)
		}
	}
}

type fakeFetcher struct{ body []byte }

func (f *fakeFetcher) Fetch(context.Context, Release) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.body)), nil
}

type fakeHostd struct {
	active      hostdproto.Status
	activations int
}

func (h *fakeHostd) Active(context.Context) (hostdproto.Status, error) { return h.active, nil }

type fakeStarter struct {
	hostd         *fakeHostd
	starts        int
	requests      []StartRequest
	activateError error
}

func (s *fakeStarter) Start(_ context.Context, request StartRequest) (Worker, error) {
	s.starts++
	s.requests = append(s.requests, request)
	return &fakeWorker{starter: s, request: request}, nil
}

type fakeWorker struct {
	starter *fakeStarter
	request StartRequest
	epoch   uint64
}

func (w *fakeWorker) Ready(context.Context) (hostdproto.Status, error) {
	w.epoch = w.starter.hostd.active.Epoch + 1
	return hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: w.request.WorkerID, APIVersion: 1, Epoch: w.epoch}, nil
}
func (w *fakeWorker) Activate(context.Context) (hostdproto.Status, error) {
	w.starter.hostd.active = hostdproto.Status{State: hostdproto.StateActive, WorkerID: w.request.WorkerID, APIVersion: 1, Epoch: w.epoch}
	w.starter.hostd.activations++
	if w.starter.activateError != nil {
		return hostdproto.Status{}, w.starter.activateError
	}
	return w.starter.hostd.active, nil
}
func (*fakeWorker) Stop(context.Context) error { return nil }

type fakeHealth struct{ err error }

func (h *fakeHealth) Check(context.Context, hostdproto.Status, Release) error { return h.err }

type fakeActivationGate struct{}

func (fakeActivationGate) Candidate(context.Context, GateRequest) error { return nil }
func (fakeActivationGate) Drain(context.Context, GateRequest) error     { return nil }
func (fakeActivationGate) Active(context.Context, GateRequest) error    { return nil }
func (fakeActivationGate) Commit(context.Context, GateRequest) error    { return nil }
func (fakeActivationGate) Rollback(context.Context, GateRequest) error  { return nil }

type blockingHealth struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingHealth) Check(context.Context, hostdproto.Status, Release) error {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	return nil
}

type nativeVerifierFunc func(context.Context, string, string, string) error

func (f nativeVerifierFunc) Verify(ctx context.Context, path, platform, architecture string) error {
	return f(ctx, path, platform, architecture)
}
