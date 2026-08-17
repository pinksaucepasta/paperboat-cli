// Package workerupdate performs ordinary Paperboat runtime updates without
// restarting paperboat-hostd. Hostd owns workloads and is the only component
// that may fence a worker; this package owns only verified runtime artifacts
// and the crash-consistent activation transaction.
package workerupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

const maxRuntimeBytes int64 = 256 << 20

var (
	ErrInvalidConfig  = errors.New("invalid worker update configuration")
	ErrInvalidRelease = errors.New("invalid worker release")
	ErrBlocked        = errors.New("worker updates require recovery")
	ErrQuarantined    = errors.New("worker release is quarantined")
	ErrUnsafeStorage  = errors.New("unsafe worker release storage")
)

// Release is derived from a verified, signed release index. Fetch transports
// its bytes but does not establish its identity: the updater independently
// checks this exact version, hash, length, platform, and architecture before
// making it executable.
type Release struct {
	Version       string
	SHA256        string
	Length        int64
	Platform      string
	Architecture  string
	HostdAPIMin   uint16
	HostdAPIMax   uint16
	RuntimeAPIMin uint16
	RuntimeAPIMax uint16
}

// Resolver returns the newest signed and cohort-eligible release. found=false
// means the signed index contains no newer eligible release.
type Resolver func(context.Context) (release Release, found bool, err error)

// Fetcher returns the signed release artifact. The returned stream is treated
// as untrusted until Manager has copied, fsynced, hash-checked, size-checked,
// and native-format-checked it in its root-owned staging path.
type Fetcher interface {
	Fetch(context.Context, Release) (io.ReadCloser, error)
}

// StartRequest is fixed update data passed to the private worker launcher. It
// deliberately has no command, argument, path, or environment supplied by a
// control-plane caller.
type StartRequest struct {
	Executable        string
	Release           Release
	WorkerID          string
	UID               int
	GID               int
	HostdEndpoint     string
	Capability        []byte
	MutationsDisabled bool
}

// Worker is a candidate process started by the private launcher. Ready must
// mean it has reconciled hostd-owned state while mutations remain disabled.
// Activate performs the candidate's authenticated hostd Activate request.
type Worker interface {
	Ready(context.Context) (hostdproto.Status, error)
	Activate(context.Context) (hostdproto.Status, error)
	Stop(context.Context) error
}

type Starter interface {
	Start(context.Context, StartRequest) (Worker, error)
}

// Hostd is intentionally limited to reading the active worker fence. The
// updater cannot execute commands or alter workload state through this API.
type Hostd interface {
	Active(context.Context) (hostdproto.Status, error)
}

// HealthChecker validates the newly active worker during the monitoring hold.
// Implementations check bounded worker health, control-plane sync, relay
// readiness, and resource limits without inspecting terminal data.
type HealthChecker interface {
	Check(context.Context, hostdproto.Status, Release) error
}

type Config struct {
	StatePath       string
	RuntimeCurrent  string
	RuntimeRollback string
	RuntimeStaged   string
	Active          Release
	OwnerUID        int
	OwnerGID        int
	WorkerUID       int
	WorkerGID       int
	HostdEndpoint   string
	Capability      []byte
	Fetcher         Fetcher
	Starter         Starter
	Hostd           Hostd
	Health          HealthChecker
	MonitorWindow   time.Duration
	HealthInterval  time.Duration
	Now             func() time.Time
}

// Manager permits exactly one transaction. It retains at most runtime-current,
// runtime-rollback, and runtime-staged. The staged slot is also the local
// quarantine slot after a failed activation, and a later verified stage
// atomically replaces it.
type Manager struct {
	mu     sync.Mutex
	config Config
	active Release
}

type Result struct {
	Version string
	Updated bool
}

func New(config Config) (*Manager, error) {
	if config.MonitorWindow == 0 {
		config.MonitorWindow = 10 * time.Minute
	}
	if config.HealthInterval == 0 {
		config.HealthInterval = time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Manager{config: config, active: config.Active}, nil
}

// Check resolves a signed cohort-eligible target and applies it through the
// safe worker-only transaction. This is the sole function that an automatic
// update scheduler may call.
func (m *Manager) Check(ctx context.Context, resolve Resolver) (Result, error) {
	if resolve == nil {
		return Result{}, ErrInvalidConfig
	}
	release, found, err := resolve(ctx)
	if err != nil || !found {
		return Result{Version: m.ActiveVersion()}, err
	}
	return m.Activate(ctx, release)
}

func (m *Manager) ActiveVersion() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.Version
}

func (m *Manager) Activate(ctx context.Context, release Release) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.recoverLocked(ctx); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err := validateRelease(release); err != nil {
		return Result{Version: m.active.Version}, err
	}
	comparison := compareVersion(release.Version, m.active.Version)
	if comparison == 0 {
		return Result{Version: m.active.Version}, nil
	}
	if comparison < 0 {
		return Result{Version: m.active.Version}, ErrInvalidRelease
	}
	if quarantine, err := m.quarantinedLocked(); err != nil {
		return Result{Version: m.active.Version}, err
	} else if quarantine == release.Version {
		return Result{Version: m.active.Version}, ErrQuarantined
	}

	journal := m.newJournal()
	if err := m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	var err error
	if journal, err = m.transition(journal, updateflow.StageChecking); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.stage(ctx, release); err != nil {
		journal.LastFailure = updateflow.FailureVerification
		_ = m.write(journal)
		return Result{Version: m.active.Version}, err
	}
	journal = withRelease(journal, release, m.config.RuntimeStaged)
	if journal, err = m.transition(journal, updateflow.StageStaged); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}

	request := m.startRequest(release, m.config.RuntimeStaged)
	if journal, err = m.transition(journal, updateflow.StageCandidateStarted); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	worker, err := m.config.Starter.Start(ctx, request)
	if err != nil {
		return Result{Version: m.active.Version}, m.failBeforeCutover(journal, worker, updateflow.FailureCandidate, err)
	}
	ready, err := worker.Ready(ctx)
	if err != nil || !matches(ready, hostdproto.StateCandidate, request.WorkerID, 0) {
		if err == nil {
			err = ErrInvalidRelease
		}
		return Result{Version: m.active.Version}, m.failBeforeCutover(journal, worker, updateflow.FailureCandidate, err)
	}
	journal.WorkerID, journal.WorkerEpoch = ready.WorkerID, ready.Epoch
	if journal, err = m.transition(journal, updateflow.StageCandidateReady); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}

	// Persist cutover intent before filesystem rotation or hostd activation.
	// Recovery can then query hostd and deterministically restore one owner.
	if journal, err = m.transition(journal, updateflow.StageCutover); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.promoteStorage(); err != nil {
		return Result{Version: m.active.Version}, m.rollbackPreActivation(journal, worker, err)
	}
	journal.StagedPath = m.config.RuntimeCurrent
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	active, err := worker.Activate(ctx)
	if err != nil || !matches(active, hostdproto.StateActive, request.WorkerID, ready.Epoch) {
		if err == nil {
			err = ErrInvalidRelease
		}
		// The hostd result is now uncertain. Leave StageCutover durable so
		// recovery queries the persisted fence rather than guessing.
		return Result{Version: m.active.Version}, err
	}
	if journal, err = m.transition(journal, updateflow.StageMonitoring); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.monitor(ctx, journal, release); err != nil {
		return Result{Version: m.active.Version}, m.rollbackActive(ctx, journal, release, worker, err)
	}
	if journal, err = m.transition(journal, updateflow.StageCommitted); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	m.active = release
	return Result{Version: release.Version, Updated: true}, m.finishCommitted(journal)
}

// Recover applies the durable recovery decision. It never restarts hostd and
// never guesses whether a candidate cut over: StageCutover is resolved only by
// querying hostd's persisted active epoch.
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoverLocked(ctx)
}

func (m *Manager) recoverLocked(ctx context.Context) error {
	journal, err := updateflow.Load(m.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrBlocked
	}
	if journal.ActiveVersion != m.active.Version {
		return ErrBlocked
	}
	switch journal.Recovery() {
	case updateflow.RecoveryKeepActive:
		return nil
	case updateflow.RecoveryDiscardCandidate:
		if err := m.removeStaged(); err != nil {
			return err
		}
		return m.write(m.idleJournal(journal, updateflow.FailureCandidate, ""))
	case updateflow.RecoveryQueryHostd:
		status, statusErr := m.config.Hostd.Active(ctx)
		if statusErr != nil {
			return statusErr
		}
		if matches(status, hostdproto.StateActive, journal.WorkerID, journal.WorkerEpoch) {
			if err := m.ensurePromoted(journal); err != nil {
				return err
			}
			journal.StagedPath = m.config.RuntimeCurrent
			next, transitionErr := m.transition(journal, updateflow.StageMonitoring)
			if transitionErr != nil {
				return transitionErr
			}
			if err := m.write(next); err != nil {
				return err
			}
			return m.monitorAndCommitRecovered(ctx, next)
		}
		if err := m.restoreStorage(); err != nil {
			return err
		}
		if err := m.removeStaged(); err != nil {
			return err
		}
		return m.write(m.idleJournal(journal, updateflow.FailureCandidate, ""))
	case updateflow.RecoveryContinueMonitor:
		return m.monitorAndCommitRecovered(ctx, journal)
	case updateflow.RecoveryFinalizeCleanup:
		m.active = releaseFromJournal(journal)
		return m.finishCommitted(journal)
	case updateflow.RecoveryPerformRollback:
		return ErrBlocked
	default:
		return ErrBlocked
	}
}

func (m *Manager) monitorAndCommitRecovered(ctx context.Context, journal updateflow.Journal) error {
	release := releaseFromJournal(journal)
	if err := m.monitor(ctx, journal, release); err != nil {
		// A process handle cannot survive updater restart. A fresh rollback
		// worker is safe because hostd owns all workload state.
		return m.rollbackActive(ctx, journal, release, nil, err)
	}
	next, err := m.transition(journal, updateflow.StageCommitted)
	if err != nil {
		return err
	}
	if err := m.write(next); err != nil {
		return err
	}
	m.active = release
	return m.finishCommitted(next)
}

func (m *Manager) monitor(ctx context.Context, journal updateflow.Journal, release Release) error {
	deadline := journal.HealthDeadline
	if deadline.IsZero() {
		return ErrBlocked
	}
	for {
		status, err := m.config.Hostd.Active(ctx)
		if err != nil || !matches(status, hostdproto.StateActive, journal.WorkerID, journal.WorkerEpoch) {
			if err != nil {
				return err
			}
			return updateflow.ErrInvalidJournal
		}
		if err := m.config.Health.Check(ctx, status, release); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		delay := m.config.HealthInterval
		if delay > remaining {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) rollbackActive(ctx context.Context, journal updateflow.Journal, failed Release, candidate Worker, cause error) error {
	next, err := m.transition(journal, updateflow.StageRollback)
	if err != nil {
		return err
	}
	next.LastFailure = updateflow.FailureHealth
	next.RollbackCount++
	if err := m.write(next); err != nil {
		return err
	}
	previous := m.active
	rollbackRequest := m.startRequest(previous, m.config.RuntimeRollback)
	rollbackWorker, startErr := m.config.Starter.Start(ctx, rollbackRequest)
	if startErr == nil {
		ready, readyErr := rollbackWorker.Ready(ctx)
		if readyErr != nil || !matches(ready, hostdproto.StateCandidate, rollbackRequest.WorkerID, 0) {
			if readyErr == nil {
				readyErr = ErrInvalidRelease
			}
			startErr = readyErr
		} else {
			active, activateErr := rollbackWorker.Activate(ctx)
			if activateErr != nil || !matches(active, hostdproto.StateActive, rollbackRequest.WorkerID, ready.Epoch) {
				if activateErr == nil {
					activateErr = ErrInvalidRelease
				}
				startErr = activateErr
			}
		}
	}
	if startErr != nil {
		next.LastFailure = updateflow.FailureRollback
		blocked, transitionErr := m.transition(next, updateflow.StageBlocked)
		if transitionErr == nil {
			_ = m.write(blocked)
		}
		return errors.Join(cause, startErr, ErrBlocked)
	}
	if err := m.restoreStorage(); err != nil {
		return errors.Join(cause, err, ErrBlocked)
	}
	if candidate != nil {
		_ = candidate.Stop(context.Background())
	}
	idle := m.idleJournal(next, updateflow.FailureHealth, failed.Version)
	idle.RollbackCount = next.RollbackCount
	if err := m.write(idle); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (m *Manager) rollbackPreActivation(journal updateflow.Journal, worker Worker, cause error) error {
	if err := m.restoreStorage(); err != nil {
		return errors.Join(cause, err, ErrBlocked)
	}
	if worker != nil {
		_ = worker.Stop(context.Background())
	}
	journal.LastFailure = updateflow.FailureCandidate
	next, err := m.transition(journal, updateflow.StageRollback)
	if err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, m.write(m.idleJournal(next, updateflow.FailureCandidate, journal.CandidateVersion)))
}

func (m *Manager) failBeforeCutover(journal updateflow.Journal, worker Worker, failure updateflow.Failure, cause error) error {
	if worker != nil {
		_ = worker.Stop(context.Background())
	}
	_ = m.removeStaged()
	journal.LastFailure = failure
	return errors.Join(cause, m.write(m.idleJournal(journal, failure, "")))
}

func (m *Manager) finishCommitted(journal updateflow.Journal) error {
	if err := m.removeStaged(); err != nil {
		return err
	}
	return m.write(m.idleJournal(journal, updateflow.FailureNone, ""))
}

func (m *Manager) stage(ctx context.Context, release Release) error {
	stream, err := m.config.Fetcher.Fetch(ctx, release)
	if err != nil {
		return err
	}
	defer stream.Close()
	directory := filepath.Dir(m.config.RuntimeStaged)
	pending, err := os.CreateTemp(directory, ".paperboat-runtime-")
	if err != nil {
		return err
	}
	pendingPath := pending.Name()
	defer os.Remove(pendingPath)
	if err := pending.Chmod(0o700); err != nil {
		pending.Close()
		return err
	}
	if err := pending.Chown(m.config.OwnerUID, m.config.OwnerGID); err != nil {
		pending.Close()
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(pending, hash), io.LimitReader(stream, release.Length+1))
	if copyErr != nil || written != release.Length || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), release.SHA256) {
		pending.Close()
		return ErrInvalidRelease
	}
	if err := pending.Sync(); err != nil {
		pending.Close()
		return err
	}
	if err := pending.Close(); err != nil {
		return err
	}
	if err := binarytarget.Validate(pendingPath, release.Platform, release.Architecture); err != nil {
		return ErrInvalidRelease
	}
	if err := os.Rename(pendingPath, m.config.RuntimeStaged); err != nil {
		return err
	}
	return syncDirectories(directory)
}

func (m *Manager) promoteStorage() error {
	if err := safeRuntimeFile(m.config.RuntimeCurrent, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := safeRuntimeFile(m.config.RuntimeStaged, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := removeRuntimeFile(m.config.RuntimeRollback, m.config.OwnerUID); err != nil {
		return err
	}
	if err := os.Rename(m.config.RuntimeCurrent, m.config.RuntimeRollback); err != nil {
		return err
	}
	if err := os.Rename(m.config.RuntimeStaged, m.config.RuntimeCurrent); err != nil {
		_ = os.Rename(m.config.RuntimeRollback, m.config.RuntimeCurrent)
		return err
	}
	return syncDirectories(filepath.Dir(m.config.RuntimeCurrent), filepath.Dir(m.config.RuntimeRollback), filepath.Dir(m.config.RuntimeStaged))
}

func (m *Manager) ensurePromoted(journal updateflow.Journal) error {
	if regularMatches(m.config.RuntimeCurrent, journal.CandidateLength, journal.CandidateDigest) {
		return nil
	}
	return m.promoteStorage()
}

func (m *Manager) restoreStorage() error {
	// Before activation, current is old and staged is candidate, so there is
	// nothing to restore. After promotion, current is candidate and rollback is
	// old; move only the verified candidate into the quarantined staged slot.
	if _, err := os.Lstat(m.config.RuntimeStaged); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := safeRuntimeFile(m.config.RuntimeCurrent, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := safeRuntimeFile(m.config.RuntimeRollback, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := os.Rename(m.config.RuntimeCurrent, m.config.RuntimeStaged); err != nil {
		return err
	}
	if err := os.Rename(m.config.RuntimeRollback, m.config.RuntimeCurrent); err != nil {
		_ = os.Rename(m.config.RuntimeStaged, m.config.RuntimeCurrent)
		return err
	}
	return syncDirectories(filepath.Dir(m.config.RuntimeCurrent), filepath.Dir(m.config.RuntimeRollback), filepath.Dir(m.config.RuntimeStaged))
}

func (m *Manager) removeStaged() error {
	return removeRuntimeFile(m.config.RuntimeStaged, m.config.OwnerUID)
}

func (m *Manager) newJournal() updateflow.Journal {
	return updateflow.Journal{Schema: updateflow.SchemaV1, TransactionID: transactionID(), Stage: updateflow.StageIdle,
		ActiveVersion: m.active.Version, BootID: "hostd", StageUpdatedAt: m.now()}
}

func (m *Manager) idleJournal(from updateflow.Journal, failure updateflow.Failure, quarantine string) updateflow.Journal {
	journal := updateflow.Journal{Schema: updateflow.SchemaV1, TransactionID: from.TransactionID, Stage: updateflow.StageIdle,
		ActiveVersion: m.active.Version, BootID: from.BootID, StageUpdatedAt: m.now(), RollbackCount: from.RollbackCount, LastFailure: failure}
	if quarantine != "" {
		journal = withRelease(journal, Release{Version: quarantine, SHA256: from.CandidateDigest, Length: from.CandidateLength, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: from.HostdAPIMin, HostdAPIMax: from.HostdAPIMax, RuntimeAPIMin: from.RuntimeAPIMin, RuntimeAPIMax: from.RuntimeAPIMax}, m.config.RuntimeStaged)
	}
	return journal
}

func (m *Manager) transition(journal updateflow.Journal, stage updateflow.Stage) (updateflow.Journal, error) {
	next, err := journal.Transition(stage, m.now())
	if err == nil && stage == updateflow.StageMonitoring {
		next.HealthDeadline = m.now().Add(m.config.MonitorWindow)
	}
	return next, err
}
func (m *Manager) now() time.Time { return m.config.Now().UTC() }
func (m *Manager) write(journal updateflow.Journal) error {
	return updateflow.Write(m.config.StatePath, journal, m.config.OwnerUID, m.config.OwnerGID)
}

func (m *Manager) quarantinedLocked() (string, error) {
	journal, err := updateflow.Load(m.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", ErrBlocked
	}
	if journal.Stage == updateflow.StageIdle && journal.LastFailure != updateflow.FailureNone && journal.CandidateVersion != "" {
		return journal.CandidateVersion, nil
	}
	return "", nil
}

func (m *Manager) startRequest(release Release, executable string) StartRequest {
	return StartRequest{Executable: executable, Release: release, WorkerID: workerID(release.Version), UID: m.config.WorkerUID, GID: m.config.WorkerGID, HostdEndpoint: m.config.HostdEndpoint, Capability: append([]byte(nil), m.config.Capability...), MutationsDisabled: true}
}

func withRelease(journal updateflow.Journal, release Release, path string) updateflow.Journal {
	journal.CandidateVersion, journal.CandidateDigest, journal.CandidateLength, journal.StagedPath = release.Version, release.SHA256, release.Length, path
	journal.HostdAPIMin, journal.HostdAPIMax, journal.RuntimeAPIMin, journal.RuntimeAPIMax = release.HostdAPIMin, release.HostdAPIMax, release.RuntimeAPIMin, release.RuntimeAPIMax
	return journal
}
func releaseFromJournal(j updateflow.Journal) Release {
	return Release{Version: j.CandidateVersion, SHA256: j.CandidateDigest, Length: j.CandidateLength, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: j.HostdAPIMin, HostdAPIMax: j.HostdAPIMax, RuntimeAPIMin: j.RuntimeAPIMin, RuntimeAPIMax: j.RuntimeAPIMax}
}
func workerID(version string) string { return "runtime-" + version }
func matches(status hostdproto.Status, state hostdproto.State, id string, epoch uint64) bool {
	return status.State == state && status.WorkerID == id && (epoch == 0 || status.Epoch == epoch)
}

func validateConfig(config Config) error {
	if config.Fetcher == nil || config.Starter == nil || config.Hostd == nil || config.Health == nil || config.OwnerUID < 0 || config.OwnerGID < 0 || config.WorkerUID <= 0 || config.WorkerGID < 0 || len(config.Capability) != 32 || config.HostdEndpoint == "" || config.MonitorWindow <= 0 || config.HealthInterval <= 0 || config.HealthInterval > config.MonitorWindow || validateRelease(config.Active) != nil {
		return ErrInvalidConfig
	}
	for _, path := range []string{config.StatePath, config.RuntimeCurrent, config.RuntimeRollback, config.RuntimeStaged} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
			return ErrInvalidConfig
		}
		if err := secureDirectory(filepath.Dir(path), config.OwnerUID); err != nil {
			return err
		}
	}
	if config.RuntimeCurrent == config.RuntimeRollback || config.RuntimeCurrent == config.RuntimeStaged || config.RuntimeRollback == config.RuntimeStaged {
		return ErrInvalidConfig
	}
	if err := safeRuntimeFile(config.RuntimeCurrent, config.OwnerUID, true); err != nil {
		return err
	}
	if !regularMatches(config.RuntimeCurrent, config.Active.Length, config.Active.SHA256) || binarytarget.Validate(config.RuntimeCurrent, config.Active.Platform, config.Active.Architecture) != nil {
		return ErrUnsafeStorage
	}
	return nil
}

func validateRelease(release Release) error {
	if !validVersion(release.Version) || len(release.SHA256) != 64 || release.Length < 1 || release.Length > maxRuntimeBytes || release.Platform != runtime.GOOS || release.Architecture != runtime.GOARCH || !hexDigest(release.SHA256) || invalidAPIRange(release.HostdAPIMin, release.HostdAPIMax) || invalidAPIRange(release.RuntimeAPIMin, release.RuntimeAPIMax) {
		return ErrInvalidRelease
	}
	return nil
}
func invalidAPIRange(minimum, maximum uint16) bool { return minimum > maximum || maximum > 1024 }
func hexDigest(value string) bool                  { _, err := hex.DecodeString(value); return err == nil }
func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
func compareVersion(left, right string) int {
	l, r := strings.Split(left, "."), strings.Split(right, ".")
	for i := range 4 {
		lv, _ := strconv.ParseUint(l[i], 10, 32)
		rv, _ := strconv.ParseUint(r[i], 10, 32)
		if lv < rv {
			return -1
		}
		if lv > rv {
			return 1
		}
	}
	return 0
}
func transactionID() string { return fmt.Sprintf("txn-%d", time.Now().UnixNano()) }

func secureDirectory(path string, owner int) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || fileOwner(info) != owner {
		return ErrUnsafeStorage
	}
	return nil
}
func safeRuntimeFile(path string, owner int, required bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || fileOwner(info) != owner {
		return ErrUnsafeStorage
	}
	return nil
}
func removeRuntimeFile(path string, owner int) error {
	if err := safeRuntimeFile(path, owner, false); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectories(filepath.Dir(path))
}
func regularMatches(path string, length int64, digest string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != length {
		return false
	}
	sum := sha256.New()
	if _, err = io.Copy(sum, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), digest)
}
func syncDirectories(paths ...string) error {
	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
