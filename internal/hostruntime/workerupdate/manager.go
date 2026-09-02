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
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

const maxRuntimeBytes int64 = 512 << 20

var (
	ErrInvalidConfig  = errors.New("invalid worker update configuration")
	ErrInvalidRelease = errors.New("invalid worker release")
	ErrBlocked        = errors.New("worker updates require recovery")
	ErrQuarantined    = errors.New("worker release is quarantined")
	ErrReleaseRevoked = errors.New("worker release is revoked")
	ErrUnsafeStorage  = errors.New("unsafe worker release storage")
)

// Release is derived from a verified, signed release index. Fetch transports
// its bytes but does not establish its identity: the updater independently
// checks this exact version, hash, length, platform, and architecture before
// making it executable.
type Release struct {
	Version           string
	SHA256            string
	Length            int64
	Platform          string
	Architecture      string
	ManifestSHA256    string
	CanaryPath        string
	CanaryStatus      int
	CanarySamples     uint16
	CanaryTimeout     time.Duration
	DrainTimeout      time.Duration
	StabilityWindow   time.Duration
	StabilityInterval time.Duration
	RollbackTimeout   time.Duration
	CLISHA256         string
	CLILength         int64
	CLIPlatform       string
	CLIArchitecture   string
	HostdAPIMin       uint16
	HostdAPIMax       uint16
	RuntimeAPIMin     uint16
	RuntimeAPIMax     uint16
	// Supervisor targets are present in every signed release index. They are
	// kept separate from the worker/CLI targets because replacing them is a
	// supervisor-class maintenance operation.
	Hostd                 ComponentTarget
	Updater               ComponentTarget
	Launcher              ComponentTarget
	SupervisorMaintenance bool
}

// ComponentTarget is the immutable target identity copied from the verified
// release index. It is never populated from a local path or a caller.
type ComponentTarget struct {
	SHA256       string
	Length       int64
	Platform     string
	Architecture string
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

// ComponentFetcher is implemented by the TUF source. The CLI target is
// resolved from the same already verified release index as the runtime.
type ComponentFetcher interface {
	FetchComponent(context.Context, Release, string) (io.ReadCloser, error)
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

// NativeVerifier is the platform-native release gate. It runs only after TUF
// digest, length, and binary-format validation has completed in a private
// staging path and before the candidate is made executable by hostd.
type NativeVerifier interface {
	Verify(context.Context, string, string, string) error
}

type Config struct {
	StatePath      string
	Binary         string
	BinaryRollback string
	BinaryStaged   string
	Active         Release
	OwnerUID       int
	OwnerGID       int
	WorkerUID      int
	WorkerGID      int
	HostdEndpoint  string
	Capability     []byte
	Fetcher        Fetcher
	Starter        Starter
	Hostd          Hostd
	Health         HealthChecker
	Gate           ActivationGate
	Events         EventSink
	NativeVerifier NativeVerifier
	// InstallPackage is the privileged macOS package boundary. A pkg is never
	// renamed into an executable slot; the installer returns the executable
	// installed by the verified package so it can be staged atomically.
	InstallPackage  func(context.Context, string) (string, error)
	MonitorWindow   time.Duration
	HealthInterval  time.Duration
	CanaryTimeout   time.Duration
	DrainTimeout    time.Duration
	RollbackTimeout time.Duration
	Now             func() time.Time
	WriteJournal    func(string, updateflow.Journal, int, int) error
}

// Manager permits exactly one transaction. It retains at most runtime-current,
// runtime-rollback, and runtime-staged. The staged slot is also the local
// quarantine slot after a failed activation, and a later verified stage
// atomically replaces it.
type Manager struct {
	mu            sync.Mutex
	config        Config
	active        Release
	activeVersion atomic.Value
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
	if config.CanaryTimeout == 0 {
		config.CanaryTimeout = 30 * time.Second
	}
	if config.DrainTimeout == 0 {
		config.DrainTimeout = 30 * time.Second
	}
	if config.RollbackTimeout == 0 {
		config.RollbackTimeout = 2 * time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.WriteJournal == nil {
		config.WriteJournal = updateflow.Write
	}
	if config.NativeVerifier == nil {
		config.NativeVerifier = nativesignature.New(nil)
	}
	if config.InstallPackage == nil && runtime.GOOS == "darwin" {
		config.InstallPackage = installDarwinPackage
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	manager := &Manager{config: config, active: config.Active}
	manager.activeVersion.Store(config.Active.Version)
	return manager, nil
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
	if m == nil {
		return ""
	}
	version := m.activeVersion.Load()
	if version == nil {
		return ""
	}
	return version.(string)
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
	m.record(ctx, EventScheduled, journal, release, "")
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
		// No candidate has started and no live state has changed. Return the
		// durable transaction to idle so a transient download, proxy, or
		// signature-source failure cannot strand the updater in "checking"
		// across a service restart. Preserve the typed verification failure for
		// status and retry diagnostics.
		cleanupErr := m.removeStaged()
		writeErr := m.write(m.idleJournal(journal, updateflow.FailureVerification, ""))
		return Result{Version: m.active.Version}, errors.Join(err, cleanupErr, writeErr)
	}
	m.record(ctx, EventDownloading, journal, release, "")
	journal = withRelease(journal, release, m.config.BinaryStaged)
	if journal, err = m.transition(journal, updateflow.StageStaged); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}

	request := m.startRequest(release, m.config.BinaryStaged)
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
	if journal, err = m.transition(journal, updateflow.StageCandidateValidating); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	m.record(ctx, EventCandidateValidating, journal, release, "")
	if err = m.gate(ctx, releaseDuration(release.CanaryTimeout, m.config.CanaryTimeout), func(gateCtx context.Context) error {
		request := m.gateRequest(journal, release, ready)
		if err := request.validate(hostdproto.StateCandidate); err != nil {
			return err
		}
		return m.config.Gate.Candidate(gateCtx, request)
	}); err != nil {
		return Result{Version: m.active.Version}, m.failBeforeCutover(journal, worker, updateflow.FailureCanary, err, release.Version)
	}
	if journal, err = m.transition(journal, updateflow.StageCandidateReady); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if journal, err = m.transition(journal, updateflow.StageDraining); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, err
	}
	m.record(ctx, EventDraining, journal, release, "")
	if err = m.gate(ctx, releaseDuration(release.DrainTimeout, m.config.DrainTimeout), func(gateCtx context.Context) error {
		request := m.gateRequest(journal, release, ready)
		if err := request.validate(hostdproto.StateCandidate); err != nil {
			return err
		}
		return m.config.Gate.Drain(gateCtx, request)
	}); err != nil {
		return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, err)
	}

	// Persist cutover intent before filesystem rotation or hostd activation.
	// Recovery can then query hostd and deterministically restore one owner.
	if journal, err = m.transition(journal, updateflow.StageCutover); err != nil {
		return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, err)
	}
	if err = m.write(journal); err != nil {
		return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, err)
	}
	m.record(ctx, EventActivating, journal, release, "")
	if err = m.promoteStorage(); err != nil {
		if restoreErr := m.restoreStorage(); restoreErr != nil {
			return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, errors.Join(err, errStorageRestoreFailed, restoreErr))
		}
		return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, err)
	}
	journal.StagedPath = m.config.Binary
	if err = m.write(journal); err != nil {
		if restoreErr := m.restoreStorage(); restoreErr != nil {
			return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, errors.Join(err, errStorageRestoreFailed, restoreErr))
		}
		return Result{Version: m.active.Version}, m.restoreAfterDrain(ctx, journal, release, worker, err)
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
	journal.HealthDeadline = m.now().Add(releaseDuration(release.StabilityWindow, m.config.MonitorWindow))
	m.record(ctx, EventStability, journal, release, "")
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
	if err = m.commitGate(ctx, journal, release); err != nil {
		return Result{Version: m.active.Version}, err
	}
	m.setActive(release)
	m.record(ctx, EventCommitted, journal, release, "")
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
		return m.write(m.newJournal())
	}
	if err != nil {
		return ErrBlocked
	}
	if journal.ActiveVersion != m.active.Version {
		if journal.ActiveDigest == "" && journal.CandidateVersion == m.active.Version && (journal.Stage == updateflow.StageMonitoring || journal.Stage == updateflow.StageCommitted) {
			return m.recoverLegacyPromotedCandidate(ctx, journal)
		}
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
	case updateflow.RecoveryRestoreDrain:
		return m.restoreAfterDrain(ctx, journal, releaseFromJournal(journal), nil, errInterruptedDrainRecovery)
	case updateflow.RecoveryQueryHostd:
		status, statusErr := m.config.Hostd.Active(ctx)
		if statusErr != nil {
			return statusErr
		}
		if matches(status, hostdproto.StateActive, journal.WorkerID, journal.WorkerEpoch) {
			if err := m.ensurePromoted(journal); err != nil {
				return err
			}
			journal.StagedPath = m.config.Binary
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
			return m.restoreAfterDrain(ctx, journal, releaseFromJournal(journal), nil, errors.Join(errInterruptedDrainRecovery, errStorageRestoreFailed, err))
		}
		return m.restoreAfterDrain(ctx, journal, releaseFromJournal(journal), nil, errInterruptedDrainRecovery)
	case updateflow.RecoveryContinueMonitor:
		return m.monitorAndCommitRecovered(ctx, journal)
	case updateflow.RecoveryFinalizeCleanup:
		release := releaseFromJournal(journal)
		if err := m.commitGate(ctx, journal, release); err != nil {
			return err
		}
		m.setActive(release)
		return m.finishCommitted(journal)
	case updateflow.RecoveryPerformRollback:
		return m.restoreBlockedTransaction(ctx, journal)
	default:
		return ErrBlocked
	}
}

// restoreBlockedTransaction retries the exact rollback already recorded in a
// valid blocked journal. The previous release and deployment binding remain
// fully authenticated by the journal and hostd; no local identity is guessed.
// This keeps paperboat-updated available after a transient rollback failure.
func (m *Manager) restoreBlockedTransaction(ctx context.Context, journal updateflow.Journal) error {
	rollback, err := m.transition(journal, updateflow.StageRollback)
	if err != nil {
		return ErrBlocked
	}
	if err := m.write(rollback); err != nil {
		return errors.Join(err, ErrBlocked)
	}
	// StageRollback is the first persisted recovery stage. A subsequent crash
	// may leave StageBlocked, which transitions back through StageRollback here.
	// restoreAfterDrain expects the pre-rollback stage for its own transition.
	recovery := rollback
	recovery.Stage = updateflow.StageDraining
	failed := releaseFromJournal(rollback)
	if err := m.restoreAfterDrain(ctx, recovery, failed, nil, errInterruptedDrainRecovery); err != nil {
		return errors.Join(err, ErrBlocked)
	}
	return nil
}

// recoverLegacyPromotedCandidate completes a transaction written before the
// journal retained the previous active release metadata. The promoted,
// verified candidate can commit after its health hold, but a failed health
// check remains blocked because reconstructing rollback identity from local
// bytes would weaken the signed release boundary.
func (m *Manager) recoverLegacyPromotedCandidate(ctx context.Context, journal updateflow.Journal) error {
	if journal.Stage == updateflow.StageMonitoring {
		if err := m.monitor(ctx, journal, m.active); err != nil {
			return errors.Join(err, ErrBlocked)
		}
		next, err := m.transition(journal, updateflow.StageCommitted)
		if err != nil {
			return err
		}
		if err := m.write(next); err != nil {
			return err
		}
		journal = next
	}
	if err := m.commitGate(ctx, journal, releaseFromJournal(journal)); err != nil {
		return err
	}
	return m.finishCommitted(journal)
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
	if err := m.commitGate(ctx, next, release); err != nil {
		return err
	}
	m.setActive(release)
	return m.finishCommitted(next)
}

func (m *Manager) commitGate(ctx context.Context, journal updateflow.Journal, release Release) error {
	return m.gate(ctx, releaseDuration(release.CanaryTimeout, m.config.CanaryTimeout), func(gateCtx context.Context) error {
		request := m.gateRequest(journal, release, hostdproto.Status{State: hostdproto.StateActive, WorkerID: journal.WorkerID, APIVersion: 1, Epoch: journal.WorkerEpoch})
		if err := request.validate(hostdproto.StateActive); err != nil {
			return err
		}
		return m.config.Gate.Commit(gateCtx, request)
	})
}

// restoreAfterDrain compensates an uncertain or interrupted drain before any
// binary cutover. The old worker remains the only active worker, but its edge
// route may already reject new streams. Recovery therefore proves the exact
// current tuple and restored end-to-end path before discarding the candidate.
func (m *Manager) restoreAfterDrain(ctx context.Context, journal updateflow.Journal, failed Release, candidate Worker, cause error) error {
	next, transitionErr := m.transition(journal, updateflow.StageRollback)
	if transitionErr != nil {
		next = journal
	}
	next.LastFailure = updateflow.FailureDrain
	journalErr := transitionErr
	if transitionErr == nil {
		journalErr = m.write(next)
	}
	status, statusErr := m.config.Hostd.Active(ctx)
	if statusErr == nil && status.State != hostdproto.StateActive {
		statusErr = ErrInvalidRelease
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, releaseDuration(failed.RollbackTimeout, m.config.RollbackTimeout))
	request := GateRequest{TransactionID: journal.TransactionID, Previous: failed, Candidate: m.active, Worker: status}
	restoreErr := statusErr
	if restoreErr == nil {
		restoreErr = request.validate(hostdproto.StateActive)
	}
	if restoreErr == nil {
		restoreErr = m.config.Gate.Rollback(rollbackCtx, request)
	}
	cancel()
	if restoreErr != nil {
		blocked, blockErr := m.transition(next, updateflow.StageBlocked)
		if blockErr == nil {
			blockErr = m.write(blocked)
		}
		return errors.Join(cause, journalErr, restoreErr, blockErr, ErrBlocked)
	}
	if journalErr != nil || errors.Is(cause, errStorageRestoreFailed) {
		blocked, blockErr := m.transition(next, updateflow.StageBlocked)
		if blockErr == nil {
			blockErr = m.write(blocked)
		}
		return errors.Join(cause, journalErr, blockErr, ErrBlocked)
	}
	if candidate != nil {
		m.stopWorker(candidate)
	}
	if err := m.removeStaged(); err != nil {
		return errors.Join(cause, err, ErrBlocked)
	}
	idle := m.idleJournal(next, updateflow.FailureDrain, failed.Version)
	if err := m.write(idle); err != nil {
		return errors.Join(cause, err, ErrBlocked)
	}
	m.record(ctx, EventRolledBack, idle, failed, safeFailure(cause))
	if errors.Is(cause, errInterruptedDrainRecovery) {
		return nil
	}
	return cause
}

var errInterruptedDrainRecovery = errors.New("interrupted drain recovered")
var errStorageRestoreFailed = errors.New("worker update storage restore failed")

func (m *Manager) setActive(release Release) {
	m.active = release
	m.activeVersion.Store(release.Version)
}

func releaseDuration(signed, fallback time.Duration) time.Duration {
	if signed > 0 {
		return signed
	}
	return fallback
}

func (m *Manager) monitor(ctx context.Context, journal updateflow.Journal, release Release) error {
	deadline := journal.HealthDeadline
	if deadline.IsZero() {
		return ErrBlocked
	}
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
	interval := releaseDuration(release.StabilityInterval, m.config.HealthInterval)
	if remaining <= 0 {
		remaining = interval
	}
	if err := m.gate(ctx, remaining, func(gateCtx context.Context) error {
		request := m.gateRequest(journal, release, status)
		request.Window, request.Interval = releaseDuration(release.StabilityWindow, remaining), interval
		if request.Interval > request.Window {
			request.Interval = request.Window
		}
		if err := request.validate(hostdproto.StateActive); err != nil {
			return err
		}
		return m.config.Gate.Active(gateCtx, request)
	}); err != nil {
		return err
	}
	status, err = m.config.Hostd.Active(ctx)
	if err != nil || !matches(status, hostdproto.StateActive, journal.WorkerID, journal.WorkerEpoch) {
		if err != nil {
			return err
		}
		return updateflow.ErrInvalidJournal
	}
	if err := m.config.Health.Check(ctx, status, release); err != nil {
		return err
	}
	return nil
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
	rollbackRequest := m.startRequest(previous, m.config.BinaryRollback)
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
	rollbackStatus, statusErr := m.config.Hostd.Active(ctx)
	if statusErr != nil {
		return errors.Join(cause, statusErr, ErrBlocked)
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(ctx, releaseDuration(failed.RollbackTimeout, m.config.RollbackTimeout))
	rollbackGateRequest := GateRequest{TransactionID: journal.TransactionID, Previous: failed, Candidate: previous, Worker: rollbackStatus}
	rollbackErr := rollbackGateRequest.validate(hostdproto.StateActive)
	if rollbackErr == nil {
		rollbackErr = m.config.Gate.Rollback(rollbackCtx, rollbackGateRequest)
	}
	rollbackCancel()
	if rollbackErr != nil {
		next.LastFailure = updateflow.FailureRollback
		if blocked, transitionErr := m.transition(next, updateflow.StageBlocked); transitionErr == nil {
			_ = m.write(blocked)
		}
		return errors.Join(cause, rollbackErr, ErrBlocked)
	}
	if candidate != nil {
		m.stopWorker(candidate)
	}
	idle := m.idleJournal(next, updateflow.FailureHealth, failed.Version)
	idle.RollbackCount = next.RollbackCount
	if err := m.write(idle); err != nil {
		return errors.Join(cause, err)
	}
	m.record(ctx, EventRolledBack, next, failed, safeFailure(cause))
	m.record(ctx, EventQuarantined, next, failed, safeFailure(cause))
	return cause
}

func (m *Manager) failBeforeCutover(journal updateflow.Journal, worker Worker, failure updateflow.Failure, cause error, quarantine ...string) error {
	if worker != nil {
		m.stopWorker(worker)
	}
	_ = m.removeStaged()
	journal.LastFailure = failure
	version := ""
	if len(quarantine) > 0 {
		version = quarantine[0]
	}
	writeErr := m.write(m.idleJournal(journal, failure, version))
	if version != "" {
		m.record(context.Background(), EventQuarantined, journal, releaseFromJournal(journal), safeFailure(cause))
	}
	return errors.Join(cause, writeErr)
}

func (m *Manager) gate(ctx context.Context, timeout time.Duration, invoke func(context.Context) error) error {
	if ctx == nil || invoke == nil || timeout <= 0 {
		return ErrActivationGate
	}
	gateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := invoke(gateCtx); err != nil {
		return errors.Join(ErrActivationGate, err)
	}
	return nil
}

func (m *Manager) gateRequest(journal updateflow.Journal, candidate Release, worker hostdproto.Status) GateRequest {
	return GateRequest{TransactionID: journal.TransactionID, Previous: m.active, Candidate: candidate, Worker: worker}
}

func (m *Manager) record(ctx context.Context, phase EventPhase, journal updateflow.Journal, release Release, failure string) {
	if m.config.Events == nil {
		return
	}
	eventCtx := ctx
	if eventCtx == nil || eventCtx.Err() != nil {
		var cancel context.CancelFunc
		eventCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	_ = m.config.Events.RecordUpdateEvent(eventCtx, Event{At: m.now(), Phase: phase, TransactionID: journal.TransactionID, FromVersion: m.active.Version, ToVersion: release.Version, Failure: failure})
}

func safeFailure(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "failed"
}

func (m *Manager) stopWorker(worker Worker) {
	if worker == nil {
		return
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = worker.Stop(stopCtx)
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
	directory := filepath.Dir(m.config.BinaryStaged)
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=same-directory-verified-runtime-download-staging
	pending, err := os.CreateTemp(directory, runtimeStagingPattern(release.Platform))
	if err != nil {
		return err
	}
	pendingPath := pending.Name()
	defer os.Remove(pendingPath)
	// The downloaded Darwin package stays private until installer(8) consumes
	// it. Native executable targets must be traversable by the enrolled worker
	// UID when hostd launches the candidate.
	stagingMode := os.FileMode(0o755)
	if release.Platform == "darwin" {
		stagingMode = 0o600
	}
	if err := pending.Chmod(stagingMode); err != nil {
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
	if release.Platform == "darwin" {
		if m.config.InstallPackage == nil {
			return ErrInvalidConfig
		}
		if err := m.config.NativeVerifier.Verify(ctx, pendingPath, release.Platform, release.Architecture); err != nil {
			return ErrInvalidRelease
		}
		installedPath, err := m.config.InstallPackage(ctx, pendingPath)
		if err != nil {
			return ErrInvalidRelease
		}
		if err := stageInstalledDarwinExecutable(installedPath, m.config.BinaryStaged, m.config.OwnerUID, m.config.OwnerGID); err != nil {
			return ErrInvalidRelease
		}
		if err := binarytarget.Validate(m.config.BinaryStaged, release.Platform, release.Architecture); err != nil {
			return ErrInvalidRelease
		}
		if err := m.config.NativeVerifier.Verify(ctx, m.config.BinaryStaged, release.Platform, release.Architecture); err != nil {
			return ErrInvalidRelease
		}
		return syncDirectories(directory, filepath.Dir(m.config.BinaryStaged))
	}
	if err := binarytarget.Validate(pendingPath, release.Platform, release.Architecture); err != nil {
		return ErrInvalidRelease
	}
	if err := m.config.NativeVerifier.Verify(ctx, pendingPath, release.Platform, release.Architecture); err != nil {
		return ErrInvalidRelease
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=verified-runtime-download-publication
	if err := os.Rename(pendingPath, m.config.BinaryStaged); err != nil {
		return err
	}
	return syncDirectories(directory)
}

// runtimeStagingPattern preserves native package extensions while a verified
// artifact is held in the private staging directory. macOS signature
// validation distinguishes a signed installer package (.pkg) from an
// executable, so the temporary package must retain that suffix until
// installer(8) consumes it.
func runtimeStagingPattern(platform string) string {
	if platform == "darwin" {
		return ".paperboat-runtime-*.pkg"
	}
	return ".paperboat-runtime-*"
}

func stageInstalledDarwinExecutable(source, destination string, ownerUID, ownerGID int) error {
	if source == "" || !filepath.IsAbs(source) || filepath.Clean(source) != source || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrInvalidRelease
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxRuntimeBytes {
		return ErrInvalidRelease
	}
	directory := filepath.Dir(destination)
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=same-directory-verified-darwin-executable-staging
	pending, err := os.CreateTemp(directory, ".paperboat-darwin-executable-")
	if err != nil {
		return err
	}
	pendingPath := pending.Name()
	defer os.Remove(pendingPath)
	if err := pending.Chmod(0o755); err != nil {
		_ = pending.Close()
		return err
	}
	if err := pending.Chown(ownerUID, ownerGID); err != nil {
		_ = pending.Close()
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		_ = pending.Close()
		return err
	}
	written, copyErr := io.Copy(pending, io.LimitReader(input, maxRuntimeBytes+1))
	closeErr := input.Close()
	if copyErr != nil || closeErr != nil || written != info.Size() {
		_ = pending.Close()
		return ErrInvalidRelease
	}
	if err := pending.Sync(); err != nil {
		_ = pending.Close()
		return err
	}
	if err := pending.Close(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=verified-darwin-package-executable-staging
	if err := os.Rename(pendingPath, destination); err != nil {
		return err
	}
	return nil
}

func (m *Manager) promoteStorage() error {
	if err := safeRuntimeFile(m.config.Binary, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := safeRuntimeFile(m.config.BinaryStaged, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := removeRuntimeFile(m.config.BinaryRollback, m.config.OwnerUID); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=current-runtime-to-rollback-slot-transition
	if err := os.Rename(m.config.Binary, m.config.BinaryRollback); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=verified-staged-runtime-slot-activation
	if err := os.Rename(m.config.BinaryStaged, m.config.Binary); err != nil {
		//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=restore-runtime-rollback-after-activation-failure
		_ = os.Rename(m.config.BinaryRollback, m.config.Binary)
		return err
	}
	return syncDirectories(filepath.Dir(m.config.Binary), filepath.Dir(m.config.BinaryRollback), filepath.Dir(m.config.BinaryStaged))
}

func (m *Manager) ensurePromoted(journal updateflow.Journal) error {
	if m.active.Platform == "darwin" || runtime.GOOS == "darwin" {
		if err := binarytarget.Validate(m.config.Binary, "darwin", "arm64"); err != nil {
			return err
		}
		return nil
	}
	if regularMatches(m.config.Binary, journal.CandidateLength, journal.CandidateDigest) {
		return nil
	}
	return m.promoteStorage()
}

func (m *Manager) restoreStorage() error {
	// Before activation, current is old and staged is candidate, so there is
	// nothing to restore. After promotion, current is candidate and rollback is
	// old; move only the verified candidate into the quarantined staged slot.
	if _, err := os.Lstat(m.config.BinaryStaged); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := safeRuntimeFile(m.config.Binary, m.config.OwnerUID, true); err != nil {
		return err
	}
	if err := safeRuntimeFile(m.config.BinaryRollback, m.config.OwnerUID, true); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=quarantine-current-runtime-before-rollback
	if err := os.Rename(m.config.Binary, m.config.BinaryStaged); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=verified-runtime-rollback-slot-activation
	if err := os.Rename(m.config.BinaryRollback, m.config.Binary); err != nil {
		//paperboat:allow-source-policy atomic-replacement owner=worker-update reason=restore-current-runtime-after-rollback-failure
		_ = os.Rename(m.config.BinaryStaged, m.config.Binary)
		return err
	}
	return syncDirectories(filepath.Dir(m.config.Binary), filepath.Dir(m.config.BinaryRollback), filepath.Dir(m.config.BinaryStaged))
}

func (m *Manager) removeStaged() error {
	return removeRuntimeFile(m.config.BinaryStaged, m.config.OwnerUID)
}

func (m *Manager) newJournal() updateflow.Journal {
	return withActiveRelease(updateflow.Journal{Schema: updateflow.SchemaV1, TransactionID: transactionID(), Stage: updateflow.StageIdle,
		ActiveVersion: m.active.Version, BootID: "hostd", StageUpdatedAt: m.now()}, m.active)
}

func (m *Manager) idleJournal(from updateflow.Journal, failure updateflow.Failure, quarantine string) updateflow.Journal {
	journal := withActiveRelease(updateflow.Journal{Schema: updateflow.SchemaV1, TransactionID: from.TransactionID, Stage: updateflow.StageIdle,
		ActiveVersion: m.active.Version, BootID: from.BootID, StageUpdatedAt: m.now(), RollbackCount: from.RollbackCount, LastFailure: failure}, m.active)
	if quarantine != "" {
		journal = withRelease(journal, Release{Version: quarantine, SHA256: from.CandidateDigest, Length: from.CandidateLength, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: from.HostdAPIMin, HostdAPIMax: from.HostdAPIMax, RuntimeAPIMin: from.RuntimeAPIMin, RuntimeAPIMax: from.RuntimeAPIMax}, m.config.BinaryStaged)
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
	return m.config.WriteJournal(m.config.StatePath, journal, m.config.OwnerUID, m.config.OwnerGID)
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
	journal.CandidateManifestDigest = release.ManifestSHA256
	journal.HostdAPIMin, journal.HostdAPIMax, journal.RuntimeAPIMin, journal.RuntimeAPIMax = release.HostdAPIMin, release.HostdAPIMax, release.RuntimeAPIMin, release.RuntimeAPIMax
	return journal
}

func withActiveRelease(journal updateflow.Journal, release Release) updateflow.Journal {
	journal.ActiveVersion = release.Version
	journal.ActiveDigest, journal.ActiveLength = release.SHA256, release.Length
	journal.ActiveHostdAPIMin, journal.ActiveHostdAPIMax = release.HostdAPIMin, release.HostdAPIMax
	journal.ActiveRuntimeAPIMin, journal.ActiveRuntimeAPIMax = release.RuntimeAPIMin, release.RuntimeAPIMax
	return journal
}

// ActiveReleaseFromJournal returns release identity that was previously
// derived from signed metadata and durably bound to the update transaction.
// Journals written before active metadata was retained remain recoverable only
// while their verified candidate is at or beyond cutover.
func ActiveReleaseFromJournal(path, version string) (Release, error) {
	journal, err := updateflow.Load(path)
	if err != nil {
		return Release{}, err
	}
	release, err := releaseForVersion(journal, version)
	if err != nil {
		return Release{}, err
	}
	return completeJournalRelease(release)
}

// RecoveryReleaseFromJournal returns the logical pre-transaction active
// release when its metadata is available. The executable may already be the
// promoted candidate, so its version is used only to bind the journal to the
// process that is attempting recovery.
func RecoveryReleaseFromJournal(path, executableVersion string) (Release, error) {
	journal, err := updateflow.Load(path)
	if err != nil {
		return Release{}, err
	}
	if journal.ActiveDigest != "" && (journal.ActiveVersion == executableVersion || journal.CandidateVersion == executableVersion && candidateMayBeActive(journal.Stage)) {
		return completeJournalRelease(activeReleaseFromJournal(journal))
	}
	release, err := releaseForVersion(journal, executableVersion)
	if err != nil {
		return Release{}, err
	}
	return completeJournalRelease(release)
}

func releaseForVersion(journal updateflow.Journal, version string) (Release, error) {
	if journal.ActiveVersion == version && journal.ActiveDigest != "" {
		return activeReleaseFromJournal(journal), nil
	}
	if journal.CandidateVersion == version && candidateMayBeActive(journal.Stage) {
		return releaseFromJournal(journal), nil
	}
	return Release{}, ErrInvalidRelease
}

func activeReleaseFromJournal(journal updateflow.Journal) Release {
	return Release{
		Version: journal.ActiveVersion, SHA256: journal.ActiveDigest, Length: journal.ActiveLength,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		HostdAPIMin: journal.ActiveHostdAPIMin, HostdAPIMax: journal.ActiveHostdAPIMax,
		RuntimeAPIMin: journal.ActiveRuntimeAPIMin, RuntimeAPIMax: journal.ActiveRuntimeAPIMax,
	}
}

func completeJournalRelease(release Release) (Release, error) {
	component := ComponentTarget{SHA256: release.SHA256, Length: release.Length, Platform: release.Platform, Architecture: release.Architecture}
	release.CLISHA256, release.CLILength, release.CLIPlatform, release.CLIArchitecture = release.SHA256, release.Length, release.Platform, release.Architecture
	release.Hostd, release.Updater, release.Launcher = component, component, component
	if err := validateRelease(release); err != nil {
		return Release{}, err
	}
	return release, nil
}

func candidateMayBeActive(stage updateflow.Stage) bool {
	return stage == updateflow.StageCutover || stage == updateflow.StageMonitoring || stage == updateflow.StageCommitted
}

func releaseFromJournal(j updateflow.Journal) Release {
	return Release{Version: j.CandidateVersion, SHA256: j.CandidateDigest, ManifestSHA256: j.CandidateManifestDigest, Length: j.CandidateLength, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: j.HostdAPIMin, HostdAPIMax: j.HostdAPIMax, RuntimeAPIMin: j.RuntimeAPIMin, RuntimeAPIMax: j.RuntimeAPIMax}
}
func workerID(version string) string { return "runtime-" + version }
func matches(status hostdproto.Status, state hostdproto.State, id string, epoch uint64) bool {
	return status.State == state && status.WorkerID == id && (epoch == 0 || status.Epoch == epoch)
}

func validateConfig(config Config) error {
	if config.Fetcher == nil || config.Starter == nil || config.Hostd == nil || config.Health == nil || config.Gate == nil || config.OwnerUID < 0 || config.OwnerGID < 0 || !validWorkerIdentity(config.WorkerUID, config.WorkerGID) || len(config.Capability) != 32 || config.HostdEndpoint == "" || config.MonitorWindow <= 0 || config.HealthInterval <= 0 || config.HealthInterval > config.MonitorWindow || config.HealthInterval > 30*time.Second || config.CanaryTimeout <= 0 || config.CanaryTimeout > 30*time.Second || config.DrainTimeout <= 0 || config.DrainTimeout > 2*time.Minute || config.RollbackTimeout <= 0 || config.RollbackTimeout > 2*time.Minute || validateRelease(config.Active) != nil {
		return ErrInvalidConfig
	}
	paths := []string{config.StatePath, config.Binary, config.BinaryRollback, config.BinaryStaged}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
			return ErrInvalidConfig
		}
		if err := secureDirectory(filepath.Dir(path), config.OwnerUID); err != nil {
			return err
		}
	}
	if config.Binary == config.BinaryRollback || config.Binary == config.BinaryStaged || config.BinaryRollback == config.BinaryStaged {
		return ErrInvalidConfig
	}
	if err := safeRuntimeFile(config.Binary, config.OwnerUID, true); err != nil {
		return err
	}
	activeMatches := regularMatches(config.Binary, config.Active.Length, config.Active.SHA256)
	if config.Active.Platform == "darwin" {
		// The signed Darwin release target is a PKG. The installed active
		// executable is the package payload, so its bytes cannot match the
		// package digest. Format validation remains mandatory.
		activeMatches = true
	}
	if !activeMatches || binarytarget.Validate(config.Binary, config.Active.Platform, config.Active.Architecture) != nil {
		return ErrUnsafeStorage
	}
	if config.Active.Platform == "darwin" && config.InstallPackage == nil {
		return ErrUnsafeStorage
	}
	return nil
}

func validateRelease(release Release) error {
	if !validVersion(release.Version) || len(release.SHA256) != 64 || release.Length < 1 || release.Length > maxRuntimeBytes || release.Platform != runtime.GOOS || release.Architecture != runtime.GOARCH || !hexDigest(release.SHA256) || invalidRequiredAPIRange(release.HostdAPIMin, release.HostdAPIMax) || invalidRequiredAPIRange(release.RuntimeAPIMin, release.RuntimeAPIMax) {
		return ErrInvalidRelease
	}
	return nil
}

func invalidAPIRange(minimum, maximum uint16) bool { return minimum > maximum || maximum > 1024 }
func invalidRequiredAPIRange(minimum, maximum uint16) bool {
	return minimum == 0 || invalidAPIRange(minimum, maximum)
}
func hexDigest(value string) bool { _, err := hex.DecodeString(value); return err == nil }
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
