// Package supervisorupdate stages and activates the three binaries whose
// process boundaries define a Paperboat installation. Unlike a worker update,
// activation is allowed to interrupt only after the updater has observed a
// stable workload generation and either no protected workload exists or an
// exact, short-lived local maintenance grant has been supplied.
package supervisorupdate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

const (
	SchemaV1               = "paperboat.supervisor-update/v1"
	DefaultGrantTTL        = 15 * time.Minute
	maxArtifactBytes int64 = 512 << 20
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

var (
	ErrInvalidConfig       = errors.New("invalid supervisor update configuration")
	ErrInvalidRelease      = errors.New("invalid supervisor release")
	ErrMaintenanceRequired = errors.New("supervisor maintenance approval required")
	ErrApprovalExpired     = errors.New("supervisor maintenance approval expired")
	ErrStaleWorkloads      = errors.New("protected workload generation changed")
	ErrBlocked             = errors.New("supervisor updates require recovery")
	ErrActivationUncertain = errors.New("supervisor activation state is uncertain")
)

// Paths are supplied by the fixed service layout. They are never accepted
// from a control request, release metadata, or a user-owned environment.
type Paths struct {
	StatePath                                         string
	HostdCurrent, HostdRollback, HostdStaged          string
	UpdaterCurrent, UpdaterRollback, UpdaterStaged    string
	LauncherCurrent, LauncherRollback, LauncherStaged string
}

type WorkloadSnapshot struct {
	Generation uint64
	Protected  uint64
}

type WorkloadSource interface {
	Snapshot(context.Context) (WorkloadSnapshot, error)
}

type Activator interface {
	Activate(context.Context) error
	Rollback(context.Context) error
}

type Config struct {
	Paths          Paths
	Active         workerupdate.Release
	Fetcher        workerupdate.ComponentFetcher
	Workloads      WorkloadSource
	NativeVerifier workerupdate.NativeVerifier
	Activator      Activator
	OwnerUID       int
	OwnerGID       int
	GrantTTL       time.Duration
	Now            func() time.Time
}

type Result struct {
	Version             string
	StagedVersion       string
	Applied             bool
	MaintenanceRequired bool
	ProtectedWorkloads  uint64
	WorkloadGeneration  uint64
	ApprovalExpiresAt   time.Time
	Stage               string
}

type Manager struct {
	mu     sync.Mutex
	config Config
	active workerupdate.Release
}

type targetState struct {
	Digest       string `json:"digest"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Applied      bool   `json:"applied"`
}

type journal struct {
	Schema             string      `json:"schema"`
	TransactionID      string      `json:"transaction_id"`
	Stage              string      `json:"stage"`
	ActiveVersion      string      `json:"active_version"`
	CandidateVersion   string      `json:"candidate_version,omitempty"`
	WorkloadGeneration uint64      `json:"workload_generation,omitempty"`
	ProtectedWorkloads uint64      `json:"protected_workloads,omitempty"`
	ApprovalID         string      `json:"approval_id,omitempty"`
	ApprovalVersion    string      `json:"approval_version,omitempty"`
	ApprovalExpiresAt  time.Time   `json:"approval_expires_at,omitempty"`
	Hostd              targetState `json:"hostd"`
	Updater            targetState `json:"updater"`
	Launcher           targetState `json:"launcher"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

const (
	stageIdle      = "idle"
	stageStaged    = "staged"
	stageApplying  = "applying"
	stageCommitted = "committed"
	stageBlocked   = "blocked"
)

func New(config Config) (*Manager, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.GrantTTL == 0 {
		config.GrantTTL = DefaultGrantTTL
	}
	if config.NativeVerifier == nil {
		config.NativeVerifier = nativesignature.New(nil)
	}
	if config.Fetcher == nil || config.Workloads == nil || config.OwnerUID < 0 || config.OwnerGID < 0 || config.GrantTTL <= 0 || config.GrantTTL > DefaultGrantTTL || validateRelease(config.Active) != nil || validatePaths(config.Paths) != nil {
		return nil, ErrInvalidConfig
	}
	for _, path := range allPaths(config.Paths) {
		if err := ensureDirectory(filepath.Dir(path), config.OwnerUID, config.OwnerGID); err != nil {
			return nil, err
		}
	}
	for _, item := range []struct {
		path   string
		target workerupdate.ComponentTarget
	}{
		{config.Paths.HostdCurrent, config.Active.Hostd}, {config.Paths.UpdaterCurrent, config.Active.Updater}, {config.Paths.LauncherCurrent, config.Active.Launcher},
	} {
		if !regularMatches(item.path, item.target) || binarytarget.Validate(item.path, item.target.Platform, item.target.Architecture) != nil {
			return nil, ErrInvalidConfig
		}
	}
	return &Manager{config: config, active: config.Active}, nil
}

func (m *Manager) ActiveVersion() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.Version
}

func (m *Manager) Check(ctx context.Context, resolve workerupdate.Resolver) (Result, error) {
	if m == nil || resolve == nil {
		return Result{}, ErrInvalidConfig
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.recoverLocked(); err != nil {
		return Result{Version: m.active.Version}, err
	}
	release, found, err := resolve(ctx)
	if err != nil || !found {
		return m.currentResultLocked(), err
	}
	if err := m.validateCandidate(release); err != nil {
		return m.currentResultLocked(), err
	}
	if compareVersion(release.Version, m.active.Version) <= 0 {
		return m.currentResultLocked(), nil
	}
	if err := m.stageLocked(ctx, release); err != nil {
		return m.currentResultLocked(), err
	}
	snapshot, err := m.config.Workloads.Snapshot(ctx)
	if err != nil {
		return m.currentResultLocked(), err
	}
	j := m.loadOrNewJournal(release)
	if j.WorkloadGeneration == 0 {
		j.WorkloadGeneration = snapshot.Generation
	}
	j.ProtectedWorkloads = snapshot.Protected
	if err := m.write(j); err != nil {
		return m.currentResultLocked(), err
	}
	result := m.resultFromJournal(j)
	if snapshot.Generation != j.WorkloadGeneration {
		return result, ErrStaleWorkloads
	}
	if snapshot.Protected > 0 && !m.grantValid(j, release.Version) {
		result.MaintenanceRequired = true
		return result, nil
	}
	if err := m.applyLocked(ctx, release, j); err != nil {
		return m.resultFromJournal(j), err
	}
	return Result{Version: release.Version, StagedVersion: release.Version, Applied: true, ProtectedWorkloads: snapshot.Protected, WorkloadGeneration: snapshot.Generation, Stage: stageIdle}, nil
}

// Approve creates and immediately consumes a one-use exact-version grant.
// Re-resolving the signed index and checking the workload generation happen
// immediately before activation; an old dashboard or CLI approval cannot be
// replayed against a different release or workload state.
func (m *Manager) Approve(ctx context.Context, version string, resolve workerupdate.Resolver) (Result, error) {
	if m == nil || resolve == nil || !versionPattern.MatchString(version) {
		return Result{}, ErrInvalidRelease
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.recoverLocked(); err != nil {
		return Result{Version: m.active.Version}, err
	}
	release, found, err := resolve(ctx)
	if err != nil {
		return Result{Version: m.active.Version}, err
	}
	if !found || release.Version != version {
		return Result{Version: m.active.Version}, ErrInvalidRelease
	}
	if err := m.validateCandidate(release); err != nil {
		return Result{Version: m.active.Version}, err
	}
	if compareVersion(release.Version, m.active.Version) <= 0 {
		return m.currentResultLocked(), nil
	}
	if err := m.stageLocked(ctx, release); err != nil {
		return m.currentResultLocked(), err
	}
	snapshot, err := m.config.Workloads.Snapshot(ctx)
	if err != nil {
		return m.currentResultLocked(), err
	}
	j := m.loadOrNewJournal(release)
	j.WorkloadGeneration = snapshot.Generation
	j.ProtectedWorkloads = snapshot.Protected
	j.ApprovalID = randomID()
	j.ApprovalVersion = release.Version
	j.ApprovalExpiresAt = m.now().Add(m.config.GrantTTL)
	if err := m.write(j); err != nil {
		return m.resultFromJournal(j), err
	}
	// Re-resolve immediately before consuming the grant. This is intentionally
	// a second signed metadata verification rather than a local version check.
	latest, found, err := resolve(ctx)
	if err != nil || !found || !sameSupervisorRelease(latest, release) {
		return m.resultFromJournal(j), ErrInvalidRelease
	}
	latestSnapshot, err := m.config.Workloads.Snapshot(ctx)
	if err != nil {
		return m.resultFromJournal(j), err
	}
	if latestSnapshot.Generation != j.WorkloadGeneration {
		return m.resultFromJournal(j), ErrStaleWorkloads
	}
	if err := m.applyLocked(ctx, release, j); err != nil {
		return m.resultFromJournal(j), err
	}
	return Result{Version: release.Version, StagedVersion: release.Version, Applied: true, ProtectedWorkloads: latestSnapshot.Protected, WorkloadGeneration: latestSnapshot.Generation, Stage: stageIdle}, nil
}

func (m *Manager) Status() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, err := loadJournal(m.config.Paths.StatePath)
	if err != nil {
		return Result{Version: m.active.Version, Stage: stageIdle}
	}
	return m.resultFromJournal(j)
}

func (m *Manager) Recover(ctx context.Context) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoverLocked()
}

func (m *Manager) recoverLocked() error {
	j, err := loadJournal(m.config.Paths.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || (j.ActiveVersion != m.active.Version && j.Stage != stageCommitted && !(j.Stage == stageApplying && j.CandidateVersion == m.active.Version)) {
		return ErrBlocked
	}
	switch j.Stage {
	case stageIdle:
		return nil
	case stageStaged:
		return nil
	case stageCommitted:
		m.active.Version = j.CandidateVersion
		m.active.Hostd = componentFromState(j.Hostd)
		m.active.Updater = componentFromState(j.Updater)
		m.active.Launcher = componentFromState(j.Launcher)
		return m.write(idleJournal(j, m.active.Version, m.now()))
	case stageApplying:
		candidate := []struct {
			current, rollback, staged string
			target                    targetState
		}{
			{m.config.Paths.HostdCurrent, m.config.Paths.HostdRollback, m.config.Paths.HostdStaged, j.Hostd},
			{m.config.Paths.UpdaterCurrent, m.config.Paths.UpdaterRollback, m.config.Paths.UpdaterStaged, j.Updater},
			{m.config.Paths.LauncherCurrent, m.config.Paths.LauncherRollback, m.config.Paths.LauncherStaged, j.Launcher},
		}
		allCandidate := true
		for _, item := range candidate {
			if !regularMatches(item.current, componentFromState(item.target)) {
				allCandidate = false
			}
		}
		if allCandidate {
			m.active.Version = j.CandidateVersion
			m.active.Hostd, m.active.Updater, m.active.Launcher = componentFromState(j.Hostd), componentFromState(j.Updater), componentFromState(j.Launcher)
			if err := m.removeStagedFiles(); err != nil {
				return err
			}
			return m.write(idleJournal(j, m.active.Version, m.now()))
		}
		// If a crash happened before the first durable applied bit, no file is
		// allowed to remain half-activated. Restore every old slot that exists.
		for _, item := range candidate {
			if !regularMatches(item.current, componentFromState(item.target)) && regularFile(item.rollback) {
				_ = os.Remove(item.current)
				if err := os.Rename(item.rollback, item.current); err != nil {
					return ErrBlocked
				}
			}
		}
		if err := m.removeStagedFiles(); err != nil {
			return err
		}
		return m.write(idleJournal(j, m.active.Version, m.now()))
	default:
		return ErrBlocked
	}
}

func (m *Manager) stageLocked(ctx context.Context, release workerupdate.Release) error {
	for _, item := range []struct {
		name, path string
		target     workerupdate.ComponentTarget
	}{
		{"hostd", m.config.Paths.HostdStaged, release.Hostd}, {"updater", m.config.Paths.UpdaterStaged, release.Updater}, {"launcher", m.config.Paths.LauncherStaged, release.Launcher},
	} {
		if regularMatches(item.path, item.target) && binarytarget.Validate(item.path, item.target.Platform, item.target.Architecture) == nil {
			continue
		}
		if regularFile(item.path) {
			if err := os.Remove(item.path); err != nil {
				return err
			}
		}
		stream, err := m.config.Fetcher.FetchComponent(ctx, release, item.name)
		if err != nil {
			return err
		}
		if err := writeArtifact(ctx, stream, item.path, item.target, m.config.OwnerUID, m.config.OwnerGID, m.config.NativeVerifier); err != nil {
			return err
		}
	}
	return m.write(m.loadOrNewJournal(release))
}

func (m *Manager) applyLocked(ctx context.Context, release workerupdate.Release, j journal) error {
	if j.ApprovalVersion != "" && j.ApprovalVersion != release.Version {
		return ErrInvalidRelease
	}
	if j.ProtectedWorkloads > 0 && !m.grantValid(j, release.Version) {
		if j.ApprovalID != "" && j.ApprovalVersion == release.Version && !j.ApprovalExpiresAt.IsZero() {
			return ErrApprovalExpired
		}
		return ErrMaintenanceRequired
	}
	j.Stage = stageApplying
	j.UpdatedAt = m.now()
	if err := m.write(j); err != nil {
		return err
	}
	items := []struct {
		current, rollback, staged string
		target                    *targetState
	}{
		{m.config.Paths.HostdCurrent, m.config.Paths.HostdRollback, m.config.Paths.HostdStaged, &j.Hostd},
		{m.config.Paths.UpdaterCurrent, m.config.Paths.UpdaterRollback, m.config.Paths.UpdaterStaged, &j.Updater},
		{m.config.Paths.LauncherCurrent, m.config.Paths.LauncherRollback, m.config.Paths.LauncherStaged, &j.Launcher},
	}
	for _, item := range items {
		if err := rotate(item.current, item.rollback, item.staged, m.config.OwnerUID); err != nil {
			restoreErr := restoreRotations(items, j)
			cleanupErr := m.removeStagedFiles()
			if restoreErr != nil || cleanupErr != nil {
				return errors.Join(err, restoreErr, cleanupErr, ErrBlocked)
			}
			_ = m.write(idleJournal(j, m.active.Version, m.now()))
			return err
		}
		item.target.Applied = true
		if err := m.write(j); err != nil {
			return err
		}
	}
	if m.config.Activator != nil {
		if err := m.config.Activator.Activate(ctx); err != nil {
			return errors.Join(ErrActivationUncertain, err)
		}
	}
	m.active = release
	j.Stage = stageCommitted
	j.ActiveVersion = release.Version
	j.UpdatedAt = m.now()
	if err := m.write(j); err != nil {
		return err
	}
	for _, path := range []string{m.config.Paths.HostdStaged, m.config.Paths.UpdaterStaged, m.config.Paths.LauncherStaged} {
		if regularFile(path) {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return m.write(idleJournal(j, release.Version, m.now()))
}

func (m *Manager) removeStagedFiles() error {
	for _, path := range []string{m.config.Paths.HostdStaged, m.config.Paths.UpdaterStaged, m.config.Paths.LauncherStaged} {
		if regularFile(path) {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func restoreRotations(items []struct {
	current, rollback, staged string
	target                    *targetState
}, j journal) error {
	_ = j
	for _, item := range items {
		if item.target == nil || !item.target.Applied || !regularFile(item.rollback) {
			continue
		}
		if regularFile(item.current) {
			if err := os.Remove(item.current); err != nil {
				return err
			}
		}
		if err := os.Rename(item.rollback, item.current); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) validateCandidate(r workerupdate.Release) error {
	if !versionPattern.MatchString(r.Version) || r.Platform != runtime.GOOS || r.Architecture != runtime.GOARCH || validateTarget(r.Hostd) != nil || validateTarget(r.Updater) != nil || validateTarget(r.Launcher) != nil {
		return ErrInvalidRelease
	}
	return nil
}

func (m *Manager) loadOrNewJournal(r workerupdate.Release) journal {
	j, err := loadJournal(m.config.Paths.StatePath)
	if err == nil && j.CandidateVersion == r.Version {
		return j
	}
	return journal{Schema: SchemaV1, TransactionID: randomID(), Stage: stageStaged, ActiveVersion: m.active.Version, CandidateVersion: r.Version, Hostd: stateFromTarget(r.Hostd), Updater: stateFromTarget(r.Updater), Launcher: stateFromTarget(r.Launcher), UpdatedAt: m.now()}
}

func (m *Manager) currentResultLocked() Result {
	return Result{Version: m.active.Version, Stage: stageIdle}
}

func (m *Manager) resultFromJournal(j journal) Result {
	return Result{Version: m.active.Version, StagedVersion: j.CandidateVersion, MaintenanceRequired: j.ProtectedWorkloads > 0 && !m.grantValid(j, j.CandidateVersion), ProtectedWorkloads: j.ProtectedWorkloads, WorkloadGeneration: j.WorkloadGeneration, ApprovalExpiresAt: j.ApprovalExpiresAt, Stage: j.Stage}
}

func (m *Manager) grantValid(j journal, version string) bool {
	return j.ApprovalID != "" && j.ApprovalVersion == version && !j.ApprovalExpiresAt.IsZero() && m.now().Before(j.ApprovalExpiresAt)
}

func (m *Manager) now() time.Time {
	return m.config.Now().UTC()
}

func validateRelease(r workerupdate.Release) error {
	if !versionPattern.MatchString(r.Version) || r.Platform != runtime.GOOS || r.Architecture != runtime.GOARCH {
		return ErrInvalidRelease
	}
	if validateTarget(r.Hostd) != nil || validateTarget(r.Updater) != nil || validateTarget(r.Launcher) != nil {
		return ErrInvalidRelease
	}
	return nil
}

func validateTarget(t workerupdate.ComponentTarget) error {
	if len(t.SHA256) != sha256.Size*2 || !isLowerHex(t.SHA256) || t.Length < 1 || t.Length > maxArtifactBytes || t.Platform != runtime.GOOS || t.Architecture != runtime.GOARCH {
		return ErrInvalidRelease
	}
	return nil
}

func validatePaths(p Paths) error {
	if !filepath.IsAbs(p.StatePath) || filepath.Clean(p.StatePath) != p.StatePath {
		return ErrInvalidConfig
	}
	paths := allPaths(p)
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
			return ErrInvalidConfig
		}
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			return ErrInvalidConfig
		}
		seen[path] = true
	}
	return nil
}

func allPaths(p Paths) []string {
	return []string{p.StatePath, p.HostdCurrent, p.HostdRollback, p.HostdStaged, p.UpdaterCurrent, p.UpdaterRollback, p.UpdaterStaged, p.LauncherCurrent, p.LauncherRollback, p.LauncherStaged}
}

func writeArtifact(ctx context.Context, stream io.ReadCloser, path string, target workerupdate.ComponentTarget, uid, gid int, verifier workerupdate.NativeVerifier) error {
	if stream == nil {
		return ErrInvalidRelease
	}
	defer stream.Close()
	file, err := os.CreateTemp(filepath.Dir(path), ".paperboat-supervisor-")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0o700); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		_ = file.Close()
		return err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(stream, target.Length+1))
	if err != nil || written != target.Length || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), target.SHA256) {
		_ = file.Close()
		return ErrInvalidRelease
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := binarytarget.Validate(temp, target.Platform, target.Architecture); err != nil {
		return ErrInvalidRelease
	}
	if verifier == nil || verifier.Verify(ctx, temp, target.Platform, target.Architecture) != nil {
		return ErrInvalidRelease
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func rotate(current, rollback, staged string, owner int) error {
	if !regularFile(current) || !regularFile(staged) {
		return ErrInvalidConfig
	}
	if regularFile(rollback) {
		if err := os.Remove(rollback); err != nil {
			return err
		}
	}
	if err := os.Rename(current, rollback); err != nil {
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		_ = os.Rename(rollback, current)
		return err
	}
	return syncDir(filepath.Dir(current), filepath.Dir(rollback), filepath.Dir(staged))
}

func regularMatches(path string, target workerupdate.ComponentTarget) bool {
	linkInfo, err := os.Lstat(path)
	if err != nil || !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 || linkInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != target.Length {
		return false
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), target.SHA256)
}

func regularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func ensureDirectory(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidConfig
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return nil
}

func syncDir(paths ...string) error {
	for _, path := range paths {
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

func loadJournal(path string) (journal, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return journal{}, err
	}
	if len(body) > 64<<10 {
		return journal{}, ErrBlocked
	}
	var j journal
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&j) != nil || decoder.Decode(&extra) != io.EOF || !validJournal(j) {
		return journal{}, ErrBlocked
	}
	return j, nil
}

func (m *Manager) write(j journal) error {
	body, err := json.Marshal(j)
	if err != nil || !validJournal(j) {
		return ErrBlocked
	}
	return atomicfile.Write(m.config.Paths.StatePath, append(body, '\n'), atomicfile.Options{Mode: 0o600, OwnerUID: m.config.OwnerUID, OwnerGID: m.config.OwnerGID})
}

func validJournal(j journal) bool {
	return j.Schema == SchemaV1 && j.TransactionID != "" && versionPattern.MatchString(j.ActiveVersion) && (j.CandidateVersion == "" || versionPattern.MatchString(j.CandidateVersion)) && (j.Stage == stageIdle || j.Stage == stageStaged || j.Stage == stageApplying || j.Stage == stageCommitted || j.Stage == stageBlocked) && !j.UpdatedAt.IsZero() && validTargetState(j.Hostd) && validTargetState(j.Updater) && validTargetState(j.Launcher) && (j.ApprovalVersion == "" || j.ApprovalVersion == j.CandidateVersion) && (j.ApprovalID == "" || j.ApprovalExpiresAt.After(j.UpdatedAt))
}

func validTargetState(t targetState) bool {
	return len(t.Digest) == 64 && isLowerHex(t.Digest) && t.Length > 0 && t.Length <= maxArtifactBytes && t.Platform != "" && t.Architecture != ""
}

func idleJournal(from journal, active string, now time.Time) journal {
	from.Stage, from.ActiveVersion, from.CandidateVersion = stageIdle, active, ""
	from.ApprovalID, from.ApprovalVersion = "", ""
	from.ApprovalExpiresAt, from.ProtectedWorkloads, from.WorkloadGeneration = time.Time{}, 0, 0
	from.UpdatedAt = now
	from.Hostd.Applied, from.Updater.Applied, from.Launcher.Applied = false, false, false
	return from
}

func stateFromTarget(t workerupdate.ComponentTarget) targetState {
	return targetState{Digest: t.SHA256, Length: t.Length, Platform: t.Platform, Architecture: t.Architecture}
}
func componentFromState(t targetState) workerupdate.ComponentTarget {
	return workerupdate.ComponentTarget{SHA256: t.Digest, Length: t.Length, Platform: t.Platform, Architecture: t.Architecture}
}
func sameSupervisorRelease(a, b workerupdate.Release) bool {
	return a.Version == b.Version && a.Hostd == b.Hostd && a.Updater == b.Updater && a.Launcher == b.Launcher
}
func compareVersion(a, b string) int {
	var av, bv [4]uint64
	_, _ = fmt.Sscanf(a, "%d.%d.%d.%d", &av[0], &av[1], &av[2], &av[3])
	_, _ = fmt.Sscanf(b, "%d.%d.%d.%d", &bv[0], &bv[1], &bv[2], &bv[3])
	for i := range av {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}
func isLowerHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
func randomID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("local-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}
