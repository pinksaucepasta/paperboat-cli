// Package updateflow defines the crash-consistent state machine used for
// ordinary worker updates. It never restarts hostd or owns live workloads.
package updateflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const SchemaV1 = "paperboat.worker-update/v1"

var (
	ErrInvalidJournal    = errors.New("invalid worker update journal")
	ErrInvalidTransition = errors.New("invalid worker update transition")
	versionPattern       = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Stage string

const (
	StageIdle                Stage = "idle"
	StageChecking            Stage = "checking"
	StageStaged              Stage = "staged"
	StageCandidateStarted    Stage = "candidate_started"
	StageCandidateValidating Stage = "candidate_validating"
	StageCandidateReady      Stage = "candidate_ready"
	StageDraining            Stage = "draining"
	StageCutover             Stage = "cutover"
	StageMonitoring          Stage = "monitoring"
	StageCommitted           Stage = "committed"
	StageRollback            Stage = "rollback"
	StageBlocked             Stage = "blocked"
)

type Failure string

const (
	FailureNone                 Failure = ""
	FailureVerification         Failure = "verification_failed"
	FailureCompatibility        Failure = "incompatible"
	FailureCandidate            Failure = "candidate_failed"
	FailureCanary               Failure = "canary_failed"
	FailureDrain                Failure = "drain_failed"
	FailureHealth               Failure = "health_failed"
	FailureRollback             Failure = "rollback_failed"
	FailureContradictoryJournal Failure = "recovery_required"
)

type Journal struct {
	Schema                  string    `json:"schema"`
	TransactionID           string    `json:"transaction_id"`
	Stage                   Stage     `json:"stage"`
	ActiveVersion           string    `json:"active_version"`
	ActiveDigest            string    `json:"active_digest,omitempty"`
	ActiveLength            int64     `json:"active_length,omitempty"`
	ActiveHostdAPIMin       uint16    `json:"active_hostd_api_min,omitempty"`
	ActiveHostdAPIMax       uint16    `json:"active_hostd_api_max,omitempty"`
	ActiveRuntimeAPIMin     uint16    `json:"active_runtime_api_min,omitempty"`
	ActiveRuntimeAPIMax     uint16    `json:"active_runtime_api_max,omitempty"`
	RollbackVersion         string    `json:"rollback_version,omitempty"`
	CandidateVersion        string    `json:"candidate_version,omitempty"`
	CandidateDigest         string    `json:"candidate_digest,omitempty"`
	CandidateManifestDigest string    `json:"candidate_manifest_digest,omitempty"`
	CandidateLength         int64     `json:"candidate_length,omitempty"`
	StagedPath              string    `json:"staged_path,omitempty"`
	HostdAPIMin             uint16    `json:"hostd_api_min,omitempty"`
	HostdAPIMax             uint16    `json:"hostd_api_max,omitempty"`
	RuntimeAPIMin           uint16    `json:"runtime_api_min,omitempty"`
	RuntimeAPIMax           uint16    `json:"runtime_api_max,omitempty"`
	WorkerID                string    `json:"worker_id,omitempty"`
	WorkerEpoch             uint64    `json:"worker_epoch,omitempty"`
	BootID                  string    `json:"boot_id"`
	StageUpdatedAt          time.Time `json:"stage_updated_at"`
	HealthDeadline          time.Time `json:"health_deadline,omitempty"`
	AttemptCount            uint32    `json:"attempt_count"`
	RollbackCount           uint32    `json:"rollback_count"`
	LastFailure             Failure   `json:"last_failure,omitempty"`
	CleanupComplete         bool      `json:"cleanup_complete"`
}

func (j Journal) Validate() error {
	if j.Schema != SchemaV1 || !validID(j.TransactionID) || !validVersion(j.ActiveVersion) || !validID(j.BootID) || j.StageUpdatedAt.IsZero() {
		return ErrInvalidJournal
	}
	if !knownStage(j.Stage) || !knownFailure(j.LastFailure) || invalidRange(j.HostdAPIMin, j.HostdAPIMax) || invalidRange(j.RuntimeAPIMin, j.RuntimeAPIMax) {
		return ErrInvalidJournal
	}
	if j.RollbackVersion != "" && !validVersion(j.RollbackVersion) || j.CandidateVersion != "" && !validVersion(j.CandidateVersion) {
		return ErrInvalidJournal
	}
	hasActiveMetadata := j.ActiveDigest != "" || j.ActiveLength != 0 || j.ActiveHostdAPIMin != 0 || j.ActiveHostdAPIMax != 0 || j.ActiveRuntimeAPIMin != 0 || j.ActiveRuntimeAPIMax != 0
	if hasActiveMetadata && (!digestPattern.MatchString(j.ActiveDigest) || j.ActiveLength < 1 || invalidRange(j.ActiveHostdAPIMin, j.ActiveHostdAPIMax) || j.ActiveHostdAPIMin == 0 || invalidRange(j.ActiveRuntimeAPIMin, j.ActiveRuntimeAPIMax) || j.ActiveRuntimeAPIMin == 0) {
		return ErrInvalidJournal
	}
	if j.CandidateDigest != "" && !digestPattern.MatchString(j.CandidateDigest) || j.CandidateManifestDigest != "" && !digestPattern.MatchString(j.CandidateManifestDigest) || j.CandidateLength < 0 {
		return ErrInvalidJournal
	}
	if j.StagedPath != "" && (!filepath.IsAbs(j.StagedPath) || filepath.Clean(j.StagedPath) != j.StagedPath) {
		return ErrInvalidJournal
	}
	if requiresCandidate(j.Stage) && (j.CandidateVersion == "" || j.CandidateDigest == "" || j.CandidateLength <= 0 || j.StagedPath == "") {
		return ErrInvalidJournal
	}
	if (j.Stage == StageCutover || j.Stage == StageMonitoring || j.Stage == StageCommitted) && (j.WorkerEpoch == 0 || !validID(j.WorkerID)) {
		return ErrInvalidJournal
	}
	return nil
}

func invalidRange(minimum, maximum uint16) bool {
	return minimum > maximum || maximum > 1024
}

func (j Journal) Transition(next Stage, now time.Time) (Journal, error) {
	if j.Validate() != nil || !allowed(j.Stage, next) || now.IsZero() || now.Before(j.StageUpdatedAt) {
		return Journal{}, ErrInvalidTransition
	}
	j.Stage, j.StageUpdatedAt = next, now.UTC()
	if next == StageMonitoring && j.HealthDeadline.IsZero() {
		j.HealthDeadline = now.UTC().Add(10 * time.Minute)
	}
	return j, nil
}

type RecoveryAction string

const (
	RecoveryKeepActive       RecoveryAction = "keep_active"
	RecoveryDiscardCandidate RecoveryAction = "discard_candidate"
	RecoveryRestoreDrain     RecoveryAction = "restore_drained_active"
	RecoveryQueryHostd       RecoveryAction = "query_hostd_epoch"
	RecoveryContinueMonitor  RecoveryAction = "continue_monitoring"
	RecoveryFinalizeCleanup  RecoveryAction = "finalize_cleanup"
	RecoveryPerformRollback  RecoveryAction = "perform_rollback"
	RecoveryRequired         RecoveryAction = "recovery_required"
)

func (j Journal) Recovery() RecoveryAction {
	if j.Validate() != nil {
		return RecoveryRequired
	}
	switch j.Stage {
	case StageIdle, StageChecking:
		return RecoveryKeepActive
	case StageStaged, StageCandidateStarted, StageCandidateValidating, StageCandidateReady:
		return RecoveryDiscardCandidate
	case StageDraining:
		return RecoveryRestoreDrain
	case StageCutover:
		return RecoveryQueryHostd
	case StageMonitoring:
		return RecoveryContinueMonitor
	case StageCommitted:
		return RecoveryFinalizeCleanup
	case StageRollback:
		return RecoveryPerformRollback
	case StageBlocked:
		// A blocked transaction already failed its rollback attempt. Startup must
		// retry that same durable rollback instead of permanently preventing the
		// updater control service from coming online.
		return RecoveryPerformRollback
	default:
		return RecoveryRequired
	}
}

func Write(path string, journal Journal, ownerUID, ownerGID int) error {
	if journal.Validate() != nil || !filepath.IsAbs(path) {
		return ErrInvalidJournal
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(body, '\n'), atomicfile.Options{Mode: 0o600, OwnerUID: ownerUID, OwnerGID: ownerGID})
}

func Load(path string) (Journal, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Journal{}, err
	}
	var journal Journal
	if len(body) > 64<<10 {
		return Journal{}, ErrInvalidJournal
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || journal.Validate() != nil {
		return Journal{}, ErrInvalidJournal
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Journal{}, ErrInvalidJournal
	}
	return journal, nil
}

func allowed(from, to Stage) bool {
	allowedNext := map[Stage][]Stage{
		StageIdle: {StageChecking}, StageChecking: {StageStaged, StageIdle, StageBlocked},
		StageStaged:              {StageCandidateStarted, StageIdle, StageBlocked},
		StageCandidateStarted:    {StageCandidateValidating, StageRollback, StageBlocked},
		StageCandidateValidating: {StageCandidateReady, StageRollback, StageBlocked},
		StageCandidateReady:      {StageDraining, StageRollback, StageBlocked},
		StageDraining:            {StageCutover, StageRollback, StageBlocked},
		StageCutover:             {StageMonitoring, StageRollback, StageBlocked},
		StageMonitoring:          {StageCommitted, StageRollback, StageBlocked},
		StageCommitted:           {StageIdle}, StageRollback: {StageIdle, StageBlocked}, StageBlocked: {StageRollback},
	}
	for _, candidate := range allowedNext[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

func validID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(value)
}
func validVersion(value string) bool { return versionPattern.MatchString(value) }
func requiresCandidate(stage Stage) bool {
	switch stage {
	case StageStaged, StageCandidateStarted, StageCandidateValidating, StageCandidateReady, StageDraining, StageCutover, StageMonitoring, StageCommitted, StageRollback:
		return true
	}
	return false
}
func knownStage(stage Stage) bool {
	for _, value := range []Stage{StageIdle, StageChecking, StageStaged, StageCandidateStarted, StageCandidateValidating, StageCandidateReady, StageDraining, StageCutover, StageMonitoring, StageCommitted, StageRollback, StageBlocked} {
		if value == stage {
			return true
		}
	}
	return false
}
func knownFailure(f Failure) bool {
	for _, value := range []Failure{FailureNone, FailureVerification, FailureCompatibility, FailureCandidate, FailureCanary, FailureDrain, FailureHealth, FailureRollback, FailureContradictoryJournal} {
		if value == f {
			return true
		}
	}
	return false
}
