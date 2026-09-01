// Package releaseplan contains the deterministic release publication and
// deployment policy boundary. It does not replace the host updater journal:
// the updater owns binary activation, while this package authenticates the
// artifact set and supplies bounded rollout/rollback inputs.
package releaseplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

const (
	ManifestSchema = "paperboat.release-artifacts/v1"
	PlanSchema     = releasepolicy.PlanSchema
	StateSchema    = "paperboat.release-deployment-state/v1"

	MaxArtifactBytes       int64  = 512 << 20
	MaxManifestBytes       int64  = 1 << 20
	MaxPlanBytes           int64  = 1 << 20
	MaxStateBytes          int64  = 256 << 10
	MaxCohortDelaySeconds  uint32 = releasepolicy.MaxCohortDelaySeconds
	MaxRoutineDeferralSec  uint32 = releasepolicy.MaxRoutineDeferralSec
	MaxSecurityDeferralSec uint32 = releasepolicy.MaxSecurityDeferralSec
	MaxCriticalDeferralSec uint32 = releasepolicy.MaxCriticalDeferralSec
	DeferralSchema         string = releasepolicy.DeferralSchema
)

var (
	ErrInvalidManifest = errors.New("invalid release artifact manifest")
	ErrInvalidPlan     = releasepolicy.ErrInvalidPolicy
	ErrInvalidState    = errors.New("invalid release deployment state")
	ErrInvalidEvent    = errors.New("invalid release deployment event")
	ErrUnsafePath      = errors.New("unsafe release path")
)

var (
	commitPattern    = regexp.MustCompile(`^[a-f0-9]{40,64}$`)
	toolchainPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
)

type artifactSpec struct {
	Platform     string
	Architecture string
	Format       string
	Name         string
}

var artifactSpecs = []artifactSpec{
	{Platform: "darwin", Architecture: "arm64", Format: "pkg", Name: "pb-darwin-arm64.pkg"},
	{Platform: "linux", Architecture: "amd64", Format: "elf", Name: "pb-linux-amd64"},
	{Platform: "linux", Architecture: "arm64", Format: "elf", Name: "pb-linux-arm64"},
	{Platform: "windows", Architecture: "amd64", Format: "pe", Name: "pb-windows-amd64.exe"},
	{Platform: "windows", Architecture: "arm64", Format: "pe", Name: "pb-windows-arm64.exe"},
}

// Artifact is the immutable identity of one native release asset. Its fields
// intentionally mirror the signed TUF target and release-index coordinates.
type Artifact struct {
	Name         string `json:"name"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	Length       int64  `json:"length"`
	SHA256       string `json:"sha256"`
}

// Manifest is reproducible: it contains no wall-clock field or local path.
// The manifest digest is referenced by the deployment plan and can therefore
// be checked against the exact artifact set before TUF publication.
type Manifest struct {
	Schema       string     `json:"schema"`
	Version      string     `json:"version"`
	SourceCommit string     `json:"source_commit"`
	Toolchain    string     `json:"toolchain"`
	Artifacts    []Artifact `json:"artifacts"`
}

func (m Manifest) Validate() error {
	if m.Schema != ManifestSchema || !releasepolicy.IsVersion(m.Version) || !commitPattern.MatchString(m.SourceCommit) || !toolchainPattern.MatchString(m.Toolchain) || len(m.Artifacts) != len(artifactSpecs) {
		return ErrInvalidManifest
	}
	for index, artifact := range m.Artifacts {
		spec := artifactSpecs[index]
		if artifact.Name != spec.Name || artifact.Platform != spec.Platform || artifact.Architecture != spec.Architecture || artifact.Format != spec.Format || artifact.Length < 1 || artifact.Length > MaxArtifactBytes || !releasepolicy.IsDigest(artifact.SHA256) {
			return ErrInvalidManifest
		}
	}
	return nil
}

func (m Manifest) Bytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (m Manifest) SHA256() (string, error) {
	body, err := m.Bytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// BuildManifest reads exactly the five canonical release files. It rejects
// symlinks, directories, extra files, and a file that changes while hashing.
func BuildManifest(version, sourceCommit, toolchain, artifactDirectory string) (Manifest, error) {
	if !absoluteCleanDirectory(artifactDirectory) || !releasepolicy.IsVersion(version) || !commitPattern.MatchString(sourceCommit) || !toolchainPattern.MatchString(toolchain) {
		return Manifest{}, ErrInvalidManifest
	}
	entries, err := os.ReadDir(artifactDirectory)
	if err != nil {
		return Manifest{}, err
	}
	if len(entries) != len(artifactSpecs) {
		return Manifest{}, ErrInvalidManifest
	}
	artifacts := make([]Artifact, 0, len(artifactSpecs))
	for _, spec := range artifactSpecs {
		info, err := os.Lstat(filepath.Join(artifactDirectory, spec.Name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > MaxArtifactBytes {
			return Manifest{}, ErrInvalidManifest
		}
		length, digest, err := hashRegularFile(filepath.Join(artifactDirectory, spec.Name), MaxArtifactBytes)
		if err != nil || length != info.Size() {
			return Manifest{}, ErrInvalidManifest
		}
		artifacts = append(artifacts, Artifact{Name: spec.Name, Platform: spec.Platform, Architecture: spec.Architecture, Format: spec.Format, Length: length, SHA256: digest})
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return Manifest{}, ErrInvalidManifest
		}
		known := false
		for _, spec := range artifactSpecs {
			if entry.Name() == spec.Name {
				known = true
				break
			}
		}
		if !known {
			return Manifest{}, ErrInvalidManifest
		}
	}
	return NewManifest(version, sourceCommit, toolchain, artifacts)
}

// NewManifest validates a manifest assembled from already-hashed release
// artifacts. The TUF publisher uses this when the artifact staging directory
// also contains platform qualification evidence that is intentionally not a
// release target.
func NewManifest(version, sourceCommit, toolchain string, artifacts []Artifact) (Manifest, error) {
	manifest := Manifest{Schema: ManifestSchema, Version: version, SourceCommit: sourceCommit, Toolchain: toolchain, Artifacts: append([]Artifact(nil), artifacts...)}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifyManifest(manifest Manifest, artifactDirectory string) error {
	if err := manifest.Validate(); err != nil || !absoluteCleanDirectory(artifactDirectory) {
		return ErrInvalidManifest
	}
	entries, err := os.ReadDir(artifactDirectory)
	if err != nil || len(entries) != len(manifest.Artifacts) {
		return ErrInvalidManifest
	}
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(artifactDirectory, artifact.Name)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != artifact.Length {
			return ErrInvalidManifest
		}
		length, digest, readErr := hashRegularFile(path, MaxArtifactBytes)
		if readErr != nil || length != artifact.Length || digest != artifact.SHA256 {
			return ErrInvalidManifest
		}
	}
	return nil
}

func LoadManifest(path string) (Manifest, error) {
	body, err := readBoundedJSON(path, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := decodeStrict(body, &manifest); err != nil || manifest.Validate() != nil {
		return Manifest{}, ErrInvalidManifest
	}
	return manifest, nil
}

type Cohort = releasepolicy.Cohort
type CanaryPolicy = releasepolicy.CanaryPolicy
type ActivationPolicy = releasepolicy.ActivationPolicy
type SecurityDeferral = releasepolicy.SecurityDeferral
type RollbackPolicy = releasepolicy.RollbackPolicy
type Plan = releasepolicy.Plan
type DeferralRequest = releasepolicy.DeferralRequest
type Deferral = releasepolicy.Deferral

// ValidatePlanAgainstManifest verifies both the signed policy identity and
// complete coverage of the canonical native artifact set.
func ValidatePlanAgainstManifest(plan Plan, manifest Manifest) error {
	if manifest.Validate() != nil {
		return ErrInvalidPlan
	}
	digest, err := manifest.SHA256()
	if err != nil || plan.ValidateAgainst(manifest.Version, digest) != nil {
		return ErrInvalidPlan
	}
	for _, spec := range artifactSpecs {
		covered := false
		for _, cohort := range plan.Cohorts {
			if cohort.Platform == spec.Platform && cohort.Architecture == spec.Architecture {
				covered = true
				break
			}
		}
		if !covered {
			return ErrInvalidPlan
		}
	}
	return nil
}

func LoadPlan(path string) (Plan, error) {
	body, err := readBoundedJSON(path, MaxPlanBytes)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if err := decodeStrict(body, &plan); err != nil || plan.Validate() != nil {
		return Plan{}, ErrInvalidPlan
	}
	return plan, nil
}

func DefaultPlan(manifest Manifest, policyRevision uint64, severity, seed string) (Plan, error) {
	digest, err := manifest.SHA256()
	if err != nil || !releasepolicy.IsIdentifier(seed) || policyRevision == 0 {
		return Plan{}, ErrInvalidPlan
	}
	targets := make([]releasepolicy.PlatformTarget, 0, len(artifactSpecs))
	for _, spec := range artifactSpecs {
		targets = append(targets, releasepolicy.PlatformTarget{Platform: spec.Platform, Architecture: spec.Architecture})
	}
	plan, err := releasepolicy.Default(manifest.Version, digest, policyRevision, severity, seed, targets)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	if err := ValidatePlanAgainstManifest(plan, manifest); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

type DeploymentState string

const (
	StateScheduled           DeploymentState = "scheduled"
	StateDownloading         DeploymentState = "downloading"
	StateCandidateValidating DeploymentState = "candidate_validating"
	StateCandidateReady      DeploymentState = "candidate_ready"
	StateDraining            DeploymentState = "draining"
	StateActivating          DeploymentState = "activating"
	StateStability           DeploymentState = "stability"
	StateRollingBack         DeploymentState = "rolling_back"
	StateCommitted           DeploymentState = "committed"
	StateRolledBack          DeploymentState = "rolled_back"
	StateQuarantined         DeploymentState = "quarantined"
	StateBlocked             DeploymentState = "blocked"
)

type State struct {
	Schema          string          `json:"schema"`
	TransactionID   string          `json:"transaction_id"`
	Version         string          `json:"version"`
	ManifestSHA256  string          `json:"manifest_sha256"`
	PreviousVersion string          `json:"previous_version"`
	State           DeploymentState `json:"state"`
	Failure         string          `json:"failure,omitempty"`
	Quarantined     bool            `json:"quarantined"`
	Revoked         bool            `json:"revoked"`
	UpdatedAt       time.Time       `json:"updated_at"`
	QuarantineUntil *time.Time      `json:"quarantine_until,omitempty"`
}

func NewState(plan Plan, transactionID, previousVersion string, now time.Time) (State, error) {
	if plan.Validate() != nil || !releasepolicy.IsIdentifier(transactionID) || !releasepolicy.IsVersion(previousVersion) || now.IsZero() {
		return State{}, ErrInvalidState
	}
	return State{Schema: StateSchema, TransactionID: transactionID, Version: plan.Version, ManifestSHA256: plan.ManifestSHA256, PreviousVersion: previousVersion, State: StateScheduled, UpdatedAt: now.UTC()}, nil
}

type Event string

const (
	EventDownloadStarted     Event = "download_started"
	EventCandidateValidating Event = "candidate_validating"
	EventCandidateReady      Event = "candidate_ready"
	EventCanaryPassed        Event = "canary_passed"
	EventCanaryFailed        Event = "canary_failed"
	EventDrainCompleted      Event = "drain_completed"
	EventDrainFailed         Event = "drain_failed"
	EventActivationStarted   Event = "activation_started"
	EventActivationPassed    Event = "activation_passed"
	EventActivationFailed    Event = "activation_failed"
	EventStabilityPassed     Event = "stability_passed"
	EventStabilityFailed     Event = "stability_failed"
	EventRollbackStarted     Event = "rollback_started"
	EventRollbackPassed      Event = "rollback_passed"
	EventRollbackFailed      Event = "rollback_failed"
	EventRevoke              Event = "revoke"
)

// Advance is the release coordinator state machine. All failure paths after
// activation enter rollback; failed rollback is blocked and remains
// quarantined, so an operator cannot accidentally retry a bad artifact.
func Advance(state State, event Event, reason string, now time.Time, quarantineSeconds uint32) (State, error) {
	if err := state.Validate(); err != nil || now.IsZero() || len(reason) > 256 || strings.ContainsAny(reason, "\x00\r\n") {
		return State{}, ErrInvalidState
	}
	next := state
	next.UpdatedAt = now.UTC()
	if reason != "" {
		next.Failure = reason
	}
	transition := func(value DeploymentState) { next.State = value }
	switch event {
	case EventDownloadStarted:
		if state.State != StateScheduled {
			return State{}, ErrInvalidEvent
		}
		transition(StateDownloading)
	case EventCandidateReady:
		if state.State != StateCandidateValidating {
			return State{}, ErrInvalidEvent
		}
		transition(StateCandidateReady)
	case EventCandidateValidating:
		if state.State != StateDownloading {
			return State{}, ErrInvalidEvent
		}
		transition(StateCandidateValidating)
	case EventCanaryPassed:
		if state.State != StateCandidateReady {
			return State{}, ErrInvalidEvent
		}
		transition(StateDraining)
	case EventCanaryFailed, EventDrainFailed:
		if event == EventCanaryFailed && state.State != StateCandidateReady || event == EventDrainFailed && state.State != StateDraining {
			return State{}, ErrInvalidEvent
		}
		transition(StateQuarantined)
		next.Quarantined = true
	case EventDrainCompleted:
		if state.State != StateDraining {
			return State{}, ErrInvalidEvent
		}
		transition(StateActivating)
	case EventActivationStarted:
		if state.State != StateActivating {
			return State{}, ErrInvalidEvent
		}
		transition(StateActivating)
	case EventActivationPassed:
		if state.State != StateActivating {
			return State{}, ErrInvalidEvent
		}
		transition(StateStability)
	case EventActivationFailed, EventStabilityFailed:
		if event == EventActivationFailed && state.State != StateActivating || event == EventStabilityFailed && state.State != StateStability {
			return State{}, ErrInvalidEvent
		}
		transition(StateRollingBack)
	case EventStabilityPassed:
		if state.State != StateStability {
			return State{}, ErrInvalidEvent
		}
		transition(StateCommitted)
	case EventRollbackStarted:
		if state.State != StateRollingBack {
			return State{}, ErrInvalidEvent
		}
		transition(StateRollingBack)
	case EventRollbackPassed:
		if state.State != StateRollingBack {
			return State{}, ErrInvalidEvent
		}
		transition(StateRolledBack)
		next.Quarantined = true
	case EventRollbackFailed:
		if state.State != StateRollingBack {
			return State{}, ErrInvalidEvent
		}
		transition(StateBlocked)
		next.Quarantined = true
	case EventRevoke:
		if state.State == StateCommitted {
			return State{}, ErrInvalidEvent
		}
		transition(StateQuarantined)
		next.Quarantined, next.Revoked = true, true
	default:
		return State{}, ErrInvalidEvent
	}
	if next.Quarantined {
		if quarantineSeconds == 0 || quarantineSeconds > 30*24*60*60 {
			return State{}, ErrInvalidState
		}
		expires := next.UpdatedAt.Add(time.Duration(quarantineSeconds) * time.Second)
		next.QuarantineUntil = &expires
	}
	return next, nil
}

func (s State) Validate() error {
	if s.Schema != StateSchema || !releasepolicy.IsIdentifier(s.TransactionID) || !releasepolicy.IsVersion(s.Version) || !releasepolicy.IsDigest(s.ManifestSHA256) || !releasepolicy.IsVersion(s.PreviousVersion) || !knownState(s.State) || s.UpdatedAt.IsZero() || len(s.Failure) > 256 || strings.ContainsAny(s.Failure, "\x00\r\n") {
		return ErrInvalidState
	}
	if s.Quarantined && s.QuarantineUntil == nil || !s.Quarantined && s.QuarantineUntil != nil || s.QuarantineUntil != nil && !s.QuarantineUntil.After(s.UpdatedAt) {
		return ErrInvalidState
	}
	if s.Revoked && !s.Quarantined {
		return ErrInvalidState
	}
	return nil
}

func (s State) Bytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func LoadState(path string) (State, error) {
	body, err := readBoundedJSON(path, MaxStateBytes)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := decodeStrict(body, &state); err != nil || state.Validate() != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func WriteFile(path string, body []byte, max int64) error {
	if !absoluteCleanPath(path) || len(body) == 0 || int64(len(body)) > max {
		return ErrUnsafePath
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=release-plan reason=same-directory-release-metadata-staging
	temporary, err := os.CreateTemp(directory, ".paperboat-release-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=release-plan reason=same-directory-synced-release-metadata-staging
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func WriteManifest(path string, manifest Manifest) error {
	body, err := manifest.Bytes()
	if err != nil {
		return err
	}
	return WriteFile(path, body, MaxManifestBytes)
}

func WritePlan(path string, plan Plan) error {
	body, err := plan.Bytes()
	if err != nil {
		return err
	}
	return WriteFile(path, body, MaxPlanBytes)
}

func WriteState(path string, state State) error {
	body, err := state.Bytes()
	if err != nil {
		return err
	}
	return WriteFile(path, body, MaxStateBytes)
}

func readBoundedJSON(path string, max int64) ([]byte, error) {
	if !absoluteCleanPath(path) {
		return nil, ErrUnsafePath
	}
	return readRegularFile(path, max)
}

func readRegularFile(path string, max int64) ([]byte, error) {
	file, info, err := openRegularFile(path, max)
	if err != nil {
		return nil, ErrUnsafePath
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(body)) != info.Size() || int64(len(body)) > max {
		return nil, ErrUnsafePath
	}
	if changed, err := regularFileChanged(file, info); err != nil || changed {
		return nil, ErrUnsafePath
	}
	return body, nil
}

func hashRegularFile(path string, max int64) (int64, string, error) {
	file, info, err := openRegularFile(path, max)
	if err != nil {
		return 0, "", ErrInvalidManifest
	}
	defer file.Close()
	hash := sha256.New()
	length, err := io.Copy(hash, io.LimitReader(file, max+1))
	if err != nil || length != info.Size() || length > max {
		return 0, "", ErrInvalidManifest
	}
	if changed, err := regularFileChanged(file, info); err != nil || changed {
		return 0, "", ErrInvalidManifest
	}
	return length, hex.EncodeToString(hash.Sum(nil)), nil
}

func openRegularFile(path string, max int64) (*os.File, os.FileInfo, error) {
	if !absoluteCleanPath(path) || max < 1 {
		return nil, nil, ErrUnsafePath
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() < 1 || pathInfo.Size() > max {
		return nil, nil, ErrUnsafePath
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fileInfo, statErr := file.Stat()
	if statErr != nil || !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) || fileInfo.Size() < 1 || fileInfo.Size() > max {
		_ = file.Close()
		return nil, nil, ErrUnsafePath
	}
	return file, fileInfo, nil
}

func regularFileChanged(file *os.File, before os.FileInfo) (bool, error) {
	after, err := file.Stat()
	if err != nil {
		return true, err
	}
	return !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()), nil
}

func decodeStrict(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func absoluteCleanDirectory(path string) bool {
	return absoluteCleanPath(path) && func() bool {
		info, err := os.Lstat(path)
		return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
	}()
}

func absoluteCleanPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func knownState(state DeploymentState) bool {
	switch state {
	case StateScheduled, StateDownloading, StateCandidateValidating, StateCandidateReady, StateDraining, StateActivating, StateStability, StateRollingBack, StateCommitted, StateRolledBack, StateQuarantined, StateBlocked:
		return true
	default:
		return false
	}
}

// ArtifactSpecs returns a copy for release workflow tests and callers that
// need to enumerate the exact publication set without inventing a new target.
func ArtifactSpecs() []Artifact {
	result := make([]Artifact, len(artifactSpecs))
	for index, spec := range artifactSpecs {
		result[index] = Artifact{Name: spec.Name, Platform: spec.Platform, Architecture: spec.Architecture, Format: spec.Format}
	}
	return result
}

func (m Manifest) Artifact(name string) (Artifact, bool) {
	for _, artifact := range m.Artifacts {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return Artifact{}, false
}
