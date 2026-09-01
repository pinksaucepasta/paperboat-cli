// Package releasepolicy owns the signed, static deployment-policy wire model.
//
// TUF publishes this model together with the artifact manifest digest. Runtime
// code resolves machine, session, configuration, and route generations at
// each activation gate; those live bindings deliberately do not belong here.
package releasepolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	PlanSchema     = "paperboat.release-deployment/v1"
	DeferralSchema = "paperboat.release-deferral/v1"

	RolloutStateActive      = "active"
	RolloutStatePaused      = "paused"
	RolloutStateQuarantined = "quarantined"

	MaxCohortDelaySeconds  uint32 = 30 * 24 * 60 * 60
	MaxRoutineDeferralSec  uint32 = 7 * 24 * 60 * 60
	MaxSecurityDeferralSec uint32 = 24 * 60 * 60
	MaxCriticalDeferralSec uint32 = 60 * 60
)

var ErrInvalidPolicy = errors.New("invalid release deployment policy")

var (
	releaseVersionPattern = regexp.MustCompile(`^20[0-9]{2}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.(0|[1-9][0-9]*)$`)
	digestPattern         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// IsIdentifier reports whether value is safe for a signed policy identity.
func IsIdentifier(value string) bool { return identifierPattern.MatchString(value) }

// IsDigest reports whether value is a lowercase SHA-256 digest.
func IsDigest(value string) bool { return digestPattern.MatchString(value) }

// IsVersion reports whether value is a calendar release version.
func IsVersion(value string) bool {
	if !releaseVersionPattern.MatchString(value) {
		return false
	}
	date := strings.ReplaceAll(value[:10], ".", "-")
	parsed, err := time.Parse("2006-01-02", date)
	return err == nil && parsed.Format("2006-01-02") == date
}

// IsPlatform reports whether the release has a supported native target.
func IsPlatform(platform, architecture string) bool {
	return platform == "darwin" && architecture == "arm64" ||
		platform == "linux" && (architecture == "amd64" || architecture == "arm64") ||
		platform == "windows" && (architecture == "amd64" || architecture == "arm64")
}

// AllowedRollbackTrigger reports whether trigger is part of the v1 failure
// vocabulary. Unknown triggers are rejected instead of being silently ignored.
func AllowedRollbackTrigger(trigger string) bool {
	switch trigger {
	case "crash_loop", "watchdog_failure", "connector_authentication", "snapshot_apply", "edge_canary", "route_protocol", "state_migration", "readiness_regression":
		return true
	default:
		return false
	}
}

type Cohort struct {
	Name           string `json:"name"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	FailureDomain  string `json:"failure_domain"`
	Percentage     uint8  `json:"percentage"`
	StartAfterSecs uint32 `json:"start_after_seconds"`
	MaxConcurrent  uint16 `json:"max_concurrent"`
}

type CanaryPolicy struct {
	Path             string `json:"path"`
	ExpectedStatus   int    `json:"expected_status"`
	TimeoutSeconds   uint32 `json:"timeout_seconds"`
	Samples          uint16 `json:"samples"`
	RequireEdge      bool   `json:"require_edge"`
	RequireConnector bool   `json:"require_connector"`
	RequireRoute     bool   `json:"require_route"`
	RequireOrigin    bool   `json:"require_origin"`
}

type ActivationPolicy struct {
	DrainTimeoutSeconds           uint32 `json:"drain_timeout_seconds"`
	StabilityWindowSeconds        uint32 `json:"stability_window_seconds"`
	StabilityProbeIntervalSeconds uint32 `json:"stability_probe_interval_seconds"`
	RollbackTimeoutSeconds        uint32 `json:"rollback_timeout_seconds"`
}

type SecurityDeferral struct {
	MaxSeconds       uint32 `json:"max_seconds"`
	RequiresApproval bool   `json:"requires_approval"`
}

type RollbackPolicy struct {
	Triggers            []string `json:"triggers"`
	QuarantineSeconds   uint32   `json:"quarantine_seconds"`
	RevokeFailedRelease bool     `json:"revoke_failed_release"`
}

// Plan is the single signed static rollout policy model shared by the
// publisher and host runtime. It contains no machine/session/route tuple.
type Plan struct {
	Schema           string           `json:"schema"`
	Version          string           `json:"version"`
	ManifestSHA256   string           `json:"manifest_sha256"`
	Channel          string           `json:"channel"`
	RolloutState     string           `json:"rollout_state"`
	Severity         string           `json:"severity"`
	PolicyRevision   uint64           `json:"policy_revision"`
	CohortSeed       string           `json:"cohort_seed"`
	Cohorts          []Cohort         `json:"cohorts"`
	Canary           CanaryPolicy     `json:"canary"`
	Activation       ActivationPolicy `json:"activation"`
	SecurityDeferral SecurityDeferral `json:"security_deferral"`
	Rollback         RollbackPolicy   `json:"rollback"`
}

// ManifestBinding is implemented by a publisher-owned artifact manifest. It
// keeps this package independent of release tooling while allowing callers to
// bind a plan to the exact version and manifest bytes.
type ManifestBinding interface {
	Validate() error
	ReleaseVersion() string
	ManifestSHA256() (string, error)
}

func (p Plan) Validate() error {
	if p.Schema != PlanSchema || !IsVersion(p.Version) || !IsDigest(p.ManifestSHA256) || p.Channel != "stable" || (p.RolloutState != RolloutStateActive && p.RolloutState != RolloutStatePaused && p.RolloutState != RolloutStateQuarantined) || p.PolicyRevision == 0 || !IsIdentifier(p.CohortSeed) || len(p.Cohorts) == 0 || len(p.Cohorts) > 256 || (p.Severity != "routine" && p.Severity != "security" && p.Severity != "critical") {
		return ErrInvalidPolicy
	}
	if p.Canary.Path == "" || len(p.Canary.Path) > 256 || !strings.HasPrefix(p.Canary.Path, "/") || strings.ContainsAny(p.Canary.Path, "\x00\r\n") || p.Canary.ExpectedStatus < 100 || p.Canary.ExpectedStatus > 599 || p.Canary.TimeoutSeconds == 0 || p.Canary.TimeoutSeconds > 60 || p.Canary.Samples == 0 || p.Canary.Samples > 1000 || !p.Canary.RequireEdge || !p.Canary.RequireConnector || !p.Canary.RequireRoute || !p.Canary.RequireOrigin {
		return ErrInvalidPolicy
	}
	if p.Activation.DrainTimeoutSeconds == 0 || p.Activation.DrainTimeoutSeconds > 120 || p.Activation.StabilityWindowSeconds == 0 || p.Activation.StabilityWindowSeconds > 24*60*60 || p.Activation.StabilityProbeIntervalSeconds == 0 || p.Activation.StabilityProbeIntervalSeconds > 60 || p.Activation.StabilityProbeIntervalSeconds > p.Activation.StabilityWindowSeconds || p.Activation.RollbackTimeoutSeconds == 0 || p.Activation.RollbackTimeoutSeconds > 120 {
		return ErrInvalidPolicy
	}
	maxDeferral := MaxRoutineDeferralSec
	if p.Severity == "security" {
		maxDeferral = MaxSecurityDeferralSec
	}
	if p.Severity == "critical" {
		maxDeferral = MaxCriticalDeferralSec
	}
	if p.SecurityDeferral.MaxSeconds == 0 || p.SecurityDeferral.MaxSeconds > maxDeferral || p.SecurityDeferral.RequiresApproval != (p.Severity != "routine") {
		return ErrInvalidPolicy
	}
	if p.Rollback.QuarantineSeconds == 0 || p.Rollback.QuarantineSeconds > 30*24*60*60 || len(p.Rollback.Triggers) == 0 || len(p.Rollback.Triggers) > 8 {
		return ErrInvalidPolicy
	}
	seenTriggers := make(map[string]struct{}, len(p.Rollback.Triggers))
	for _, trigger := range p.Rollback.Triggers {
		if !AllowedRollbackTrigger(trigger) {
			return ErrInvalidPolicy
		}
		if _, duplicate := seenTriggers[trigger]; duplicate {
			return ErrInvalidPolicy
		}
		seenTriggers[trigger] = struct{}{}
	}
	seen := make(map[string]struct{}, len(p.Cohorts))
	coverage := make(map[string][]Cohort)
	for _, cohort := range p.Cohorts {
		if !IsIdentifier(cohort.Name) || !IsPlatform(cohort.Platform, cohort.Architecture) || cohort.FailureDomain == "" || cohort.FailureDomain != "*" && !IsIdentifier(cohort.FailureDomain) || len(cohort.FailureDomain) > 128 || strings.ContainsAny(cohort.FailureDomain, "\x00\r\n") || cohort.MaxConcurrent == 0 || cohort.Percentage > 100 || cohort.StartAfterSecs > MaxCohortDelaySeconds {
			return ErrInvalidPolicy
		}
		key := cohort.Platform + "\x00" + cohort.Architecture + "\x00" + cohort.FailureDomain
		fullKey := key + "\x00" + cohort.Name
		if _, duplicate := seen[fullKey]; duplicate {
			return ErrInvalidPolicy
		}
		seen[fullKey] = struct{}{}
		coverage[key] = append(coverage[key], cohort)
	}
	for _, waves := range coverage {
		sort.SliceStable(waves, func(i, j int) bool { return waves[i].StartAfterSecs < waves[j].StartAfterSecs })
		if waves[0].StartAfterSecs != 0 || waves[len(waves)-1].Percentage != 100 {
			return ErrInvalidPolicy
		}
		for index := 1; index < len(waves); index++ {
			if waves[index].StartAfterSecs <= waves[index-1].StartAfterSecs || waves[index].Percentage < waves[index-1].Percentage {
				return ErrInvalidPolicy
			}
		}
	}
	return nil
}

// ValidateAgainst binds the static policy to the exact release identity. The
// caller validates artifact-platform coverage because that belongs to its
// manifest model, not this production-owned wire package.
func (p Plan) ValidateAgainst(version, manifestSHA256 string) error {
	if err := p.Validate(); err != nil || p.Version != version || p.ManifestSHA256 != manifestSHA256 {
		return ErrInvalidPolicy
	}
	return nil
}

// SupportsPlatform reports whether this plan has at least one cohort for the
// exact platform and architecture. It deliberately does not inspect the
// caller's failure domain or the current rollout wave; those are runtime
// eligibility decisions.
func (p Plan) SupportsPlatform(platform, architecture string) bool {
	if p.Validate() != nil || !IsPlatform(platform, architecture) {
		return false
	}
	for _, cohort := range p.Cohorts {
		if cohort.Platform == platform && cohort.Architecture == architecture {
			return true
		}
	}
	return false
}

func (p Plan) Bytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (p Plan) SHA256() (string, error) {
	body, err := p.Bytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// PlanSHA256 is the explicit name used by TUF custom metadata and runtime
// activation inputs. It is intentionally identical to SHA256 over canonical
// plan bytes.
func (p Plan) PlanSHA256() (string, error) { return p.SHA256() }

// CohortFor deterministically selects the newest eligible wave for a target.
// Exact failure-domain cohorts win ties over the wildcard cohort so an
// operator can safely carve out a domain without relying on input ordering.
func (p Plan) CohortFor(machineID, platform, architecture, failureDomain string, elapsed time.Duration) (string, bool) {
	return p.cohortFor(machineID, platform, architecture, failureDomain, elapsed, false)
}

// CohortForManual selects the same deterministic cohort as CohortFor while
// ignoring only the wave start time. It still enforces rollout state, exact
// platform/architecture, failure-domain matching, and the cohort percentage.
// Manual update must never become a bypass for a paused, quarantined, or
// revoked release.
func (p Plan) CohortForManual(machineID, platform, architecture, failureDomain string) (string, bool) {
	return p.cohortFor(machineID, platform, architecture, failureDomain, 0, true)
}

func (p Plan) cohortFor(machineID, platform, architecture, failureDomain string, elapsed time.Duration, bypassTiming bool) (string, bool) {
	if p.Validate() != nil || p.RolloutState != RolloutStateActive || !IsIdentifier(machineID) || !IsPlatform(platform, architecture) || !IsIdentifier(failureDomain) || elapsed < 0 {
		return "", false
	}
	digest := sha256.Sum256([]byte(p.CohortSeed + "\x00" + machineID + "\x00" + platform + "\x00" + architecture + "\x00" + failureDomain))
	bucket := binary.BigEndian.Uint64(digest[:8]) % 10000
	var selected Cohort
	found := false
	for _, cohort := range p.Cohorts {
		if cohort.Platform != platform || cohort.Architecture != architecture || cohort.FailureDomain != "*" && cohort.FailureDomain != failureDomain || !bypassTiming && elapsed < time.Duration(cohort.StartAfterSecs)*time.Second || bucket >= uint64(cohort.Percentage)*100 {
			continue
		}
		if !found || cohort.StartAfterSecs > selected.StartAfterSecs || cohort.StartAfterSecs == selected.StartAfterSecs && selected.FailureDomain == "*" && cohort.FailureDomain == failureDomain {
			selected, found = cohort, true
		}
	}
	if !found {
		return "", false
	}
	return selected.Name, true
}

func (p Plan) String() string {
	return fmt.Sprintf("%s %s policy=%d severity=%s", p.Schema, p.Version, p.PolicyRevision, p.Severity)
}

// PlatformTarget identifies a release platform and architecture.
type PlatformTarget struct {
	Platform     string
	Architecture string
}

func Default(version, manifestSHA256 string, policyRevision uint64, severity, seed string, platforms []PlatformTarget) (Plan, error) {
	if !IsVersion(version) || !IsDigest(manifestSHA256) || !IsIdentifier(seed) || policyRevision == 0 {
		return Plan{}, ErrInvalidPolicy
	}
	deferral := MaxRoutineDeferralSec
	if severity == "security" {
		deferral = MaxSecurityDeferralSec
	}
	if severity == "critical" {
		deferral = MaxCriticalDeferralSec
	}
	cohorts := make([]Cohort, 0, len(platforms)*3)
	seenPlatforms := make(map[string]struct{}, len(platforms))
	for _, target := range platforms {
		if !IsPlatform(target.Platform, target.Architecture) {
			return Plan{}, ErrInvalidPolicy
		}
		key := target.Platform + "\x00" + target.Architecture
		if _, duplicate := seenPlatforms[key]; duplicate {
			return Plan{}, ErrInvalidPolicy
		}
		seenPlatforms[key] = struct{}{}
		for _, wave := range []struct {
			name  string
			pct   uint8
			delay uint32
			max   uint16
		}{{"canary", 1, 0, 1}, {"early", 10, 60 * 60, 10}, {"general", 100, 2 * 60 * 60, 100}} {
			cohorts = append(cohorts, Cohort{Name: wave.name, Platform: target.Platform, Architecture: target.Architecture, FailureDomain: "*", Percentage: wave.pct, StartAfterSecs: wave.delay, MaxConcurrent: wave.max})
		}
	}
	plan := Plan{
		Schema: PlanSchema, Version: version, ManifestSHA256: manifestSHA256, Channel: "stable", RolloutState: RolloutStateActive, Severity: severity, PolicyRevision: policyRevision, CohortSeed: seed,
		Cohorts:          cohorts,
		Canary:           CanaryPolicy{Path: "/healthz", ExpectedStatus: 200, TimeoutSeconds: 10, Samples: 3, RequireEdge: true, RequireConnector: true, RequireRoute: true, RequireOrigin: true},
		Activation:       ActivationPolicy{DrainTimeoutSeconds: 30, StabilityWindowSeconds: 10 * 60, StabilityProbeIntervalSeconds: 30, RollbackTimeoutSeconds: 60},
		SecurityDeferral: SecurityDeferral{MaxSeconds: deferral, RequiresApproval: severity != "routine"},
		Rollback:         RollbackPolicy{Triggers: []string{"crash_loop", "watchdog_failure", "connector_authentication", "snapshot_apply", "edge_canary", "route_protocol", "state_migration", "readiness_regression"}, QuarantineSeconds: 7 * 24 * 60 * 60, RevokeFailedRelease: true},
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

type DeferralRequest struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	PlanSHA256     string `json:"plan_sha256,omitempty"`
	RequestedSecs  uint32 `json:"requested_seconds"`
	Reason         string `json:"reason"`
	ApprovedBy     string `json:"approved_by,omitempty"`
}

type Deferral struct {
	Schema         string    `json:"schema"`
	Version        string    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	PlanSHA256     string    `json:"plan_sha256"`
	GrantedSecs    uint32    `json:"granted_seconds"`
	GrantedAt      time.Time `json:"granted_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ApprovedBy     string    `json:"approved_by,omitempty"`
}

// Validate checks the durable deferral envelope without binding it to a
// particular release. The plan-specific severity maximum is enforced by
// Plan.DeferralActive.
func (d Deferral) Validate() error {
	if d.Schema != DeferralSchema || !IsVersion(d.Version) || !IsDigest(d.ManifestSHA256) || !IsDigest(d.PlanSHA256) || d.GrantedSecs == 0 || d.GrantedSecs > MaxRoutineDeferralSec || d.ExpiresAt.IsZero() || d.GrantedAt.IsZero() || !d.ExpiresAt.After(d.GrantedAt) || !d.ExpiresAt.Equal(d.GrantedAt.Add(time.Duration(d.GrantedSecs)*time.Second)) || d.ApprovedBy != "" && !IsIdentifier(d.ApprovedBy) {
		return ErrInvalidPolicy
	}
	return nil
}

func (d Deferral) Bytes() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (p Plan) GrantDeferral(request DeferralRequest, now time.Time) (Deferral, error) {
	planDigest, digestErr := p.PlanSHA256()
	if p.Validate() != nil || digestErr != nil || request.Version != p.Version || request.ManifestSHA256 != "" && request.ManifestSHA256 != p.ManifestSHA256 || request.PlanSHA256 != "" && request.PlanSHA256 != planDigest || request.RequestedSecs == 0 || request.RequestedSecs > p.SecurityDeferral.MaxSeconds || strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 256 || strings.ContainsAny(request.Reason, "\x00\r\n") || request.ApprovedBy != "" && !IsIdentifier(request.ApprovedBy) || p.SecurityDeferral.RequiresApproval && request.ApprovedBy == "" || now.IsZero() {
		return Deferral{}, ErrInvalidPolicy
	}
	now = now.UTC()
	return Deferral{Schema: DeferralSchema, Version: request.Version, ManifestSHA256: p.ManifestSHA256, PlanSHA256: planDigest, GrantedSecs: request.RequestedSecs, GrantedAt: now, ExpiresAt: now.Add(time.Duration(request.RequestedSecs) * time.Second), ApprovedBy: request.ApprovedBy}, nil
}

// DeferralActive validates a persisted deferral against this exact signed
// plan. It returns true only while the grant is active. An expired but valid
// grant is safe to ignore and allows normal eligibility to resume; malformed,
// future-dated, overlong, or differently bound grants fail closed.
func (p Plan) DeferralActive(deferral Deferral, now time.Time) (bool, error) {
	if p.Validate() != nil || now.IsZero() {
		return false, ErrInvalidPolicy
	}
	if err := deferral.Validate(); err != nil {
		return false, err
	}
	planDigest, err := p.PlanSHA256()
	if err != nil || deferral.Version != p.Version || deferral.ManifestSHA256 != p.ManifestSHA256 || deferral.PlanSHA256 != planDigest || deferral.GrantedSecs > p.SecurityDeferral.MaxSeconds || deferral.GrantedAt.After(now) || p.SecurityDeferral.RequiresApproval && !IsIdentifier(deferral.ApprovedBy) {
		return false, ErrInvalidPolicy
	}
	return now.Before(deferral.ExpiresAt), nil
}
