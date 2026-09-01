// Package releaseindex validates the signed, fixed-name TUF release selector.
package releaseindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

const SchemaV1 = "paperboat.release-index/v1"

var ErrInvalid = errors.New("signed release index is invalid")
var versionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)
var dependencyVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
var valuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$`)
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

type Index struct {
	Schema                 string              `json:"schema"`
	ReleaseID              string              `json:"release_id"`
	Version                string              `json:"version"`
	Channel                string              `json:"channel"`
	Severity               string              `json:"severity"`
	CreatedAt              time.Time           `json:"created_at"`
	Platform               string              `json:"platform"`
	Architecture           string              `json:"architecture"`
	BinaryFormat           string              `json:"binary_format"`
	Targets                []Target            `json:"targets"`
	HostdAPIMin            uint16              `json:"hostd_api_min"`
	HostdAPIMax            uint16              `json:"hostd_api_max"`
	RuntimeAPIMin          uint16              `json:"runtime_api_min"`
	RuntimeAPIMax          uint16              `json:"runtime_api_max"`
	MinimumVersion         string              `json:"minimum_permitted_version,omitempty"`
	RevokedVersions        []string            `json:"revoked_versions,omitempty"`
	RolloutPolicyRevision  uint64              `json:"rollout_policy_revision"`
	SupervisorMaintenance  bool                `json:"supervisor_maintenance_required"`
	ManifestSHA256         string              `json:"manifest_sha256"`
	DeploymentPlanSHA256   string              `json:"deployment_plan_sha256"`
	DeploymentPlan         *releasepolicy.Plan `json:"deployment_plan"`
	Revoked                bool                `json:"revoked,omitempty"`
	Stability              string              `json:"stability,omitempty"`
	NativeTested           bool                `json:"native_tested,omitempty"`
	TestedWindowsBuilds    []string            `json:"tested_windows_builds,omitempty"`
	OpenSSHPackageID       string              `json:"openssh_package_id,omitempty"`
	OpenSSHApprovedVersion string              `json:"openssh_approved_version,omitempty"`
}

type Target struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	AssetName    string `json:"asset_name"`
	Repository   string `json:"repository"`
	DownloadURL  string `json:"download_url"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
}

func Decode(reader io.Reader, now time.Time) (Index, error) {
	if reader == nil {
		return Index{}, ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 64<<10+1))
	decoder.DisallowUnknownFields()
	var index Index
	var extra any
	if decoder.Decode(&index) != nil || decoder.Decode(&extra) != io.EOF || index.Validate(now) != nil {
		return Index{}, ErrInvalid
	}
	return index, nil
}

func (i Index) Validate(now time.Time) error {
	if i.Schema != SchemaV1 || !valuePattern.MatchString(i.ReleaseID) || !versionPattern.MatchString(i.Version) || i.Channel != expectedChannel(i.Platform, i.Architecture) || i.CreatedAt.IsZero() || i.RolloutPolicyRevision == 0 {
		return ErrInvalid
	}
	if i.Severity != "routine" && i.Severity != "security" && i.Severity != "critical" {
		return ErrInvalid
	}
	if !validPlatform(i.Platform, i.Architecture, i.BinaryFormat) || i.HostdAPIMin == 0 || i.HostdAPIMin > i.HostdAPIMax || i.RuntimeAPIMin == 0 || i.RuntimeAPIMin > i.RuntimeAPIMax {
		return ErrInvalid
	}
	if i.Platform == "windows" {
		if i.OpenSSHPackageID != "Microsoft.OpenSSH.Preview" || !dependencyVersionPattern.MatchString(i.OpenSSHApprovedVersion) || len(i.TestedWindowsBuilds) == 0 || len(i.TestedWindowsBuilds) > 16 {
			return ErrInvalid
		}
		for _, build := range i.TestedWindowsBuilds {
			if !valuePattern.MatchString(build) {
				return ErrInvalid
			}
		}
		if i.Stability != "stable" || !i.NativeTested {
			return ErrInvalid
		}
	} else if i.Stability != "" || i.NativeTested || len(i.TestedWindowsBuilds) != 0 || i.OpenSSHPackageID != "" || i.OpenSSHApprovedVersion != "" {
		return ErrInvalid
	}
	if i.MinimumVersion != "" && !releasepolicy.IsVersion(i.MinimumVersion) {
		return ErrInvalid
	}
	revoked := map[string]bool{}
	for _, version := range i.RevokedVersions {
		if !versionPattern.MatchString(version) || revoked[version] {
			return ErrInvalid
		}
		revoked[version] = true
	}
	if len(i.Targets) != 1 {
		return ErrInvalid
	}
	target := i.Targets[0]
	assetName := AssetName(i.Platform, i.Architecture)
	if target.Component != "pb" || target.TargetPath != assetName || target.AssetName != assetName || !validRepository(target.Repository) || target.Platform != i.Platform || target.Architecture != i.Architecture || target.BinaryFormat != i.BinaryFormat || target.Length < 1 || target.Length > 512<<20 || len(target.SHA256) != sha256.Size*2 || !lowerHex(target.SHA256) || !ValidDownloadURL(target.DownloadURL, target.Repository, i.Version, assetName) {
		return ErrInvalid
	}
	if now.IsZero() || i.CreatedAt.After(now.Add(5*time.Minute)) || !releasepolicy.IsDigest(i.ManifestSHA256) || !releasepolicy.IsDigest(i.DeploymentPlanSHA256) || i.DeploymentPlan == nil || i.DeploymentPlan.ValidateAgainst(i.Version, i.ManifestSHA256) != nil || i.RolloutPolicyRevision != i.DeploymentPlan.PolicyRevision || i.Severity != i.DeploymentPlan.Severity {
		return ErrInvalid
	}
	planDigest, err := i.DeploymentPlan.PlanSHA256()
	if err != nil || planDigest != i.DeploymentPlanSHA256 {
		return ErrInvalid
	}
	if !i.DeploymentPlan.SupportsPlatform(i.Platform, i.Architecture) {
		return ErrInvalid
	}
	return nil
}

func expectedChannel(platform, architecture string) string {
	return "stable"
}

// EligibilityInput contains the live values used to select a release. The
// failure domain is deliberately required and must come from a current
// host-local observation; callers cannot use a wildcard or omit it.
type EligibilityInput struct {
	MachineID     string
	Platform      string
	Architecture  string
	FailureDomain string
	Now           time.Time
	BypassCohort  bool
	Deferral      *releasepolicy.Deferral
}

// EligibleFor applies every runtime safety gate. Manual selection bypasses
// only cohort wave timing. Rollout state, revocation, minimum-version,
// platform/architecture, exact failure-domain matching, and active deferrals
// remain mandatory.
func (i Index) EligibleFor(input EligibilityInput) bool {
	if i.Validate(input.Now) != nil || !releasepolicy.IsIdentifier(input.MachineID) || input.Platform != i.Platform || input.Architecture != i.Architecture || !releasepolicy.IsPlatform(input.Platform, input.Architecture) || !releasepolicy.IsIdentifier(input.FailureDomain) || input.Now.Before(i.CreatedAt) || i.Revoked || versionRevoked(i.Version, i.RevokedVersions) || i.MinimumVersion != "" && compareVersion(i.Version, i.MinimumVersion) < 0 || i.DeploymentPlan.RolloutState != releasepolicy.RolloutStateActive {
		return false
	}
	if input.Deferral != nil {
		active, err := i.DeploymentPlan.DeferralActive(*input.Deferral, input.Now)
		if err != nil || active {
			return false
		}
	}
	var cohort string
	var eligible bool
	if input.BypassCohort {
		cohort, eligible = i.DeploymentPlan.CohortForManual(input.MachineID, input.Platform, input.Architecture, input.FailureDomain)
	} else {
		cohort, eligible = i.DeploymentPlan.CohortFor(input.MachineID, input.Platform, input.Architecture, input.FailureDomain, input.Now.Sub(i.CreatedAt))
	}
	return cohort != "" && eligible
}

func versionRevoked(version string, revoked []string) bool {
	for _, candidate := range revoked {
		if candidate == version {
			return true
		}
	}
	return false
}

// Eligible is retained as a strict compatibility wrapper. Without a live
// failure-domain observation it always refuses selection, preventing old
// callers from silently reverting to wildcard eligibility.
func (i Index) Eligible(machineID string, now time.Time, bypassCohort bool) bool {
	return i.EligibleFor(EligibilityInput{MachineID: machineID, Platform: i.Platform, Architecture: i.Architecture, FailureDomain: "", Now: now, BypassCohort: bypassCohort})
}

func (i Index) Component(name string) (Target, bool) {
	for _, target := range i.Targets {
		if target.Component == name {
			return target, true
		}
	}
	return Target{}, false
}
func validPlatform(platform, arch, format string) bool {
	if arch != "amd64" && arch != "arm64" {
		return false
	}
	return platform == "linux" && format == "elf" || platform == "darwin" && format == "pkg" || platform == "windows" && format == "pe"
}

// AssetName is the only public release asset naming rule. A platform has one
// immutable artifact and the installed pb executable contains every role.
func AssetName(platform, architecture string) string {
	name := "pb-" + platform + "-" + architecture
	if platform == "windows" {
		name += ".exe"
	}
	if platform == "darwin" {
		name += ".pkg"
	}
	return name
}

// ValidDownloadURL binds a signed target to an immutable GitHub release asset.
// No server-hosted target or mutable latest/download endpoint is accepted.
func ValidDownloadURL(raw, repository, version, assetName string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && validRepository(repository) && parsed.Scheme == "https" && parsed.Hostname() == "github.com" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "/"+repository+"/releases/download/"+version+"/"+assetName
}

func validRepository(value string) bool {
	return repositoryPattern.MatchString(value)
}

func compareVersion(left, right string) int {
	lhs, rhs := strings.Split(left, "."), strings.Split(right, ".")
	if len(lhs) != 4 || len(rhs) != 4 {
		return 0
	}
	for index := range lhs {
		var leftValue, rightValue uint64
		for _, digit := range lhs[index] {
			leftValue = leftValue*10 + uint64(digit-'0')
		}
		for _, digit := range rhs[index] {
			rightValue = rightValue*10 + uint64(digit-'0')
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}
func lowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
