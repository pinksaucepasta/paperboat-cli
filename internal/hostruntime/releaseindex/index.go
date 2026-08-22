// Package releaseindex validates the signed, fixed-name TUF release selector.
package releaseindex

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

const SchemaV1 = "paperboat.release-index/v1"
const RolloutSchemaV1 = "paperboat.release-rollout/v1"

var ErrInvalid = errors.New("signed release index is invalid")
var versionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)
var dependencyVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
var valuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$`)

type Index struct {
	Schema                 string    `json:"schema"`
	ReleaseID              string    `json:"release_id"`
	Version                string    `json:"version"`
	Channel                string    `json:"channel"`
	Severity               string    `json:"severity"`
	CreatedAt              time.Time `json:"created_at"`
	Platform               string    `json:"platform"`
	Architecture           string    `json:"architecture"`
	BinaryFormat           string    `json:"binary_format"`
	Targets                []Target  `json:"targets"`
	HostdAPIMin            uint16    `json:"hostd_api_min"`
	HostdAPIMax            uint16    `json:"hostd_api_max"`
	RuntimeAPIMin          uint16    `json:"runtime_api_min"`
	RuntimeAPIMax          uint16    `json:"runtime_api_max"`
	MinimumVersion         string    `json:"minimum_permitted_version,omitempty"`
	RevokedVersions        []string  `json:"revoked_versions,omitempty"`
	RolloutPolicyRevision  uint64    `json:"rollout_policy_revision"`
	SupervisorMaintenance  bool      `json:"supervisor_maintenance_required"`
	Rollout                Rollout   `json:"rollout"`
	Revoked                bool      `json:"revoked,omitempty"`
	Stability              string    `json:"stability,omitempty"`
	NativeTested           bool      `json:"native_tested,omitempty"`
	TestedWindowsBuilds    []string  `json:"tested_windows_builds,omitempty"`
	OpenSSHPackageID       string    `json:"openssh_package_id,omitempty"`
	OpenSSHApprovedVersion string    `json:"openssh_approved_version,omitempty"`
}

type Target struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
}
type Rollout struct {
	Schema     string     `json:"schema"`
	CohortSeed string     `json:"cohort_seed"`
	Percentage uint8      `json:"percentage"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
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
	if i.MinimumVersion != "" && !versionPattern.MatchString(i.MinimumVersion) {
		return ErrInvalid
	}
	revoked := map[string]bool{}
	for _, version := range i.RevokedVersions {
		if !versionPattern.MatchString(version) || revoked[version] {
			return ErrInvalid
		}
		revoked[version] = true
	}
	required := map[string]bool{"cli": false, "runtime": false, "hostd": false, "updater": false, "launcher": false}
	if len(i.Targets) != len(required) {
		return ErrInvalid
	}
	for _, target := range i.Targets {
		if _, ok := required[target.Component]; !ok || required[target.Component] || target.TargetPath != target.Component+"-"+i.Platform+"-"+i.Architecture || target.Platform != i.Platform || target.Architecture != i.Architecture || target.BinaryFormat != i.BinaryFormat || target.Length < 1 || target.Length > 512<<20 || len(target.SHA256) != sha256.Size*2 || !lowerHex(target.SHA256) {
			return ErrInvalid
		}
		required[target.Component] = true
	}
	if i.Rollout.Schema != RolloutSchemaV1 || len(i.Rollout.CohortSeed) < 1 || len(i.Rollout.CohortSeed) > 128 || strings.ContainsAny(i.Rollout.CohortSeed, "\x00\r\n") || i.Rollout.Percentage > 100 {
		return ErrInvalid
	}
	if i.Rollout.NotBefore != nil && i.Rollout.ExpiresAt != nil && !i.Rollout.ExpiresAt.After(*i.Rollout.NotBefore) {
		return ErrInvalid
	}
	if i.Rollout.NotBefore != nil && i.Rollout.NotBefore.IsZero() || i.Rollout.ExpiresAt != nil && i.Rollout.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	_ = now
	return nil
}

func expectedChannel(platform, architecture string) string {
	return "stable"
}

func (i Index) Eligible(machineID string, now time.Time, bypassCohort bool) bool {
	if i.Validate(now) != nil || strings.TrimSpace(machineID) == "" || i.Revoked || i.Rollout.NotBefore != nil && now.Before(*i.Rollout.NotBefore) || i.Rollout.ExpiresAt != nil && !now.Before(*i.Rollout.ExpiresAt) {
		return false
	}
	if bypassCohort {
		return true
	}
	digest := sha256.Sum256([]byte(i.Rollout.CohortSeed + "\x00" + machineID))
	return binary.BigEndian.Uint64(digest[:8])%10000 < uint64(i.Rollout.Percentage)*100
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
	return platform == "linux" && format == "elf" || platform == "darwin" && format == "mach-o" || platform == "windows" && format == "pe"
}
func lowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
