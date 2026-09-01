package releaseplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testVersion = "2026.08.31.1"

func testManifest(t *testing.T) Manifest {
	t.Helper()
	artifacts := make([]Artifact, 0, len(artifactSpecs))
	for _, spec := range artifactSpecs {
		body := []byte("release-" + spec.Name)
		sum := sha256.Sum256(body)
		artifacts = append(artifacts, Artifact{Name: spec.Name, Platform: spec.Platform, Architecture: spec.Architecture, Format: spec.Format, Length: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
	}
	return Manifest{Schema: ManifestSchema, Version: testVersion, SourceCommit: "0123456789abcdef0123456789abcdef01234567", Toolchain: "go1.26.6", Artifacts: artifacts}
}

func TestBuildManifestRequiresExactReproducibleAssetSet(t *testing.T) {
	directory := t.TempDir()
	manifest := testManifest(t)
	for _, artifact := range manifest.Artifacts {
		body := []byte("release-" + artifact.Name)
		if err := os.WriteFile(filepath.Join(directory, artifact.Name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	built, err := BuildManifest(testVersion, manifest.SourceCommit, manifest.Toolchain, directory)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if got, want := built, manifest; got.Version != want.Version || got.SourceCommit != want.SourceCommit || len(got.Artifacts) != len(want.Artifacts) {
		t.Fatalf("manifest=%+v want=%+v", got, want)
	}
	first, err := built.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	second, err := built.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("manifest encoding is not deterministic")
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildManifest(testVersion, manifest.SourceCommit, manifest.Toolchain, directory); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("extra asset error=%v, want ErrInvalidManifest", err)
	}
}

func TestBuildManifestRejectsSymlinkAndChangingDigest(t *testing.T) {
	directory := t.TempDir()
	manifest := testManifest(t)
	for _, artifact := range manifest.Artifacts {
		if err := os.WriteFile(filepath.Join(directory, artifact.Name), []byte("release-"+artifact.Name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(directory, manifest.Artifacts[0].Name)
	body := filepath.Join(directory, "real-artifact")
	if err := os.Rename(link, body); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(body, link); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildManifest(testVersion, manifest.SourceCommit, manifest.Toolchain, directory); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("symlink error=%v, want ErrInvalidManifest", err)
	}
}

func TestDefaultPlanProviderInputsAndCohortsAreDeterministic(t *testing.T) {
	manifest := testManifest(t)
	plan, err := DefaultPlan(manifest, 7, "security", "seed-2026-08-31")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlanAgainstManifest(plan, manifest); err != nil {
		t.Fatal(err)
	}
	first, ok := plan.CohortFor("machine-a", "linux", "amd64", "iad-1", 3*time.Hour)
	if !ok || first != "general" {
		t.Fatalf("cohort=%q ok=%v, want general", first, ok)
	}
	second, ok := plan.CohortFor("machine-a", "linux", "amd64", "iad-1", 3*time.Hour)
	if !ok || second != first {
		t.Fatalf("repeat cohort=%q ok=%v, first=%q", second, ok, first)
	}
	if _, ok := plan.CohortFor("machine-a", "linux", "386", "iad-1", 3*time.Hour); ok {
		t.Fatal("unsupported target was eligible")
	}
	target := TargetBinding{MachineID: "machine-a", AccountID: "account-a", HostID: "host-a", TunnelID: "tunnel-a", ConnectorID: "connector-a", EdgeNodeID: "edge-a", FailureDomain: "iad-1", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5}
	previous := ReleaseRef{Version: "2026.08.30.1", ManifestSHA256: stringsRepeat("a", 64)}
	inputs, err := ProviderInputsForPlan(plan, "transaction-a", target, previous, "edge_canary")
	if err != nil {
		t.Fatal(err)
	}
	if err := inputs.ValidateAgainst(plan); err != nil {
		t.Fatal(err)
	}
	body, err := inputs.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || string(body[len(body)-1:]) != "\n" {
		t.Fatal("provider input is not newline-terminated JSON")
	}
	if containsAny(string(body), "token", "secret", "password", "private_key", "file://", "https://") {
		t.Fatalf("provider input contains a forbidden secret/path/url field: %s", body)
	}
}

func TestProviderInputsRejectFenceMutation(t *testing.T) {
	manifest := testManifest(t)
	plan, err := DefaultPlan(manifest, 1, "routine", "seed")
	if err != nil {
		t.Fatal(err)
	}
	target := TargetBinding{MachineID: "machine", AccountID: "account", HostID: "host", TunnelID: "tunnel", ConnectorID: "connector", EdgeNodeID: "edge", FailureDomain: "*", ProcessEpoch: 1, SessionGeneration: 1, ConfigGeneration: 1, RouteGeneration: 1}
	previous := ReleaseRef{Version: "2026.08.30.1", ManifestSHA256: stringsRepeat("b", 64)}
	inputs, err := ProviderInputsForPlan(plan, "tx", target, previous, "edge_canary")
	if err != nil {
		t.Fatal(err)
	}
	inputs.Drain.Target.ProcessEpoch++
	if err := inputs.ValidateAgainst(plan); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("mutated target error=%v, want ErrInvalidPlan", err)
	}
	inputs, err = ProviderInputsForPlan(plan, "tx", target, previous, "edge_canary")
	if err != nil {
		t.Fatal(err)
	}
	inputs.Rollback.Trigger = "unknown"
	if err := inputs.ValidateAgainst(plan); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("mutated trigger error=%v, want ErrInvalidPlan", err)
	}
}

func TestDeferralBoundsAndApproval(t *testing.T) {
	manifest := testManifest(t)
	plan, err := DefaultPlan(manifest, 1, "security", "seed")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60))
	if _, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance", ApprovedBy: "operator-1"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance"}, now); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("missing approval error=%v", err)
	}
	if _, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: MaxSecurityDeferralSec + 1, Reason: "maintenance", ApprovedBy: "operator-1"}, now); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("overlong deferral error=%v", err)
	}
}

func TestAdvanceRequiresValidationThenQuarantinesAndBlocks(t *testing.T) {
	manifest := testManifest(t)
	plan, err := DefaultPlan(manifest, 1, "routine", "seed")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	state, err := NewState(plan, "tx", "2026.08.30.1", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{EventDownloadStarted, EventCandidateValidating, EventCandidateReady, EventCanaryPassed, EventDrainCompleted, EventActivationStarted, EventActivationPassed, EventStabilityPassed} {
		state, err = Advance(state, event, "", now.Add(time.Minute), plan.Rollback.QuarantineSeconds)
		if err != nil {
			t.Fatalf("event %s: %v", event, err)
		}
	}
	if state.State != StateCommitted || state.Quarantined || state.Revoked {
		t.Fatalf("committed state=%+v", state)
	}
	failure, err := NewState(plan, "tx-failure", "2026.08.30.1", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{EventDownloadStarted, EventCandidateValidating, EventCandidateReady, EventCanaryFailed} {
		failure, err = Advance(failure, event, "edge canary failed", now.Add(time.Minute), plan.Rollback.QuarantineSeconds)
		if err != nil {
			t.Fatalf("failure event %s: %v", event, err)
		}
	}
	if failure.State != StateQuarantined || !failure.Quarantined {
		t.Fatalf("quarantined state=%+v", failure)
	}
	quarantine, err := failure.QuarantineOutput(now.Add(2 * time.Minute))
	if err != nil || quarantine.Schema != QuarantineSchema {
		t.Fatalf("quarantine=%+v err=%v", quarantine, err)
	}
	revoked, err := Advance(failure, EventRevoke, "operator revoked", now.Add(3*time.Minute), plan.Rollback.QuarantineSeconds)
	if err != nil {
		t.Fatal(err)
	}
	output, err := revoked.RevocationOutput(now.Add(4 * time.Minute))
	if err != nil || output.Schema != RevocationSchema || !revoked.Revoked {
		t.Fatalf("revocation=%+v state=%+v err=%v", output, revoked, err)
	}
	rollback, err := NewState(plan, "tx-rollback", "2026.08.30.1", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{EventDownloadStarted, EventCandidateValidating, EventCandidateReady, EventCanaryPassed, EventDrainCompleted, EventActivationStarted, EventActivationFailed, EventRollbackStarted, EventRollbackFailed} {
		rollback, err = Advance(rollback, event, "rollback failed", now.Add(time.Minute), plan.Rollback.QuarantineSeconds)
		if err != nil {
			t.Fatalf("rollback event %s: %v", event, err)
		}
	}
	if rollback.State != StateBlocked || !rollback.Quarantined {
		t.Fatalf("blocked state=%+v", rollback)
	}
}

func TestStrictLoadRejectsUnknownAndTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.release-artifacts/v1","unknown":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unknown field error=%v", err)
	}
}

func stringsRepeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
