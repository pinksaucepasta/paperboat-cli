package releasepolicy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testPolicy(t *testing.T) Plan {
	t.Helper()
	targets := []PlatformTarget{
		{Platform: "darwin", Architecture: "arm64"},
		{Platform: "linux", Architecture: "amd64"},
		{Platform: "linux", Architecture: "arm64"},
		{Platform: "windows", Architecture: "amd64"},
		{Platform: "windows", Architecture: "arm64"},
	}
	plan, err := Default("2026.08.31.1", strings.Repeat("a", 64), 4, "security", "seed-2026", targets)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestDefaultPolicyIsCanonicalAndDeterministic(t *testing.T) {
	plan := testPolicy(t)
	body, err := plan.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := plan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || !strings.HasSuffix(string(body), "\n") || len(digest) != 64 || !IsDigest(digest) {
		t.Fatalf("invalid canonical policy bytes or digest: bytes=%d digest=%q", len(body), digest)
	}
	first, ok := plan.CohortFor("machine-a", "linux", "amd64", "iad-1", 3*time.Hour)
	if !ok || first != "general" {
		t.Fatalf("cohort=%q ok=%v, want general", first, ok)
	}
	second, ok := plan.CohortFor("machine-a", "linux", "amd64", "iad-1", 3*time.Hour)
	if !ok || second != first {
		t.Fatalf("repeat cohort=%q ok=%v first=%q", second, ok, first)
	}
}

func TestPolicyBindingAndBoundsFailClosed(t *testing.T) {
	plan := testPolicy(t)
	if err := plan.ValidateAgainst(plan.Version, plan.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(plan.ValidateAgainst(plan.Version, strings.Repeat("b", 64)), ErrInvalidPolicy) {
		t.Fatal("manifest digest mismatch was accepted")
	}
	plan.Rollback.Triggers[0] = "unknown"
	if !errors.Is(plan.Validate(), ErrInvalidPolicy) {
		t.Fatal("unknown rollback trigger was accepted")
	}
}

func TestDeferralRequiresApprovalAndHasBoundedOutput(t *testing.T) {
	plan := testPolicy(t)
	when := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	deferral, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance", ApprovedBy: "operator-1"}, when)
	if err != nil {
		t.Fatal(err)
	}
	body, err := deferral.Bytes()
	if err != nil || len(body) == 0 || !strings.HasSuffix(string(body), "\n") {
		t.Fatalf("deferral bytes err=%v len=%d", err, len(body))
	}
	if _, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance"}, when); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("missing approval was accepted")
	}
}

func TestManualSelectionOnlyBypassesWaveTiming(t *testing.T) {
	plan := testPolicy(t)
	for index := range plan.Cohorts {
		if plan.Cohorts[index].Platform != "linux" || plan.Cohorts[index].Architecture != "amd64" {
			continue
		}
		switch plan.Cohorts[index].Name {
		case "canary":
			plan.Cohorts[index].Percentage = 0
		case "early", "general":
			plan.Cohorts[index].Percentage = 100
		}
	}
	if regular, ok := plan.CohortFor("machine-a", "linux", "amd64", "iad-1", 0); ok || regular != "" {
		t.Fatalf("regular selection=%q ok=%v before wave start", regular, ok)
	}
	manual, ok := plan.CohortForManual("machine-a", "linux", "amd64", "iad-1")
	if !ok || manual != "general" {
		t.Fatalf("manual selection=%q ok=%v", manual, ok)
	}
	for _, state := range []string{RolloutStatePaused, RolloutStateQuarantined} {
		plan.RolloutState = state
		if cohort, ok := plan.CohortForManual("machine-a", "linux", "amd64", "iad-1"); ok || cohort != "" {
			t.Fatalf("state=%s selected cohort=%q ok=%v", state, cohort, ok)
		}
	}
}

func TestDeferralIsBoundToPlanAndExpires(t *testing.T) {
	plan := testPolicy(t)
	granted := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	deferral, err := plan.GrantDeferral(DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance", ApprovedBy: "operator-1"}, granted)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := plan.DeferralActive(deferral, granted.Add(30*time.Minute)); err != nil || !active {
		t.Fatalf("active=%v err=%v", active, err)
	}
	if active, err := plan.DeferralActive(deferral, granted.Add(time.Hour)); err != nil || active {
		t.Fatalf("expired active=%v err=%v", active, err)
	}
	changed := deferral
	changed.PlanSHA256 = strings.Repeat("b", 64)
	if _, err := plan.DeferralActive(changed, granted.Add(30*time.Minute)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("plan digest mismatch err=%v", err)
	}
	future := deferral
	future.GrantedAt = granted.Add(time.Minute)
	future.ExpiresAt = future.GrantedAt.Add(time.Duration(future.GrantedSecs) * time.Second)
	if _, err := plan.DeferralActive(future, granted); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("future deferral err=%v", err)
	}
	tooLong := deferral
	tooLong.GrantedSecs = MaxSecurityDeferralSec + 1
	tooLong.ExpiresAt = tooLong.GrantedAt.Add(time.Duration(tooLong.GrantedSecs) * time.Second)
	if _, err := plan.DeferralActive(tooLong, granted.Add(30*time.Minute)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("overlong security deferral err=%v", err)
	}
}

func TestPlanRejectsUnsafeDeferralPolicyShape(t *testing.T) {
	plan := testPolicy(t)
	plan.SecurityDeferral.MaxSeconds = 0
	if !errors.Is(plan.Validate(), ErrInvalidPolicy) {
		t.Fatal("zero deferral maximum accepted")
	}
	plan = testPolicy(t)
	plan.SecurityDeferral.RequiresApproval = false
	if !errors.Is(plan.Validate(), ErrInvalidPolicy) {
		t.Fatal("security policy without approval accepted")
	}
}
