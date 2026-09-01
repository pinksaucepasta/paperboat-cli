package releaseindex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

func fixture() Index {
	manifest := strings.Repeat("b", 64)
	plan, err := releasepolicy.Default("2026.08.18.7", manifest, 1, "routine", "seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		panic(err)
	}
	planDigest, _ := plan.PlanSHA256()
	i := Index{Schema: SchemaV1, ReleaseID: "rel_1", Version: "2026.08.18.7", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC().Add(-3 * time.Hour), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1, ManifestSHA256: manifest, DeploymentPlanSHA256: planDigest, DeploymentPlan: &plan}
	name := AssetName("linux", "amd64")
	i.Targets = []Target{{Component: "pb", TargetPath: name, AssetName: name, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/2026.08.18.7/" + name, SHA256: strings.Repeat("a", 64), Length: 100, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}}
	return i
}

func TestDecodeAndEligibility(t *testing.T) {
	i := fixture()
	body, _ := json.Marshal(i)
	now := time.Now().UTC()
	got, err := Decode(strings.NewReader(string(body)), now)
	if err != nil || !got.EligibleFor(EligibilityInput{MachineID: "machine", Platform: "linux", Architecture: "amd64", FailureDomain: "iad-1", Now: now}) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if target, ok := got.Component("pb"); !ok || target.Component != "pb" {
		t.Fatal("pb target missing")
	}
}
func TestRejectsMissingDuplicateAndUnknown(t *testing.T) {
	i := fixture()
	i.Targets = nil
	if i.Validate(time.Now()) == nil {
		t.Fatal("missing accepted")
	}
	i = fixture()
	i.Targets = append(i.Targets, i.Targets[0])
	if i.Validate(time.Now()) == nil {
		t.Fatal("duplicate target accepted")
	}
	body, _ := json.Marshal(fixture())
	body = append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
	if _, err := Decode(strings.NewReader(string(body)), time.Now()); err == nil {
		t.Fatal("unknown accepted")
	}
}
func TestManualBypassDoesNotBypassSafety(t *testing.T) {
	i := fixture()
	for index := range i.DeploymentPlan.Cohorts {
		if i.DeploymentPlan.Cohorts[index].Platform == "linux" && i.DeploymentPlan.Cohorts[index].Architecture == "amd64" {
			i.DeploymentPlan.Cohorts[index].Percentage = 100
		}
	}
	digest, err := i.DeploymentPlan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	i.DeploymentPlanSHA256 = digest
	now := time.Now().UTC()
	i.CreatedAt = now
	input := EligibilityInput{MachineID: "machine", Platform: "linux", Architecture: "amd64", FailureDomain: "iad-1", Now: now, BypassCohort: true}
	if !i.EligibleFor(input) {
		t.Fatal("manual cohort bypass rejected")
	}
	i.Revoked = true
	if i.EligibleFor(input) {
		t.Fatal("revoked release accepted")
	}
}

func TestRejectsNonCanonicalGitHubRepository(t *testing.T) {
	for _, repository := range []string{"example owner/paperboat", "example/paper boat", "example//paperboat", "example/paperboat/extra", " example/paperboat"} {
		i := fixture()
		i.Targets[0].Repository = repository
		i.Targets[0].DownloadURL = "https://github.com/" + repository + "/releases/download/" + i.Version + "/" + i.Targets[0].AssetName
		if i.Validate(time.Now()) == nil {
			t.Fatalf("repository %q was accepted", repository)
		}
	}
}

func TestEligibilityRequiresExactLiveTargetAndSafetyState(t *testing.T) {
	i := fixture()
	now := time.Now().UTC()
	valid := EligibilityInput{MachineID: "machine", Platform: "linux", Architecture: "amd64", FailureDomain: "iad-1", Now: now}
	if !i.EligibleFor(valid) {
		t.Fatal("valid live target rejected")
	}
	for name, input := range map[string]EligibilityInput{
		"missing domain":  valid,
		"wildcard domain": valid,
		"wrong platform":  valid,
		"wrong arch":      valid,
		"bad machine":     valid,
	} {
		switch name {
		case "missing domain":
			input.FailureDomain = ""
		case "wildcard domain":
			input.FailureDomain = "*"
		case "wrong platform":
			input.Platform = "darwin"
			input.Architecture = "arm64"
		case "wrong arch":
			input.Architecture = "arm64"
		case "bad machine":
			input.MachineID = "machine with spaces"
		}
		if i.EligibleFor(input) {
			t.Fatalf("%s accepted", name)
		}
	}
	paused := i
	paused.DeploymentPlan = clonePlan(i.DeploymentPlan)
	paused.DeploymentPlan.RolloutState = releasepolicy.RolloutStatePaused
	paused.DeploymentPlanSHA256, _ = paused.DeploymentPlan.PlanSHA256()
	if paused.EligibleFor(valid) {
		t.Fatal("paused release accepted")
	}
	quarantined := i
	quarantined.DeploymentPlan = clonePlan(i.DeploymentPlan)
	quarantined.DeploymentPlan.RolloutState = releasepolicy.RolloutStateQuarantined
	quarantined.DeploymentPlanSHA256, _ = quarantined.DeploymentPlan.PlanSHA256()
	if quarantined.EligibleFor(valid) {
		t.Fatal("quarantined release accepted")
	}
	minimum := i
	minimum.MinimumVersion = "2026.08.19.1"
	if minimum.EligibleFor(valid) {
		t.Fatal("release below signed minimum accepted")
	}
	revoked := i
	revoked.RevokedVersions = []string{revoked.Version}
	if revoked.EligibleFor(valid) {
		t.Fatal("revoked version accepted")
	}
}

func TestEligibilityDeferralAndManualTimingBoundaries(t *testing.T) {
	i := fixture()
	now := time.Now().UTC()
	deferral, err := i.DeploymentPlan.GrantDeferral(releasepolicy.DeferralRequest{Version: i.Version, RequestedSecs: 3600, Reason: "maintenance"}, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	input := EligibilityInput{MachineID: "machine", Platform: i.Platform, Architecture: i.Architecture, FailureDomain: "iad-1", Now: now, Deferral: &deferral}
	if i.EligibleFor(input) {
		t.Fatal("active deferral did not block")
	}
	input.Deferral = nil
	if !i.EligibleFor(input) {
		t.Fatal("selection without deferral rejected")
	}

	timing := fixture()
	timing.DeploymentPlan = clonePlan(timing.DeploymentPlan)
	for index := range timing.DeploymentPlan.Cohorts {
		if timing.DeploymentPlan.Cohorts[index].Platform == "linux" && timing.DeploymentPlan.Cohorts[index].Architecture == "amd64" {
			switch timing.DeploymentPlan.Cohorts[index].Name {
			case "canary":
				timing.DeploymentPlan.Cohorts[index].Percentage = 0
			case "early", "general":
				timing.DeploymentPlan.Cohorts[index].Percentage = 100
			}
		}
	}
	timing.DeploymentPlanSHA256, err = timing.DeploymentPlan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	timing.CreatedAt = now.Add(-time.Second)
	manualInput := EligibilityInput{MachineID: "machine", Platform: timing.Platform, Architecture: timing.Architecture, FailureDomain: "iad-1", Now: now, BypassCohort: true}
	if timing.EligibleFor(manualInput) == false {
		t.Fatal("manual timing bypass rejected")
	}
	manualInput.BypassCohort = false
	if timing.EligibleFor(manualInput) {
		t.Fatal("normal selection bypassed wave timing")
	}
}

func TestIndexValidationBindsPlanDigestRevisionAndSeverity(t *testing.T) {
	i := fixture()
	mutated := i
	mutated.DeploymentPlanSHA256 = strings.Repeat("c", 64)
	if mutated.Validate(time.Now()) == nil {
		t.Fatal("plan digest tamper accepted")
	}
	mutated = i
	mutated.RolloutPolicyRevision++
	if mutated.Validate(time.Now()) == nil {
		t.Fatal("policy revision mismatch accepted")
	}
	mutated = i
	mutated.Severity = "critical"
	if mutated.Validate(time.Now()) == nil {
		t.Fatal("index severity mismatch accepted")
	}
}

func clonePlan(plan *releasepolicy.Plan) *releasepolicy.Plan {
	if plan == nil {
		return nil
	}
	copy := *plan
	copy.Cohorts = append([]releasepolicy.Cohort(nil), plan.Cohorts...)
	copy.Rollback.Triggers = append([]string(nil), plan.Rollback.Triggers...)
	return &copy
}
