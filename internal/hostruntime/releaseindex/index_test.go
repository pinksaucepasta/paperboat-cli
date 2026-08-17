package releaseindex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture() Index {
	i := Index{Schema: SchemaV1, ReleaseID: "rel_1", Version: "2026.08.18.7", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1, Rollout: Rollout{Schema: RolloutSchemaV1, CohortSeed: "seed", Percentage: 100}}
	for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
		i.Targets = append(i.Targets, Target{Component: component, TargetPath: component + "-linux-amd64", SHA256: strings.Repeat("a", 64), Length: 100, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"})
	}
	return i
}

func TestDecodeAndEligibility(t *testing.T) {
	i := fixture()
	body, _ := json.Marshal(i)
	got, err := Decode(strings.NewReader(string(body)), time.Now())
	if err != nil || !got.Eligible("machine", time.Now(), false) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if target, ok := got.Component("runtime"); !ok || target.Component != "runtime" {
		t.Fatal("runtime target missing")
	}
}
func TestRejectsMissingDuplicateAndUnknown(t *testing.T) {
	i := fixture()
	i.Targets = i.Targets[:4]
	if i.Validate(time.Now()) == nil {
		t.Fatal("missing accepted")
	}
	i = fixture()
	i.Targets[4] = i.Targets[0]
	if i.Validate(time.Now()) == nil {
		t.Fatal("duplicate accepted")
	}
	body, _ := json.Marshal(fixture())
	body = append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
	if _, err := Decode(strings.NewReader(string(body)), time.Now()); err == nil {
		t.Fatal("unknown accepted")
	}
}
func TestManualBypassDoesNotBypassSafety(t *testing.T) {
	i := fixture()
	i.Rollout.Percentage = 0
	if !i.Eligible("machine", time.Now(), true) {
		t.Fatal("manual cohort bypass rejected")
	}
	i.Revoked = true
	if i.Eligible("machine", time.Now(), true) {
		t.Fatal("revoked release accepted")
	}
}
