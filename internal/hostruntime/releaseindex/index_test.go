package releaseindex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture() Index {
	i := Index{Schema: SchemaV1, ReleaseID: "rel_1", Version: "2026.08.18.7", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1, Rollout: Rollout{Schema: RolloutSchemaV1, CohortSeed: "seed", Percentage: 100}}
	name := AssetName("linux", "amd64")
	i.Targets = []Target{{Component: "pb", TargetPath: name, AssetName: name, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/2026.08.18.7/" + name, SHA256: strings.Repeat("a", 64), Length: 100, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}}
	return i
}

func TestDecodeAndEligibility(t *testing.T) {
	i := fixture()
	body, _ := json.Marshal(i)
	got, err := Decode(strings.NewReader(string(body)), time.Now())
	if err != nil || !got.Eligible("machine", time.Now(), false) {
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
	i.Rollout.Percentage = 0
	if !i.Eligible("machine", time.Now(), true) {
		t.Fatal("manual cohort bypass rejected")
	}
	i.Revoked = true
	if i.Eligible("machine", time.Now(), true) {
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
