package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

func TestPublishedReleaseIndexMatchesRuntimeContract(t *testing.T) {
	components := make([]componentTarget, 0, 5)
	for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
		components = append(components, componentTarget{Component: component, TargetPath: component + "-linux-amd64", SHA256: strings.Repeat("a", 64), Length: 100, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"})
	}
	body, err := json.Marshal(releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_2026.08.18.8", Version: "2026.08.18.8", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: components, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1, Rollout: rolloutPolicy{Schema: "paperboat.release-rollout/v1", CohortSeed: "release-2026.08.18.8", Percentage: 5}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := releaseindex.Decode(bytes.NewReader(body), time.Now().UTC())
	if err != nil || decoded.Version != "2026.08.18.8" || len(decoded.Targets) != 5 {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}

func TestRolloutMutationsAreMonotonicAndSignedIndexCompatible(t *testing.T) {
	index := releaseIndex{RolloutPolicyRevision: 4, Rollout: rolloutPolicy{Percentage: 5}}
	if err := applyRolloutMutation(&index, "promote", 5, 25); err != nil || index.Rollout.Percentage != 25 || index.Revoked {
		t.Fatalf("promote index=%+v err=%v", index, err)
	}
	if err := applyRolloutMutation(&index, "pause", 6, 0); err != nil || index.Rollout.Percentage != 0 || index.Revoked {
		t.Fatalf("pause index=%+v err=%v", index, err)
	}
	if err := applyRolloutMutation(&index, "quarantine", 7, 0); err != nil || !index.Revoked {
		t.Fatalf("quarantine index=%+v err=%v", index, err)
	}
	for _, test := range []struct {
		op         string
		revision   uint64
		percentage uint8
	}{{"promote", 7, 50}, {"pause", 8, 1}, {"unknown", 8, 0}} {
		copy := index
		if err := applyRolloutMutation(&copy, test.op, test.revision, test.percentage); err == nil {
			t.Fatalf("mutation %+v unexpectedly succeeded", test)
		}
	}
}
