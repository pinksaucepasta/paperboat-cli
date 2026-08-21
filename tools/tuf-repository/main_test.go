package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestVerifyMetaReferenceRejectsMissingAndMismatchedVersionedMetadata(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "metadata"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"signed":{"version":7}}`)
	digest := sha256.Sum256(body)
	meta := metadata.MetaFile(7)
	meta.Length = int64(len(body))
	meta.Hashes = metadata.Hashes{"sha256": digest[:]}
	if err := verifyMetaReference(repo, "7.snapshot.json", meta); err == nil {
		t.Fatal("missing versioned metadata unexpectedly verified")
	}
	path := filepath.Join(repo, "metadata", "7.snapshot.json")
	if err := os.WriteFile(path, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyMetaReference(repo, "7.snapshot.json", meta); err == nil {
		t.Fatal("hash-mismatched versioned metadata unexpectedly verified")
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyMetaReference(repo, "7.snapshot.json", meta); err != nil {
		t.Fatalf("valid versioned metadata rejected: %v", err)
	}
}

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

func TestWindowsAMD64QualificationRequiresExplicitPassedArtifactEvidence(t *testing.T) {
	components := windowsAMD64Components()
	qualification := validWindowsAMD64Qualification(components)
	if err := validateWindowsAMD64Qualification(qualification, qualification.ReleaseVersion, components); err != nil {
		t.Fatalf("valid qualification rejected: %v", err)
	}
	for name, mutate := range map[string]func(*windowsAMD64Qualification){
		"native-tested-false": func(q *windowsAMD64Qualification) { q.NativeTested = false },
		"not-passed":          func(q *windowsAMD64Qualification) { q.Status = "skipped" },
		"wrong-architecture":  func(q *windowsAMD64Qualification) { q.Architecture = "arm64" },
		"missing-component":   func(q *windowsAMD64Qualification) { q.Artifacts = q.Artifacts[:4] },
		"changed-hash":        func(q *windowsAMD64Qualification) { q.Artifacts[0].SHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := qualification
			candidate.Artifacts = append([]windowsAMD64QualifiedArtifact(nil), qualification.Artifacts...)
			mutate(&candidate)
			if err := validateWindowsAMD64Qualification(candidate, candidate.ReleaseVersion, components); err == nil {
				t.Fatal("invalid qualification unexpectedly accepted")
			}
		})
	}
}

func TestLoadWindowsAMD64QualificationRequiresAbsoluteStrictEvidence(t *testing.T) {
	if _, _, _, err := loadWindowsAMD64Qualification(""); err == nil {
		t.Fatal("missing qualification evidence unexpectedly accepted")
	}
	path := filepath.Join(t.TempDir(), "qualification.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.windows-native-qualification/v1","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadWindowsAMD64Qualification(path); err == nil {
		t.Fatal("unknown qualification evidence field unexpectedly accepted")
	}
}

func TestWindowsAMD64SignedQualificationBindsEvidenceAndEveryComponent(t *testing.T) {
	components := windowsAMD64Components()
	qualification := validWindowsAMD64Qualification(components)
	evidenceBody, err := json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	evidenceInfo, err := metadata.TargetFile().FromBytes(windowsAMD64QualificationTarget, evidenceBody, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "targets"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTargetForTest(t, repo, windowsAMD64QualificationTarget, evidenceInfo, evidenceBody)
	evidenceDigest := hex.EncodeToString(evidenceInfo.Hashes["sha256"])
	targetFiles := map[string]*metadata.TargetFiles{windowsAMD64QualificationTarget: evidenceInfo}
	for componentIndex := range components {
		component := &components[componentIndex]
		body := []byte(component.Component + "-binary")
		info, err := metadata.TargetFile().FromBytes(component.TargetPath, body, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		component.SHA256, component.Length = hex.EncodeToString(info.Hashes["sha256"]), info.Length
		for index := range qualification.Artifacts {
			if qualification.Artifacts[index].Component == component.Component {
				qualification.Artifacts[index].SHA256, qualification.Artifacts[index].Length = component.SHA256, component.Length
			}
		}
		customBody, err := json.Marshal(componentTargetCustom{Schema: "paperboat.tuf-component/v1", Kind: "component", Component: component.Component, Version: qualification.ReleaseVersion, Platform: "windows", Architecture: "amd64", BinaryFormat: "pe", NativeQualification: qualificationBinding(qualification, evidenceDigest, *component)})
		if err != nil {
			t.Fatal(err)
		}
		raw := json.RawMessage(customBody)
		info.Custom, info.Path = &raw, component.TargetPath
		targetFiles[component.TargetPath] = info
	}
	// Re-signing the in-memory evidence is not enough: its TUF target must contain
	// the exact qualified artifact hashes that are referenced by the release index.
	evidenceBody, err = json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	evidenceInfo, err = metadata.TargetFile().FromBytes(windowsAMD64QualificationTarget, evidenceBody, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	targetFiles[windowsAMD64QualificationTarget] = evidenceInfo
	writeTargetForTest(t, repo, windowsAMD64QualificationTarget, evidenceInfo, evidenceBody)
	evidenceDigest = hex.EncodeToString(evidenceInfo.Hashes["sha256"])
	for _, component := range components {
		info := targetFiles[component.TargetPath]
		custom := componentTargetCustom{Schema: "paperboat.tuf-component/v1", Kind: "component", Component: component.Component, Version: qualification.ReleaseVersion, Platform: "windows", Architecture: "amd64", BinaryFormat: "pe", NativeQualification: qualificationBinding(qualification, evidenceDigest, component)}
		customBody, err := json.Marshal(custom)
		if err != nil {
			t.Fatal(err)
		}
		raw := json.RawMessage(customBody)
		info.Custom = &raw
	}
	index := releaseIndex{Version: qualification.ReleaseVersion, Platform: "windows", Architecture: "amd64", Stability: "stable", NativeTested: true, TestedWindowsBuilds: []string{qualification.WindowsBuild}, Targets: components}
	if err := validateWindowsAMD64SignedQualification(repo, targetFiles, index); err != nil {
		t.Fatalf("valid signed qualification rejected: %v", err)
	}
	var custom componentTargetCustom
	if err := json.Unmarshal(*targetFiles[components[0].TargetPath].Custom, &custom); err != nil {
		t.Fatal(err)
	}
	custom.NativeQualification.ArtifactSHA256 = strings.Repeat("f", 64)
	customBody, err := json.Marshal(custom)
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(customBody)
	targetFiles[components[0].TargetPath].Custom = &raw
	if err := validateWindowsAMD64SignedQualification(repo, targetFiles, index); err == nil {
		t.Fatal("hash-mismatched signed qualification unexpectedly accepted")
	}
}

func windowsAMD64Components() []componentTarget {
	components := make([]componentTarget, 0, 5)
	for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
		components = append(components, componentTarget{Component: component, TargetPath: component + "-windows-amd64", SHA256: strings.Repeat("a", 64), Length: 100, Platform: "windows", Architecture: "amd64", BinaryFormat: "pe"})
	}
	return components
}

func validWindowsAMD64Qualification(components []componentTarget) windowsAMD64Qualification {
	artifacts := make([]windowsAMD64QualifiedArtifact, 0, len(components))
	for _, component := range components {
		artifacts = append(artifacts, windowsAMD64QualifiedArtifact{Component: component.Component, TargetPath: component.TargetPath, SHA256: component.SHA256, Length: component.Length, Platform: "windows", Architecture: "amd64", Status: "passed"})
	}
	return windowsAMD64Qualification{Schema: windowsAMD64QualificationSchema, ReleaseVersion: "2026.08.18.9", Platform: "windows", Architecture: "amd64", Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "windows-11-iot-amd64", Artifacts: artifacts}
}

func writeTargetForTest(t *testing.T, repo, name string, info *metadata.TargetFiles, body []byte) {
	t.Helper()
	path := filepath.Join(repo, "targets", hex.EncodeToString(info.Hashes["sha256"])+"."+name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
