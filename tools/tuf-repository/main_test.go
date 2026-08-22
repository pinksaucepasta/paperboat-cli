package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

func TestCIKeyEnvironmentAndSupportedTargets(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	t.Setenv(tufKeyEnvironmentName("targets-1"), base64.RawStdEncoding.EncodeToString(seed))
	key, err := loadKey("targets-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Seed(), seed) {
		t.Fatal("environment key seed changed while loading")
	}
	want := []releaseTargetPlatform{
		{platform: "darwin", architecture: "arm64"},
		{platform: "linux", architecture: "amd64"},
		{platform: "linux", architecture: "arm64"},
		{platform: "windows", architecture: "amd64"},
		{platform: "windows", architecture: "arm64"},
	}
	got := supportedReleaseTargets()
	if len(got) != len(want) {
		t.Fatalf("targets=%v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("target[%d]=%v, want %v", index, got[index], want[index])
		}
	}
}

func TestCISigningPublishesCompleteSupportedRelease(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	// Online publication must not require the offline root keys after the
	// repository and signing state have been initialized.
	for _, name := range []string{"root-1", "root-2", "root-3"} {
		t.Setenv(tufKeyEnvironmentName(name), "not-an-offline-root-key")
	}
	artifacts := t.TempDir()
	version := "2026.08.22.13"
	qualified := map[string][]windowsNativeQualifiedArtifact{"amd64": {}, "arm64": {}}
	for _, target := range supportedReleaseTargets() {
		for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
			name := component + "-" + target.platform + "-" + target.architecture
			body := []byte("test release artifact " + name)
			if err := os.WriteFile(filepath.Join(artifacts, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
			if target.platform == "windows" {
				digest := sha256.Sum256(body)
				qualified[target.architecture] = append(qualified[target.architecture], windowsNativeQualifiedArtifact{Component: component, TargetPath: name, SHA256: hex.EncodeToString(digest[:]), Length: int64(len(body)), Platform: "windows", Architecture: target.architecture, Status: "passed"})
			}
		}
	}
	evidencePaths := make(map[string]string, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		evidence, err := json.Marshal(windowsNativeQualification{Schema: windowsNativeQualificationSchema, ReleaseVersion: version, Platform: "windows", Architecture: architecture, Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "windows-" + architecture + "-test", Artifacts: qualified[architecture]})
		if err != nil {
			t.Fatal(err)
		}
		evidencePath := filepath.Join(artifacts, windowsNativeQualificationTarget(architecture))
		if err := os.WriteFile(evidencePath, evidence, 0o600); err != nil {
			t.Fatal(err)
		}
		evidencePaths[architecture] = evidencePath
	}
	if err := publish(repository, version, artifacts, evidencePaths, 1, 100, "routine", false); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(repository); err != nil {
		t.Fatal(err)
	}
	targets, err := metadata.Targets().FromFile(filepath.Join(repository, "metadata", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := targets.Signed.Targets["cli-darwin-amd64"]; exists {
		t.Fatal("unsupported macOS amd64 target was published")
	}
	if _, exists := targets.Signed.Targets["cli-darwin-arm64"]; !exists {
		t.Fatal("macOS arm64 target was not published")
	}
}

func TestCIOnlineSigningRejectsUnauthorizedKeyWithoutLoadingRootKeys(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root-1", "root-2", "root-3"} {
		t.Setenv(tufKeyEnvironmentName(name), "not-an-offline-root-key")
	}
	unauthorizedSeed := bytes.Repeat([]byte{99}, ed25519.SeedSize)
	t.Setenv(tufKeyEnvironmentName("targets-1"), base64.RawStdEncoding.EncodeToString(unauthorizedSeed))
	root, _, _, _, err := loadSet(repository)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadSigningState(repository, root, "targets", "snapshot", "timestamp")
	if err == nil || !strings.Contains(err.Error(), "targets-1 is not authorized for targets") {
		t.Fatalf("unauthorized online key error = %v", err)
	}
}

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

func TestWindowsNativeQualificationRequiresExplicitPassedArtifactEvidence(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			components := windowsComponents(architecture)
			qualification := validWindowsQualification(architecture, components)
			if err := validateWindowsNativeQualification(qualification, qualification.ReleaseVersion, architecture, components); err != nil {
				t.Fatalf("valid qualification rejected: %v", err)
			}
			for name, mutate := range map[string]func(*windowsNativeQualification){
				"native-tested-false": func(q *windowsNativeQualification) { q.NativeTested = false },
				"not-passed":          func(q *windowsNativeQualification) { q.Status = "skipped" },
				"wrong-architecture": func(q *windowsNativeQualification) {
					q.Architecture = map[string]string{"amd64": "arm64", "arm64": "amd64"}[architecture]
				},
				"missing-component": func(q *windowsNativeQualification) { q.Artifacts = q.Artifacts[:4] },
				"changed-hash":      func(q *windowsNativeQualification) { q.Artifacts[0].SHA256 = strings.Repeat("b", 64) },
			} {
				t.Run(name, func(t *testing.T) {
					candidate := qualification
					candidate.Artifacts = append([]windowsNativeQualifiedArtifact(nil), qualification.Artifacts...)
					mutate(&candidate)
					if err := validateWindowsNativeQualification(candidate, candidate.ReleaseVersion, architecture, components); err == nil {
						t.Fatal("invalid qualification unexpectedly accepted")
					}
				})
			}
		})
	}
}

func TestLoadWindowsAMD64QualificationRequiresAbsoluteStrictEvidence(t *testing.T) {
	if _, _, _, err := loadWindowsNativeQualification("", "amd64"); err == nil {
		t.Fatal("missing qualification evidence unexpectedly accepted")
	}
	path := filepath.Join(t.TempDir(), "qualification.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.windows-native-qualification/v1","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadWindowsNativeQualification(path, "amd64"); err == nil {
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
	evidenceInfo, err := metadata.TargetFile().FromBytes(windowsNativeQualificationTarget("amd64"), evidenceBody, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "targets"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTargetForTest(t, repo, windowsNativeQualificationTarget("amd64"), evidenceInfo, evidenceBody)
	evidenceDigest := hex.EncodeToString(evidenceInfo.Hashes["sha256"])
	targetFiles := map[string]*metadata.TargetFiles{windowsNativeQualificationTarget("amd64"): evidenceInfo}
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
	evidenceInfo, err = metadata.TargetFile().FromBytes(windowsNativeQualificationTarget("amd64"), evidenceBody, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	targetFiles[windowsNativeQualificationTarget("amd64")] = evidenceInfo
	writeTargetForTest(t, repo, windowsNativeQualificationTarget("amd64"), evidenceInfo, evidenceBody)
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
	if err := validateWindowsNativeSignedQualification(repo, targetFiles, index); err != nil {
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
	if err := validateWindowsNativeSignedQualification(repo, targetFiles, index); err == nil {
		t.Fatal("hash-mismatched signed qualification unexpectedly accepted")
	}
}

func windowsAMD64Components() []componentTarget {
	return windowsComponents("amd64")
}

func windowsComponents(architecture string) []componentTarget {
	components := make([]componentTarget, 0, 5)
	for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
		components = append(components, componentTarget{Component: component, TargetPath: component + "-windows-" + architecture, SHA256: strings.Repeat("a", 64), Length: 100, Platform: "windows", Architecture: architecture, BinaryFormat: "pe"})
	}
	return components
}

func validWindowsAMD64Qualification(components []componentTarget) windowsNativeQualification {
	return validWindowsQualification("amd64", components)
}

func validWindowsQualification(architecture string, components []componentTarget) windowsNativeQualification {
	artifacts := make([]windowsNativeQualifiedArtifact, 0, len(components))
	for _, component := range components {
		artifacts = append(artifacts, windowsNativeQualifiedArtifact{Component: component.Component, TargetPath: component.TargetPath, SHA256: component.SHA256, Length: component.Length, Platform: "windows", Architecture: architecture, Status: "passed"})
	}
	return windowsNativeQualification{Schema: windowsNativeQualificationSchema, ReleaseVersion: "2026.08.18.9", Platform: "windows", Architecture: architecture, Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "windows-11-" + architecture, Artifacts: artifacts}
}

func writeTargetForTest(t *testing.T, repo, name string, info *metadata.TargetFiles, body []byte) {
	t.Helper()
	path := filepath.Join(repo, "targets", hex.EncodeToString(info.Hashes["sha256"])+"."+name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
