package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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
	for _, target := range supportedReleaseTargets() {
		name := releaseAssetName(target.platform, target.architecture)
		body := []byte("test release asset " + name)
		if err := os.WriteFile(filepath.Join(artifacts, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidencePaths := make(map[string]string, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		evidence, err := json.Marshal(windowsNativeQualification{Schema: windowsNativeQualificationSchema, ReleaseVersion: version, Platform: "windows", Architecture: architecture, Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "windows-" + architecture + "-test"})
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
	if _, exists := targets.Signed.Targets["pb-darwin-amd64.pkg"]; exists {
		t.Fatal("unsupported macOS amd64 target was published")
	}
	if _, exists := targets.Signed.Targets["pb-darwin-arm64.pkg"]; !exists {
		t.Fatal("macOS arm64 target was not published")
	}
	wantNames := map[string]bool{}
	for _, target := range supportedReleaseTargets() {
		wantNames[releaseAssetName(target.platform, target.architecture)] = false
	}
	if len(targets.Signed.Targets) != len(wantNames) {
		t.Fatalf("published target count=%d, want %d", len(targets.Signed.Targets), len(wantNames))
	}
	for name := range targets.Signed.Targets {
		if _, ok := wantNames[name]; !ok {
			t.Fatalf("unexpected published target %q", name)
		}
		wantNames[name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("required published target %q is missing", name)
		}
	}
	for _, target := range supportedReleaseTargets() {
		name := releaseAssetName(target.platform, target.architecture)
		info := targets.Signed.Targets[name]
		var custom assetTargetCustom
		if info == nil || info.Custom == nil || json.Unmarshal(*info.Custom, &custom) != nil || custom.Schema != "paperboat.tuf-asset/v1" || custom.Kind != "github-release-asset" || custom.Version != version || custom.AssetName != name || custom.ReleaseIndex.Schema != "paperboat.release-index/v1" {
			t.Fatalf("asset %q custom metadata is invalid: %+v", name, custom)
		}
		if _, err := os.Stat(filepath.Join(repository, "targets")); err == nil {
			entries, readErr := os.ReadDir(filepath.Join(repository, "targets"))
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("local TUF target blobs were published: %v", readErr)
			}
		}
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

func TestSigningStateThresholdRequiresUniqueAuthorizedKeys(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	root, _, _, _, err := loadSet(repository)
	if err != nil {
		t.Fatal(err)
	}
	state := initialSigningState()
	state.Roles["targets"] = []string{"targets-1", "targets-1"}
	if err := validateSigningState(root, state, "targets"); err == nil || !strings.Contains(err.Error(), "unique authorized keys") {
		t.Fatalf("duplicate threshold error = %v", err)
	}
}

func TestValidateSignersTrustsRootChainAndDoesNotMutateRepository(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	trustedRoot := filepath.Join(repository, "metadata", "1.root.json")
	root, _, _, _, err := loadSet(repository)
	if err != nil {
		t.Fatal(err)
	}
	timestamp2Seed := bytes.Repeat([]byte{88}, ed25519.SeedSize)
	t.Setenv(tufKeyEnvironmentName("timestamp-2"), base64.RawStdEncoding.EncodeToString(timestamp2Seed))
	timestamp2, err := metadata.KeyFromPublicKey(ed25519.NewKeyFromSeed(timestamp2Seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	oldTimestampID := root.Signed.Roles["timestamp"].KeyIDs[0]
	if err := root.Signed.RevokeKey(oldTimestampID, "timestamp"); err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(timestamp2, "timestamp"); err != nil {
		t.Fatal(err)
	}
	root.Signed.Version = 2
	root.ClearSignatures()
	if err := sign(root, "root-1", "root-2", "root-3"); err != nil {
		t.Fatal(err)
	}
	rootBody := mustMetadataBytes(root)
	if err := os.WriteFile(filepath.Join(repository, "metadata", "2.root.json"), rootBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "metadata", "root.json"), rootBody, 0o600); err != nil {
		t.Fatal(err)
	}
	state := initialSigningState()
	state.Roles["timestamp"] = []string{"timestamp-2"}
	if err := writeSigningState(repository, state); err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(signingStatePath(repository))
	if err != nil {
		t.Fatal(err)
	}
	rootBefore, err := os.ReadFile(filepath.Join(repository, "metadata", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSigners(repository, trustedRoot); err != nil {
		t.Fatal(err)
	}
	stateAfter, _ := os.ReadFile(signingStatePath(repository))
	rootAfter, _ := os.ReadFile(filepath.Join(repository, "metadata", "root.json"))
	if !bytes.Equal(stateBefore, stateAfter) || !bytes.Equal(rootBefore, rootAfter) {
		t.Fatal("signer validation mutated the repository")
	}
	t.Setenv(tufKeyEnvironmentName("timestamp-2"), base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{99}, ed25519.SeedSize)))
	if err := validateSigners(repository, trustedRoot); err == nil || !strings.Contains(err.Error(), "timestamp-2 is not authorized for timestamp") {
		t.Fatalf("unauthorized rotated timestamp key error = %v", err)
	}
}

func TestValidateSignersRejectsUnchainedServedRoot(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	trustedRoot := filepath.Join(repository, "metadata", "1.root.json")
	served, err := metadata.Root().FromFile(filepath.Join(repository, "metadata", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	served.Signed.Version++
	served.ClearSignatures()
	if err := sign(served, "root-1", "root-2", "root-3"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "metadata", "root.json"), mustMetadataBytes(served), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSigners(repository, trustedRoot); err == nil || !strings.Contains(err.Error(), "served root does not match") {
		t.Fatalf("unchained served root error = %v", err)
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
	name := releaseAssetName("linux", "amd64")
	component := componentTarget{Component: "pb", TargetPath: name, AssetName: name, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/2026.08.18.8/" + name, SHA256: strings.Repeat("a", 64), Length: 100, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}
	body, err := json.Marshal(releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_2026.08.18.8", Version: "2026.08.18.8", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: []componentTarget{component}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1, Rollout: rolloutPolicy{Schema: "paperboat.release-rollout/v1", CohortSeed: "release-2026.08.18.8", Percentage: 5}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := releaseindex.Decode(bytes.NewReader(body), time.Now().UTC())
	if err != nil || decoded.Version != "2026.08.18.8" || len(decoded.Targets) != 1 || decoded.Targets[0].Component != "pb" {
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
