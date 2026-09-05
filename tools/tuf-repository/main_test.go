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
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
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
	if err := publish(repository, version, artifacts, evidencePaths, 1, "routine", false); err != nil {
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
	var signedManifestDigest, signedPlanDigest string
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
		if custom.ReleaseIndex.DeploymentPlan == nil || custom.ReleaseIndex.ManifestSHA256 == "" || custom.ReleaseIndex.DeploymentPlanSHA256 == "" {
			t.Fatalf("asset %q has no signed deployment policy: %+v", name, custom.ReleaseIndex)
		}
		if err := custom.ReleaseIndex.DeploymentPlan.Validate(); err != nil || custom.ReleaseIndex.DeploymentPlan.Version != version || custom.ReleaseIndex.DeploymentPlan.ManifestSHA256 != custom.ReleaseIndex.ManifestSHA256 {
			t.Fatalf("asset %q deployment policy is invalid: %+v err=%v", name, custom.ReleaseIndex.DeploymentPlan, err)
		}
		planDigest, err := custom.ReleaseIndex.DeploymentPlan.PlanSHA256()
		if err != nil || planDigest != custom.ReleaseIndex.DeploymentPlanSHA256 {
			t.Fatalf("asset %q deployment policy digest=%q want=%q err=%v", name, planDigest, custom.ReleaseIndex.DeploymentPlanSHA256, err)
		}
		if signedManifestDigest == "" {
			signedManifestDigest, signedPlanDigest = custom.ReleaseIndex.ManifestSHA256, custom.ReleaseIndex.DeploymentPlanSHA256
		} else if custom.ReleaseIndex.ManifestSHA256 != signedManifestDigest || custom.ReleaseIndex.DeploymentPlanSHA256 != signedPlanDigest {
			t.Fatalf("asset %q does not share signed release policy", name)
		}
		if _, err := os.Stat(filepath.Join(repository, "targets")); err == nil {
			entries, readErr := os.ReadDir(filepath.Join(repository, "targets"))
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("local TUF target blobs were published: %v", readErr)
			}
		}
	}
}

func TestRefreshRenewsOnlySnapshotAndTimestamp(t *testing.T) {
	repository := newPublishedTestRepository(t, "2026.08.22.16")

	rootBefore := readTestMetadata(t, filepath.Join(repository, "metadata", "root.json"))
	targetsBefore := readTestMetadata(t, filepath.Join(repository, "metadata", "targets.json"))
	snapshotBefore := readTestMetadata(t, filepath.Join(repository, "metadata", "snapshot.json"))
	timestampBefore := readTestMetadata(t, filepath.Join(repository, "metadata", "timestamp.json"))
	if err := refresh(repository); err != nil {
		t.Fatal(err)
	}

	rootAfter := readTestMetadata(t, filepath.Join(repository, "metadata", "root.json"))
	targetsAfter := readTestMetadata(t, filepath.Join(repository, "metadata", "targets.json"))
	snapshotAfter := readTestMetadata(t, filepath.Join(repository, "metadata", "snapshot.json"))
	timestampAfter := readTestMetadata(t, filepath.Join(repository, "metadata", "timestamp.json"))
	if !bytes.Equal(rootBefore, rootAfter) {
		t.Fatal("refresh changed root metadata")
	}
	if !bytes.Equal(targetsBefore, targetsAfter) {
		t.Fatal("refresh changed targets metadata")
	}

	root, targets, snapshot, timestamp, err := loadSet(repository)
	if err != nil {
		t.Fatal(err)
	}
	previousSnapshot, err := metadata.Snapshot().FromBytes(snapshotBefore)
	if err != nil {
		t.Fatal(err)
	}
	previousTimestamp, err := metadata.Timestamp().FromBytes(timestampBefore)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Signed.Version != previousSnapshot.Signed.Version+1 || timestamp.Signed.Version != previousTimestamp.Signed.Version+1 {
		t.Fatalf("versions after refresh: snapshot=%d timestamp=%d, before snapshot=%d timestamp=%d", snapshot.Signed.Version, timestamp.Signed.Version, previousSnapshot.Signed.Version, previousTimestamp.Signed.Version)
	}
	if !snapshot.Signed.Expires.After(time.Now().UTC()) || !timestamp.Signed.Expires.After(time.Now().UTC()) {
		t.Fatalf("refresh did not produce future expirations: snapshot=%s timestamp=%s", snapshot.Signed.Expires, timestamp.Signed.Expires)
	}
	if root.Signed.Version == 0 || targets.Signed.Version == 0 || snapshot.Signed.Meta["targets.json"].Version != targets.Signed.Version || timestamp.Signed.Meta["snapshot.json"].Version != snapshot.Signed.Version {
		t.Fatalf("refreshed metadata references are inconsistent: root=%d targets=%d snapshot=%d timestamp=%d", root.Signed.Version, targets.Signed.Version, snapshot.Signed.Version, timestamp.Signed.Version)
	}
	if bytes.Equal(snapshotBefore, snapshotAfter) || bytes.Equal(timestampBefore, timestampAfter) {
		t.Fatal("refresh did not rewrite snapshot and timestamp metadata")
	}
	if err := verifyPublished(repository); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRejectsExpiredTargetsWithoutChangingMetadata(t *testing.T) {
	repository := newPublishedTestRepository(t, "2026.08.22.17")
	targetsPath := filepath.Join(repository, "metadata", "targets.json")
	targets, err := metadata.Targets().FromFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	targets.Signed.Expires = time.Now().UTC().Add(-time.Minute)
	if err := os.WriteFile(targetsPath, mustMetadataBytes(targets), 0o600); err != nil {
		t.Fatal(err)
	}
	timestampBefore := readTestMetadata(t, filepath.Join(repository, "metadata", "timestamp.json"))
	if err := refresh(repository); err == nil || !strings.Contains(err.Error(), "expired targets metadata") {
		t.Fatalf("expired targets refresh error = %v", err)
	}
	if timestampAfter := readTestMetadata(t, filepath.Join(repository, "metadata", "timestamp.json")); !bytes.Equal(timestampBefore, timestampAfter) {
		t.Fatal("failed refresh changed timestamp metadata")
	}
}

func newPublishedTestRepository(t *testing.T, version string) string {
	t.Helper()
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	for index, name := range roles {
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 31)}, ed25519.SeedSize)))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	artifacts := t.TempDir()
	for _, target := range supportedReleaseTargets() {
		name := releaseAssetName(target.platform, target.architecture)
		if err := os.WriteFile(filepath.Join(artifacts, name), []byte("test release asset "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidencePaths := make(map[string]string, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		evidence := []byte(`{"schema":"paperboat.windows-native-qualification/v1","release_version":"` + version + `","platform":"windows","architecture":"` + architecture + `","status":"passed","native_tested":true,"windows_build":"26100","runner":"refresh-test-` + architecture + `"}`)
		evidencePath := filepath.Join(artifacts, windowsNativeQualificationTarget(architecture))
		if err := os.WriteFile(evidencePath, evidence, 0o600); err != nil {
			t.Fatal(err)
		}
		evidencePaths[architecture] = evidencePath
	}
	if err := publish(repository, version, artifacts, evidencePaths, 1, "routine", false); err != nil {
		t.Fatal(err)
	}
	return repository
}

func readTestMetadata(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
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

func TestVerifyPublishedRejectsTamperedSignedDeploymentPolicy(t *testing.T) {
	t.Setenv("PAPERBOAT_TUF_CI", "1")
	t.Setenv("PAPERBOAT_RELEASE_SOURCE_COMMIT", strings.Repeat("c", 40))
	t.Setenv("PAPERBOAT_RELEASE_TOOLCHAIN", "go1.26.6")
	for index, name := range roles {
		seed := bytes.Repeat([]byte{byte(index + 11)}, ed25519.SeedSize)
		t.Setenv(tufKeyEnvironmentName(name), base64.RawStdEncoding.EncodeToString(seed))
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := initialize(repository); err != nil {
		t.Fatal(err)
	}
	artifacts := t.TempDir()
	version := "2026.08.22.14"
	for _, target := range supportedReleaseTargets() {
		name := releaseAssetName(target.platform, target.architecture)
		if err := os.WriteFile(filepath.Join(artifacts, name), []byte("tamper-test-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidencePaths := make(map[string]string, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		evidence, err := json.Marshal(windowsNativeQualification{Schema: windowsNativeQualificationSchema, ReleaseVersion: version, Platform: "windows", Architecture: architecture, Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "tamper-test-" + architecture})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(artifacts, windowsNativeQualificationTarget(architecture))
		if err := os.WriteFile(path, evidence, 0o600); err != nil {
			t.Fatal(err)
		}
		evidencePaths[architecture] = path
	}
	if err := publish(repository, version, artifacts, evidencePaths, 3, "routine", false); err != nil {
		t.Fatal(err)
	}
	targetsPath := filepath.Join(repository, "metadata", "targets.json")
	targets, err := metadata.Targets().FromFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	name := releaseAssetName("linux", "amd64")
	info := targets.Signed.Targets[name]
	if info == nil || info.Custom == nil {
		t.Fatal("published target custom metadata is missing")
	}
	var custom assetTargetCustom
	if err := json.Unmarshal(*info.Custom, &custom); err != nil || custom.ReleaseIndex.DeploymentPlan == nil {
		t.Fatalf("decode signed policy: %v", err)
	}
	custom.ReleaseIndex.DeploymentPlan.Canary.Path = "/tampered"
	mutated, err := json.Marshal(custom)
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(mutated)
	info.Custom = &raw
	if err := os.WriteFile(targetsPath, mustMetadataBytes(targets), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublished(repository); err == nil {
		t.Fatal("tampered signed deployment policy unexpectedly verified")
	}
}

func TestPublicationPreflightRejectsMissingRequiredPolicyFields(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	custom := validAssetTargetCustomFixture(t, now)
	body, err := json.Marshal(custom)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	var releaseIndexDocument map[string]json.RawMessage
	if err := json.Unmarshal(document["release_index"], &releaseIndexDocument); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"manifest_sha256", "deployment_plan_sha256", "deployment_plan"} {
		t.Run(field, func(t *testing.T) {
			missing := make(map[string]json.RawMessage, len(releaseIndexDocument))
			for key, value := range releaseIndexDocument {
				missing[key] = value
			}
			delete(missing, field)
			document["release_index"], err = json.Marshal(missing)
			if err != nil {
				t.Fatal(err)
			}
			malformed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeAndValidateAssetTargetCustom(malformed, now); err == nil {
				t.Fatalf("missing %s passed the publication preflight", field)
			}
		})
	}

	valid, err := decodeAndValidateAssetTargetCustom(body, now)
	if err != nil || valid.ReleaseIndex.ManifestSHA256 == "" || valid.ReleaseIndex.DeploymentPlanSHA256 == "" || valid.ReleaseIndex.DeploymentPlan == nil {
		t.Fatalf("complete policy failed the publication preflight: custom=%+v err=%v", valid, err)
	}
}

func validAssetTargetCustomFixture(t *testing.T, now time.Time) assetTargetCustom {
	t.Helper()
	version := "2026.08.22.15"
	manifest := strings.Repeat("a", 64)
	plan, err := releasepolicy.Default(version, manifest, 1, "routine", "release-seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := plan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	name := releaseAssetName("linux", "amd64")
	digest := strings.Repeat("b", 64)
	component := componentTarget{Component: "pb", TargetPath: name, AssetName: name, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/" + version + "/" + name, SHA256: digest, Length: 4, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}
	index := releaseIndex{Schema: releaseindex.SchemaV1, ReleaseID: "rel_" + version, Version: version, Channel: "stable", Severity: "routine", CreatedAt: now, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: []componentTarget{component}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: plan.PolicyRevision, ManifestSHA256: manifest, DeploymentPlanSHA256: planDigest, DeploymentPlan: &plan}
	return assetTargetCustom{Schema: "paperboat.tuf-asset/v1", Kind: "github-release-asset", Version: version, Platform: "linux", Architecture: "amd64", Format: "elf", AssetName: name, Repository: component.Repository, URL: component.DownloadURL, SHA256: digest, Length: component.Length, ReleaseIndex: index}
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
	manifestDigest := strings.Repeat("a", 64)
	plan, err := releasepolicy.Default("2026.08.18.8", manifestDigest, 1, "routine", "release-seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := plan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_2026.08.18.8", Version: "2026.08.18.8", Channel: "stable", Severity: "routine", CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: []componentTarget{component}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: plan.PolicyRevision, ManifestSHA256: manifestDigest, DeploymentPlanSHA256: planDigest, DeploymentPlan: &plan})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := releaseindex.Decode(bytes.NewReader(body), time.Now().UTC())
	if err != nil || decoded.Version != "2026.08.18.8" || len(decoded.Targets) != 1 || decoded.Targets[0].Component != "pb" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}

func TestDeploymentPolicyMutationsAreMonotonicAndConsistent(t *testing.T) {
	plan, err := releasepolicy.Default("2026.08.18.8", strings.Repeat("a", 64), 4, "routine", "release-seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := applyDeploymentMutation(&plan, "promote", 5, 25); err != nil || plan.RolloutState != releasepolicy.RolloutStateActive {
		t.Fatalf("promote plan=%+v err=%v", plan, err)
	}
	if plan.Cohorts[0].Percentage != 25 || plan.Cohorts[1].Percentage != 25 || plan.Cohorts[2].Percentage != 100 {
		t.Fatalf("promote percentages=%v", plan.Cohorts)
	}
	if err := applyDeploymentMutation(&plan, "pause", 6, 0); err != nil || plan.RolloutState != releasepolicy.RolloutStatePaused {
		t.Fatalf("pause plan=%+v err=%v", plan, err)
	}
	if err := applyDeploymentMutation(&plan, "quarantine", 7, 0); err != nil || plan.RolloutState != releasepolicy.RolloutStateQuarantined {
		t.Fatalf("quarantine plan=%+v err=%v", plan, err)
	}
	for _, test := range []struct {
		op         string
		revision   uint64
		percentage uint8
	}{{"promote", 8, 50}, {"pause", 8, 1}, {"unknown", 8, 0}, {"promote", 6, 50}} {
		copy := plan
		if err := applyDeploymentMutation(&copy, test.op, test.revision, test.percentage); err == nil {
			t.Fatalf("mutation %+v unexpectedly succeeded", test)
		}
	}
}
