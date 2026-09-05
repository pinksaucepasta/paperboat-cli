package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
	"github.com/pinksaucepasta/paperboat/tools/releaseplan"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const keychainService = "com.pinksaucepasta.paperboat.tuf.production"
const windowsNativeQualificationSchema = "paperboat.windows-native-qualification/v1"

var releaseVersionPattern = regexp.MustCompile(`^20[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$`)

func windowsNativeQualificationTarget(architecture string) string {
	return "windows-" + architecture + "-native-qualification.json"
}

func releaseRepository() string {
	if value := strings.TrimSpace(os.Getenv("PAPERBOAT_GITHUB_REPOSITORY")); value != "" {
		return value
	}
	return "pinksaucepasta/paperboat-cli"
}

func releaseAssetName(platform, architecture string) string {
	return releaseindex.AssetName(platform, architecture)
}

func releaseAssetFormat(platform string) string {
	switch platform {
	case "darwin":
		return "pkg"
	case "linux":
		return "elf"
	case "windows":
		return "pe"
	default:
		return ""
	}
}

var roles = []string{"root-1", "root-2", "root-3", "targets-1", "targets-2", "snapshot-1", "timestamp-1"}

// Keep the publisher's release-index wire model exactly aligned with the
// runtime verifier. In particular, the policy digests and deployment plan are
// required fields and must never drift into an optional/omitempty encoding.
type componentTarget = releaseindex.Target
type releaseIndex = releaseindex.Index

type windowsNativeQualification struct {
	Schema         string `json:"schema"`
	ReleaseVersion string `json:"release_version"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	Status         string `json:"status"`
	NativeTested   bool   `json:"native_tested"`
	WindowsBuild   string `json:"windows_build"`
	Runner         string `json:"runner"`
}

// assetTargetCustom is the only custom target published for a release. It
// binds the TUF digest to the immutable GitHub asset URL and carries the
// signed release policy inline, so no release-index JSON or target bytes need
// to be served by the Paperboat origin.
type assetTargetCustom struct {
	Schema       string       `json:"schema"`
	Kind         string       `json:"kind"`
	Version      string       `json:"version"`
	Platform     string       `json:"platform"`
	Architecture string       `json:"architecture"`
	Format       string       `json:"format"`
	AssetName    string       `json:"asset_name"`
	Repository   string       `json:"repository"`
	URL          string       `json:"url"`
	SHA256       string       `json:"sha256"`
	Length       int64        `json:"length"`
	ReleaseIndex releaseIndex `json:"release_index"`
}
type signingState struct {
	Schema string              `json:"schema"`
	Roles  map[string][]string `json:"roles"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "paperboat-tuf:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if runtime.GOOS != "darwin" && os.Getenv("PAPERBOAT_TUF_CI") != "1" {
		return errors.New("production signing is restricted to the macOS release workstation")
	}
	if len(args) == 0 {
		return errors.New("usage: paperboat-tuf <init|publish|promote|pause|quarantine|refresh|rotate|status|validate-signers|verify-published>")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf init -repository DIR")
		}
		return initialize(*repo)
	case "publish":
		fs := flag.NewFlagSet("publish", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		version := fs.String("version", "", "release version")
		artifacts := fs.String("artifacts", "", "release artifact directory")
		rolloutRevision := fs.Uint64("rollout-revision", 0, "monotonic signed rollout policy revision")
		severity := fs.String("severity", "routine", "routine, security, or critical")
		manifestPath := fs.String("manifest", "", "precomputed exact five-artifact manifest")
		planPath := fs.String("deployment-plan", "", "precomputed signed deployment policy input")
		supervisorMaintenance := fs.Bool("supervisor-maintenance", false, "release updates stable supervisor components")
		amd64QualificationEvidence := fs.String("windows-amd64-native-evidence", "", "absolute JSON evidence for Windows amd64 native qualification")
		arm64QualificationEvidence := fs.String("windows-arm64-native-evidence", "", "absolute JSON evidence for Windows arm64 native qualification")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf publish -repository DIR -version VERSION -artifacts DIR -manifest FILE -deployment-plan FILE -windows-amd64-native-evidence FILE -windows-arm64-native-evidence FILE -rollout-revision N")
		}
		if *rolloutRevision == 0 || (*severity != "routine" && *severity != "security" && *severity != "critical") {
			return errors.New("valid rollout revision and severity are required")
		}
		return publishWithPolicy(*repo, *version, *artifacts, map[string]string{"amd64": *amd64QualificationEvidence, "arm64": *arm64QualificationEvidence}, *rolloutRevision, *severity, *supervisorMaintenance, *manifestPath, *planPath)
	case "refresh":
		fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf refresh -repository DIR")
		}
		return refresh(*repo)
	case "promote", "pause", "quarantine":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		revision := fs.Uint64("rollout-revision", 0, "new monotonic signed rollout policy revision")
		percentage := fs.Uint("percentage", 0, "eligible cohort percentage (promote only)")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *revision == 0 || *percentage > 100 || args[0] != "promote" && *percentage != 0 {
			return fmt.Errorf("usage: paperboat-tuf %s -repository DIR -rollout-revision N%s", args[0], map[bool]string{true: " -percentage 0..100"}[args[0] == "promote"])
		}
		return mutateRollout(*repo, args[0], *revision, uint8(*percentage))
	case "rotate":
		fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		role := fs.String("role", "", "root, targets, snapshot, or timestamp")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf rotate -repository DIR -role ROLE")
		}
		return rotate(*repo, *role)
	case "status":
		fs := flag.NewFlagSet("status", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf status -repository DIR")
		}
		return status(*repo)
	case "validate-signers":
		fs := flag.NewFlagSet("validate-signers", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		trustedRoot := fs.String("trusted-root", "", "absolute trusted root metadata file")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf validate-signers -repository DIR -trusted-root FILE")
		}
		return validateSigners(*repo, *trustedRoot)
	case "verify-published":
		fs := flag.NewFlagSet("verify-published", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf verify-published -repository DIR")
		}
		return verifyPublished(*repo)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// validateSigners performs the release authority gate without changing the
// repository. It first advances from the client's embedded trusted root
// through every numbered root, then binds the configured online private keys
// to the roles authorized by that trusted current root.
func validateSigners(repo, trustedRootPath string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(trustedRootPath) || filepath.Clean(trustedRootPath) != trustedRootPath {
		return errors.New("trusted root path must be absolute and clean")
	}
	trusted, err := metadata.Root().FromFile(trustedRootPath)
	if err != nil {
		return fmt.Errorf("load trusted root: %w", err)
	}
	if err := verifyRoot(trusted); err != nil {
		return fmt.Errorf("verify trusted root: %w", err)
	}
	current := trusted
	for version := trusted.Signed.Version + 1; ; version++ {
		path := filepath.Join(repo, "metadata", fmt.Sprintf("%d.root.json", version))
		next, loadErr := metadata.Root().FromFile(path)
		if errors.Is(loadErr, os.ErrNotExist) {
			break
		}
		if loadErr != nil {
			return fmt.Errorf("load root version %d: %w", version, loadErr)
		}
		if next.Signed.Version != version {
			return fmt.Errorf("root version %d has invalid signed version %d", version, next.Signed.Version)
		}
		if err := current.VerifyDelegate("root", next); err != nil {
			return fmt.Errorf("verify root version %d with previous root: %w", version, err)
		}
		if err := verifyRoot(next); err != nil {
			return fmt.Errorf("verify root version %d with new root: %w", version, err)
		}
		current = next
	}
	served, err := metadata.Root().FromFile(filepath.Join(repo, "metadata", "root.json"))
	if err != nil {
		return fmt.Errorf("load served root: %w", err)
	}
	if served.Signed.Version != current.Signed.Version || !bytes.Equal(mustMetadataBytes(served), mustMetadataBytes(current)) {
		return errors.New("served root does not match the trusted numbered root chain")
	}
	state, err := loadSigningState(repo, current, "targets", "snapshot", "timestamp")
	if err != nil {
		return err
	}
	count := len(state.Roles["targets"]) + len(state.Roles["snapshot"]) + len(state.Roles["timestamp"])
	fmt.Printf("root=%d online_signers=%d validated\n", current.Signed.Version, count)
	return nil
}

// verifyPublished checks the complete metadata set as it will be served. In
// particular, it catches a partial publication that leaves timestamp.json or
// snapshot.json present while omitting the versioned files they reference.
func verifyPublished(repo string) error {
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return fmt.Errorf("load published metadata: %w", err)
	}
	if err := verifyRoot(root); err != nil {
		return fmt.Errorf("verify root: %w", err)
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		return fmt.Errorf("verify targets: %w", err)
	}
	if err := root.VerifyDelegate("snapshot", snapshot); err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	if err := root.VerifyDelegate("timestamp", timestamp); err != nil {
		return fmt.Errorf("verify timestamp: %w", err)
	}
	if err := verifyPublishedDeploymentPolicies(targets); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		body []byte
	}{
		{fmt.Sprintf("%d.root.json", root.Signed.Version), mustMetadataBytes(root)},
		{fmt.Sprintf("%d.targets.json", targets.Signed.Version), mustMetadataBytes(targets)},
		{fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version), mustMetadataBytes(snapshot)},
	} {
		if err := verifyPublishedFile(filepath.Join(repo, "metadata", item.name), item.body); err != nil {
			return err
		}
	}
	if err := verifyPublishedFile(filepath.Join(repo, "metadata", "timestamp.json"), mustMetadataBytes(timestamp)); err != nil {
		return err
	}
	if meta, ok := timestamp.Signed.Meta["snapshot.json"]; ok {
		if err := verifyMetaReference(repo, fmt.Sprintf("%d.snapshot.json", meta.Version), meta); err != nil {
			return err
		}
	} else {
		return errors.New("timestamp does not reference snapshot.json")
	}
	for name, meta := range snapshot.Signed.Meta {
		if err := verifyMetaReference(repo, fmt.Sprintf("%d.%s", meta.Version, name), meta); err != nil {
			return err
		}
	}
	return nil
}

// decodeAndValidateAssetTargetCustom validates the exact custom metadata
// bytes that will be signed or served. Decoding into the runtime release-index
// type is intentional: it catches omitted required fields at the JSON boundary
// instead of trusting a publisher-side struct that may have silently supplied
// zero values. The same preflight is used before signing and after publication.
func decodeAndValidateAssetTargetCustom(body []byte, now time.Time) (assetTargetCustom, error) {
	if len(body) == 0 {
		return assetTargetCustom{}, errors.New("signed asset custom metadata is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var custom assetTargetCustom
	var extra any
	if err := decoder.Decode(&custom); err != nil {
		return assetTargetCustom{}, fmt.Errorf("decode signed asset custom metadata: %w", err)
	}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return assetTargetCustom{}, errors.New("signed asset custom metadata has trailing JSON")
		}
		return assetTargetCustom{}, fmt.Errorf("decode signed asset custom metadata trailer: %w", err)
	}
	if custom.Schema != "paperboat.tuf-asset/v1" || custom.Kind != "github-release-asset" {
		return assetTargetCustom{}, errors.New("signed asset custom metadata has an invalid schema")
	}
	indexBody, err := json.Marshal(custom.ReleaseIndex)
	if err != nil {
		return assetTargetCustom{}, fmt.Errorf("encode signed release index: %w", err)
	}
	index, err := releaseindex.Decode(bytes.NewReader(indexBody), now)
	if err != nil {
		return assetTargetCustom{}, fmt.Errorf("signed release index is invalid: %w", err)
	}
	target, ok := index.Component("pb")
	if !ok || custom.Version != index.Version || custom.Platform != index.Platform || custom.Architecture != index.Architecture || custom.Format != index.BinaryFormat || custom.AssetName != target.AssetName || custom.Repository != target.Repository || custom.URL != target.DownloadURL || custom.SHA256 != target.SHA256 || custom.Length != target.Length {
		return assetTargetCustom{}, errors.New("signed asset custom metadata does not match its release index")
	}
	return custom, nil
}

func verifyPublishedDeploymentPolicies(targets *metadata.Metadata[metadata.TargetsType]) error {
	return verifyPublishedDeploymentPoliciesAt(targets, time.Now().UTC())
}

func verifyPublishedDeploymentPoliciesAt(targets *metadata.Metadata[metadata.TargetsType], now time.Time) error {
	if targets == nil || len(targets.Signed.Targets) != len(supportedReleaseTargets()) {
		return errors.New("published TUF targets do not contain the exact release set")
	}
	var manifestDigest, planDigest string
	var planBytes []byte
	for _, releaseTarget := range supportedReleaseTargets() {
		name := releaseAssetName(releaseTarget.platform, releaseTarget.architecture)
		info := targets.Signed.Targets[name]
		if info == nil || info.Custom == nil {
			return fmt.Errorf("published TUF target %s has no signed custom metadata", name)
		}
		custom, err := decodeAndValidateAssetTargetCustom(*info.Custom, now)
		if err != nil {
			return fmt.Errorf("published TUF target %s has invalid deployment policy: %w", name, err)
		}
		target, ok := custom.ReleaseIndex.Component("pb")
		digest, hasDigest := info.Hashes["sha256"]
		if !ok || !hasDigest || len(digest) != sha256.Size || info.Length != target.Length || hex.EncodeToString(digest) != target.SHA256 {
			return fmt.Errorf("published TUF target %s does not match its signed release index", name)
		}
		plan := custom.ReleaseIndex.DeploymentPlan
		if err := plan.Validate(); err != nil || plan.Version != custom.Version || plan.ManifestSHA256 != custom.ReleaseIndex.ManifestSHA256 || custom.ReleaseIndex.DeploymentPlanSHA256 == "" {
			return fmt.Errorf("published TUF target %s has an invalid deployment policy binding", name)
		}
		actualPlanDigest, err := plan.PlanSHA256()
		if err != nil || actualPlanDigest != custom.ReleaseIndex.DeploymentPlanSHA256 {
			return fmt.Errorf("published TUF target %s has a deployment policy digest mismatch", name)
		}
		if len(custom.ReleaseIndex.ManifestSHA256) != sha256.Size*2 || !lowerHex(custom.ReleaseIndex.ManifestSHA256) {
			return fmt.Errorf("published TUF target %s has an invalid manifest digest", name)
		}
		encoded, err := plan.Bytes()
		if err != nil {
			return fmt.Errorf("encode deployment policy %s: %w", name, err)
		}
		if manifestDigest == "" {
			manifestDigest, planDigest, planBytes = custom.ReleaseIndex.ManifestSHA256, custom.ReleaseIndex.DeploymentPlanSHA256, encoded
		} else if manifestDigest != custom.ReleaseIndex.ManifestSHA256 || planDigest != custom.ReleaseIndex.DeploymentPlanSHA256 || !bytes.Equal(planBytes, encoded) {
			return errors.New("published TUF targets do not share one immutable deployment policy")
		}
	}
	return nil
}

// validateTargetsForPublication is the write/signing boundary for release
// targets. An empty target set is valid only for a newly initialized
// repository; once targets exist, the complete five-asset contract must pass
// the same validation used by verify-published.
func validateTargetsForPublication(targets *metadata.Metadata[metadata.TargetsType], now time.Time) error {
	if targets == nil {
		return errors.New("TUF targets metadata is nil")
	}
	if len(targets.Signed.Targets) == 0 {
		return nil
	}
	return verifyPublishedDeploymentPoliciesAt(targets, now)
}

func verifyMetaReference(repo, name string, meta *metadata.MetaFiles) error {
	body, err := os.ReadFile(filepath.Join(repo, "metadata", name))
	if err != nil {
		return fmt.Errorf("missing referenced metadata %s: %w", name, err)
	}
	if meta.Length != 0 && int64(len(body)) != meta.Length {
		return fmt.Errorf("metadata length mismatch %s", name)
	}
	if digest, ok := meta.Hashes["sha256"]; ok {
		sum := sha256.Sum256(body)
		if !bytes.Equal(sum[:], digest) {
			return fmt.Errorf("metadata hash mismatch %s", name)
		}
	}
	return nil
}

func mustMetadataBytes[T metadata.Roles](value *metadata.Metadata[T]) []byte {
	body, err := value.ToBytes(false)
	if err != nil {
		panic(err)
	}
	return body
}

func verifyPublishedFile(path string, expected []byte) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("missing published metadata %s: %w", filepath.Base(path), err)
	}
	if !bytes.Equal(body, expected) {
		return fmt.Errorf("published metadata differs from signed set: %s", filepath.Base(path))
	}
	return nil
}

func initialize(repo string) error {
	repo, err := validateRepository(repo, false)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(repo, "metadata", "1.root.json")); err == nil {
		if _, stateErr := os.Stat(signingStatePath(repo)); stateErr == nil {
			return errors.New("repository is already initialized")
		}
		root, loadErr := metadata.Root().FromFile(filepath.Join(repo, "metadata", "root.json"))
		if loadErr != nil {
			return loadErr
		}
		state := initialSigningState()
		if matchErr := validateSigningState(root, state); matchErr != nil {
			return matchErr
		}
		return writeSigningState(repo, state)
	}
	for _, name := range roles {
		if _, err := loadKey(name); err == nil {
			continue
		}
		if keyExists(name) {
			return fmt.Errorf("Keychain item %q exists but cannot be loaded", name)
		}
		if err := createKey(name); err != nil {
			return err
		}
	}
	root := metadata.Root(time.Now().UTC().Add(730 * 24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, name := range roles {
		private, err := loadKey(name)
		if err != nil {
			return err
		}
		role := strings.TrimSuffix(name, "-1")
		role = strings.TrimSuffix(role, "-2")
		role = strings.TrimSuffix(role, "-3")
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			return err
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			return err
		}
	}
	root.Signed.Roles["root"].Threshold = 2
	root.Signed.Roles["targets"].Threshold = 2
	if err := sign(root, "root-1", "root-2"); err != nil {
		return err
	}
	if err := verifyRoot(root); err != nil {
		return err
	}
	targets := metadata.Targets(time.Now().UTC().Add(90 * 24 * time.Hour))
	if err := sign(targets, "targets-1", "targets-2"); err != nil {
		return err
	}
	snapshot := metadata.Snapshot(time.Now().UTC().Add(7 * 24 * time.Hour))
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)
	if err := sign(snapshot, "snapshot-1"); err != nil {
		return err
	}
	timestamp := metadata.Timestamp(time.Now().UTC().Add(24 * time.Hour))
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
	if err := sign(timestamp, "timestamp-1"); err != nil {
		return err
	}
	if err := writeSet(repo, root, targets, snapshot, timestamp); err != nil {
		return err
	}
	return writeSigningState(repo, initialSigningState())
}

func publish(repo, version, artifacts string, qualificationEvidencePaths map[string]string, rolloutRevision uint64, severity string, supervisorMaintenance bool) error {
	return publishWithPolicy(repo, version, artifacts, qualificationEvidencePaths, rolloutRevision, severity, supervisorMaintenance, "", "")
}

func publishWithPolicy(repo, version, artifacts string, qualificationEvidencePaths map[string]string, rolloutRevision uint64, severity string, supervisorMaintenance bool, manifestPath, planPath string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if !releaseVersionPattern.MatchString(version) || !filepath.IsAbs(artifacts) || filepath.Clean(artifacts) != artifacts {
		return errors.New("version must be YYYY.MM.DD.N and artifacts must be an absolute clean directory")
	}
	manifest, deploymentPlan, err := loadPublicationPolicy(artifacts, version, rolloutRevision, severity, manifestPath, planPath)
	if err != nil {
		return err
	}
	manifestSHA256, err := manifest.SHA256()
	if err != nil {
		return fmt.Errorf("hash release manifest: %w", err)
	}
	deploymentPlanSHA256, err := deploymentPlan.PlanSHA256()
	if err != nil {
		return fmt.Errorf("hash deployment plan: %w", err)
	}
	qualifications := make(map[string]windowsNativeQualification, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		path := strings.TrimSpace(qualificationEvidencePaths[architecture])
		if path == "" {
			return fmt.Errorf("absolute Windows %s native qualification evidence is required", architecture)
		}
		qualification, _, _, err := loadWindowsNativeQualification(path, architecture)
		if err != nil {
			return err
		}
		if err := validateWindowsNativeQualificationHeader(qualification, version, architecture); err != nil {
			return err
		}
		qualifications[architecture] = qualification
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	state, err := loadSigningState(repo, root, "targets", "snapshot", "timestamp")
	if err != nil {
		return err
	}
	targets.Signed.Targets = map[string]*metadata.TargetFiles{}
	createdAt := time.Now().UTC()
	githubRepository := releaseRepository()
	for _, releaseTarget := range supportedReleaseTargets() {
		platform, architecture := releaseTarget.platform, releaseTarget.architecture
		format := releaseAssetFormat(platform)
		name := releaseAssetName(platform, architecture)
		local := filepath.Join(artifacts, name)
		info, err := metadata.TargetFile().FromFile(local, "sha256")
		if err != nil {
			return fmt.Errorf("release asset %s: %w", name, err)
		}
		digest := hex.EncodeToString(info.Hashes["sha256"])
		manifestArtifact, ok := manifest.Artifact(name)
		if !ok || manifestArtifact.Length != info.Length || manifestArtifact.SHA256 != digest {
			return fmt.Errorf("release asset %s does not match the release manifest", name)
		}
		downloadURL := "https://github.com/" + githubRepository + "/releases/download/" + version + "/" + name
		if !releaseindex.ValidDownloadURL(downloadURL, githubRepository, version, name) {
			return fmt.Errorf("GitHub repository %q or release URL is invalid", githubRepository)
		}
		component := componentTarget{Component: "pb", TargetPath: name, AssetName: name, Repository: githubRepository, DownloadURL: downloadURL, SHA256: digest, Length: info.Length, Platform: platform, Architecture: architecture, BinaryFormat: format}
		channel, stability, nativeTested := "stable", "", false
		var testedBuilds []string
		openSSHID, openSSHVersion := "", ""
		if platform == "windows" {
			stability = "stable"
			openSSHID, openSSHVersion = "Microsoft.OpenSSH.Preview", "10.0.0.0"
			qualification := qualifications[architecture]
			nativeTested, testedBuilds = true, []string{qualification.WindowsBuild}
		}
		planCopy := deploymentPlan
		index := releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_" + version, Version: version, Channel: channel, Severity: severity, CreatedAt: createdAt, Platform: platform, Architecture: architecture, BinaryFormat: format, Targets: []componentTarget{component}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: deploymentPlan.PolicyRevision, SupervisorMaintenance: supervisorMaintenance, Stability: stability, NativeTested: nativeTested, TestedWindowsBuilds: testedBuilds, OpenSSHPackageID: openSSHID, OpenSSHApprovedVersion: openSSHVersion, ManifestSHA256: manifestSHA256, DeploymentPlanSHA256: deploymentPlanSHA256, DeploymentPlan: &planCopy}
		custom := assetTargetCustom{Schema: "paperboat.tuf-asset/v1", Kind: "github-release-asset", Version: version, Platform: platform, Architecture: architecture, Format: format, AssetName: name, Repository: githubRepository, URL: downloadURL, SHA256: digest, Length: info.Length, ReleaseIndex: index}
		customBody, err := json.Marshal(custom)
		if err != nil {
			return err
		}
		if _, err := decodeAndValidateAssetTargetCustom(customBody, createdAt); err != nil {
			return fmt.Errorf("release asset %s failed publication preflight: %w", name, err)
		}
		raw := json.RawMessage(customBody)
		info.Custom, info.Path = &raw, name
		targets.Signed.Targets[name] = info
	}
	if err := validateTargetsForPublication(targets, createdAt); err != nil {
		return fmt.Errorf("release publication preflight failed: %w", err)
	}
	targets.Signed.Version++
	targets.Signed.Expires = time.Now().UTC().Add(90 * 24 * time.Hour)
	targets.ClearSignatures()
	if err := sign(targets, state.Roles["targets"]...); err != nil {
		return err
	}
	snapshot.Signed.Version++
	snapshot.Signed.Expires = time.Now().UTC().Add(7 * 24 * time.Hour)
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)
	snapshot.ClearSignatures()
	if err := sign(snapshot, state.Roles["snapshot"]...); err != nil {
		return err
	}
	timestamp.Signed.Version++
	timestamp.Signed.Expires = time.Now().UTC().Add(24 * time.Hour)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
	timestamp.ClearSignatures()
	if err := sign(timestamp, state.Roles["timestamp"]...); err != nil {
		return err
	}
	return writeSet(repo, root, targets, snapshot, timestamp)
}

func loadPublicationPolicy(artifacts, version string, rolloutRevision uint64, severity, manifestPath, planPath string) (releaseplan.Manifest, releaseplan.Plan, error) {
	if (manifestPath == "") != (planPath == "") {
		return releaseplan.Manifest{}, releaseplan.Plan{}, errors.New("manifest and deployment plan must be supplied together")
	}
	if manifestPath != "" {
		manifest, err := releaseplan.LoadManifest(manifestPath)
		if err != nil {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("load release manifest: %w", err)
		}
		if err := releaseplan.VerifyManifest(manifest, artifacts); err != nil {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("verify release manifest: %w", err)
		}
		plan, err := releaseplan.LoadPlan(planPath)
		if err != nil {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("load deployment plan: %w", err)
		}
		if err := releaseplan.ValidatePlanAgainstManifest(plan, manifest); err != nil || plan.Version != version || plan.PolicyRevision != rolloutRevision || plan.Severity != severity {
			return releaseplan.Manifest{}, releaseplan.Plan{}, errors.New("deployment plan does not match release publication inputs")
		}
		return manifest, plan, nil
	}
	commit, err := releaseSourceCommit()
	if err != nil {
		return releaseplan.Manifest{}, releaseplan.Plan{}, err
	}
	toolchain, err := releaseToolchain()
	if err != nil {
		return releaseplan.Manifest{}, releaseplan.Plan{}, err
	}
	specs := releaseplan.ArtifactSpecs()
	artifactsForManifest := make([]releaseplan.Artifact, 0, len(specs))
	for _, spec := range specs {
		path := filepath.Join(artifacts, spec.Name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > releaseplan.MaxArtifactBytes {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("release asset %s is invalid", spec.Name)
		}
		file, err := os.Open(path)
		if err != nil {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("open release asset %s: %w", spec.Name, err)
		}
		hash := sha256.New()
		length, copyErr := io.Copy(hash, io.LimitReader(file, releaseplan.MaxArtifactBytes+1))
		stat, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || stat == nil || length != info.Size() || length > releaseplan.MaxArtifactBytes || !os.SameFile(info, stat) || !info.ModTime().Equal(stat.ModTime()) {
			return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("release asset %s changed while hashing", spec.Name)
		}
		artifactsForManifest = append(artifactsForManifest, releaseplan.Artifact{Name: spec.Name, Platform: spec.Platform, Architecture: spec.Architecture, Format: spec.Format, Length: length, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	manifest, err := releaseplan.NewManifest(version, commit, toolchain, artifactsForManifest)
	if err != nil {
		return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("build release manifest: %w", err)
	}
	plan, err := releaseplan.DefaultPlan(manifest, rolloutRevision, severity, "release-"+version)
	if err != nil {
		return releaseplan.Manifest{}, releaseplan.Plan{}, fmt.Errorf("build deployment plan: %w", err)
	}
	return manifest, plan, nil
}

func releaseSourceCommit() (string, error) {
	for _, name := range []string{"PAPERBOAT_RELEASE_SOURCE_COMMIT", "GITHUB_SHA"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			if !regexp.MustCompile(`^[a-f0-9]{40,64}$`).MatchString(value) {
				return "", fmt.Errorf("%s is not a lowercase commit SHA", name)
			}
			return value, nil
		}
	}
	output, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", errors.New("release source commit is unavailable; set PAPERBOAT_RELEASE_SOURCE_COMMIT")
	}
	value := strings.TrimSpace(string(output))
	if !regexp.MustCompile(`^[a-f0-9]{40,64}$`).MatchString(value) {
		return "", errors.New("git release source commit is invalid")
	}
	return value, nil
}

func releaseToolchain() (string, error) {
	value := strings.TrimSpace(os.Getenv("PAPERBOAT_RELEASE_TOOLCHAIN"))
	if value == "" {
		value = runtime.Version()
	}
	if !regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(value) {
		return "", errors.New("release toolchain is unavailable; set PAPERBOAT_RELEASE_TOOLCHAIN")
	}
	return value, nil
}

func lowerHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) > 0 && value == strings.ToLower(value)
}

func loadWindowsNativeQualification(path, architecture string) (windowsNativeQualification, []byte, string, error) {
	if architecture != "amd64" && architecture != "arm64" {
		return windowsNativeQualification{}, nil, "", errors.New("Windows native qualification architecture is invalid")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return windowsNativeQualification{}, nil, "", fmt.Errorf("absolute Windows %s native qualification evidence is required", architecture)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return windowsNativeQualification{}, nil, "", fmt.Errorf("Windows %s native qualification evidence file is invalid", architecture)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return windowsNativeQualification{}, nil, "", fmt.Errorf("read Windows %s native qualification evidence: %w", architecture, err)
	}
	var qualification windowsNativeQualification
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&qualification) != nil || decoder.Decode(&extra) != io.EOF {
		return windowsNativeQualification{}, nil, "", fmt.Errorf("Windows %s native qualification evidence is malformed", architecture)
	}
	digest := sha256.Sum256(body)
	return qualification, body, hex.EncodeToString(digest[:]), nil
}

func validateWindowsNativeQualificationHeader(qualification windowsNativeQualification, version, architecture string) error {
	if qualification.Schema != windowsNativeQualificationSchema || qualification.ReleaseVersion != version || qualification.Platform != "windows" || qualification.Architecture != architecture || qualification.Status != "passed" || !qualification.NativeTested || !safeEvidenceValue(qualification.WindowsBuild) || !safeEvidenceValue(qualification.Runner) {
		return fmt.Errorf("Windows %s native qualification evidence is incomplete or not passed", architecture)
	}
	return nil
}

func safeEvidenceValue(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}

func refresh(repo string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := validateRefreshMetadataFreshness(root, targets, now); err != nil {
		return err
	}
	if err := validateTargetsForPublication(targets, now); err != nil {
		return fmt.Errorf("release publication preflight failed: %w", err)
	}
	state, err := loadSigningState(repo, root, "snapshot", "timestamp")
	if err != nil {
		return err
	}
	snapshot.Signed.Version++
	snapshot.Signed.Expires = now.Add(7 * 24 * time.Hour)
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)
	snapshot.ClearSignatures()
	if err := sign(snapshot, state.Roles["snapshot"]...); err != nil {
		return err
	}
	timestamp.Signed.Version++
	timestamp.Signed.Expires = now.Add(24 * time.Hour)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
	timestamp.ClearSignatures()
	if err := sign(timestamp, state.Roles["timestamp"]...); err != nil {
		return err
	}
	return writeSet(repo, root, targets, snapshot, timestamp)
}

func validateRefreshMetadataFreshness(root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], now time.Time) error {
	if root == nil || !root.Signed.Expires.After(now) {
		if root == nil {
			return errors.New("cannot refresh metadata with a missing root expiration")
		}
		return fmt.Errorf("cannot refresh metadata with expired root metadata: expires %s", root.Signed.Expires.UTC().Format(time.RFC3339Nano))
	}
	if targets == nil || !targets.Signed.Expires.After(now) {
		if targets == nil {
			return errors.New("cannot refresh metadata with a missing targets expiration")
		}
		return fmt.Errorf("cannot refresh metadata with expired targets metadata: expires %s", targets.Signed.Expires.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// mutateRollout changes only the signed static deployment policy carried by
// every release target. It never accepts artifact paths or target names from
// the caller. All targets must start with byte-identical policy and receive the
// same revision and resulting digest before the metadata set is re-signed.
func mutateRollout(repo, operation string, revision uint64, percentage uint8) error {
	if revision == 0 || operation == "promote" && (percentage == 0 || percentage > 100) || operation != "promote" && percentage != 0 {
		return errors.New("invalid deployment policy mutation")
	}
	if operation != "promote" && operation != "pause" && operation != "quarantine" {
		return errors.New("invalid deployment policy mutation")
	}
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	state, err := loadSigningState(repo, root, "targets", "snapshot", "timestamp")
	if err != nil {
		return err
	}
	type update struct {
		info *metadata.TargetFiles
		name string
		raw  json.RawMessage
	}
	updates := make([]update, 0, len(supportedReleaseTargets()))
	var baselinePlanBytes []byte
	var baselineManifestDigest, baselinePlanDigest string
	for _, releaseTarget := range supportedReleaseTargets() {
		platform, architecture := releaseTarget.platform, releaseTarget.architecture
		name := releaseAssetName(platform, architecture)
		info := targets.Signed.Targets[name]
		if info == nil || len(info.Hashes["sha256"]) != sha256.Size || info.Custom == nil {
			return fmt.Errorf("signed release asset %s is unavailable", name)
		}
		var custom assetTargetCustom
		decoder := json.NewDecoder(strings.NewReader(string(*info.Custom)))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != "paperboat.tuf-asset/v1" || custom.Kind != "github-release-asset" || custom.ReleaseIndex.Schema != "paperboat.release-index/v1" || custom.ReleaseIndex.Platform != platform || custom.ReleaseIndex.Architecture != architecture || custom.ReleaseIndex.DeploymentPlan == nil {
			return fmt.Errorf("signed release asset %s cannot accept revision %d", name, revision)
		}
		plan := *custom.ReleaseIndex.DeploymentPlan
		if plan.ValidateAgainst(custom.ReleaseIndex.Version, custom.ReleaseIndex.ManifestSHA256) != nil || custom.ReleaseIndex.Version != custom.Version || custom.ReleaseIndex.ManifestSHA256 == "" {
			return fmt.Errorf("signed release asset %s has an invalid deployment policy binding", name)
		}
		currentPlanDigest, err := plan.PlanSHA256()
		if err != nil || currentPlanDigest != custom.ReleaseIndex.DeploymentPlanSHA256 || custom.ReleaseIndex.RolloutPolicyRevision != plan.PolicyRevision {
			return fmt.Errorf("signed release asset %s has inconsistent deployment policy metadata", name)
		}
		currentPlanBytes, err := plan.Bytes()
		if err != nil {
			return fmt.Errorf("encode deployment policy %s: %w", name, err)
		}
		if baselinePlanBytes == nil {
			baselinePlanBytes = append([]byte(nil), currentPlanBytes...)
			baselineManifestDigest, baselinePlanDigest = custom.ReleaseIndex.ManifestSHA256, custom.ReleaseIndex.DeploymentPlanSHA256
		} else if !bytes.Equal(baselinePlanBytes, currentPlanBytes) || baselineManifestDigest != custom.ReleaseIndex.ManifestSHA256 || baselinePlanDigest != custom.ReleaseIndex.DeploymentPlanSHA256 {
			return errors.New("signed release targets do not share one deployment policy")
		}
		if err := applyDeploymentMutation(&plan, operation, revision, percentage); err != nil {
			return fmt.Errorf("mutate deployment policy %s: %w", name, err)
		}
		updatedPlanDigest, err := plan.PlanSHA256()
		if err != nil {
			return fmt.Errorf("hash deployment policy %s: %w", name, err)
		}
		custom.ReleaseIndex.RolloutPolicyRevision = plan.PolicyRevision
		custom.ReleaseIndex.DeploymentPlanSHA256 = updatedPlanDigest
		custom.ReleaseIndex.DeploymentPlan = &plan
		updated, err := json.Marshal(custom)
		if err != nil {
			return err
		}
		updates = append(updates, update{info: info, name: name, raw: json.RawMessage(updated)})
	}
	for _, item := range updates {
		raw := item.raw
		item.info.Custom, item.info.Path = &raw, item.name
	}
	return signTargetsSet(repo, root, targets, snapshot, timestamp, state)
}

type releaseTargetPlatform struct {
	platform     string
	architecture string
}

func supportedReleaseTargets() []releaseTargetPlatform {
	return []releaseTargetPlatform{
		{platform: "darwin", architecture: "arm64"},
		{platform: "linux", architecture: "amd64"},
		{platform: "linux", architecture: "arm64"},
		{platform: "windows", architecture: "amd64"},
		{platform: "windows", architecture: "arm64"},
	}
}

func applyDeploymentMutation(plan *releasepolicy.Plan, operation string, revision uint64, percentage uint8) error {
	if plan == nil || plan.Validate() != nil || revision == 0 || revision <= plan.PolicyRevision {
		return errors.New("deployment policy mutation is not monotonic")
	}
	switch operation {
	case "promote":
		if percentage == 0 || percentage > 100 || plan.RolloutState == releasepolicy.RolloutStateQuarantined {
			return errors.New("invalid promote policy")
		}
		plan.RolloutState = releasepolicy.RolloutStateActive
		for index := range plan.Cohorts {
			if plan.Cohorts[index].Name != "general" && plan.Cohorts[index].Percentage < percentage {
				plan.Cohorts[index].Percentage = percentage
			}
		}
	case "pause":
		if percentage != 0 || plan.RolloutState == releasepolicy.RolloutStateQuarantined {
			return errors.New("invalid pause policy")
		}
		plan.RolloutState = releasepolicy.RolloutStatePaused
	case "quarantine":
		if percentage != 0 {
			return errors.New("invalid quarantine policy")
		}
		plan.RolloutState = releasepolicy.RolloutStateQuarantined
	default:
		return errors.New("invalid deployment policy mutation")
	}
	plan.PolicyRevision = revision
	if err := plan.Validate(); err != nil {
		return err
	}
	return nil
}

func signTargetsSet(repo string, root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], snapshot *metadata.Metadata[metadata.SnapshotType], timestamp *metadata.Metadata[metadata.TimestampType], state signingState) error {
	now := time.Now().UTC()
	if err := validateTargetsForPublication(targets, now); err != nil {
		return fmt.Errorf("release publication preflight failed: %w", err)
	}
	targets.Signed.Version++
	targets.Signed.Expires = now.Add(90 * 24 * time.Hour)
	targets.ClearSignatures()
	if err := sign(targets, state.Roles["targets"]...); err != nil {
		return err
	}
	snapshot.Signed.Version++
	snapshot.Signed.Expires = now.Add(7 * 24 * time.Hour)
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)
	snapshot.ClearSignatures()
	if err := sign(snapshot, state.Roles["snapshot"]...); err != nil {
		return err
	}
	timestamp.Signed.Version++
	timestamp.Signed.Expires = now.Add(24 * time.Hour)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
	timestamp.ClearSignatures()
	if err := sign(timestamp, state.Roles["timestamp"]...); err != nil {
		return err
	}
	return writeSet(repo, root, targets, snapshot, timestamp)
}

func rotate(repo, role string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if role != "root" && role != "targets" && role != "snapshot" && role != "timestamp" {
		return errors.New("role must be root, targets, snapshot, or timestamp")
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	if err := validateTargetsForPublication(targets, time.Now().UTC()); err != nil {
		return fmt.Errorf("release publication preflight failed: %w", err)
	}
	state, err := loadSigningState(repo, root)
	if err != nil {
		return err
	}
	oldNames := append([]string(nil), state.Roles[role]...)
	newName := nextKeyName(role)
	if err := createKey(newName); err != nil {
		return err
	}
	private, err := loadKey(newName)
	if err != nil {
		return err
	}
	key, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return err
	}
	oldKey, err := loadKey(oldNames[0])
	if err != nil {
		return err
	}
	oldTUF, _ := metadata.KeyFromPublicKey(oldKey.Public())
	oldID, _ := oldTUF.ID()
	if err := root.Signed.RevokeKey(oldID, role); err != nil {
		return err
	}
	if err := root.Signed.AddKey(key, role); err != nil {
		return err
	}
	root.Signed.Version++
	root.Signed.Expires = time.Now().UTC().Add(730 * 24 * time.Hour)
	root.ClearSignatures()
	rootSigners := append([]string(nil), state.Roles["root"]...)
	if role == "root" {
		state.Roles["root"] = append(append([]string(nil), oldNames[1:]...), newName)
		rootSigners = append(rootSigners, newName) // Old and new thresholds must both verify.
	}
	if err := sign(root, rootSigners...); err != nil {
		return err
	}
	if err := verifyRoot(root); err != nil {
		return err
	}
	if role == "targets" {
		state.Roles["targets"] = append(append([]string(nil), oldNames[1:]...), newName)
		targets.Signed.Version++
		targets.Signed.Expires = time.Now().UTC().Add(90 * 24 * time.Hour)
		targets.ClearSignatures()
		if err := sign(targets, state.Roles["targets"]...); err != nil {
			return err
		}
		snapshot.Signed.Version++
		snapshot.Signed.Expires = time.Now().UTC().Add(7 * 24 * time.Hour)
		snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)
		snapshot.ClearSignatures()
		if err := sign(snapshot, state.Roles["snapshot"]...); err != nil {
			return err
		}
		timestamp.Signed.Version++
		timestamp.Signed.Expires = time.Now().UTC().Add(24 * time.Hour)
		timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
		timestamp.ClearSignatures()
		if err := sign(timestamp, state.Roles["timestamp"]...); err != nil {
			return err
		}
	}
	if role == "snapshot" {
		state.Roles["snapshot"] = []string{newName}
		snapshot.Signed.Version++
		snapshot.Signed.Expires = time.Now().UTC().Add(7 * 24 * time.Hour)
		snapshot.ClearSignatures()
		if err := sign(snapshot, newName); err != nil {
			return err
		}
		timestamp.Signed.Version++
		timestamp.Signed.Expires = time.Now().UTC().Add(24 * time.Hour)
		timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)
		timestamp.ClearSignatures()
		if err := sign(timestamp, state.Roles["timestamp"]...); err != nil {
			return err
		}
	}
	if role == "timestamp" {
		state.Roles["timestamp"] = []string{newName}
		timestamp.Signed.Version++
		timestamp.Signed.Expires = time.Now().UTC().Add(24 * time.Hour)
		timestamp.ClearSignatures()
		if err := sign(timestamp, newName); err != nil {
			return err
		}
	}
	if err := writeSet(repo, root, targets, snapshot, timestamp); err != nil {
		return err
	}
	return writeSigningState(repo, state)
}

func status(repo string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	if err := verifyRoot(root); err != nil {
		return err
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		return err
	}
	if err := root.VerifyDelegate("snapshot", snapshot); err != nil {
		return err
	}
	if err := root.VerifyDelegate("timestamp", timestamp); err != nil {
		return err
	}
	fmt.Printf("root=%d expires=%s targets=%d expires=%s snapshot=%d expires=%s timestamp=%d expires=%s targets_count=%d\n",
		root.Signed.Version, root.Signed.Expires.Format(time.RFC3339), targets.Signed.Version, targets.Signed.Expires.Format(time.RFC3339), snapshot.Signed.Version, snapshot.Signed.Expires.Format(time.RFC3339), timestamp.Signed.Version, timestamp.Signed.Expires.Format(time.RFC3339), len(targets.Signed.Targets))
	return nil
}

func createKey(name string) error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	secret := base64.RawStdEncoding.EncodeToString(private.Seed())
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-a", name, "-s", keychainService, "-l", "Paperboat TUF production "+name, "-T", "", "-w", secret)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("store %s in Keychain: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func loadKey(name string) (ed25519.PrivateKey, error) {
	if encoded := strings.TrimSpace(os.Getenv(tufKeyEnvironmentName(name))); encoded != "" {
		seed, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("environment key %s is invalid", name)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	output, err := exec.Command("/usr/bin/security", "find-generic-password", "-a", name, "-s", keychainService, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("load %s from Keychain: %w", name, err)
	}
	seed, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(output)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("Keychain item %s is invalid", name)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func tufKeyEnvironmentName(name string) string {
	return "PAPERBOAT_TUF_KEY_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

func keyExists(name string) bool {
	if strings.TrimSpace(os.Getenv(tufKeyEnvironmentName(name))) != "" {
		return true
	}
	return exec.Command("/usr/bin/security", "find-generic-password", "-a", name, "-s", keychainService).Run() == nil
}

func nextKeyName(role string) string {
	for generation := int64(1); ; generation++ {
		name := role + "-" + strconv.FormatInt(generation, 10)
		if !keyExists(name) {
			return name
		}
	}
}

func sign[T metadata.Roles](value *metadata.Metadata[T], names ...string) error {
	for _, name := range names {
		private, err := loadKey(name)
		if err != nil {
			return err
		}
		signer, err := signature.LoadSigner(private, crypto.Hash(0))
		if err != nil {
			return err
		}
		if _, err := value.Sign(signer); err != nil {
			return err
		}
	}
	return nil
}

func validateRepository(path string, existing bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("repository path must be absolute and clean")
	}
	if existing {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("repository directory is invalid")
		}
	}
	return path, nil
}

func initialSigningState() signingState {
	return signingState{Schema: "paperboat.tuf-signing-state/v1", Roles: map[string][]string{
		"root":      {"root-1", "root-2", "root-3"},
		"targets":   {"targets-1", "targets-2"},
		"snapshot":  {"snapshot-1"},
		"timestamp": {"timestamp-1"},
	}}
}

func signingStatePath(repo string) string { return filepath.Join(repo, ".signing-state.json") }

func loadSigningState(repo string, root *metadata.Metadata[metadata.RootType], requiredRoles ...string) (signingState, error) {
	body, err := os.ReadFile(signingStatePath(repo))
	if err != nil {
		return signingState{}, err
	}
	var state signingState
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF || state.Schema != "paperboat.tuf-signing-state/v1" {
		return signingState{}, errors.New("TUF signing state is invalid")
	}
	if err := validateSigningState(root, state, requiredRoles...); err != nil {
		return signingState{}, err
	}
	return state, nil
}

func validateSigningState(root *metadata.Metadata[metadata.RootType], state signingState, requiredRoles ...string) error {
	if len(requiredRoles) == 0 {
		requiredRoles = []string{"root", "targets", "snapshot", "timestamp"}
	}
	for _, role := range requiredRoles {
		if role != "root" && role != "targets" && role != "snapshot" && role != "timestamp" {
			return fmt.Errorf("unknown TUF signing role %q", role)
		}
		configured := root.Signed.Roles[role]
		if configured == nil || len(state.Roles[role]) < configured.Threshold {
			return errors.New("TUF signing state does not satisfy role thresholds")
		}
		authorizedKeyIDs := make(map[string]struct{}, len(state.Roles[role]))
		for _, name := range state.Roles[role] {
			private, err := loadKey(name)
			if err != nil {
				return err
			}
			key, err := metadata.KeyFromPublicKey(private.Public())
			if err != nil {
				return err
			}
			id, err := key.ID()
			if err != nil {
				return err
			}
			found := false
			for _, allowed := range configured.KeyIDs {
				if id == allowed {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Keychain item %s is not authorized for %s", name, role)
			}
			authorizedKeyIDs[id] = struct{}{}
		}
		if len(authorizedKeyIDs) < configured.Threshold {
			return errors.New("TUF signing state does not satisfy role thresholds with unique authorized keys")
		}
	}
	return nil
}

func writeSigningState(repo string, state signingState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(signingStatePath(repo), append(body, '\n'), 0o600)
}

func loadSet(repo string) (*metadata.Metadata[metadata.RootType], *metadata.Metadata[metadata.TargetsType], *metadata.Metadata[metadata.SnapshotType], *metadata.Metadata[metadata.TimestampType], error) {
	root, err := metadata.Root().FromFile(filepath.Join(repo, "metadata", "root.json"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targets, err := metadata.Targets().FromFile(filepath.Join(repo, "metadata", "targets.json"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	snapshot, err := metadata.Snapshot().FromFile(filepath.Join(repo, "metadata", "snapshot.json"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	timestamp, err := metadata.Timestamp().FromFile(filepath.Join(repo, "metadata", "timestamp.json"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return root, targets, snapshot, timestamp, nil
}

func writeSet(repo string, root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], snapshot *metadata.Metadata[metadata.SnapshotType], timestamp *metadata.Metadata[metadata.TimestampType]) error {
	if err := os.MkdirAll(filepath.Join(repo, "metadata"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(repo, "targets"), 0o755); err != nil {
		return err
	}
	if err := validateTargetsForPublication(targets, time.Now().UTC()); err != nil {
		return fmt.Errorf("release publication preflight failed: %w", err)
	}
	if err := verifyRoot(root); err != nil {
		return err
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		return err
	}
	if err := root.VerifyDelegate("snapshot", snapshot); err != nil {
		return err
	}
	if err := root.VerifyDelegate("timestamp", timestamp); err != nil {
		return err
	}
	entries := []struct {
		name string
		body []byte
	}{}
	for _, item := range []struct {
		name   string
		encode func(bool) ([]byte, error)
	}{
		{fmt.Sprintf("%d.root.json", root.Signed.Version), root.ToBytes}, {"root.json", root.ToBytes},
		{fmt.Sprintf("%d.targets.json", targets.Signed.Version), targets.ToBytes}, {"targets.json", targets.ToBytes},
		{fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version), snapshot.ToBytes}, {"snapshot.json", snapshot.ToBytes}, {"timestamp.json", timestamp.ToBytes},
	} {
		body, err := item.encode(false)
		if err != nil {
			return err
		}
		entries = append(entries, struct {
			name string
			body []byte
		}{item.name, body})
	}
	for _, entry := range entries {
		if err := atomicWrite(filepath.Join(repo, "metadata", entry.name), entry.body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func verifyRoot(root *metadata.Metadata[metadata.RootType]) error {
	return root.VerifyDelegate("root", root)
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	//paperboat:allow-source-policy atomic-replacement owner=tuf-repository reason=same-directory-fsynced-staging
	tmp, err := os.CreateTemp(filepath.Dir(path), ".paperboat-tuf-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=tuf-repository reason=verified-metadata-publication
	if err := replaceFile(name, path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}
