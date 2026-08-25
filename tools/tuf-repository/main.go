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

type componentTarget struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	AssetName    string `json:"asset_name"`
	Repository   string `json:"repository"`
	DownloadURL  string `json:"download_url"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
}
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
type rolloutPolicy struct {
	Schema     string `json:"schema"`
	CohortSeed string `json:"cohort_seed"`
	Percentage uint8  `json:"percentage"`
}
type releaseIndex struct {
	Schema                 string            `json:"schema"`
	ReleaseID              string            `json:"release_id"`
	Version                string            `json:"version"`
	Channel                string            `json:"channel"`
	Severity               string            `json:"severity"`
	CreatedAt              time.Time         `json:"created_at"`
	Platform               string            `json:"platform"`
	Architecture           string            `json:"architecture"`
	BinaryFormat           string            `json:"binary_format"`
	Targets                []componentTarget `json:"targets"`
	HostdAPIMin            uint16            `json:"hostd_api_min"`
	HostdAPIMax            uint16            `json:"hostd_api_max"`
	RuntimeAPIMin          uint16            `json:"runtime_api_min"`
	RuntimeAPIMax          uint16            `json:"runtime_api_max"`
	MinimumVersion         string            `json:"minimum_permitted_version,omitempty"`
	RevokedVersions        []string          `json:"revoked_versions,omitempty"`
	RolloutPolicyRevision  uint64            `json:"rollout_policy_revision"`
	SupervisorMaintenance  bool              `json:"supervisor_maintenance_required"`
	Rollout                rolloutPolicy     `json:"rollout"`
	Revoked                bool              `json:"revoked,omitempty"`
	Stability              string            `json:"stability,omitempty"`
	NativeTested           bool              `json:"native_tested,omitempty"`
	TestedWindowsBuilds    []string          `json:"tested_windows_builds,omitempty"`
	OpenSSHPackageID       string            `json:"openssh_package_id,omitempty"`
	OpenSSHApprovedVersion string            `json:"openssh_approved_version,omitempty"`
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
		percentage := fs.Uint("percentage", 0, "initial eligible cohort percentage")
		severity := fs.String("severity", "routine", "routine, security, or critical")
		supervisorMaintenance := fs.Bool("supervisor-maintenance", false, "release updates stable supervisor components")
		amd64QualificationEvidence := fs.String("windows-amd64-native-evidence", "", "absolute JSON evidence for Windows amd64 native qualification")
		arm64QualificationEvidence := fs.String("windows-arm64-native-evidence", "", "absolute JSON evidence for Windows arm64 native qualification")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf publish -repository DIR -version VERSION -artifacts DIR -windows-amd64-native-evidence FILE -windows-arm64-native-evidence FILE -rollout-revision N -percentage 0..100")
		}
		if *rolloutRevision == 0 || *percentage > 100 || (*severity != "routine" && *severity != "security" && *severity != "critical") {
			return errors.New("valid rollout revision, percentage, and severity are required")
		}
		return publish(*repo, *version, *artifacts, map[string]string{"amd64": *amd64QualificationEvidence, "arm64": *arm64QualificationEvidence}, *rolloutRevision, uint8(*percentage), *severity, *supervisorMaintenance)
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

func publish(repo, version, artifacts string, qualificationEvidencePaths map[string]string, rolloutRevision uint64, percentage uint8, severity string, supervisorMaintenance bool) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if !releaseVersionPattern.MatchString(version) || !filepath.IsAbs(artifacts) || filepath.Clean(artifacts) != artifacts {
		return errors.New("version must be YYYY.MM.DD.N and artifacts must be an absolute clean directory")
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
		index := releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_" + version, Version: version, Channel: channel, Severity: severity, CreatedAt: createdAt, Platform: platform, Architecture: architecture, BinaryFormat: format, Targets: []componentTarget{component}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: rolloutRevision, SupervisorMaintenance: supervisorMaintenance, Rollout: rolloutPolicy{Schema: "paperboat.release-rollout/v1", CohortSeed: "release-" + version, Percentage: percentage}, Stability: stability, NativeTested: nativeTested, TestedWindowsBuilds: testedBuilds, OpenSSHPackageID: openSSHID, OpenSSHApprovedVersion: openSSHVersion}
		customBody, err := json.Marshal(assetTargetCustom{Schema: "paperboat.tuf-asset/v1", Kind: "github-release-asset", Version: version, Platform: platform, Architecture: architecture, Format: format, AssetName: name, Repository: githubRepository, URL: downloadURL, SHA256: digest, Length: info.Length, ReleaseIndex: index})
		if err != nil {
			return err
		}
		raw := json.RawMessage(customBody)
		info.Custom, info.Path = &raw, name
		targets.Signed.Targets[name] = info
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
	state, err := loadSigningState(repo, root, "snapshot", "timestamp")
	if err != nil {
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

// mutateRollout changes only policy carried by the already signed asset target
// custom metadata. It never accepts artifact paths or target names from the
// caller. The resulting targets, snapshot, and timestamp metadata are signed
// with their configured production roles before publication.
func mutateRollout(repo, operation string, revision uint64, percentage uint8) error {
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
		if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != "paperboat.tuf-asset/v1" || custom.Kind != "github-release-asset" || custom.ReleaseIndex.Schema != "paperboat.release-index/v1" || custom.ReleaseIndex.Platform != platform || custom.ReleaseIndex.Architecture != architecture || revision <= custom.ReleaseIndex.RolloutPolicyRevision {
			return fmt.Errorf("signed release asset %s cannot accept revision %d", name, revision)
		}
		if err := applyRolloutMutation(&custom.ReleaseIndex, operation, revision, percentage); err != nil {
			return err
		}
		updated, err := json.Marshal(custom)
		if err != nil {
			return err
		}
		raw := json.RawMessage(updated)
		info.Custom, info.Path = &raw, name
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

func applyRolloutMutation(index *releaseIndex, operation string, revision uint64, percentage uint8) error {
	if index == nil || revision == 0 || revision <= index.RolloutPolicyRevision || percentage > 100 {
		return errors.New("rollout mutation is not monotonic")
	}
	if operation != "promote" && operation != "pause" && operation != "quarantine" || operation != "promote" && percentage != 0 {
		return errors.New("invalid signed rollout operation")
	}
	index.RolloutPolicyRevision = revision
	switch operation {
	case "promote":
		index.Rollout.Percentage = percentage
		index.Revoked = false
	case "pause":
		index.Rollout.Percentage = 0
	case "quarantine":
		index.Rollout.Percentage = 0
		index.Revoked = true
	}
	return nil
}

func signTargetsSet(repo string, root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], snapshot *metadata.Metadata[metadata.SnapshotType], timestamp *metadata.Metadata[metadata.TimestampType], state signingState) error {
	now := time.Now().UTC()
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

func copyConsistentTarget(repo, source, name string, info *metadata.TargetFiles) error {
	digest := info.Hashes["sha256"]
	if len(digest) != sha256.Size {
		return errors.New("target has no sha256 digest")
	}
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), hex.EncodeToString(digest)) {
		return errors.New("target changed while publishing")
	}
	return atomicWrite(filepath.Join(repo, "targets", hex.EncodeToString(digest)+"."+name), body, 0o755)
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
