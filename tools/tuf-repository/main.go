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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const keychainService = "com.pinksaucepasta.paperboat.tuf.production"
const windowsNativeQualificationSchema = "paperboat.windows-native-qualification/v1"
const windowsNativeQualificationResultBindingSchema = "paperboat.windows-native-qualification-result-binding/v1"

func windowsNativeQualificationTarget(architecture string) string {
	return "windows-" + architecture + "-native-qualification.json"
}

func windowsNativeQualificationReportTarget(architecture string) string {
	return "windows-" + architecture + "-native-qualification-report.json"
}

var roles = []string{"root-1", "root-2", "root-3", "targets-1", "targets-2", "snapshot-1", "timestamp-1"}

type componentTarget struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
}
type windowsNativeQualification struct {
	Schema              string                                  `json:"schema"`
	ReleaseVersion      string                                  `json:"release_version"`
	Platform            string                                  `json:"platform"`
	Architecture        string                                  `json:"architecture"`
	Status              string                                  `json:"status"`
	NativeTested        bool                                    `json:"native_tested"`
	WindowsBuild        string                                  `json:"windows_build"`
	Runner              string                                  `json:"runner"`
	QualificationResult windowsNativeQualificationResultBinding `json:"qualification_result"`
	Artifacts           []windowsNativeQualifiedArtifact        `json:"artifacts"`
}
type windowsNativeQualificationResultBinding struct {
	Schema           string `json:"schema"`
	TargetPath       string `json:"target_path"`
	SHA256           string `json:"sha256"`
	Length           int64  `json:"length"`
	NativeTestSHA256 string `json:"native_test_sha256"`
	NativeTestLength int64  `json:"native_test_length"`
}
type windowsNativeQualifiedArtifact struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Status       string `json:"status"`
}
type windowsNativeQualificationBinding struct {
	Schema         string `json:"schema"`
	EvidenceTarget string `json:"evidence_target"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	ReleaseVersion string `json:"release_version"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	Status         string `json:"status"`
	NativeTested   bool   `json:"native_tested"`
	WindowsBuild   string `json:"windows_build"`
	Runner         string `json:"runner"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactLength int64  `json:"artifact_length"`
}
type componentTargetCustom struct {
	Schema              string                             `json:"schema"`
	Kind                string                             `json:"kind"`
	Component           string                             `json:"component"`
	Version             string                             `json:"version"`
	Platform            string                             `json:"platform"`
	Architecture        string                             `json:"architecture"`
	BinaryFormat        string                             `json:"binary_format"`
	NativeQualification *windowsNativeQualificationBinding `json:"native_qualification,omitempty"`
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
		return errors.New("usage: paperboat-tuf <init|publish|publish-bootstrap|promote|pause|quarantine|refresh|rotate|status|validate-signers|verify-published>")
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
	case "publish-bootstrap":
		fs := flag.NewFlagSet("publish-bootstrap", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		artifact := fs.String("artifact", "", "absolute unified pb artifact")
		version := fs.String("version", "", "artifact version")
		platform := fs.String("platform", "", "darwin, linux, or windows")
		architecture := fs.String("architecture", "", "amd64 or arm64")
		qualificationOnly := fs.Bool("qualification-only", false, "acknowledge that this target is for qualification and carries no release claim")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || !*qualificationOnly {
			return errors.New("usage: paperboat-tuf publish-bootstrap -repository DIR -artifact FILE -version VERSION -platform PLATFORM -architecture ARCH -qualification-only")
		}
		return publishBootstrap(*repo, *artifact, *version, *platform, *architecture)
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

// publishBootstrap adds only the unified bootstrap binary. It does not create
// release indexes, rollout metadata, stability claims, or installer targets.
// This keeps native qualification bootstrapping separate from a GA release.
func publishBootstrap(repo, artifact, version, platform, architecture string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(artifact) || filepath.Clean(artifact) != artifact || strings.TrimSpace(version) == "" || strings.ContainsAny(version, "\x00\r\n/\\") || !slices.Contains([]string{"darwin", "linux", "windows"}, platform) || !slices.Contains([]string{"amd64", "arm64"}, architecture) {
		return errors.New("bootstrap target parameters are invalid")
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	state, err := loadSigningState(repo, root, "targets", "snapshot", "timestamp")
	if err != nil {
		return err
	}
	name := "pb-" + platform + "-" + architecture
	info, err := metadata.TargetFile().FromFile(artifact, "sha256")
	if err != nil {
		return err
	}
	custom, err := json.Marshal(map[string]string{"schema": "paperboat.tuf-target/v1", "kind": "pb", "version": version, "platform": platform, "architecture": architecture})
	if err != nil {
		return err
	}
	raw := json.RawMessage(custom)
	info.Custom, info.Path = &raw, name
	targets.Signed.Targets[name] = info
	if err := copyConsistentTarget(repo, artifact, name, info); err != nil {
		return err
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
	if strings.TrimSpace(version) == "" || !filepath.IsAbs(artifacts) {
		return errors.New("version and absolute artifacts directory are required")
	}
	qualifications := make(map[string]windowsNativeQualification, 2)
	qualificationBodies := make(map[string][]byte, 2)
	qualificationDigests := make(map[string]string, 2)
	qualificationInfos := make(map[string]*metadata.TargetFiles, 2)
	for _, architecture := range []string{"amd64", "arm64"} {
		qualification, body, digest, err := loadWindowsNativeQualification(qualificationEvidencePaths[architecture], architecture)
		if err != nil {
			return err
		}
		if err := validateWindowsNativeQualificationResult(qualification, version, architecture, artifacts); err != nil {
			return err
		}
		qualifications[architecture], qualificationBodies[architecture], qualificationDigests[architecture] = qualification, body, digest
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
	for _, architecture := range []string{"amd64", "arm64"} {
		name := windowsNativeQualificationTarget(architecture)
		info, err := metadata.TargetFile().FromBytes(name, qualificationBodies[architecture], "sha256")
		if err != nil {
			return err
		}
		custom, _ := json.Marshal(map[string]string{"schema": windowsNativeQualificationSchema, "kind": "windows-native-qualification", "platform": "windows", "architecture": architecture, "status": "passed"})
		raw := json.RawMessage(custom)
		info.Custom, info.Path = &raw, name
		targets.Signed.Targets[name], qualificationInfos[architecture] = info, info
	}
	createdAt := time.Now().UTC()
	for _, releaseTarget := range supportedReleaseTargets() {
		platform, architecture := releaseTarget.platform, releaseTarget.architecture
		format := map[string]string{"darwin": "mach-o", "linux": "elf", "windows": "pe"}[platform]
		components := make([]componentTarget, 0, 5)
		componentFiles := make(map[string]*metadata.TargetFiles, 5)
		componentPaths := make(map[string]string, 5)
		for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
			name := component + "-" + platform + "-" + architecture
			local := filepath.Join(artifacts, name)
			info, err := metadata.TargetFile().FromFile(local, "sha256")
			if err != nil {
				return fmt.Errorf("target %s: %w", name, err)
			}
			components = append(components, componentTarget{Component: component, TargetPath: name, SHA256: hex.EncodeToString(info.Hashes["sha256"]), Length: info.Length, Platform: platform, Architecture: architecture, BinaryFormat: format})
			componentFiles[name], componentPaths[name] = info, local
		}
		channel, stability, nativeTested := "stable", "", false
		var testedBuilds []string
		openSSHID, openSSHVersion := "", ""
		if platform == "windows" {
			stability = "stable"
			openSSHID, openSSHVersion = "Microsoft.OpenSSH.Preview", "10.0.0.0"
			qualification := qualifications[architecture]
			if err := validateWindowsNativeQualification(qualification, version, architecture, components); err != nil {
				return err
			}
			nativeTested, testedBuilds = true, []string{qualification.WindowsBuild}
		}
		for _, component := range components {
			custom := componentTargetCustom{Schema: "paperboat.tuf-component/v1", Kind: "component", Component: component.Component, Version: version, Platform: platform, Architecture: architecture, BinaryFormat: format}
			if platform == "windows" {
				custom.NativeQualification = qualificationBinding(qualifications[architecture], qualificationDigests[architecture], component)
			}
			customBody, err := json.Marshal(custom)
			if err != nil {
				return err
			}
			raw := json.RawMessage(customBody)
			info := componentFiles[component.TargetPath]
			info.Custom, info.Path = &raw, component.TargetPath
			targets.Signed.Targets[component.TargetPath] = info
			if err := copyConsistentTarget(repo, componentPaths[component.TargetPath], component.TargetPath, info); err != nil {
				return err
			}
		}
		// Direct bootstrap and CLI self-update select this fixed target name.
		// Keep it as an exact alias of the qualified CLI bytes while
		// component-aware runtime updaters use cli-* through a release index.
		cliName := "cli-" + platform + "-" + architecture
		aliasName := "pb-" + platform + "-" + architecture
		aliasInfo, err := metadata.TargetFile().FromFile(componentPaths[cliName], "sha256")
		if err != nil {
			return fmt.Errorf("bootstrap alias %s: %w", aliasName, err)
		}
		cliInfo := componentFiles[cliName]
		if aliasInfo.Length != cliInfo.Length || !bytes.Equal(aliasInfo.Hashes["sha256"], cliInfo.Hashes["sha256"]) {
			return fmt.Errorf("bootstrap alias %s does not match %s", aliasName, cliName)
		}
		aliasCustom, err := json.Marshal(map[string]string{"schema": "paperboat.tuf-target/v1", "kind": "pb", "version": version, "platform": platform, "architecture": architecture})
		if err != nil {
			return err
		}
		aliasRaw := json.RawMessage(aliasCustom)
		aliasInfo.Custom, aliasInfo.Path = &aliasRaw, aliasName
		targets.Signed.Targets[aliasName] = aliasInfo
		if err := copyConsistentTarget(repo, componentPaths[cliName], aliasName, aliasInfo); err != nil {
			return err
		}
		indexName := "release-index-" + channel + "-" + platform + "-" + architecture + ".json"
		indexBody, err := json.Marshal(releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_" + version, Version: version, Channel: channel, Severity: severity, CreatedAt: createdAt, Platform: platform, Architecture: architecture, BinaryFormat: format, Targets: components, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: rolloutRevision, SupervisorMaintenance: supervisorMaintenance, Rollout: rolloutPolicy{Schema: "paperboat.release-rollout/v1", CohortSeed: "release-" + version, Percentage: percentage}, Stability: stability, NativeTested: nativeTested, TestedWindowsBuilds: testedBuilds, OpenSSHPackageID: openSSHID, OpenSSHApprovedVersion: openSSHVersion})
		if err != nil {
			return err
		}
		indexInfo, err := metadata.TargetFile().FromBytes(indexName, indexBody, "sha256")
		if err != nil {
			return err
		}
		indexCustom, _ := json.Marshal(map[string]string{"schema": "paperboat.tuf-release-index/v1", "kind": "release-index", "channel": channel, "platform": platform, "architecture": architecture})
		indexRaw := json.RawMessage(indexCustom)
		indexInfo.Custom, indexInfo.Path = &indexRaw, indexName
		targets.Signed.Targets[indexName] = indexInfo
		indexLocal := filepath.Join(artifacts, indexName)
		indexFile, err := os.OpenFile(indexLocal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create release index %s: %w", indexName, err)
		}
		if _, err = indexFile.Write(indexBody); err == nil {
			err = indexFile.Sync()
		}
		err = errors.Join(err, indexFile.Close())
		if err != nil {
			return err
		}
		if err := copyConsistentTarget(repo, indexLocal, indexName, indexInfo); err != nil {
			return err
		}
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		if err := copyConsistentTarget(repo, qualificationEvidencePaths[architecture], windowsNativeQualificationTarget(architecture), qualificationInfos[architecture]); err != nil {
			return err
		}
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

func validateWindowsNativeQualification(qualification windowsNativeQualification, version, architecture string, components []componentTarget) error {
	if architecture != "amd64" && architecture != "arm64" || qualification.Schema != windowsNativeQualificationSchema || qualification.ReleaseVersion != version || qualification.Platform != "windows" || qualification.Architecture != architecture || qualification.Status != "passed" || !qualification.NativeTested || !safeEvidenceValue(qualification.WindowsBuild) || !safeEvidenceValue(qualification.Runner) {
		return fmt.Errorf("Windows %s native qualification evidence is incomplete or not passed", architecture)
	}
	result := qualification.QualificationResult
	if result.Schema != windowsNativeQualificationResultBindingSchema || result.TargetPath != windowsNativeQualificationReportTarget(architecture) || !validSHA256(result.SHA256) || result.Length < 1 || result.Length > 4<<20 || !validSHA256(result.NativeTestSHA256) || result.NativeTestLength < 1 {
		return fmt.Errorf("Windows %s native qualification result binding is invalid", architecture)
	}
	if len(components) != 5 || len(qualification.Artifacts) != len(components) {
		return fmt.Errorf("Windows %s native qualification evidence does not cover every component", architecture)
	}
	expected := make(map[string]componentTarget, len(components))
	for _, component := range components {
		if component.Component == "" || expected[component.Component].Component != "" {
			return fmt.Errorf("Windows %s component set is invalid", architecture)
		}
		expected[component.Component] = component
	}
	for _, artifact := range qualification.Artifacts {
		component, ok := expected[artifact.Component]
		if !ok || artifact.TargetPath != component.TargetPath || artifact.SHA256 != component.SHA256 || artifact.Length != component.Length || artifact.Platform != "windows" || artifact.Architecture != architecture || artifact.Status != "passed" {
			return fmt.Errorf("Windows %s native qualification evidence does not match component %q", architecture, artifact.Component)
		}
		delete(expected, artifact.Component)
	}
	if len(expected) != 0 {
		return fmt.Errorf("Windows %s native qualification evidence is missing a component", architecture)
	}
	return nil
}

func validateWindowsNativeQualificationResult(qualification windowsNativeQualification, version, architecture, artifacts string) error {
	if err := validateWindowsNativeQualification(qualification, version, architecture, qualificationArtifactsAsComponents(qualification)); err != nil {
		return err
	}
	result := qualification.QualificationResult
	path := filepath.Join(artifacts, result.TargetPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != result.Length {
		return fmt.Errorf("Windows %s native qualification report is invalid", architecture)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Windows %s native qualification report: %w", architecture, err)
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != result.SHA256 {
		return fmt.Errorf("Windows %s native qualification report digest does not match its evidence", architecture)
	}
	var report struct {
		Schema           string            `json:"schema"`
		Platform         string            `json:"platform"`
		Architecture     string            `json:"architecture"`
		Stability        string            `json:"stability"`
		NativeTested     bool              `json:"native_tested"`
		Version          string            `json:"version"`
		Status           string            `json:"status"`
		WindowsBuild     string            `json:"windows_build"`
		Runner           string            `json:"runner"`
		MSISHA256        string            `json:"msi_sha256"`
		UpgradeMSISHA256 string            `json:"upgrade_msi_sha256"`
		NativeTestSHA256 string            `json:"native_test_sha256"`
		NativeTestLength int64             `json:"native_test_length"`
		Events           []json.RawMessage `json:"events"`
		Failure          json.RawMessage   `json:"failure"`
	}
	if json.Unmarshal(body, &report) != nil || report.Schema != "paperboat.windows-native-qualification-report/v1" || report.Platform != "windows" || report.Architecture != architecture || report.Stability != "stable" || !report.NativeTested || report.Version != version || report.Status != "passed" || report.WindowsBuild != qualification.WindowsBuild || report.Runner != qualification.Runner || !validSHA256(report.MSISHA256) || !validSHA256(report.UpgradeMSISHA256) || report.NativeTestSHA256 != result.NativeTestSHA256 || report.NativeTestLength != result.NativeTestLength || len(report.Events) == 0 || string(report.Failure) != "null" {
		return fmt.Errorf("Windows %s native qualification report is incomplete or not passed", architecture)
	}
	return nil
}

func qualificationArtifactsAsComponents(qualification windowsNativeQualification) []componentTarget {
	components := make([]componentTarget, 0, len(qualification.Artifacts))
	for _, artifact := range qualification.Artifacts {
		components = append(components, componentTarget{Component: artifact.Component, TargetPath: artifact.TargetPath, SHA256: artifact.SHA256, Length: artifact.Length, Platform: artifact.Platform, Architecture: artifact.Architecture, BinaryFormat: "pe"})
	}
	return components
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func qualificationBinding(qualification windowsNativeQualification, evidenceDigest string, component componentTarget) *windowsNativeQualificationBinding {
	return &windowsNativeQualificationBinding{
		Schema:         windowsNativeQualificationSchema,
		EvidenceTarget: windowsNativeQualificationTarget(qualification.Architecture),
		EvidenceSHA256: evidenceDigest,
		ReleaseVersion: qualification.ReleaseVersion,
		Platform:       qualification.Platform,
		Architecture:   qualification.Architecture,
		Status:         qualification.Status,
		NativeTested:   qualification.NativeTested,
		WindowsBuild:   qualification.WindowsBuild,
		Runner:         qualification.Runner,
		ArtifactSHA256: component.SHA256,
		ArtifactLength: component.Length,
	}
}

func safeEvidenceValue(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}

func validateWindowsNativeSignedQualification(repo string, targetFiles map[string]*metadata.TargetFiles, index releaseIndex) error {
	if index.Platform != "windows" || index.Architecture != "amd64" && index.Architecture != "arm64" || index.Stability != "stable" || !index.NativeTested || len(index.TestedWindowsBuilds) != 1 {
		return errors.New("release index does not declare a stable native Windows release")
	}
	evidenceTarget := windowsNativeQualificationTarget(index.Architecture)
	evidenceInfo := targetFiles[evidenceTarget]
	if evidenceInfo == nil {
		return errors.New("native qualification evidence target is absent")
	}
	evidenceBody, err := readConsistentTarget(repo, evidenceTarget, evidenceInfo)
	if err != nil {
		return fmt.Errorf("read native qualification evidence: %w", err)
	}
	var qualification windowsNativeQualification
	decoder := json.NewDecoder(strings.NewReader(string(evidenceBody)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&qualification) != nil || decoder.Decode(&extra) != io.EOF {
		return errors.New("native qualification evidence target is malformed")
	}
	if err := validateWindowsNativeQualification(qualification, index.Version, index.Architecture, index.Targets); err != nil || qualification.WindowsBuild != index.TestedWindowsBuilds[0] {
		return errors.New("native qualification evidence does not match release index")
	}
	evidenceDigest := hex.EncodeToString(evidenceInfo.Hashes["sha256"])
	for _, component := range index.Targets {
		info := targetFiles[component.TargetPath]
		if info == nil || info.Length != component.Length || hex.EncodeToString(info.Hashes["sha256"]) != component.SHA256 || info.Custom == nil {
			return fmt.Errorf("component target %q does not match release index", component.TargetPath)
		}
		var custom componentTargetCustom
		decoder := json.NewDecoder(strings.NewReader(string(*info.Custom)))
		decoder.DisallowUnknownFields()
		extra = nil
		if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.NativeQualification == nil {
			return fmt.Errorf("component target %q has no qualification binding", component.TargetPath)
		}
		binding := custom.NativeQualification
		if binding.Schema != windowsNativeQualificationSchema || binding.EvidenceTarget != evidenceTarget || binding.EvidenceSHA256 != evidenceDigest || binding.ReleaseVersion != index.Version || binding.Platform != "windows" || binding.Architecture != index.Architecture || binding.Status != "passed" || !binding.NativeTested || binding.WindowsBuild != qualification.WindowsBuild || binding.Runner != qualification.Runner || binding.ArtifactSHA256 != component.SHA256 || binding.ArtifactLength != component.Length {
			return fmt.Errorf("component target %q has an invalid qualification binding", component.TargetPath)
		}
	}
	return nil
}

func readConsistentTarget(repo, name string, info *metadata.TargetFiles) ([]byte, error) {
	if info == nil || len(info.Hashes["sha256"]) != sha256.Size || info.Length < 1 {
		return nil, errors.New("target metadata is invalid")
	}
	digest := hex.EncodeToString(info.Hashes["sha256"])
	body, err := os.ReadFile(filepath.Join(repo, "targets", digest+"."+name))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != info.Length {
		return nil, errors.New("target length does not match metadata")
	}
	actual := sha256.Sum256(body)
	if hex.EncodeToString(actual[:]) != digest {
		return nil, errors.New("target hash does not match metadata")
	}
	return body, nil
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

// mutateRollout changes only policy carried by the already signed fixed
// release-index targets. It never accepts artifact paths or target names from
// the caller. The resulting targets, snapshot, and timestamp metadata are
// signed with their configured production roles before publication.
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
		channel := "stable"
		name := "release-index-" + channel + "-" + platform + "-" + architecture + ".json"
		info := targets.Signed.Targets[name]
		if info == nil || len(info.Hashes["sha256"]) != sha256.Size {
			return fmt.Errorf("signed release index %s is unavailable", name)
		}
		digest := hex.EncodeToString(info.Hashes["sha256"])
		body, err := os.ReadFile(filepath.Join(repo, "targets", digest+"."+name))
		if err != nil {
			return fmt.Errorf("read signed release index %s: %w", name, err)
		}
		if int64(len(body)) != info.Length {
			return fmt.Errorf("signed release index %s has the wrong length", name)
		}
		var index releaseIndex
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&index) != nil || decoder.Decode(&extra) != io.EOF || index.Schema != "paperboat.release-index/v1" || index.Platform != platform || index.Architecture != architecture || revision <= index.RolloutPolicyRevision {
			return fmt.Errorf("signed release index %s cannot accept revision %d", name, revision)
		}
		if platform == "windows" {
			if err := validateWindowsNativeSignedQualification(repo, targets.Signed.Targets, index); err != nil {
				return fmt.Errorf("signed release index %s has no valid native qualification: %w", name, err)
			}
		}
		if err := applyRolloutMutation(&index, operation, revision, percentage); err != nil {
			return err
		}
		updated, err := json.Marshal(index)
		if err != nil {
			return err
		}
		updatedInfo, err := metadata.TargetFile().FromBytes(name, updated, "sha256")
		if err != nil {
			return err
		}
		custom, _ := json.Marshal(map[string]string{"schema": "paperboat.tuf-release-index/v1", "kind": "release-index", "channel": channel, "platform": platform, "architecture": architecture})
		raw := json.RawMessage(custom)
		updatedInfo.Custom, updatedInfo.Path = &raw, name
		//paperboat:allow-source-policy atomic-replacement owner=tuf-repository reason=same-directory-release-index-staging
		temporary, err := os.CreateTemp(repo, ".release-index-*")
		if err != nil {
			return err
		}
		temporaryPath := temporary.Name()
		if _, err = temporary.Write(updated); err == nil {
			err = temporary.Sync()
		}
		err = errors.Join(err, temporary.Close())
		if err == nil {
			err = copyConsistentTarget(repo, temporaryPath, name, updatedInfo)
		}
		removeErr := os.Remove(temporaryPath)
		if err != nil {
			return errors.Join(err, removeErr)
		}
		targets.Signed.Targets[name] = updatedInfo
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
