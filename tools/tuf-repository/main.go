package main

import (
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
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const keychainService = "com.pinksaucepasta.paperboat.tuf.production"

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
type rolloutPolicy struct {
	Schema     string `json:"schema"`
	CohortSeed string `json:"cohort_seed"`
	Percentage uint8  `json:"percentage"`
}
type releaseIndex struct {
	Schema                string            `json:"schema"`
	ReleaseID             string            `json:"release_id"`
	Version               string            `json:"version"`
	Channel               string            `json:"channel"`
	Severity              string            `json:"severity"`
	CreatedAt             time.Time         `json:"created_at"`
	Platform              string            `json:"platform"`
	Architecture          string            `json:"architecture"`
	BinaryFormat          string            `json:"binary_format"`
	Targets               []componentTarget `json:"targets"`
	HostdAPIMin           uint16            `json:"hostd_api_min"`
	HostdAPIMax           uint16            `json:"hostd_api_max"`
	RuntimeAPIMin         uint16            `json:"runtime_api_min"`
	RuntimeAPIMax         uint16            `json:"runtime_api_max"`
	RolloutPolicyRevision uint64            `json:"rollout_policy_revision"`
	SupervisorMaintenance bool              `json:"supervisor_maintenance_required"`
	Rollout               rolloutPolicy     `json:"rollout"`
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
	if runtime.GOOS != "darwin" {
		return errors.New("production signing is restricted to the macOS release workstation")
	}
	if len(args) == 0 {
		return errors.New("usage: paperboat-tuf <init|publish|refresh|rotate|status>")
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
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf publish -repository DIR -version VERSION -artifacts DIR -rollout-revision N -percentage 0..100")
		}
		if *rolloutRevision == 0 || *percentage > 100 || (*severity != "routine" && *severity != "security" && *severity != "critical") {
			return errors.New("valid rollout revision, percentage, and severity are required")
		}
		return publish(*repo, *version, *artifacts, *rolloutRevision, uint8(*percentage), *severity, *supervisorMaintenance)
	case "refresh":
		fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
		repo := fs.String("repository", "", "repository directory")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: paperboat-tuf refresh -repository DIR")
		}
		return refresh(*repo)
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
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
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

func publish(repo, version, artifacts string, rolloutRevision uint64, percentage uint8, severity string, supervisorMaintenance bool) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	if strings.TrimSpace(version) == "" || !filepath.IsAbs(artifacts) {
		return errors.New("version and absolute artifacts directory are required")
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	state, err := loadSigningState(repo, root)
	if err != nil {
		return err
	}
	targets.Signed.Targets = map[string]*metadata.TargetFiles{}
	createdAt := time.Now().UTC()
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, architecture := range []string{"amd64", "arm64"} {
			format := map[string]string{"darwin": "mach-o", "linux": "elf", "windows": "pe"}[platform]
			components := make([]componentTarget, 0, 5)
			for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
				name := component + "-" + platform + "-" + architecture
				local := filepath.Join(artifacts, name)
				info, err := metadata.TargetFile().FromFile(local, "sha256")
				if err != nil {
					return fmt.Errorf("target %s: %w", name, err)
				}
				custom, _ := json.Marshal(map[string]any{"schema": "paperboat.tuf-component/v1", "kind": "component", "component": component, "version": version, "platform": platform, "architecture": architecture, "binary_format": format})
				raw := json.RawMessage(custom)
				info.Custom, info.Path = &raw, name
				targets.Signed.Targets[name] = info
				if err := copyConsistentTarget(repo, local, name, info); err != nil {
					return err
				}
				components = append(components, componentTarget{Component: component, TargetPath: name, SHA256: hex.EncodeToString(info.Hashes["sha256"]), Length: info.Length, Platform: platform, Architecture: architecture, BinaryFormat: format})
			}
			indexName := "release-index-stable-" + platform + "-" + architecture + ".json"
			indexBody, err := json.Marshal(releaseIndex{Schema: "paperboat.release-index/v1", ReleaseID: "rel_" + version, Version: version, Channel: "stable", Severity: severity, CreatedAt: createdAt, Platform: platform, Architecture: architecture, BinaryFormat: format, Targets: components, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: rolloutRevision, SupervisorMaintenance: supervisorMaintenance, Rollout: rolloutPolicy{Schema: "paperboat.release-rollout/v1", CohortSeed: "release-" + version, Percentage: percentage}})
			if err != nil {
				return err
			}
			indexInfo, err := metadata.TargetFile().FromBytes(indexName, indexBody, "sha256")
			if err != nil {
				return err
			}
			indexCustom, _ := json.Marshal(map[string]string{"schema": "paperboat.tuf-release-index/v1", "kind": "release-index", "channel": "stable", "platform": platform, "architecture": architecture})
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

func refresh(repo string) error {
	repo, err := validateRepository(repo, true)
	if err != nil {
		return err
	}
	root, targets, snapshot, timestamp, err := loadSet(repo)
	if err != nil {
		return err
	}
	state, err := loadSigningState(repo, root)
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

func keyExists(name string) bool {
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

func loadSigningState(repo string, root *metadata.Metadata[metadata.RootType]) (signingState, error) {
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
	if err := validateSigningState(root, state); err != nil {
		return signingState{}, err
	}
	return state, nil
}

func validateSigningState(root *metadata.Metadata[metadata.RootType], state signingState) error {
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		configured := root.Signed.Roles[role]
		if configured == nil || len(state.Roles[role]) < configured.Threshold {
			return errors.New("TUF signing state does not satisfy role thresholds")
		}
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
