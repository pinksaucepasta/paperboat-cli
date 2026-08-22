package bootstrap

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const ReleaseIndexTargetSchemaV1 = "paperboat.tuf-release-index/v1"

const (
	ArtifactTargetSchemaV1 = "paperboat.tuf-target/v1"
	ArtifactKindPB         = "pb"
)

var (
	ErrArtifactTarget   = errors.New("pb TUF target descriptor is invalid")
	ErrArtifactMismatch = errors.New("pb TUF target metadata does not match the requested artifact")

	//go:embed trusted-root.json
	trustedRoot []byte
)

type ArtifactTarget struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	RepositoryURL string `json:"repository_url"`
	TargetPath    string `json:"target_path"`
}

type tufTargetCustom struct {
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

type tufReleaseIndexCustom struct {
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	Channel      string `json:"channel"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}
type tufReleaseComponentCustom struct {
	Schema              string                                `json:"schema"`
	Kind                string                                `json:"kind"`
	Component           string                                `json:"component"`
	Version             string                                `json:"version"`
	Platform            string                                `json:"platform"`
	Architecture        string                                `json:"architecture"`
	BinaryFormat        string                                `json:"binary_format"`
	NativeQualification *tufWindowsNativeQualificationBinding `json:"native_qualification,omitempty"`
}

type tufWindowsNativeQualificationBinding struct {
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

type tufWindowsNativeQualificationTargetCustom struct {
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Status       string `json:"status"`
}

type tufWindowsNativeQualification struct {
	Schema         string                              `json:"schema"`
	ReleaseVersion string                              `json:"release_version"`
	Platform       string                              `json:"platform"`
	Architecture   string                              `json:"architecture"`
	Status         string                              `json:"status"`
	NativeTested   bool                                `json:"native_tested"`
	WindowsBuild   string                              `json:"windows_build"`
	Runner         string                              `json:"runner"`
	Artifacts      []tufWindowsNativeQualifiedArtifact `json:"artifacts"`
}

type tufWindowsNativeQualifiedArtifact struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Status       string `json:"status"`
}

// FetchVerifiedReleaseIndex fetches the fixed stable selector through TUF.
// Unsigned discovery data cannot influence the selected target name.
func FetchVerifiedReleaseIndex(ctx context.Context, repositoryURL, stateDirectory string, httpClient *http.Client, now time.Time) (releaseindex.Index, error) {
	return fetchVerifiedReleaseIndex(ctx, repositoryURL, stateDirectory, httpClient, now, runtime.GOOS, runtime.GOARCH)
}

// fetchVerifiedReleaseIndex is the runtime-independent form used by the
// staged release contract. Production callers must use the exported wrapper,
// which remains bound to the executing platform.
func fetchVerifiedReleaseIndex(ctx context.Context, repositoryURL, stateDirectory string, httpClient *http.Client, now time.Time, platform, architecture string) (releaseindex.Index, error) {
	parsed, err := url.Parse(repositoryURL)
	if !supportedReleasePlatform(platform, architecture) || err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return releaseindex.Index{}, ErrArtifactTarget
	}
	if err := secureDirectory(stateDirectory); err != nil {
		return releaseindex.Index{}, err
	}
	configuration, err := config.New(strings.TrimRight(repositoryURL, "/")+"/metadata/", trustedRoot)
	if err != nil {
		return releaseindex.Index{}, err
	}
	configuration.LocalMetadataDir = filepath.Join(stateDirectory, "metadata")
	configuration.LocalTargetsDir = filepath.Join(stateDirectory, "targets")
	configuration.RemoteTargetsURL = strings.TrimRight(repositoryURL, "/") + "/targets/"
	configuration.PrefixTargetsWithHash = true
	configuration.MaxRootRotations, configuration.RootMaxLength, configuration.TimestampMaxLength, configuration.SnapshotMaxLength, configuration.TargetsMaxLength = 32, 128<<10, 64<<10, 256<<10, 512<<10
	httpClient = secureArtifactHTTPClient(httpClient, parsedOrigin(repositoryURL))
	if err := configuration.SetDefaultFetcherHTTPClient(httpClient); err != nil {
		return releaseindex.Index{}, err
	}
	client, err := updater.New(configuration)
	if err != nil {
		return releaseindex.Index{}, err
	}
	if err := client.Refresh(); err != nil {
		return releaseindex.Index{}, err
	}
	channel := "stable"
	name := "release-index-" + channel + "-" + platform + "-" + architecture + ".json"
	info, err := client.GetTargetInfo(name)
	if err != nil {
		return releaseindex.Index{}, err
	}
	if info.Length < 1 || info.Length > 64<<10 || info.Custom == nil {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	var custom tufReleaseIndexCustom
	decoder := json.NewDecoder(strings.NewReader(string(*info.Custom)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != ReleaseIndexTargetSchemaV1 || custom.Kind != "release-index" || custom.Channel != channel || custom.Platform != platform || custom.Architecture != architecture {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	path, _, err := client.DownloadTarget(info, "", "")
	if err != nil {
		return releaseindex.Index{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return releaseindex.Index{}, err
	}
	defer file.Close()
	index, err := releaseindex.Decode(file, now)
	if err != nil || index.Platform != platform || index.Architecture != architecture {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	return index, nil
}

// FetchVerifiedReleaseComponent obtains one component named by an already
// verified release index. Both the index and the TUF target metadata must agree
// on the fixed component name, platform, architecture, length, and digest.
// The caller receives only a local verified artifact path; it must still stage
// the bytes into its own privileged release directory.
func FetchVerifiedReleaseComponent(ctx context.Context, repositoryURL, stateDirectory string, index releaseindex.Index, component string, httpClient *http.Client, now time.Time) (string, error) {
	return fetchVerifiedReleaseComponent(ctx, repositoryURL, stateDirectory, index, component, httpClient, now, runtime.GOOS, runtime.GOARCH)
}

// fetchVerifiedReleaseComponent lets the staged-release contract exercise
// every supported native target from one isolated signed repository. It is
// intentionally unexported so running software remains platform-bound.
func fetchVerifiedReleaseComponent(ctx context.Context, repositoryURL, stateDirectory string, index releaseindex.Index, component string, httpClient *http.Client, now time.Time, platform, architecture string) (string, error) {
	return fetchVerifiedReleaseComponentWithRoot(ctx, repositoryURL, stateDirectory, index, component, httpClient, now, trustedRoot, platform, architecture)
}

// fetchVerifiedReleaseComponentWithRoot is split from the production wrapper
// so tests can exercise malformed signed metadata with an isolated test root.
func fetchVerifiedReleaseComponentWithRoot(ctx context.Context, repositoryURL, stateDirectory string, index releaseindex.Index, component string, httpClient *http.Client, now time.Time, root []byte, platform, architecture string) (string, error) {
	if !supportedReleasePlatform(platform, architecture) || index.Validate(now) != nil || index.Platform != platform || index.Architecture != architecture || !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return "", ErrArtifactTarget
	}
	target, ok := index.Component(component)
	if !ok || component != "runtime" && component != "cli" && component != "hostd" && component != "updater" && component != "launcher" {
		return "", ErrArtifactTarget
	}
	if err := secureDirectory(stateDirectory); err != nil {
		return "", err
	}
	parsed, err := url.Parse(repositoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrArtifactTarget
	}
	configuration, err := config.New(strings.TrimRight(repositoryURL, "/")+"/metadata/", root)
	if err != nil {
		return "", err
	}
	configuration.LocalMetadataDir = filepath.Join(stateDirectory, "metadata")
	configuration.LocalTargetsDir = filepath.Join(stateDirectory, "targets")
	configuration.RemoteTargetsURL = strings.TrimRight(repositoryURL, "/") + "/targets/"
	configuration.PrefixTargetsWithHash = true
	configuration.MaxRootRotations, configuration.RootMaxLength, configuration.TimestampMaxLength, configuration.SnapshotMaxLength, configuration.TargetsMaxLength = 32, 128<<10, 64<<10, 256<<10, 512<<10
	httpClient = secureArtifactHTTPClient(httpClient, parsedOrigin(repositoryURL))
	if err := configuration.SetDefaultFetcherHTTPClient(httpClient); err != nil {
		return "", err
	}
	client, err := updater.New(configuration)
	if err != nil {
		return "", err
	}
	if err := client.Refresh(); err != nil {
		return "", err
	}
	info, err := client.GetTargetInfo(target.TargetPath)
	if err != nil || info == nil {
		return "", ErrArtifactMismatch
	}
	digest, hasDigest := info.Hashes["sha256"]
	if !hasDigest || info.Length != target.Length || hex.EncodeToString(digest) != target.SHA256 || info.Custom == nil {
		return "", ErrArtifactMismatch
	}
	custom, ok := decodeReleaseComponentCustom(*info.Custom)
	if !ok || !validReleaseComponentCustom(custom, index, target, component) {
		return "", ErrArtifactMismatch
	}
	if target.Platform == "windows" {
		if err := verifyWindowsNativeQualification(client, custom.NativeQualification, index, target); err != nil {
			return "", err
		}
	}
	path, _, err := client.DownloadTarget(info, "", "")
	if err != nil {
		return "", err
	}
	return path, nil
}

// validReleaseComponentCustom requires the signed target descriptor to agree
// with the signed release-index entry. Keeping this decoder strict prevents a
// publisher and verifier schema drift from silently weakening that binding.
func decodeReleaseComponentCustom(raw json.RawMessage) (tufReleaseComponentCustom, bool) {
	var custom tufReleaseComponentCustom
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF {
		return tufReleaseComponentCustom{}, false
	}
	return custom, true
}

func validReleaseComponentCustom(custom tufReleaseComponentCustom, index releaseindex.Index, target releaseindex.Target, component string) bool {
	base :=
		custom.Schema == "paperboat.tuf-component/v1" &&
			custom.Kind == "component" &&
			custom.Component == component &&
			custom.Version == index.Version &&
			custom.Platform == target.Platform &&
			custom.Architecture == target.Architecture &&
			custom.BinaryFormat == target.BinaryFormat
	if !base {
		return false
	}
	if target.Platform == "windows" {
		return custom.NativeQualification != nil
	}
	return custom.NativeQualification == nil
}

func verifyWindowsNativeQualification(client *updater.Updater, binding *tufWindowsNativeQualificationBinding, index releaseindex.Index, target releaseindex.Target) error {
	if !validWindowsNativeQualificationBinding(binding, index, target) {
		return ErrArtifactMismatch
	}
	info, err := client.GetTargetInfo(binding.EvidenceTarget)
	if err != nil {
		return ErrArtifactMismatch
	}
	digest, hasDigest := info.Hashes["sha256"]
	if !hasDigest || hex.EncodeToString(digest) != binding.EvidenceSHA256 || info.Length < 1 || info.Length > 1<<20 || info.Custom == nil || !validWindowsNativeQualificationTargetCustom(*info.Custom, target.Architecture) {
		return ErrArtifactMismatch
	}
	path, _, err := client.DownloadTarget(info, "", "")
	if err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !validWindowsNativeQualificationEvidence(body, binding, index) {
		return ErrArtifactMismatch
	}
	return nil
}

func validWindowsNativeQualificationBinding(binding *tufWindowsNativeQualificationBinding, index releaseindex.Index, target releaseindex.Target) bool {
	return binding != nil &&
		index.Platform == "windows" &&
		index.Architecture == target.Architecture &&
		binding.Schema == "paperboat.windows-native-qualification/v1" &&
		binding.EvidenceTarget == "windows-"+target.Architecture+"-native-qualification.json" &&
		len(binding.EvidenceSHA256) == 64 && lowerHex(binding.EvidenceSHA256) &&
		binding.ReleaseVersion == index.Version &&
		binding.Platform == "windows" &&
		binding.Architecture == target.Architecture &&
		binding.Status == "passed" &&
		binding.NativeTested &&
		safeQualificationValue(binding.WindowsBuild) &&
		safeQualificationValue(binding.Runner) &&
		binding.ArtifactSHA256 == target.SHA256 &&
		binding.ArtifactLength == target.Length
}

func validWindowsNativeQualificationTargetCustom(raw json.RawMessage, architecture string) bool {
	var custom tufWindowsNativeQualificationTargetCustom
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var extra any
	return decoder.Decode(&custom) == nil && decoder.Decode(&extra) == io.EOF &&
		custom.Schema == "paperboat.windows-native-qualification/v1" &&
		custom.Kind == "windows-native-qualification" &&
		custom.Platform == "windows" &&
		custom.Architecture == architecture &&
		custom.Status == "passed"
}

func validWindowsNativeQualificationEvidence(raw []byte, binding *tufWindowsNativeQualificationBinding, index releaseindex.Index) bool {
	var qualification tufWindowsNativeQualification
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&qualification) != nil || decoder.Decode(&extra) != io.EOF || binding == nil ||
		qualification.Schema != "paperboat.windows-native-qualification/v1" ||
		qualification.ReleaseVersion != index.Version ||
		qualification.Platform != "windows" ||
		qualification.Architecture != index.Architecture ||
		qualification.Status != "passed" || !qualification.NativeTested ||
		qualification.WindowsBuild != binding.WindowsBuild || qualification.Runner != binding.Runner ||
		!safeQualificationValue(qualification.WindowsBuild) || !safeQualificationValue(qualification.Runner) ||
		index.Stability != "stable" || !index.NativeTested || len(index.TestedWindowsBuilds) != 1 ||
		qualification.WindowsBuild != index.TestedWindowsBuilds[0] || len(qualification.Artifacts) != len(index.Targets) {
		return false
	}
	expected := make(map[string]releaseindex.Target, len(index.Targets))
	for _, component := range index.Targets {
		expected[component.Component] = component
	}
	for _, artifact := range qualification.Artifacts {
		component, ok := expected[artifact.Component]
		if !ok || artifact.TargetPath != component.TargetPath || artifact.SHA256 != component.SHA256 || artifact.Length != component.Length || artifact.Platform != "windows" || artifact.Architecture != index.Architecture || artifact.Status != "passed" {
			return false
		}
		delete(expected, artifact.Component)
	}
	return len(expected) == 0
}

func safeQualificationValue(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}

func lowerHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func supportedReleasePlatform(platform, architecture string) bool {
	return platform == "linux" && (architecture == "amd64" || architecture == "arm64") ||
		platform == "darwin" && architecture == "arm64" ||
		platform == "windows" && (architecture == "amd64" || architecture == "arm64")
}

func VerifyArtifactTarget(target ArtifactTarget) error {
	return verifyArtifactTarget(target, runtime.GOOS, runtime.GOARCH)
}

func verifyArtifactTarget(target ArtifactTarget, platform, architecture string) error {
	parsed, err := url.Parse(target.RepositoryURL)
	wantPath := "pb-" + target.Platform + "-" + target.Architecture
	if !supportedReleasePlatform(platform, architecture) || err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		target.Schema != ArtifactTargetSchemaV1 || target.Kind != ArtifactKindPB || target.Version == "" || target.Platform != platform ||
		target.Architecture != architecture || target.TargetPath != wantPath || strings.Contains(target.TargetPath, "/") {
		return ErrArtifactTarget
	}
	return nil
}

func FetchVerifiedArtifact(ctx context.Context, target ArtifactTarget, stateDirectory string, httpClient *http.Client) (string, error) {
	return fetchVerifiedArtifact(ctx, target, stateDirectory, httpClient, trustedRoot, runtime.GOOS, runtime.GOARCH)
}

func fetchVerifiedArtifact(ctx context.Context, target ArtifactTarget, stateDirectory string, httpClient *http.Client, root []byte, platform, architecture string) (string, error) {
	if err := verifyArtifactTarget(target, platform, architecture); err != nil {
		return "", err
	}
	if !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return "", ErrArtifactTarget
	}
	if err := secureDirectory(stateDirectory); err != nil {
		return "", err
	}
	metadataDir := filepath.Join(stateDirectory, "metadata")
	targetsDir := filepath.Join(stateDirectory, "targets")
	configuration, err := config.New(strings.TrimRight(target.RepositoryURL, "/")+"/metadata/", root)
	if err != nil {
		return "", err
	}
	configuration.LocalMetadataDir = metadataDir
	configuration.LocalTargetsDir = targetsDir
	configuration.RemoteTargetsURL = strings.TrimRight(target.RepositoryURL, "/") + "/targets/"
	configuration.PrefixTargetsWithHash = true
	configuration.MaxRootRotations = 32
	configuration.RootMaxLength = 128 << 10
	configuration.TimestampMaxLength = 64 << 10
	configuration.SnapshotMaxLength = 256 << 10
	configuration.TargetsMaxLength = 512 << 10
	httpClient = secureArtifactHTTPClient(httpClient, parsedOrigin(target.RepositoryURL))
	if err := configuration.SetDefaultFetcherHTTPClient(httpClient); err != nil {
		return "", err
	}
	client, err := updater.New(configuration)
	if err != nil {
		return "", err
	}
	if err := client.Refresh(); err != nil {
		return "", err
	}
	info, err := client.GetTargetInfo(target.TargetPath)
	if err != nil {
		return "", err
	}
	if info.Length < 1 || info.Length > 256<<20 || info.Custom == nil {
		return "", ErrArtifactMismatch
	}
	var custom tufTargetCustom
	decoder := json.NewDecoder(strings.NewReader(string(*info.Custom)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != ArtifactTargetSchemaV1 || custom.Kind != target.Kind ||
		custom.Version != target.Version || custom.Platform != target.Platform || custom.Architecture != target.Architecture {
		return "", ErrArtifactMismatch
	}
	path, _, err := client.DownloadTarget(info, "", "")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return "", err
	}
	if err := secureArtifactFile(path); err != nil {
		return "", err
	}
	return path, nil
}

func parsedOrigin(raw string) string {
	parsed, _ := url.Parse(raw)
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

func secureArtifactHTTPClient(base *http.Client, origin string) *http.Client {
	result := &http.Client{}
	if base != nil {
		*result = *base
	}
	if result.Timeout <= 0 {
		result.Timeout = 2 * time.Minute
	}
	previous := result.CheckRedirect
	result.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || parsedOrigin(request.URL.String()) != origin || request.URL.Scheme != "https" || request.URL.User != nil {
			return ErrArtifactTarget
		}
		if previous != nil {
			return previous(request, via)
		}
		return nil
	}
	return result
}
