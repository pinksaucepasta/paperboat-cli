package bootstrap

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// tufAssetCustom is the signed contract published for every release asset.
// The release policy is embedded in the asset target metadata so bootstrap and
// the updater have one TUF target to verify and download. There is no separate
// launcher, runtime, CLI, updater, or release-index artifact.
type tufAssetCustom struct {
	Schema       string             `json:"schema"`
	Kind         string             `json:"kind"`
	Version      string             `json:"version"`
	Platform     string             `json:"platform"`
	Architecture string             `json:"architecture"`
	Format       string             `json:"format"`
	AssetName    string             `json:"asset_name"`
	Repository   string             `json:"repository"`
	URL          string             `json:"url"`
	SHA256       string             `json:"sha256"`
	Length       int64              `json:"length"`
	ReleaseIndex releaseindex.Index `json:"release_index"`
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
	name := releaseindex.AssetName(platform, architecture)
	info, err := client.GetTargetInfo(name)
	if err != nil || info == nil || info.Length < 1 || info.Length > 512<<20 || info.Custom == nil {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	custom, ok := decodeTUFAssetCustom(*info.Custom)
	if !ok || custom.ReleaseIndex.Validate(now) != nil || custom.ReleaseIndex.Platform != platform || custom.ReleaseIndex.Architecture != architecture {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	target, ok := custom.ReleaseIndex.Component("pb")
	digest, hasDigest := info.Hashes["sha256"]
	if !ok || !validTUFAssetCustom(custom, custom.ReleaseIndex, target, info.Length, digest, hasDigest) || name != target.TargetPath {
		return releaseindex.Index{}, ErrArtifactMismatch
	}
	return custom.ReleaseIndex, nil
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
		return "", ErrArtifactMismatch
	}
	if component != "pb" {
		return "", ErrArtifactTarget
	}
	target, ok := index.Component("pb")
	if !ok {
		return "", ErrArtifactMismatch
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
	custom, ok := decodeTUFAssetCustom(*info.Custom)
	if !ok || !validTUFAssetCustom(custom, index, target, info.Length, digest, hasDigest) {
		return "", ErrArtifactMismatch
	}
	return downloadVerifiedGitHubAsset(ctx, httpClient, custom.URL, stateDirectory, target.AssetName, info.Length, digest)
}

func decodeTUFAssetCustom(raw json.RawMessage) (tufAssetCustom, bool) {
	var custom tufAssetCustom
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF {
		return tufAssetCustom{}, false
	}
	return custom, true
}

// validTUFAssetCustom binds the TUF target metadata, the signed release index,
// and the immutable GitHub asset identity. infoDigest is the sha256 recorded by
// TUF itself; requiring it here prevents a custom field from becoming the
// source of truth for downloaded bytes.
func validTUFAssetCustom(custom tufAssetCustom, index releaseindex.Index, target releaseindex.Target, infoLength int64, infoDigest []byte, infoDigestPresent bool) bool {
	assetName := releaseindex.AssetName(target.Platform, target.Architecture)
	if custom.Schema != "paperboat.tuf-asset/v1" || custom.Kind != "github-release-asset" ||
		custom.Version != index.Version || custom.Platform != target.Platform || custom.Architecture != target.Architecture ||
		custom.Format != target.BinaryFormat || custom.AssetName != assetName || custom.Repository != target.Repository ||
		custom.URL != target.DownloadURL || !releaseindex.ValidDownloadURL(custom.URL, custom.Repository, index.Version, assetName) ||
		custom.SHA256 != target.SHA256 || custom.Length != target.Length || !infoDigestPresent ||
		infoLength != target.Length || hex.EncodeToString(infoDigest) != target.SHA256 ||
		custom.ReleaseIndex.Version != index.Version || custom.ReleaseIndex.Platform != index.Platform ||
		custom.ReleaseIndex.Architecture != index.Architecture || custom.ReleaseIndex.BinaryFormat != index.BinaryFormat {
		return false
	}
	if len(custom.ReleaseIndex.Targets) != 1 {
		return false
	}
	return custom.ReleaseIndex.Targets[0] == target
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
	wantPath := releaseindex.AssetName(target.Platform, target.Architecture)
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
	if err != nil || info == nil {
		return "", ErrArtifactMismatch
	}
	if info.Length < 1 || info.Length > 512<<20 || info.Custom == nil {
		return "", ErrArtifactMismatch
	}
	custom, ok := decodeTUFAssetCustom(*info.Custom)
	if !ok || custom.ReleaseIndex.Validate(time.Now().UTC()) != nil || custom.ReleaseIndex.Version != target.Version || custom.ReleaseIndex.Platform != target.Platform || custom.ReleaseIndex.Architecture != target.Architecture {
		return "", ErrArtifactMismatch
	}
	signedTarget, ok := custom.ReleaseIndex.Component("pb")
	if !ok || signedTarget.TargetPath != target.TargetPath {
		return "", ErrArtifactMismatch
	}
	digest, hasDigest := info.Hashes["sha256"]
	if !validTUFAssetCustom(custom, custom.ReleaseIndex, signedTarget, info.Length, digest, hasDigest) {
		return "", ErrArtifactMismatch
	}
	path, err := downloadVerifiedGitHubAsset(ctx, httpClient, custom.URL, targetsDir, signedTarget.AssetName, info.Length, digest)
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

func downloadVerifiedGitHubAsset(ctx context.Context, base *http.Client, rawURL, directory, name string, expectedLength int64, expectedDigest []byte) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || filepath.Base(name) != name || name == "." || expectedLength < 1 || expectedLength > 512<<20 || len(expectedDigest) != sha256.Size {
		return "", ErrArtifactMismatch
	}
	if err := secureDirectory(directory); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	if base != nil {
		*client = *base
		if client.Timeout <= 0 {
			client.Timeout = 5 * time.Minute
		}
	}
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		host := strings.ToLower(request.URL.Hostname())
		if len(via) >= 5 || request.URL.Scheme != "https" || request.URL.User != nil || host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com") && !strings.HasSuffix(host, ".blob.core.windows.net") {
			return ErrArtifactTarget
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > expectedLength {
		return "", fmt.Errorf("%w: GitHub asset response", ErrArtifactMismatch)
	}
	//paperboat:allow-source-policy atomic-replacement owner=release-bootstrap reason=same-directory-TUF-verified-GitHub-asset-staging
	pending, err := os.CreateTemp(directory, ".pb-download-")
	if err != nil {
		return "", err
	}
	pendingPath := pending.Name()
	committed := false
	defer func() {
		_ = pending.Close()
		if !committed {
			_ = os.Remove(pendingPath)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(pending, hash), io.LimitReader(response.Body, expectedLength+1))
	if copyErr != nil || written != expectedLength || !equalBytes(hash.Sum(nil), expectedDigest) {
		return "", ErrArtifactMismatch
	}
	if err := pending.Sync(); err != nil {
		return "", err
	}
	if err := pending.Chmod(0o700); err != nil {
		return "", err
	}
	if err := pending.Close(); err != nil {
		return "", err
	}
	destination := filepath.Join(directory, name)
	//paperboat:allow-source-policy atomic-replacement owner=release-bootstrap reason=verified-GitHub-asset-publication
	if err := os.Rename(pendingPath, destination); err != nil {
		return "", err
	}
	committed = true
	return destination, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
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
