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
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	Component    string `json:"component"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// FetchVerifiedReleaseIndex fetches the fixed stable selector through TUF.
// Unsigned discovery data cannot influence the selected target name.
func FetchVerifiedReleaseIndex(ctx context.Context, repositoryURL, stateDirectory string, httpClient *http.Client, now time.Time) (releaseindex.Index, error) {
	parsed, err := url.Parse(repositoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
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
	name := "release-index-" + channel + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".json"
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
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != ReleaseIndexTargetSchemaV1 || custom.Kind != "release-index" || custom.Channel != channel || custom.Platform != runtime.GOOS || custom.Architecture != runtime.GOARCH {
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
	if err != nil || index.Platform != runtime.GOOS || index.Architecture != runtime.GOARCH {
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
	if index.Validate(now) != nil || index.Platform != runtime.GOOS || index.Architecture != runtime.GOARCH || !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
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
	configuration, err := config.New(strings.TrimRight(repositoryURL, "/")+"/metadata/", trustedRoot)
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
	digest, hasDigest := info.Hashes["sha256"]
	if err != nil || !hasDigest || info.Length != target.Length || hex.EncodeToString(digest) != target.SHA256 || info.Custom == nil {
		return "", ErrArtifactMismatch
	}
	var custom tufReleaseComponentCustom
	decoder := json.NewDecoder(strings.NewReader(string(*info.Custom)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != "paperboat.tuf-component/v1" || custom.Kind != "component" || custom.Component != component || custom.Version != index.Version || custom.Platform != target.Platform || custom.Architecture != target.Architecture {
		return "", ErrArtifactMismatch
	}
	path, _, err := client.DownloadTarget(info, "", "")
	if err != nil {
		return "", err
	}
	return path, nil
}

func VerifyArtifactTarget(target ArtifactTarget) error {
	parsed, err := url.Parse(target.RepositoryURL)
	wantPath := "pb-" + target.Platform + "-" + target.Architecture
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		target.Schema != ArtifactTargetSchemaV1 || target.Kind != ArtifactKindPB || target.Version == "" || target.Platform != runtime.GOOS ||
		target.Architecture != runtime.GOARCH || target.TargetPath != wantPath || strings.Contains(target.TargetPath, "/") {
		return ErrArtifactTarget
	}
	return nil
}

func FetchVerifiedArtifact(ctx context.Context, target ArtifactTarget, stateDirectory string, httpClient *http.Client) (string, error) {
	return fetchVerifiedArtifact(ctx, target, stateDirectory, httpClient, trustedRoot)
}

func fetchVerifiedArtifact(ctx context.Context, target ArtifactTarget, stateDirectory string, httpClient *http.Client, root []byte) (string, error) {
	if err := VerifyArtifactTarget(target); err != nil {
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
