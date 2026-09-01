package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

// TestStagedTUFRepository runs the same signed bootstrap, release-index, and
// component consumers used by a native runtime, but serves the freshly signed
// repository from the workflow's isolated staging directory. This must run
// before that directory is activated on the public origin.
func TestStagedTUFRepository(t *testing.T) {
	releaseRoot, githubRoot, err := stagedReleaseVerificationDirectories()
	if err != nil {
		t.Fatal(err)
	}
	if releaseRoot == "" {
		t.Skip("staged release verification is not configured")
	}
	version := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_TUF_VERSION"))
	if version == "" {
		t.Fatal("PAPERBOAT_TEST_TUF_VERSION is not set")
	}
	if !cleanAbsoluteDirectory(releaseRoot) || !cleanAbsoluteDirectory(githubRoot) {
		t.Fatal("staged release paths must be absolute, clean directories")
	}
	currentBody := readStagedRegularFile(t, filepath.Join(releaseRoot, "current.json"))
	var current struct {
		Schema  string `json:"schema"`
		Version string `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(currentBody))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Schema != "paperboat.release-current/v1" || current.Version != version {
		t.Fatal("staged current.json does not select the verified release")
	}
	assertStagedFileEquals(t, filepath.Join(releaseRoot, "install"), filepath.Join(githubRoot, "install.sh"))
	assertStagedFileEquals(t, filepath.Join(releaseRoot, "windows"), filepath.Join(githubRoot, "install.ps1"))

	repositoryRoot := filepath.Join(releaseRoot, "tuf")
	server := stagedTUFServer(t, repositoryRoot)
	defer server.Close()
	client := server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, target := range []struct{ platform, architecture string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"},
	} {
		t.Run(target.platform+"-"+target.architecture, func(t *testing.T) {
			stateRoot := t.TempDir()
			bootstrap := ArtifactTarget{
				Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: version,
				Platform: target.platform, Architecture: target.architecture, RepositoryURL: server.URL,
				TargetPath: releaseindex.AssetName(target.platform, target.architecture),
			}
			bootstrapPath, err := fetchVerifiedArtifact(ctx, bootstrap, filepath.Join(stateRoot, "bootstrap"), client, trustedRoot, target.platform, target.architecture)
			if err != nil {
				t.Fatal(err)
			}
			bootstrapBody, err := os.ReadFile(bootstrapPath)
			if err != nil {
				t.Fatal(err)
			}
			githubBootstrap := readStagedRegularFile(t, filepath.Join(githubRoot, stagedBootstrapAssetName(target.platform, bootstrap.TargetPath)))
			if !bytes.Equal(bootstrapBody, githubBootstrap) {
				t.Fatal("staged bootstrap target differs from the immutable GitHub asset")
			}

			now := time.Now().UTC()
			index, err := fetchVerifiedReleaseIndex(ctx, server.URL, filepath.Join(stateRoot, "index"), client, now, target.platform, target.architecture)
			if err != nil {
				t.Fatal(err)
			}
			if index.Version != version {
				t.Fatalf("staged release index version=%q, want %q", index.Version, version)
			}
			targetInfo, ok := index.Component("pb")
			if !ok {
				t.Fatal("staged release index has no pb component")
			}
			path, err := fetchVerifiedReleaseComponent(ctx, server.URL, filepath.Join(stateRoot, "pb"), index, "pb", client, now, target.platform, target.architecture)
			if err != nil {
				t.Fatalf("pb component: %v", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			if targetInfo.Length != int64(len(body)) || targetInfo.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("pb component does not match its signed target")
			}
			githubComponent := readStagedRegularFile(t, filepath.Join(githubRoot, targetInfo.TargetPath))
			if !bytes.Equal(body, githubComponent) {
				t.Fatal("pb component differs from the immutable GitHub asset")
			}
			if !bytes.Equal(bootstrapBody, body) {
				t.Fatal("staged bootstrap target and signed pb component are not identical")
			}
		})
	}
}

func stagedBootstrapAssetName(_ string, targetPath string) string {
	return targetPath
}

func TestStagedBootstrapAssetNameUsesWindowsExecutableSuffix(t *testing.T) {
	if got := stagedBootstrapAssetName("windows", "pb-windows-amd64.exe"); got != "pb-windows-amd64.exe" {
		t.Fatalf("Windows bootstrap asset = %q", got)
	}
	if got := stagedBootstrapAssetName("linux", "pb-linux-amd64"); got != "pb-linux-amd64" {
		t.Fatalf("Linux bootstrap asset = %q", got)
	}
}

func TestStagedReleaseVerificationCannotSkipWhenRequired(t *testing.T) {
	t.Setenv("PAPERBOAT_TEST_REQUIRE_STAGED", "1")
	t.Setenv("PAPERBOAT_TEST_RELEASE_DIRECTORY", "")
	t.Setenv("PAPERBOAT_TEST_GITHUB_RELEASE_DIRECTORY", "")
	if _, _, err := stagedReleaseVerificationDirectories(); err == nil {
		t.Fatal("required staged verification accepted missing directories")
	}
}

func TestStagedReleaseVerificationRejectsInvalidRequireFlag(t *testing.T) {
	t.Setenv("PAPERBOAT_TEST_REQUIRE_STAGED", "true")
	t.Setenv("PAPERBOAT_TEST_RELEASE_DIRECTORY", "")
	t.Setenv("PAPERBOAT_TEST_GITHUB_RELEASE_DIRECTORY", "")
	if _, _, err := stagedReleaseVerificationDirectories(); err == nil {
		t.Fatal("invalid staged verification gate was accepted")
	}
}

func stagedReleaseVerificationDirectories() (string, string, error) {
	releaseRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_RELEASE_DIRECTORY"))
	githubRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_GITHUB_RELEASE_DIRECTORY"))
	require := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_REQUIRE_STAGED"))
	if require != "" && require != "1" {
		return "", "", fmt.Errorf("PAPERBOAT_TEST_REQUIRE_STAGED must be exactly 1 when set, got %q", require)
	}
	if releaseRoot == "" || githubRoot == "" {
		if require == "1" {
			return "", "", errors.New("required staged release or downloaded GitHub release directory is not set")
		}
		return "", "", nil
	}
	return releaseRoot, githubRoot, nil
}

func cleanAbsoluteDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func readStagedRegularFile(t *testing.T, path string) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("required staged file is unavailable: %s", filepath.Base(path))
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertStagedFileEquals(t *testing.T, staged, immutable string) {
	t.Helper()
	if !bytes.Equal(readStagedRegularFile(t, staged), readStagedRegularFile(t, immutable)) {
		t.Fatalf("staged %s differs from immutable GitHub asset %s", filepath.Base(staged), filepath.Base(immutable))
	}
}

func stagedTUFServer(t *testing.T, root string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		relative := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(request.URL.Path)), "/")
		if relative == "" || strings.Contains(relative, "..") {
			http.NotFound(writer, request)
			return
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.NotFound(writer, request)
			return
		}
		file, err := os.Open(path)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		defer file.Close()
		http.ServeContent(writer, request, filepath.Base(path), info.ModTime(), file)
	}))
}
