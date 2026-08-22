package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
				TargetPath: "pb-" + target.platform + "-" + target.architecture,
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
			for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
				targetInfo, ok := index.Component(component)
				if !ok {
					t.Fatalf("staged release index has no %s component", component)
				}
				path, err := fetchVerifiedReleaseComponent(ctx, server.URL, filepath.Join(stateRoot, component), index, component, client, now, target.platform, target.architecture)
				if err != nil {
					t.Fatalf("component %s: %v", component, err)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(body)
				if targetInfo.Length != int64(len(body)) || targetInfo.SHA256 != hex.EncodeToString(digest[:]) {
					t.Fatalf("component %s does not match its signed target", component)
				}
				githubComponent := readStagedRegularFile(t, filepath.Join(githubRoot, targetInfo.TargetPath))
				if !bytes.Equal(body, githubComponent) {
					t.Fatalf("component %s differs from the immutable GitHub asset", component)
				}
				if component == "cli" && !bytes.Equal(bootstrapBody, body) {
					t.Fatal("staged bootstrap alias and signed CLI component are not identical")
				}
			}
			if target.platform == "windows" {
				evidence := "windows-" + target.architecture + "-native-qualification.json"
				assertSignedTargetMatchesFile(t, filepath.Join(repositoryRoot, "metadata", "targets.json"), evidence, filepath.Join(githubRoot, evidence))
			}
		})
	}
}

func stagedBootstrapAssetName(platform, targetPath string) string {
	if platform == "windows" {
		return targetPath + ".exe"
	}
	return targetPath
}

func TestStagedBootstrapAssetNameUsesWindowsExecutableSuffix(t *testing.T) {
	if got := stagedBootstrapAssetName("windows", "pb-windows-amd64"); got != "pb-windows-amd64.exe" {
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

func stagedReleaseVerificationDirectories() (string, string, error) {
	releaseRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_RELEASE_DIRECTORY"))
	githubRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_GITHUB_RELEASE_DIRECTORY"))
	if releaseRoot == "" || githubRoot == "" {
		if strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_REQUIRE_STAGED")) == "1" {
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

func assertSignedTargetMatchesFile(t *testing.T, targetsPath, name, immutable string) {
	t.Helper()
	var envelope struct {
		Signed struct {
			Targets map[string]struct {
				Length int64             `json:"length"`
				Hashes map[string]string `json:"hashes"`
			} `json:"targets"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(readStagedRegularFile(t, targetsPath), &envelope); err != nil {
		t.Fatal(err)
	}
	descriptor, ok := envelope.Signed.Targets[name]
	if !ok {
		t.Fatalf("signed TUF targets metadata has no %s", name)
	}
	body := readStagedRegularFile(t, immutable)
	digest := sha256.Sum256(body)
	if descriptor.Length != int64(len(body)) || descriptor.Hashes["sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("signed TUF target %s differs from the immutable GitHub asset", name)
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
