package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type testTUFRepository struct {
	root  []byte
	files map[string][]byte
}

func newTestTUFRepository(t *testing.T, body []byte, version string, expires time.Time) testTUFRepository {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(time.Now().UTC().Add(24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	targetPath := releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)
	targets := metadata.Targets(time.Now().UTC().Add(24 * time.Hour))
	info, err := metadata.TargetFile().FromBytes(targetPath, body, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(body)
	format := "elf"
	if runtime.GOOS == "darwin" {
		format = "dmg"
	}
	repository := "pinksaucepasta/paperboat-cli"
	index := releaseindex.Index{
		Schema: releaseindex.SchemaV1, ReleaseID: "rel_" + version, Version: version, Channel: "stable", Severity: "routine",
		CreatedAt: time.Now().UTC(), Platform: runtime.GOOS, Architecture: runtime.GOARCH, BinaryFormat: format,
		Targets:     []releaseindex.Target{{Component: "pb", TargetPath: targetPath, AssetName: targetPath, Repository: repository, DownloadURL: "https://github.com/" + repository + "/releases/download/" + version + "/" + targetPath, SHA256: hex.EncodeToString(digestBytes[:]), Length: int64(len(body)), Platform: runtime.GOOS, Architecture: runtime.GOARCH, BinaryFormat: format}},
		HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1,
		Rollout: releaseindex.Rollout{Schema: releaseindex.RolloutSchemaV1, CohortSeed: "release-" + version, Percentage: 100},
	}
	custom, _ := json.Marshal(tufAssetCustom{Schema: "paperboat.tuf-asset/v1", Kind: "github-release-asset", Version: version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, Format: format, AssetName: targetPath, Repository: repository, URL: index.Targets[0].DownloadURL, SHA256: hex.EncodeToString(digestBytes[:]), Length: int64(len(body)), ReleaseIndex: index})
	raw := json.RawMessage(custom)
	info.Custom, info.Path = &raw, targetPath
	targets.Signed.Targets[targetPath] = info
	snapshot := metadata.Snapshot(time.Now().UTC().Add(24 * time.Hour))
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(1)
	timestamp := metadata.Timestamp(expires)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	for _, item := range []struct {
		role  string
		value interface {
			Sign(signature.Signer) (*metadata.Signature, error)
		}
	}{
		{"root", root}, {"targets", targets}, {"snapshot", snapshot}, {"timestamp", timestamp},
	} {
		signer, err := signature.LoadSigner(keys[item.role], crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.value.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	rootBytes, _ := root.ToBytes(false)
	targetsBytes, _ := targets.ToBytes(false)
	snapshotBytes, _ := snapshot.ToBytes(false)
	timestampBytes, _ := timestamp.ToBytes(false)
	targetDigest := hex.EncodeToString(info.Hashes["sha256"])
	return testTUFRepository{root: rootBytes, files: map[string][]byte{
		"/metadata/timestamp.json":                                            timestampBytes,
		"/metadata/1.snapshot.json":                                           snapshotBytes,
		"/metadata/1.targets.json":                                            targetsBytes,
		"/targets/" + targetDigest + "." + targetPath:                         body,
		"/" + repository + "/releases/download/" + version + "/" + targetPath: body,
	}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (r testTUFRepository) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := r.files[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write(body)
	}))
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	transport := client.Transport
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() == "github.com" {
			clone := request.Clone(request.Context())
			clonedURL := *request.URL
			clonedURL.Scheme, clonedURL.Host = target.Scheme, target.Host
			clone.URL = &clonedURL
			request = clone
		}
		return transport.RoundTrip(request)
	})
	return server
}

func descriptor(repositoryURL, version string) ArtifactTarget {
	return ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: repositoryURL, TargetPath: releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)}
}

func TestFetchVerifiedArtifactThroughTUF(t *testing.T) {
	body := []byte("verified pb binary")
	repository := newTestTUFRepository(t, body, "2026.08.07.1", time.Now().UTC().Add(time.Hour))
	server := repository.server(t)
	defer server.Close()
	path, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07.1"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("artifact=%q err=%v", got, err)
	}
	if err := secureArtifactFile(path); err != nil {
		t.Fatalf("artifact security error=%v", err)
	}
}

func TestFetchVerifiedArtifactRejectsTargetMismatch(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("expected"), "2026.08.07.1", time.Now().UTC().Add(time.Hour))
	for path := range repository.files {
		if strings.Contains(path, "/releases/download/") {
			repository.files[path] = []byte("tampered")
		}
	}
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07.1"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("tampered target was accepted")
	}
}

func TestFetchVerifiedArtifactRejectsExpiredTimestampAndWrongVersion(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("pb"), "2026.08.07.1", time.Now().UTC().Add(-time.Minute))
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07.1"), filepath.Join(t.TempDir(), "expired-tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("expired timestamp was accepted")
	}
	repository = newTestTUFRepository(t, []byte("pb"), "2026.08.07.1", time.Now().UTC().Add(time.Hour))
	server = repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.08.1"), filepath.Join(t.TempDir(), "wrong-version-tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("wrong version error=%v", err)
	}
}

func TestVerifyArtifactTargetRejectsWrongPlatformAndOrigin(t *testing.T) {
	target := descriptor("https://updates.example.test/paperboat", "2026.08.07.1")
	target.Platform = "unsupported"
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("platform err=%v", err)
	}
	target = descriptor("http://updates.example.test/paperboat", "2026.08.07")
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("origin err=%v", err)
	}
}

func TestReleaseIndexDiscoveryRejectsUnsignedTargetSelectionInputs(t *testing.T) {
	state := filepath.Join(t.TempDir(), "tuf")
	for _, repository := range []string{
		"http://releases.example.test", "https://user@releases.example.test",
		"https://releases.example.test?target=attacker", "https://releases.example.test/#fragment",
	} {
		if _, err := FetchVerifiedReleaseIndex(context.Background(), repository, state, nil, time.Now().UTC()); !errors.Is(err, ErrArtifactTarget) {
			t.Fatalf("repository=%q error=%v", repository, err)
		}
	}
}

func TestFetchVerifiedReleaseComponentRejectsMissingTargetMetadata(t *testing.T) {
	repository := newTestReleaseComponentRepositoryWithoutTargets(t)
	server := repository.server(t)
	defer server.Close()

	now := time.Now().UTC()
	index := testLinuxReleaseIndex()
	if _, err := fetchVerifiedReleaseComponentWithRoot(context.Background(), server.URL, filepath.Join(t.TempDir(), "tuf"), index, "pb", server.Client(), now, repository.root, "linux", "amd64"); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("missing signed target metadata error=%v", err)
	}
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTestReleaseComponentRepositoryWithoutTargets(t *testing.T) testTUFRepository {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(time.Now().UTC().Add(24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	targets := metadata.Targets(time.Now().UTC().Add(24 * time.Hour))
	snapshot := metadata.Snapshot(time.Now().UTC().Add(24 * time.Hour))
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(1)
	timestamp := metadata.Timestamp(time.Now().UTC().Add(time.Hour))
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	for _, item := range []struct {
		role  string
		value interface {
			Sign(signature.Signer) (*metadata.Signature, error)
		}
	}{
		{"root", root}, {"targets", targets}, {"snapshot", snapshot}, {"timestamp", timestamp},
	} {
		signer, err := signature.LoadSigner(keys[item.role], crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.value.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	targetsBytes, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestampBytes, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return testTUFRepository{root: rootBytes, files: map[string][]byte{
		"/metadata/timestamp.json":  timestampBytes,
		"/metadata/1.snapshot.json": snapshotBytes,
		"/metadata/1.targets.json":  targetsBytes,
	}}
}

func testLinuxReleaseIndex() releaseindex.Index {
	name := releaseindex.AssetName("linux", "amd64")
	targets := []releaseindex.Target{{Component: "pb", TargetPath: name, AssetName: name, Repository: "pinksaucepasta/paperboat-cli", DownloadURL: "https://github.com/pinksaucepasta/paperboat-cli/releases/download/2026.08.22.22/" + name, SHA256: fmt.Sprintf("%064x", 1), Length: 1, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}}
	return releaseindex.Index{
		Schema: releaseindex.SchemaV1, ReleaseID: "rel_2026.08.22.22", Version: "2026.08.22.22", Channel: "stable", Severity: "routine",
		CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: targets,
		HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1,
		Rollout: releaseindex.Rollout{Schema: releaseindex.RolloutSchemaV1, CohortSeed: "release-2026.08.22.22", Percentage: 100},
	}
}
