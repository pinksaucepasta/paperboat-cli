package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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
	targetPath := "pb-" + runtime.GOOS + "-" + runtime.GOARCH
	targets := metadata.Targets(time.Now().UTC().Add(24 * time.Hour))
	info, err := metadata.TargetFile().FromBytes(targetPath, body, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	custom, _ := json.Marshal(tufTargetCustom{ArtifactTargetSchemaV1, ArtifactKindPB, version, runtime.GOOS, runtime.GOARCH})
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
	digest := hex.EncodeToString(info.Hashes["sha256"])
	return testTUFRepository{root: rootBytes, files: map[string][]byte{
		"/metadata/timestamp.json":              timestampBytes,
		"/metadata/1.snapshot.json":             snapshotBytes,
		"/metadata/1.targets.json":              targetsBytes,
		"/targets/" + digest + "." + targetPath: body,
	}}
}

func (r testTUFRepository) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := r.files[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write(body)
	}))
}

func descriptor(repositoryURL, version string) ArtifactTarget {
	return ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: repositoryURL, TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH}
}

func TestFetchVerifiedArtifactThroughTUF(t *testing.T) {
	body := []byte("verified pb binary")
	repository := newTestTUFRepository(t, body, "2026.08.07", time.Now().UTC().Add(time.Hour))
	server := repository.server(t)
	defer server.Close()
	path, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("artifact=%q err=%v", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
}

func TestFetchVerifiedArtifactRejectsTargetMismatch(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("expected"), "2026.08.07", time.Now().UTC().Add(time.Hour))
	for path := range repository.files {
		if len(path) > len("/targets/") && path[:len("/targets/")] == "/targets/" {
			repository.files[path] = []byte("tampered")
		}
	}
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root); err == nil {
		t.Fatal("tampered target was accepted")
	}
}

func TestFetchVerifiedArtifactRejectsExpiredTimestampAndWrongVersion(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("pb"), "2026.08.07", time.Now().UTC().Add(-time.Minute))
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "expired-tuf"), server.Client(), repository.root); err == nil {
		t.Fatal("expired timestamp was accepted")
	}
	repository = newTestTUFRepository(t, []byte("pb"), "2026.08.07", time.Now().UTC().Add(time.Hour))
	server = repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.08"), filepath.Join(t.TempDir(), "wrong-version-tuf"), server.Client(), repository.root); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("wrong version error=%v", err)
	}
}

func TestVerifyArtifactTargetRejectsWrongPlatformAndOrigin(t *testing.T) {
	target := descriptor("https://updates.example.test/paperboat", "2026.08.07")
	target.Platform = "unsupported"
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("platform err=%v", err)
	}
	target = descriptor("http://updates.example.test/paperboat", "2026.08.07")
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("origin err=%v", err)
	}
}
