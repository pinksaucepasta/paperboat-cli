package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestProductionTUFRepository(t *testing.T) {
	repositoryURL := os.Getenv("PAPERBOAT_TEST_TUF_REPOSITORY_URL")
	if repositoryURL == "" {
		t.Skip("PAPERBOAT_TEST_TUF_REPOSITORY_URL is not set")
	}
	version := os.Getenv("PAPERBOAT_TEST_TUF_VERSION")
	if version == "" {
		t.Fatal("PAPERBOAT_TEST_TUF_VERSION is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := ArtifactTarget{
		Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: version,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: repositoryURL,
		TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH,
	}
	root := t.TempDir()
	path, err := FetchVerifiedArtifact(ctx, target, filepath.Join(root, "legacy"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() < 1 {
		t.Fatalf("downloaded target info=%v error=%v", info, err)
	}
	if err := secureArtifactFile(path); err != nil {
		t.Fatalf("downloaded target security error=%v", err)
	}
	legacyBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	index, err := FetchVerifiedReleaseIndex(ctx, repositoryURL, filepath.Join(root, "index"), nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if index.Version != version {
		t.Fatalf("signed release index version=%q, want %q", index.Version, version)
	}
	cliTarget, ok := index.Component("cli")
	if !ok {
		t.Fatal("signed release index has no CLI component")
	}
	cliPath, err := FetchVerifiedReleaseComponent(ctx, repositoryURL, filepath.Join(root, "component"), index, "cli", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cliBody, err := os.ReadFile(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cliBody)
	if cliTarget.SHA256 != hex.EncodeToString(digest[:]) || cliTarget.Length != int64(len(cliBody)) || !bytes.Equal(legacyBody, cliBody) {
		t.Fatal("legacy bootstrap target and signed CLI component are not identical")
	}
}
