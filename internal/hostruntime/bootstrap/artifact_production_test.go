package bootstrap

import (
	"context"
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
	path, err := FetchVerifiedArtifact(ctx, target, filepath.Join(t.TempDir(), "tuf"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() < 1 || info.Mode().Perm() != 0o700 {
		t.Fatalf("downloaded target info=%v error=%v", info, err)
	}
}
