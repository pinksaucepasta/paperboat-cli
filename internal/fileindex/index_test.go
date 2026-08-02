package fileindex

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestRefreshCachesAndDetectsDirectoryChanges(t *testing.T) {
	root := t.TempDir()
	cachePath := filepath.Join(t.TempDir(), "index.json")
	first := filepath.Join(root, "workspace", "alpha.txt")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := Refresh(context.Background(), root, cachePath)
	if err != nil || !slices.Contains(files, first) {
		t.Fatalf("first refresh files=%v err=%v", files, err)
	}
	if cached, ok := Load(root, cachePath); !ok || !slices.Contains(cached, first) {
		t.Fatalf("cached files=%v ok=%t", cached, ok)
	}

	second := filepath.Join(root, "workspace", "beta.txt")
	if err := os.WriteFile(second, []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Some filesystems expose coarse directory timestamps.
	now := time.Now().Add(time.Second)
	if err := os.Chtimes(filepath.Dir(second), now, now); err != nil {
		t.Fatal(err)
	}
	files, err = Refresh(context.Background(), root, cachePath)
	if err != nil || !slices.Contains(files, first) || !slices.Contains(files, second) {
		t.Fatalf("incremental refresh files=%v err=%v", files, err)
	}
}

func TestRefreshExcludesHiddenAndDependencyTrees(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{".hidden/secret.txt", "node_modules/pkg/index.js", "vendor/pkg/source.go", "visible/report.txt"} {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := Refresh(context.Background(), root, filepath.Join(t.TempDir(), "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "report.txt" {
		t.Fatalf("files=%v", files)
	}
}

func TestDarwinIndexExcludesSystemLibraryAndApplicationBundles(t *testing.T) {
	root := filepath.Join("fixtures", "home")
	if !skipDirectory("darwin", root, root, "Library") {
		t.Fatal("macOS user Library was not excluded")
	}
	if !skipDirectory("darwin", root, filepath.Join(root, "Downloads"), "Example.app") {
		t.Fatal("application bundle was not excluded")
	}
	if skipDirectory("linux", root, root, "Library") || skipDirectory("darwin", root, root, "Documents") {
		t.Fatal("ordinary user directory was excluded")
	}
}

func TestBackgroundRefreshIsConsumedWithoutStaleCache(t *testing.T) {
	root := t.TempDir()
	cachePath := filepath.Join(t.TempDir(), "index.json")
	file := filepath.Join(root, "current.txt")
	if err := os.WriteFile(file, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	RefreshInBackground(root, cachePath)
	files, err := Current(context.Background(), root, cachePath)
	if err != nil || !slices.Contains(files, file) {
		t.Fatalf("current files=%v err=%v", files, err)
	}
}
