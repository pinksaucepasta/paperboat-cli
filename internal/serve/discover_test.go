package serve

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDiscoverSourcesIncludesRootFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "docs", "index.html"), "docs")
	mustWrite(t, filepath.Join(root, ".hidden", "secret"), "secret")
	mustWrite(t, filepath.Join(root, "node_modules", "pkg", "index.js"), "dependency")
	sources, err := DiscoverSources(context.Background(), root, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]SourceKind{
		mustCanonical(t, root):                                      SourceDirectory,
		mustCanonical(t, filepath.Join(root, "docs")):               SourceDirectory,
		mustCanonical(t, filepath.Join(root, "docs", "index.html")): SourceFile,
	}
	if len(sources) != len(want) {
		t.Fatalf("sources = %#v", sources)
	}
	for _, source := range sources {
		if want[source.Path] != source.Kind {
			t.Errorf("unexpected source %#v", source)
		}
	}
}

func TestDiscoverSourcesIsBounded(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		mustWrite(t, filepath.Join(root, fmtUint(uint16(i))+".txt"), "data")
	}
	sources, err := DiscoverSources(context.Background(), root, 5, 2)
	if err != nil || len(sources) != 5 {
		t.Fatalf("sources=%d err=%v", len(sources), err)
	}
}

func mustCanonical(t *testing.T, path string) string {
	t.Helper()
	value, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
