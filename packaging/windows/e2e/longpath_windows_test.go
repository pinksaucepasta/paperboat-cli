//go:build windows && paperboat_native_e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestNativeLongPathFilesystemLifecycle(t *testing.T) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\FileSystem`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open long-path policy: %v", err)
	}
	defer key.Close()
	enabled, _, err := key.GetIntegerValue("LongPathsEnabled")
	if err != nil {
		t.Fatalf("read long-path policy: %v", err)
	}
	if enabled != 1 {
		t.Skip("LongPathsEnabled is disabled; the disabled-policy MSI path matrix covers the legacy boundary")
	}

	root := t.TempDir()
	dir := root
	for len(filepath.Join(dir, "paperboat-long-path.txt")) <= 300 {
		dir = filepath.Join(dir, "paperboat-long-path-segment")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create extended path of length %d: %v", len(dir), err)
	}
	original := filepath.Join(dir, "paperboat-long-path.txt")
	renamed := filepath.Join(dir, "paperboat-long-path-renamed.txt")
	want := []byte("paperboat-native-windows-long-path\n")
	if err := os.WriteFile(original, want, 0o600); err != nil {
		t.Fatalf("write extended path of length %d: %v", len(original), err)
	}
	if err := os.Rename(original, renamed); err != nil {
		t.Fatalf("rename extended path: %v", err)
	}
	got, err := os.ReadFile(renamed)
	if err != nil {
		t.Fatalf("read extended path: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("extended path payload mismatch: got %q", strings.TrimSpace(string(got)))
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatalf("remove extended path: %v", err)
	}
	t.Logf("qualified native extended filesystem path length=%d", len(renamed))
}
