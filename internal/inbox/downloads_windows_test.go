//go:build windows

package inbox

import (
	"path/filepath"
	"testing"
)

func TestDownloadsDirUsesWindowsKnownFolder(t *testing.T) {
	path, err := DownloadsDir()
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("DownloadsDir()=%q, %v", path, err)
	}
}
