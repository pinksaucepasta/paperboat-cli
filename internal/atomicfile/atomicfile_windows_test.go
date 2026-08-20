//go:build windows

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDefaultDescriptorAllowsOwnerAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, body := range []string{"first\n", "second\n"} {
		if err := Write(path, []byte(body), Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != body {
			t.Fatalf("contents=%q err=%v", contents, err)
		}
	}
}
