//go:build !windows

package envinject

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

func TestSecureStateFileUnixPreservesExact0600Rule(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{name: "owner-only", mode: 0o600, want: true},
		{name: "group-readable", mode: 0o640, want: false},
		{name: "world-readable", mode: 0o644, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.json")
			if err := atomicfile.Write(path, []byte("opaque-state"), atomicfile.CurrentOwnerOptions(test.mode)); err != nil {
				t.Fatalf("write state atomically: %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := secureStateFile(path, info, 4096); got != test.want {
				t.Fatalf("secureStateFile(mode=%o)=%v, want %v", info.Mode().Perm(), got, test.want)
			}
		})
	}
}
