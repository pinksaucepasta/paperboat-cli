//go:build unix

package releaseeligibility

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixEligibilityRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	info, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParentSecurity(link, info); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked parent error=%v, want ErrUnsafePath", err)
	}
}

func TestUnixEligibilityRejectsWritableOrForeignParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParentSecurity(root, info); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("writable parent error=%v, want ErrUnsafePath", err)
	}

	if os.Geteuid() != 0 {
		t.Skip("foreign owner check requires root")
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 65534, -1); err != nil {
		t.Skipf("cannot create foreign-owner fixture: %v", err)
	}
	info, err = os.Stat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParentSecurity(foreign, info); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("foreign parent error=%v, want ErrUnsafePath", err)
	}
}
