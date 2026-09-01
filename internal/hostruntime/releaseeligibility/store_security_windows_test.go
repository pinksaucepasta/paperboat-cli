//go:build windows

package releaseeligibility

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsEligibilityRejectsUnprotectedParent(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParentSecurity(root, info); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("unprotected parent error=%v, want ErrUnsafePath", err)
	}
}

func TestWindowsEligibilityRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "junction-or-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("reparse fixture unavailable: %v", err)
	}
	info, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParentSecurity(link, info); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("reparse parent error=%v, want ErrUnsafePath", err)
	}
}
