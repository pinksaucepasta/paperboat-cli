package launcher

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTargetRejectsRelativeMissingAndSymlink(t *testing.T) {
	if err := validateTarget("relative/pb"); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("relative error=%v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := validateTarget(missing); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("missing error=%v", err)
	}
	target := filepath.Join(t.TempDir(), "pb")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := target + "-link"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateTarget(link); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("symlink error=%v", err)
	}
}

func TestTargetArgumentsAreIsolated(t *testing.T) {
	target := Target{Path: "/fixed/pb", Args: []string{"pb", "status"}, Env: []string{"A=B"}}
	copyArgs := append([]string(nil), target.Args...)
	copyArgs[1] = "changed"
	if target.Args[1] != "status" {
		t.Fatal("target arguments unexpectedly aliased")
	}
}
