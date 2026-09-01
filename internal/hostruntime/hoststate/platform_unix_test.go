//go:build darwin || linux

package hoststate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRejectsSymlinkLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, lockFile)); err != nil {
		t.Fatal(err)
	}
	store, _, err := Open(Config{Root: root})
	if store != nil {
		store.Close()
	}
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Open with symlink lock = %v", err)
	}
}

func TestOpenRejectsHardLinkedState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, primaryFile), filepath.Join(root, "unexpected-hardlink.json")); err != nil {
		t.Fatal(err)
	}
	reopened, status, err := Open(Config{Root: root})
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrCorrupt) || !status.Degraded || status.Code != "primary_unreadable" {
		t.Fatalf("hard-linked state opened=%v status=%+v err=%v", reopened != nil, status, err)
	}
}

func TestOpenRejectsWorldReadableState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, primaryFile), 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, status, err := Open(Config{Root: root})
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrCorrupt) || !status.Degraded || status.Code != "primary_unreadable" {
		t.Fatalf("permissive state opened=%v status=%+v err=%v", reopened != nil, status, err)
	}
}
