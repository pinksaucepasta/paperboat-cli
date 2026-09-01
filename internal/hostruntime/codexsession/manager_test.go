//go:build darwin || linux

package codexsession

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolvePathRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	inside := filepath.Join(root, "inside")
	outside := t.TempDir()
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	manager, err := New(Config{StateRoot: state, WorkspaceRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	wantInside, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := manager.ResolvePath("inside"); err != nil || got != wantInside {
		t.Fatalf("inside = %q, %v", got, err)
	}
	for _, path := range []string{"..", filepath.Join(root, "escape")} {
		if _, err := manager.ResolvePath(path); !errors.Is(err, ErrWorkspaceEscape) {
			t.Fatalf("ResolvePath(%q) = %v", path, err)
		}
	}
}

func TestDirectoriesAreSortedAndExcludeEscapingSymlinks(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	for _, name := range []string{"zeta", ".hidden", "alpha"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	manager, err := New(Config{StateRoot: state, WorkspaceRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	page, err := manager.Directories("~", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".hidden", "alpha", "zeta"}
	if len(page.Directories) != len(want) {
		t.Fatalf("directories = %v", page.Directories)
	}
	for i := range want {
		if page.Directories[i] != want[i] {
			t.Fatalf("directories = %v", page.Directories)
		}
	}
}

func TestResolvedEnvironmentUsesCurrentManagedValues(t *testing.T) {
	value := "first"
	config := Config{
		Environment: []string{"PATH=/bin", "TOKEN=base"},
		ManagedEnvironment: func() ([]string, error) {
			return []string{"EMPTY=", "TOKEN=" + value}, nil
		},
	}
	first, err := resolvedEnvironment(config)
	if err != nil || !reflect.DeepEqual(first, []string{"EMPTY=", "PATH=/bin", "TOKEN=first"}) {
		t.Fatalf("first=%q err=%v", first, err)
	}
	value = "second"
	second, err := resolvedEnvironment(config)
	if err != nil || !reflect.DeepEqual(second, []string{"EMPTY=", "PATH=/bin", "TOKEN=second"}) {
		t.Fatalf("second=%q err=%v", second, err)
	}
}
