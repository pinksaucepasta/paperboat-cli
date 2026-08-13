//go:build linux || darwin

package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesRegularFileWithExactMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new\n"), Options{Mode: 0o640, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestWriteRejectsSymlinkAndWrongOwner(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path  string
		owner int
	}{
		{path: link, owner: os.Geteuid()},
		{path: target, owner: os.Geteuid() + 1},
	} {
		err := Write(test.path, []byte("unsafe"), Options{Mode: 0o600, OwnerUID: test.owner, OwnerGID: -1})
		var typed *Error
		if !errors.As(err, &typed) || typed.Stage != StageValidate {
			t.Fatalf("error=%v", err)
		}
	}
	data, _ := os.ReadFile(target)
	if string(data) != "safe" {
		t.Fatalf("target changed: %q", data)
	}
}
