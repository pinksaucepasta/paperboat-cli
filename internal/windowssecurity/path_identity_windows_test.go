//go:build windows

package windowssecurity

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHandlePathMatchesLongAndShortSpellings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "canonical-path-target")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	handle := openPathIdentityTestHandle(t, path)
	defer windows.CloseHandle(handle)
	if !HandlePathMatches(handle, path) {
		t.Fatal("canonical path did not match its open handle")
	}

	shortPath, err := shortPathName(path)
	if err != nil {
		t.Skipf("8.3 short names are unavailable on this volume: %v", err)
	}
	if shortPath == "" || filepath.Clean(shortPath) == filepath.Clean(path) {
		t.Skip("Windows did not assign a distinct 8.3 short name")
	}
	if !HandlePathMatches(handle, shortPath) {
		t.Fatalf("short path %q did not match its canonical handle", shortPath)
	}
}

func TestHandlePathMatchesRejectsDifferentObject(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	handle := openPathIdentityTestHandle(t, first)
	defer windows.CloseHandle(handle)
	if HandlePathMatches(handle, second) {
		t.Fatal("a handle matched a different filesystem object")
	}
}

func TestHandlePathMatchesRejectsReparseRedirection(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a directory symlink requires Windows developer mode or elevation: %v", err)
	}
	pointer, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if HandlePathMatches(handle, link) {
		t.Fatal("a handle that followed a reparse point matched the reparse path")
	}
}

func openPathIdentityTestHandle(t *testing.T, path string) windows.Handle {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func shortPathName(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		buffer = make([]uint16, n+1)
	}
}
