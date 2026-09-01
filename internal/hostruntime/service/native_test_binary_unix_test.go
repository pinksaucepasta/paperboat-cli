//go:build darwin || linux

package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nativeServiceTestPreferredRoot = "/usr/local/libexec/paperboat-test"

// installNativeServiceTestExecutable places the test binary outside /tmp so
// Linux systemd's PrivateTmp namespace can execute it. Root-capable runs use
// the conventional /usr/local/libexec location. Unprivileged user-systemd
// runs use a private cache directory that remains visible inside PrivateTmp.
// Each opt-in test gets a unique directory and removes only that directory
// after native services have been uninstalled.
func installNativeServiceTestExecutable(t *testing.T, source string) string {
	t.Helper()
	if err := validateNativeServiceTestExecutable(source); err != nil {
		t.Fatalf("invalid native test executable %q: %v", source, err)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("locate native test executable cache: %v", err)
	}
	root, err := createNativeServiceTestExecutableRoot(
		nativeServiceTestPreferredRoot,
		cacheRoot,
	)
	if err != nil {
		t.Fatalf("create native test executable root: %v", err)
	}
	t.Cleanup(func() { cleanupNativeServiceTestExecutableRoot(root) })
	destination := filepath.Join(root, "service.test")
	if err := copyNativeServiceTestExecutable(source, destination); err != nil {
		t.Fatalf("copy native test executable: %v", err)
	}
	return destination
}

func validateNativeServiceTestExecutable(source string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("must be a private regular executable")
	}
	return nil
}

// createNativeServiceTestExecutableRoot prefers the conventional system
// location, but only after proving that it is a safe directory in which this
// process can create a unique child. A failed preferred attempt is expected
// for an ordinary user and falls back to the private cache location.
func createNativeServiceTestExecutableRoot(preferred, fallback string) (string, error) {
	preferredRoot, preferredErr := createNativeServiceTestExecutableRootAt(preferred, "run-", 0o755)
	if preferredErr == nil {
		return preferredRoot, nil
	}
	fallbackRoot, fallbackErr := createNativeServiceTestExecutableRootAt(fallback, "paperboat-native-service-", 0o700)
	if fallbackErr == nil {
		return fallbackRoot, nil
	}
	return "", fmt.Errorf("preferred root: %v; fallback root: %w", preferredErr, fallbackErr)
}

func createNativeServiceTestExecutableRootAt(base, prefix string, baseMode os.FileMode) (string, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || base == string(filepath.Separator) {
		return "", errors.New("root must be a non-root absolute path")
	}
	if err := prepareNativeServiceTestExecutableBase(base, baseMode); err != nil {
		return "", err
	}
	root, err := os.MkdirTemp(base, prefix)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		cleanupNativeServiceTestExecutableRoot(root)
		if err != nil {
			return "", err
		}
		return "", errors.New("created root is not a private directory")
	}
	return root, nil
}

func prepareNativeServiceTestExecutableBase(base string, mode os.FileMode) error {
	info, err := os.Lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(base, mode); err != nil {
			return err
		}
		info, err = os.Lstat(base)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("base must be a non-writable-by-others directory")
	}
	return nil
}

func cleanupNativeServiceTestExecutableRoot(root string) {
	if root == "" {
		return
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	_ = os.RemoveAll(root)
}

func copyNativeServiceTestExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		if err != nil {
			return err
		}
		return errors.New("copied executable has unsafe mode")
	}
	return nil
}

func TestCreateNativeServiceTestExecutableRootFallsBackToPrivateCache(t *testing.T) {
	preferred := filepath.Join(t.TempDir(), "preferred-file")
	if err := os.WriteFile(preferred, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(t.TempDir(), "cache")
	root, err := createNativeServiceTestExecutableRoot(preferred, fallback)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupNativeServiceTestExecutableRoot(root)
	if !strings.HasPrefix(root, fallback+string(filepath.Separator)) {
		t.Fatalf("root=%q escaped fallback=%q", root, fallback)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("root info=%v err=%v", info, err)
	}
}

func TestCreateNativeServiceTestExecutableRootUsesWritablePreferredLocation(t *testing.T) {
	preferred := filepath.Join(t.TempDir(), "preferred")
	fallback := filepath.Join(t.TempDir(), "cache")
	root, err := createNativeServiceTestExecutableRoot(preferred, fallback)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root, preferred+string(filepath.Separator)) {
		t.Fatalf("root=%q escaped preferred=%q", root, preferred)
	}
	cleanupNativeServiceTestExecutableRoot(root)
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root remains after exact cleanup: %v", err)
	}
}

func TestCreateNativeServiceTestExecutableRootRejectsUnsafeBases(t *testing.T) {
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err := os.WriteFile(unsafe, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createNativeServiceTestExecutableRootAt(unsafe, "run-", 0o755); err == nil {
		t.Fatal("file base accepted")
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := createNativeServiceTestExecutableRootAt(symlink, "run-", 0o755); err == nil {
		t.Fatal("symlink base accepted")
	}
	if _, err := createNativeServiceTestExecutableRootAt("relative", "run-", 0o755); err == nil {
		t.Fatal("relative base accepted")
	}
}

func TestCopyNativeServiceTestExecutableUsesExclusivePrivateExecutable(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	contents := []byte("native service test binary")
	if err := os.WriteFile(source, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if err := copyNativeServiceTestExecutable(source, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != string(contents) {
		t.Fatalf("destination=%q err=%v", data, err)
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Mode().Perm() != 0o755 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("destination info=%v err=%v", info, err)
	}
	if err := copyNativeServiceTestExecutable(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second copy err=%v, want os.ErrExist", err)
	}
}
