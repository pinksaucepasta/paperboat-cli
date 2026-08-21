//go:build windows

package managedssh

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func InstallManagedIdentityPublicKey(home string, ownerUID uint32, publicKey string) error {
	expected, err := managedIdentityPublicKeyContent(publicKey)
	if err != nil {
		return err
	}
	directory, sid, unlock, err := openWindowsSSHDirectory(home, true)
	if err != nil {
		return err
	}
	defer unlock()
	existing, exists, err := readWindowsSSHFile(directory, ManagedIdentityPublicKeyFilename, sid, true)
	if err != nil {
		return err
	}
	// A prior Paperboat-owned public selector may belong to a rotated CLI
	// session. It is safe to replace that public-only file atomically; only an
	// unowned or malformed file is a conflict.
	if exists && !isManagedIdentityPublicKey(existing, "") {
		return ErrManagedIdentityFileConflict
	}
	if bytes.Equal(existing, expected) {
		return nil
	}
	return writeWindowsOwnedSSHFile(directory, ManagedIdentityPublicKeyFilename, sid, expected)
}

func ValidateManagedIdentityPublicKey(home string, ownerUID uint32, publicKey string) error {
	expected, err := managedIdentityPublicKeyContent(publicKey)
	if err != nil {
		return err
	}
	directory, sid, unlock, err := openWindowsSSHDirectory(home, false)
	if err != nil {
		return err
	}
	defer unlock()
	value, exists, err := readWindowsSSHFile(directory, ManagedIdentityPublicKeyFilename, sid, true)
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(value, expected) {
		return ErrManagedIdentityFileConflict
	}
	return nil
}

func UninstallManagedIdentityPublicKey(home string, ownerUID uint32) error {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return ErrManagedIdentityFileConflict
	}
	directoryPath := filepath.Join(home, ".ssh")
	directoryInfo, directoryErr := os.Lstat(directoryPath)
	if errors.Is(directoryErr, os.ErrNotExist) {
		return nil
	}
	if directoryErr != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || windowsReparsePoint(directoryPath) {
		return errors.Join(ErrManagedIdentityFileConflict, directoryErr)
	}
	_, identityErr := os.Lstat(filepath.Join(directoryPath, ManagedIdentityPublicKeyFilename))
	if errors.Is(identityErr, os.ErrNotExist) {
		return nil
	}
	if identityErr != nil {
		return errors.Join(ErrManagedIdentityFileConflict, identityErr)
	}
	directory, sid, unlock, err := openWindowsSSHDirectory(home, false)
	if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	value, exists, err := readWindowsSSHFile(directory, ManagedIdentityPublicKeyFilename, sid, true)
	if err != nil || !exists {
		return err
	}
	if !isManagedIdentityPublicKey(value, "") {
		return ErrManagedIdentityFileConflict
	}
	return removeWindowsOwnedSSHFile(directory, ManagedIdentityPublicKeyFilename, sid)
}
