//go:build darwin || linux

package managedssh

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

func InstallManagedIdentityPublicKey(home string, ownerUID uint32, publicKey string) error {
	expected, err := managedIdentityPublicKeyContent(publicKey)
	if err != nil {
		return err
	}
	directoryFD, closeDirectory, err := openSSHConfigDirectory(home, ownerUID)
	if err != nil {
		return err
	}
	defer closeDirectory()
	unlock, err := lockOpenSSHConfig(directoryFD, ownerUID)
	if err != nil {
		return err
	}
	defer unlock()
	existing, exists, err := readOpenSSHFileAt(directoryFD, ManagedIdentityPublicKeyFilename, ownerUID)
	if err != nil {
		return err
	}
	if exists && !isManagedIdentityPublicKey(existing, publicKey) {
		return ErrManagedIdentityFileConflict
	}
	if bytes.Equal(existing, expected) {
		return nil
	}
	return writeOpenSSHFileAt(directoryFD, ManagedIdentityPublicKeyFilename, ownerUID, expected)
}

func ValidateManagedIdentityPublicKey(home string, ownerUID uint32, publicKey string) error {
	expected, err := managedIdentityPublicKeyContent(publicKey)
	if err != nil {
		return err
	}
	directoryFD, closeDirectory, err := openExistingOpenSSHConfigDirectory(home, ownerUID)
	if err != nil {
		return err
	}
	defer closeDirectory()
	value, exists, err := readOpenSSHFileAt(directoryFD, ManagedIdentityPublicKeyFilename, ownerUID)
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(value, expected) {
		return ErrManagedIdentityFileConflict
	}
	return nil
}

func UninstallManagedIdentityPublicKey(home string, ownerUID uint32) error {
	directoryFD, closeDirectory, err := openExistingOpenSSHConfigDirectory(home, ownerUID)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer closeDirectory()
	unlock, err := lockOpenSSHConfig(directoryFD, ownerUID)
	if err != nil {
		return err
	}
	defer unlock()
	value, exists, err := readOpenSSHFileAt(directoryFD, ManagedIdentityPublicKeyFilename, ownerUID)
	if err != nil || !exists {
		return err
	}
	if !isManagedIdentityPublicKey(value, "") {
		return ErrManagedIdentityFileConflict
	}
	return unlinkOpenSSHAt(directoryFD, ManagedIdentityPublicKeyFilename)
}
