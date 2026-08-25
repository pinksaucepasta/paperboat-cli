//go:build !windows

package config

import "os"

func prepareSharedLockParent(path string) error {
	return os.MkdirAll(path, 0o700)
}

func createSharedLockDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}

func validateSharedLockDirectory(string) error { return nil }

func writeSharedLockOwner(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func quarantineSharedLock(path, stalePath string) error {
	//paperboat:allow-source-policy atomic-replacement owner=runtime-auth reason=stale-lock-quarantine
	if err := os.Rename(path, stalePath); err != nil {
		return err
	}
	return os.RemoveAll(stalePath)
}

func cleanupNewSharedLock(path string) error {
	return os.RemoveAll(path)
}
