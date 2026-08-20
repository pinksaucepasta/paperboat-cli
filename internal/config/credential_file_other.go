//go:build !darwin && !linux && !windows

package config

import (
	"fmt"
	"os"
)

func writeCredentialFile(path string, value []byte) error { return atomicWrite(path, value, 0o600) }

func validateCredentialDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("credential directory must be mode 0700")
	}
	return nil
}

func readCredentialFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("credential file must be regular mode 0600")
	}
	return os.ReadFile(path)
}
