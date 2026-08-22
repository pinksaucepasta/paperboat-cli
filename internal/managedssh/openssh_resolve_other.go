//go:build !darwin && !linux && !windows

package managedssh

import (
	"os/exec"
	"path/filepath"
)

func resolveOpenSSHExecutable(value string) (string, error) {
	if value == "" {
		value = "ssh"
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil || filepath.Clean(path) != path {
		return "", ErrOpenSSHExecution
	}
	return path, nil
}
