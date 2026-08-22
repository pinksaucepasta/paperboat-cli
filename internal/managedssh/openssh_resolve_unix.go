//go:build darwin || linux

package managedssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || strings.ContainsRune(path, 0) {
		return "", ErrOpenSSHExecution
	}
	return path, nil
}
