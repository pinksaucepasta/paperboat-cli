//go:build darwin || linux

package config

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func writeCredentialFile(path string, value []byte) error { return atomicWrite(path, value, 0o600) }

func validateCredentialDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("credential directory must be owner-controlled mode 0700")
	}
	return nil
}

func readCredentialFile(path string) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("credential file must be owner-owned regular mode 0600")
	}
	return io.ReadAll(io.LimitReader(file, 1<<20))
}
