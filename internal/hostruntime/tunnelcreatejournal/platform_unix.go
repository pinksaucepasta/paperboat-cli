//go:build darwin || linux

package tunnelcreatejournal

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type processLock struct {
	file *os.File
}

func ensurePrivateDirectory(name string) error {
	if err := os.MkdirAll(name, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return ErrInvalid
	}
	if err := os.Chmod(name, 0o700); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(name))
}

func acquireProcessLock(name string) (*processLock, error) {
	fd, err := unix.Open(name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, ErrInvalid
	}
	closeWith := func(cause error) (*processLock, error) {
		_ = file.Close()
		return nil, cause
	}
	if err := validateOpenedPrivateFile(name, file); err != nil {
		return closeWith(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(ErrLocked)
		}
		return closeWith(err)
	}
	return &processLock{file: file}, nil
}

func (lock *processLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
}

func readPrivateFile(name string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validateOpenedPrivateFile(name, file); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > limit {
		return nil, ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrInvalid
	}
	return body, nil
}

func validateOpenedPrivateFile(name string, file *os.File) error {
	opened, err := file.Stat()
	pathInfo, pathErr := os.Lstat(name)
	if err != nil || pathErr != nil || !opened.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) || opened.Mode().Perm()&0o077 != 0 {
		return ErrInvalid
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ErrInvalid
	}
	return nil
}

func removePrivateFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	if err := validateOpenedPrivateFile(name, file); err != nil {
		file.Close()
		return err
	}
	if err := os.Remove(name); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
