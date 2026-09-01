//go:build darwin || linux

package hoststate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type processLock struct {
	file *os.File
}

func ensurePrivateDirectory(name string) error {
	_, statErr := os.Lstat(name)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return statErr
	}
	if err := os.MkdirAll(name, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwner(info) != os.Geteuid() {
		if err != nil {
			return err
		}
		return ErrInvalidState
	}
	if err := os.Chmod(name, 0o700); err != nil {
		return err
	}
	if created {
		return syncDirectory(filepath.Dir(name))
	}
	return nil
}

func acquireProcessLock(name string) (*processLock, error) {
	_, statErr := os.Lstat(name)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, statErr
	}
	fd, err := unix.Open(name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrInvalidState
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidState
	}
	closeWith := func(cause error) (*processLock, error) {
		_ = file.Close()
		return nil, cause
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWith(err)
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(name)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) || fileOwner(info) != os.Geteuid() || fileLinkCount(info) != 1 || info.Mode().Perm()&0o077 != 0 {
		return closeWith(ErrInvalidState)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(ErrLocked)
		}
		return closeWith(err)
	}
	if err = file.Truncate(0); err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = file.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return closeWith(fmt.Errorf("write host state lock owner: %w", err))
	}
	if created {
		if err := syncDirectory(filepath.Dir(name)); err != nil {
			_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			return closeWith(fmt.Errorf("sync host state lock parent: %w", err))
		}
	}
	return &processLock{file: file}, nil
}

func (l *processLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
}

func readPrivateFile(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || fileOwner(info) != os.Geteuid() || info.Size() < 0 || info.Size() > limit {
		return nil, ErrInvalidState
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrInvalidState
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidState
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || fileLinkCount(opened) != 1 {
		return nil, ErrInvalidState
	}
	buffer, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buffer)) != opened.Size() || int64(len(buffer)) > limit {
		return nil, ErrInvalidState
	}
	return buffer, nil
}

func syncDirectory(name string) error {
	directory, err := os.Open(filepath.Clean(name))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func fileOwner(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func fileLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}
