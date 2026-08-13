//go:build darwin || linux

package localdaemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type processLock struct {
	file *os.File
}

func acquireProcessLock(path string, uid int) (*processLock, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || uid < 0 {
		return nil, ErrInvalidInventoryConfig
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	closeWith := func(cause error) (*processLock, error) {
		_ = file.Close()
		return nil, cause
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || fileOwner(info) != uid {
		if err != nil {
			return closeWith(err)
		}
		return closeWith(localapi.ErrUnsafeSocket)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		if err != nil {
			return closeWith(err)
		}
		return closeWith(localapi.ErrUnsafeSocket)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(localapi.ErrAlreadyRunning)
		}
		return closeWith(err)
	}
	err = file.Truncate(0)
	if err == nil {
		_, err = file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return closeWith(fmt.Errorf("record local daemon PID: %w", err))
	}
	return &processLock{file: file}, nil
}

func (l *processLock) CanRemoveStaleSocket(_ context.Context, _ string) bool {
	return l != nil && l.file != nil
}

func (l *processLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return errors.Join(unlockErr, file.Close())
}

func fileOwner(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}
