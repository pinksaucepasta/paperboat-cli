//go:build darwin || linux

package environmentkey

import (
	"errors"
	"os"
	"sync"
	"syscall"
)

func lockPortablePath(path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrInvalid
		}
		return nil, errors.Join(ErrUnavailable, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, err)
	}
	if !securePortableFile(info) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, err)
	}
	var once sync.Once
	var unlockErr error
	return func() error {
		once.Do(func() {
			unlockErr = errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
		})
		return unlockErr
	}, nil
}
