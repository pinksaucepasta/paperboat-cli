//go:build windows

package config

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func removeSharedLock(path string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.RemoveAll(path)
		if err == nil || time.Now().After(deadline) || !sharedLockRemovalRetryable(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sharedLockRemovalRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
