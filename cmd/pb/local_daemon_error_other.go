//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func localDaemonSocketUnavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
