//go:build !windows

package main

import (
	"context"
	"errors"
)

func repairWindowsOpenSSH(context.Context) error {
	return errors.New("doctor --repair is currently available for native Windows hosts only")
}
