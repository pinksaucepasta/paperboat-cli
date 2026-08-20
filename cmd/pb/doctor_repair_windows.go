//go:build windows

package main

import (
	"context"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
)

func repairWindowsOpenSSH(ctx context.Context) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return elevation.RunRuntimeService(ctx, executable, elevation.ActionRepair, nil)
}
