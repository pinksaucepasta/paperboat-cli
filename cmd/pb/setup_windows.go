//go:build windows

package main

import (
	"context"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
)

func setupPlatformHostPrerequisites(ctx context.Context) (uint16, error) {
	executable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	if err := elevation.RunOpenSSH(ctx, executable, elevation.ActionOpenSSHSetup); err != nil {
		return 0, err
	}
	return windowsopenssh.DefaultConfig(nil).Port, nil
}
