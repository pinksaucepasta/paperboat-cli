//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
)

func runPurgeCommand(ctx context.Context, args []string, _ io.Reader, _, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("purge accepts no arguments")
	}
	if !elevation.IsCurrentProcessElevated() {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return elevation.RunRuntimeService(ctx, executable, elevation.ActionPurge, nil)
	}
	return hostinstall.Purge(ctx)
}
