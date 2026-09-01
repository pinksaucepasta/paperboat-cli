//go:build windows

package hostruntimecmd

import (
	"context"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
)

func RepairManagedHost(ctx context.Context) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return elevation.RunRuntimeService(ctx, executable, elevation.ActionRepair, nil)
}
