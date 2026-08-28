//go:build !windows

package hostruntimecmd

import (
	"context"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
)

func bootstrapLocalDaemonInstaller(cfg *config.Config) func(context.Context) error {
	return func(ctx context.Context) error {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return localdaemon.InstallCurrentUserService(ctx, executable, cfg.Path(), cfg.ServerURL)
	}
}
