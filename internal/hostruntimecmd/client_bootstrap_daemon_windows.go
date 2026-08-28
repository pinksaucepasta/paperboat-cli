//go:build windows

package hostruntimecmd

import (
	"context"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func bootstrapLocalDaemonInstaller(*config.Config) func(context.Context) error {
	// The Windows runtime installer immediately following CLI bootstrap owns
	// PaperboatLocalDaemon as a silent SCM service for both client and host
	// modes. Creating the old interactive ONLOGON task here leaves a visible
	// console behind whenever later installation fails.
	return func(context.Context) error { return nil }
}
