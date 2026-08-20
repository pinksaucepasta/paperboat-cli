//go:build windows && !paperboat_native_e2e

package hostruntimecmd

import (
	"context"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
)

func runWindowsHostdNativeE2E(context.Context, hostinstall.WindowsRuntimeConfig) (bool, error) {
	return false, nil
}
