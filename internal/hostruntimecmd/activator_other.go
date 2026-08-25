//go:build !windows

package hostruntimecmd

import (
	"context"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func runActivator(context.Context, []string, io.Writer, io.Writer) error {
	return service.ErrUnsupportedPlatform
}
