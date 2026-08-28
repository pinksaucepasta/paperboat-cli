//go:build !windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
)

func runLocalDaemonService(context.Context, []string, io.Writer, io.Writer) error {
	return errors.New("local daemon service is only available on Windows")
}
