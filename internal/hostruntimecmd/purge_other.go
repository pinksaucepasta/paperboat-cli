//go:build !darwin && !linux && !windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
)

func runPurgeCommand(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	return errors.New("complete uninstall is unsupported on this platform")
}
