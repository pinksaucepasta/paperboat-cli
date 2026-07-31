//go:build !darwin && !linux

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
)

func runServiceCommand(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	return errors.New("system service management is unsupported on this platform")
}
