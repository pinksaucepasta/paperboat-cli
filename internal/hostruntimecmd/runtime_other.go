//go:build !darwin && !linux

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
)

var errHostRuntimeUnsupported = errors.New("host runtime is unsupported on this platform")

func runBootstrap(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	return errHostRuntimeUnsupported
}

func runProduction(context.Context, io.Writer) error {
	return errHostRuntimeUnsupported
}
