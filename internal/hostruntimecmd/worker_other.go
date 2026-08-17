//go:build !darwin && !linux

package hostruntimecmd

import (
	"context"
	"io"
)

func runHostd(context.Context, io.Writer) error { return errHostRuntimeUnsupported }
func runWorker(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	return errHostRuntimeUnsupported
}
func runUpdated(context.Context, []string, io.Writer, io.Writer) error {
	return errHostRuntimeUnsupported
}
