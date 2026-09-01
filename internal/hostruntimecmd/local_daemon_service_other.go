//go:build !windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"
)

func executeLocalDaemonService(_ context.Context, _ []string, _ io.Writer, stderr io.Writer) int {
	writeError(stderr, errors.New("local daemon service is only available on Windows"))
	return 1
}
