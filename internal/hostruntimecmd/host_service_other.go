//go:build !darwin && !linux

package hostruntimecmd

import (
	"context"
	"fmt"
	"io"
)

func ExecuteHostService(context.Context, []string, io.Writer) int {
	fmt.Fprintln(io.Discard, "host service unsupported")
	return 2
}
