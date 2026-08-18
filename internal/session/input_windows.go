//go:build windows

package session

import (
	"context"
	"os"
)

// Windows console input is delivered by the console handle itself. The
// ConPTY implementation owns cancellation of that handle; keep this helper
// honest by checking cancellation before the blocking read rather than
// claiming Unix poll semantics on Windows.
func readLocalInput(ctx context.Context, file *os.File, p []byte) (int, error) {
	if ctx == nil || file == nil {
		return 0, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return file.Read(p)
}
