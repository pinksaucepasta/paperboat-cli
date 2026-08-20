//go:build windows

package session

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows console input is delivered by the console handle itself. The
// ConPTY implementation owns cancellation of that handle; keep this helper
// honest by checking cancellation before the blocking read rather than
// claiming Unix poll semantics on Windows.
func readLocalInput(ctx context.Context, file *os.File, p []byte) (int, error) {
	if ctx == nil || file == nil {
		return 0, os.ErrInvalid
	}
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	handle := windows.Handle(file.Fd())
	stop := context.AfterFunc(ctx, func() {
		// Windows ReadFile on console and pipe handles does not observe Go
		// context cancellation. Cancel the outstanding operation without
		// closing the process-owned stdin handle so repeated sessions remain
		// usable.
		_ = windows.CancelIoEx(handle, nil)
	})
	n, err := file.Read(p)
	stop()
	if cause := context.Cause(ctx); cause != nil && (err == nil || errors.Is(err, windows.ERROR_OPERATION_ABORTED)) {
		return n, cause
	}
	return n, err
}
