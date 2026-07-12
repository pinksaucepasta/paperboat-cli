//go:build windows

package session

import (
	"context"
	"os"

	"golang.org/x/sys/windows"
)

func readLocalInput(ctx context.Context, file *os.File, p []byte) (int, error) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(windows.Handle(file.Fd()), nil)
		case <-done:
		}
	}()
	n, err := file.Read(p)
	close(done)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}
