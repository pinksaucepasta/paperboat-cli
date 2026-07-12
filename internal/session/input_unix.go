//go:build !windows

package session

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func readLocalInput(ctx context.Context, file *os.File, p []byte) (int, error) {
	poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ready, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if ready > 0 {
			return file.Read(p)
		}
	}
}
