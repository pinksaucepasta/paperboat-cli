//go:build linux

package localapi

import (
	"context"

	"golang.org/x/sys/unix"
)

func watchProcessExit(pid int) (<-chan struct{}, func()) {
	done := make(chan struct{})
	if pid <= 0 {
		return done, func() {}
	}
	fileDescriptor, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if err == unix.ESRCH {
			close(done)
		}
		return done, func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer unix.Close(fileDescriptor)
		poll := []unix.PollFd{{Fd: int32(fileDescriptor), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		for ctx.Err() == nil {
			count, pollErr := unix.Poll(poll, 250)
			if pollErr == unix.EINTR {
				continue
			}
			if pollErr == nil && count > 0 {
				close(done)
				return
			}
			if pollErr != nil {
				return
			}
		}
	}()
	return done, cancel
}
