//go:build windows

package localapi

import (
	"context"

	"golang.org/x/sys/windows"
)

func watchProcessExit(pid int) (<-chan struct{}, func()) {
	done := make(chan struct{})
	if pid <= 0 {
		return done, func() {}
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		close(done)
		return done, func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer windows.CloseHandle(process)
		for {
			state, waitErr := windows.WaitForSingleObject(process, 250)
			if waitErr != nil {
				return
			}
			if state == windows.WAIT_OBJECT_0 {
				close(done)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	return done, cancel
}
