//go:build darwin

package localapi

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

const darwinProcessZombie = 5

func watchProcessExit(pid int) (<-chan struct{}, func()) {
	done := make(chan struct{})
	if pid <= 0 {
		return done, func() {}
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		close(done)
		return done, func() {}
	}
	started := process.Proc.P_starttime
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, currentErr := unix.SysctlKinfoProc("kern.proc.pid", pid)
				if currentErr != nil || current.Proc.P_starttime != started || current.Proc.P_stat == darwinProcessZombie {
					close(done)
					return
				}
			}
		}
	}()
	return done, cancel
}
