//go:build darwin

package processlifetime

import (
	"os"

	"golang.org/x/sys/unix"
)

// ArmParentDeath registers an exact process-exit event for the current parent.
func ArmParentDeath() error {
	parent := unix.Getppid()
	if parent <= 1 {
		return ErrParentUnavailable
	}
	queue, err := unix.Kqueue()
	if err != nil {
		return err
	}
	change := unix.Kevent_t{Ident: uint64(parent), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	if _, err := unix.Kevent(queue, []unix.Kevent_t{change}, nil, nil); err != nil {
		_ = unix.Close(queue)
		return err
	}
	if unix.Getppid() != parent {
		_ = unix.Close(queue)
		return ErrParentUnavailable
	}
	go func() {
		defer unix.Close(queue)
		events := make([]unix.Kevent_t, 1)
		if count, waitErr := unix.Kevent(queue, nil, events, nil); waitErr == nil && count == 1 {
			_ = unix.Kill(os.Getpid(), unix.SIGTERM)
		}
	}()
	return nil
}
