//go:build darwin || linux

package localapi

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func watchPeerHangup(ctx context.Context, connection net.Conn, peer Peer, cancel context.CancelFunc) {
	systemConnection, ok := connection.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := systemConnection.SyscallConn()
	if err != nil {
		return
	}
	fileDescriptor := -1
	if err := raw.Control(func(value uintptr) { fileDescriptor = int(value) }); err != nil || fileDescriptor < 0 {
		return
	}
	processExit, closeProcessExit := watchProcessExit(peer.PID)
	defer closeProcessExit()
	for ctx.Err() == nil {
		select {
		case <-processExit:
			cancel()
			return
		default:
		}
		poll := []unix.PollFd{{Fd: int32(fileDescriptor), Events: unix.POLLHUP | unix.POLLERR}}
		count, pollErr := unix.Poll(poll, 250)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			return
		}
		if count > 0 && poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			cancel()
			return
		}
	}
}

func watchControlHangup(ctx context.Context, connection net.Conn, peer Peer, cancel context.CancelFunc) {
	watchPeerHangup(ctx, connection, peer, cancel)
}
