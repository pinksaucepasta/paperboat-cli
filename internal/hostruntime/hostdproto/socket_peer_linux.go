//go:build linux

package hostdproto

import (
	"net"
	"syscall"
)

func peerUID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var result error
	err = raw.Control(func(fd uintptr) {
		credentials, credentialErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credentialErr != nil {
			result = credentialErr
			return
		}
		uid = int(credentials.Uid)
	})
	if err != nil {
		return -1, err
	}
	if result != nil {
		return -1, result
	}
	return uid, nil
}
