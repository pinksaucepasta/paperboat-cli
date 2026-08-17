//go:build darwin

package hostdproto

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var result error
	err = raw.Control(func(fd uintptr) {
		credentials, peerErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if peerErr != nil {
			result = peerErr
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
