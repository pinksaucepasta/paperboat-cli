//go:build linux

package udpsocket

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func SupportsPathErrors() bool { return true }

func readPathError(connection *net.UDPConn) (PathError, bool, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return PathError{}, false, err
	}
	var oob = make([]byte, 256)
	var oobn, flags int
	var receiveErr error
	if err := raw.Control(func(fd uintptr) {
		_, oobn, flags, _, receiveErr = unix.Recvmsg(int(fd), make([]byte, 1), oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	}); err != nil {
		return PathError{}, false, err
	}
	if errors.Is(receiveErr, unix.EAGAIN) || errors.Is(receiveErr, unix.EWOULDBLOCK) {
		return PathError{}, false, nil
	}
	if receiveErr != nil {
		return PathError{}, false, receiveErr
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return PathError{}, false, errors.New("truncated UDP path error control message")
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return PathError{}, false, err
	}
	for _, message := range messages {
		family := Family(0)
		switch {
		case message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_RECVERR:
			family = FamilyIPv4
		case message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_RECVERR:
			family = FamilyIPv6
		default:
			continue
		}
		pathError, err := decodeLinuxExtendedError(family, message.Data)
		return pathError, err == nil, err
	}
	return PathError{}, false, errors.New("UDP error queue entry omitted extended error")
}
