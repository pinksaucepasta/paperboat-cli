//go:build linux

package udpsocket

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func socketControl(network string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		err := raw.Control(func(fd uintptr) {
			switch network {
			case "udp4":
				if controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); controlErr == nil {
					controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1)
				}
			case "udp6":
				if controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); controlErr == nil {
					controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				}
				if controlErr == nil {
					controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
				}
			default:
				controlErr = ErrInvalid
			}
		})
		return errors.Join(err, controlErr)
	}
}
