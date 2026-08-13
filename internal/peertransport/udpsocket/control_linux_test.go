//go:build linux

package udpsocket

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func verifySocketControls(t *testing.T, connection *net.UDPConn, ipv6 bool) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var discover, receiveErrors, v6only int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		if ipv6 {
			discover, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER)
			if controlErr == nil {
				receiveErrors, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR)
			}
			if controlErr == nil {
				v6only, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
			}
		} else {
			discover, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
			if controlErr == nil {
				receiveErrors, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if discover != unix.IP_PMTUDISC_DO || receiveErrors != 1 || ipv6 && v6only != 1 {
		t.Fatalf("discover=%d recverr=%d v6only=%d", discover, receiveErrors, v6only)
	}
}
