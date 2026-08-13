//go:build darwin

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
	var option, v6only int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		if ipv6 {
			option, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG)
			if controlErr == nil {
				v6only, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
			}
		} else {
			option, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if option != 1 || ipv6 && v6only != 1 {
		t.Fatalf("dontfrag=%d v6only=%d", option, v6only)
	}
}
