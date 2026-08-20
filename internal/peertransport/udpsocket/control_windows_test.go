//go:build windows

package udpsocket

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func verifySocketControls(t *testing.T, connection *net.UDPConn, ipv6 bool) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var dontFragment, v6only int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		if ipv6 {
			dontFragment, controlErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, winIPv6DontFragment)
			if controlErr == nil {
				v6only, controlErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			}
		} else {
			dontFragment, controlErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, winIPDontFragment)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if dontFragment != 1 || ipv6 && v6only != 1 {
		t.Fatalf("dont_fragment=%d v6only=%d", dontFragment, v6only)
	}
}
