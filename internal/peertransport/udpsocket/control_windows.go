//go:build windows

package udpsocket

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// These values are defined by the Windows SDK's Ws2ipdef.h. x/sys/windows
// exposes setsockopt but does not currently export these two option names.
const (
	winIPDontFragment   = 14
	winIPv6DontFragment = 14
)

// Windows supports non-fragmenting UDP through IP_DONTFRAGMENT and
// IPV6_DONTFRAG. Paperboat's authenticated probe then measures the usable path
// payload without silently succeeding through IP fragmentation.
func socketControl(network string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			switch network {
			case "udp4":
				controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, winIPDontFragment, 1)
			case "udp6":
				controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, winIPv6DontFragment, 1)
				if controlErr == nil {
					controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1)
				}
			default:
				controlErr = ErrInvalid
			}
		}); err != nil {
			return err
		}
		return controlErr
	}
}
