//go:build windows

package udpsocket

import "syscall"

// Windows does not expose the Linux/Darwin path-MTU socket controls through
// the portable Go socket API. Keep socket creation explicit and reject an
// unknown family; path-error reporting is separately reported as unsupported.
func socketControl(network string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		switch network {
		case "udp4", "udp6":
			return nil
		default:
			return ErrInvalid
		}
	}
}
