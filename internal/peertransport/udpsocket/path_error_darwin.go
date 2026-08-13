//go:build darwin

package udpsocket

import "net"

func SupportsPathErrors() bool { return false }

func readPathError(*net.UDPConn) (PathError, bool, error) {
	return PathError{}, false, ErrPathErrorUnsupported
}
