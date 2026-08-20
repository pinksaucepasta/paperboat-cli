//go:build !darwin && !linux && !windows

package managedssh

import (
	"errors"
	"net"
)

func ListenOwnerSocket(string) (net.Listener, error) {
	return nil, errors.New("managed SSH agent sockets are unsupported on this platform")
}
