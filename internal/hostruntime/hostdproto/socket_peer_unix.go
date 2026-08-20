//go:build linux || darwin

package hostdproto

import (
	"net"

	"github.com/pinksaucepasta/paperboat/internal/ospeer"
)

func peerUID(connection *net.UnixConn) (int, error) {
	identity, err := ospeer.Get(connection)
	if err != nil {
		return -1, err
	}
	return identity.UID, nil
}
