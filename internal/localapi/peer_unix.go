//go:build linux || darwin

package localapi

import (
	"net"

	"github.com/pinksaucepasta/paperboat/internal/ospeer"
)

func peerIdentity(connection net.Conn) (Peer, error) {
	identity, err := ospeer.Get(connection)
	if err != nil {
		return Peer{}, ErrPermission
	}
	return Peer{UID: identity.UID, GID: identity.GID, PID: identity.PID}, nil
}
