//go:build windows

package localapi

import "net"

type localPeerConnection interface {
	localAPIPeer() Peer
}

func peerIdentity(connection net.Conn) (Peer, error) {
	peerConnection, ok := connection.(localPeerConnection)
	if !ok {
		return Peer{}, ErrPermission
	}
	return peerConnection.localAPIPeer(), nil
}
