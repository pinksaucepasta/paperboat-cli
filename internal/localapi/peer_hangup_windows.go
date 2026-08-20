//go:build windows

package localapi

import (
	"context"
	"net"
)

// Hijacked stream bridges observe local EOF themselves. Process exit is the
// additional ownership signal needed to terminate a stream whose client dies
// without a clean pipe close.
func watchPeerHangup(ctx context.Context, _ net.Conn, peer Peer, cancel context.CancelFunc) {
	processExit, closeProcessExit := watchProcessExit(peer.PID)
	defer closeProcessExit()
	select {
	case <-ctx.Done():
	case <-processExit:
		cancel()
	}
}

// A file-transfer-key lease deliberately has no byte bridge after its HTTP
// upgrade, so wait for either a process exit or pipe EOF. No application data
// is read from this control connection after the successful response.
func watchControlHangup(ctx context.Context, connection net.Conn, peer Peer, cancel context.CancelFunc) {
	processExit, closeProcessExit := watchProcessExit(peer.PID)
	defer closeProcessExit()
	closed := make(chan struct{})
	go func() {
		var value [1]byte
		_, _ = connection.Read(value[:])
		close(closed)
	}()
	select {
	case <-ctx.Done():
	case <-processExit:
		cancel()
	case <-closed:
		cancel()
	}
}
