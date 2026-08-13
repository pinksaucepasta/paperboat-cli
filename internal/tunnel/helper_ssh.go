package tunnel

import (
	"context"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

// DialSSH opens one authorized application stream. Once authorized, the
// stream carries the OpenSSH protocol unchanged end to end.
func (t *PeerTerminalTunnel) DialSSH(ctx context.Context, info resolver.ConnectInfo, operationID string) (Conn, error) {
	if operationID == "" {
		return nil, ErrPeerTerminalInvalid
	}
	return t.dial(ctx, info, "ssh", peerApplication{
		stream:      "ssh",
		operationID: operationID,
		raw: func(_ context.Context, stream io.ReadWriteCloser) (Conn, error) {
			return &sshStreamConn{ReadWriteCloser: stream}, nil
		},
	}, nil)
}

type sshStreamConn struct{ io.ReadWriteCloser }

func (*sshStreamConn) Resize(uint16, uint16) error { return ErrPeerTerminalInvalid }

func (c *sshStreamConn) CloseWrite() error {
	if closer, ok := c.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return ErrInputEOFUnsupported
}

// OpenSSH consumes stream EOF directly and does not use terminal exit status.
func (*sshStreamConn) Wait() (int, error) { return 0, ErrPeerTerminalInvalid }

var _ Conn = (*sshStreamConn)(nil)
var _ InputHalfCloser = (*sshStreamConn)(nil)
