package tunnel

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

// DialCodexHTTP opens one root-pinned E2EE stream for a single Codex HTTP or
// WebSocket connection. Session credentials remain mandatory inside the stream.
func (t *PeerTerminalTunnel) DialCodexHTTP(ctx context.Context, info resolver.ConnectInfo) (net.Conn, error) {
	connection, err := t.dial(ctx, info, "codex", peerApplication{stream: "codex-http", raw: func(_ context.Context, stream io.ReadWriteCloser) (Conn, error) {
		return &previewStreamConn{ReadWriteCloser: stream}, nil
	}}, nil)
	if err != nil {
		return nil, err
	}
	return &codexHTTPConn{Conn: connection}, nil
}

type codexHTTPConn struct{ Conn }

func (*codexHTTPConn) LocalAddr() net.Addr  { return codexPeerAddr("cli") }
func (*codexHTTPConn) RemoteAddr() net.Addr { return codexPeerAddr("machine") }
func (c *codexHTTPConn) SetDeadline(value time.Time) error {
	return c.Conn.(interface{ SetDeadline(time.Time) error }).SetDeadline(value)
}
func (c *codexHTTPConn) SetReadDeadline(value time.Time) error {
	return c.Conn.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(value)
}
func (c *codexHTTPConn) SetWriteDeadline(value time.Time) error {
	return c.Conn.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(value)
}

type codexPeerAddr string

func (codexPeerAddr) Network() string  { return "paperboat-peer" }
func (a codexPeerAddr) String() string { return string(a) }
