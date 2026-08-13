// Package fixedpacket adapts one nominated ICE connection to net.PacketConn.
package fixedpacket

import (
	"errors"
	"net"
	"time"
)

var ErrWrongPeer = errors.New("datagram destination is not the nominated peer")

// Conn preserves the packet boundaries of the underlying ICE connection and
// rejects every destination except its nominated peer.
type Conn struct {
	conn   net.Conn
	remote net.Addr
}

func New(conn net.Conn) (*Conn, error) {
	if conn == nil || conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		return nil, errors.New("fixed peer connection requires local and remote addresses")
	}
	return &Conn{conn: conn, remote: conn.RemoteAddr()}, nil
}

func (c *Conn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(buffer)
	return n, c.remote, err
}

func (c *Conn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	if !sameAddr(c.remote, destination) {
		return 0, ErrWrongPeer
	}
	return c.conn.Write(payload)
}

func (c *Conn) Close() error                           { return c.conn.Close() }
func (c *Conn) LocalAddr() net.Addr                    { return c.conn.LocalAddr() }
func (c *Conn) SetDeadline(value time.Time) error      { return c.conn.SetDeadline(value) }
func (c *Conn) SetReadDeadline(value time.Time) error  { return c.conn.SetReadDeadline(value) }
func (c *Conn) SetWriteDeadline(value time.Time) error { return c.conn.SetWriteDeadline(value) }
func (c *Conn) RemoteAddr() net.Addr                   { return c.remote }

func sameAddr(left, right net.Addr) bool {
	return left != nil && right != nil && left.Network() == right.Network() && left.String() == right.String()
}

var _ net.PacketConn = (*Conn)(nil)
