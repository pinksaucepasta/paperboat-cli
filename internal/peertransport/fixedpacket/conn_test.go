package fixedpacket

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnCarriesPacketsOnlyToFixedPeer(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn, err := New(&addressConn{Conn: left, local: testAddr("left"), remote: testAddr("right")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4)
		_, err := right.Read(buffer)
		done <- err
	}()
	if _, err := conn.WriteTo([]byte("test"), testAddr("right")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("no"), testAddr("other")); !errors.Is(err, ErrWrongPeer) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewRejectsMissingAddresses(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := New(&addressConn{Conn: left}); err == nil {
		t.Fatal("missing addresses accepted")
	}
}

type testAddr string

func (a testAddr) Network() string { return "udp" }
func (a testAddr) String() string  { return string(a) }

type addressConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *addressConn) LocalAddr() net.Addr                    { return c.local }
func (c *addressConn) RemoteAddr() net.Addr                   { return c.remote }
func (c *addressConn) SetDeadline(value time.Time) error      { return c.Conn.SetDeadline(value) }
func (c *addressConn) SetReadDeadline(value time.Time) error  { return c.Conn.SetReadDeadline(value) }
func (c *addressConn) SetWriteDeadline(value time.Time) error { return c.Conn.SetWriteDeadline(value) }
