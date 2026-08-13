// Package wsscarrier owns the bounded net.Conn facade for Paperboat WSS paths.
package wsscarrier

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/coder/websocket"
	//paperboat:allow-source-policy tailscale-import owner=peer-transport reason=selected-wss-net-conn-carrier
	"tailscale.com/net/wsconn"
)

const MaximumMessageBytes = 28 + 65535

var relayIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Config struct {
	RelayID         string
	MaximumDeadline time.Duration
}

type Conn struct {
	conn            net.Conn
	maximumDeadline time.Duration
	writeMu         sync.Mutex
	deadlineMu      sync.RWMutex
	readDeadline    time.Time
	writeDeadline   time.Time
	closeOnce       sync.Once
	closeErr        error
}

func New(ctx context.Context, connection *websocket.Conn, config Config) (*Conn, error) {
	if ctx == nil || connection == nil || !relayIDPattern.MatchString(config.RelayID) || config.MaximumDeadline <= 0 || config.MaximumDeadline > 24*time.Hour {
		return nil, errors.New("invalid WSS carrier configuration")
	}
	connection.SetReadLimit(MaximumMessageBytes)
	return &Conn{
		conn:            wsconn.NetConn(ctx, connection, websocket.MessageBinary, "paperboat-relay/"+config.RelayID),
		maximumDeadline: config.MaximumDeadline,
	}, nil
}

func (c *Conn) Read(payload []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	n, err := c.conn.Read(payload)
	if err != nil && c.deadlineElapsed(true) {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	if len(payload) > MaximumMessageBytes {
		return 0, errors.New("WSS carrier message exceeds limit")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.conn.Write(payload)
	if err != nil && c.deadlineElapsed(false) {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *Conn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *Conn) SetDeadline(deadline time.Time) error {
	if err := c.validDeadline(deadline); err != nil {
		return err
	}
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return c.conn.SetDeadline(deadline)
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	if err := c.validDeadline(deadline); err != nil {
		return err
	}
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return c.conn.SetReadDeadline(deadline)
}

func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	if err := c.validDeadline(deadline); err != nil {
		return err
	}
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return c.conn.SetWriteDeadline(deadline)
}

func (c *Conn) deadlineElapsed(read bool) bool {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	c.deadlineMu.RUnlock()
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (c *Conn) validDeadline(deadline time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	if !deadline.IsZero() && deadline.After(time.Now().Add(c.maximumDeadline)) {
		return errors.New("WSS carrier deadline exceeds limit")
	}
	return nil
}

var _ net.Conn = (*Conn)(nil)
