package relaycarrier

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const secureConnChunk = 32 << 10

type SecureConn struct {
	stream *SecureStream
	local  net.Addr
	remote net.Addr

	readMu        sync.Mutex
	readBuffer    []byte
	readDeadline  time.Time
	writeMu       sync.Mutex
	writeDeadline time.Time
	deadlineMu    sync.RWMutex
}

func NewSecureConn(stream *SecureStream, localID, remoteID string) (*SecureConn, error) {
	if stream == nil || stream.carrier == nil || stream.session == nil || !boundedAttachmentID(localID) || !boundedAttachmentID(remoteID) || localID == remoteID {
		return nil, ErrInvalid
	}
	return &SecureConn{stream: stream, local: secureAddr(localID), remote: secureAddr(remoteID)}, nil
}

func (c *SecureConn) Read(target []byte) (int, error) {
	if c == nil || c.stream == nil {
		return 0, net.ErrClosed
	}
	if len(target) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuffer) == 0 {
		ctx, cancel := c.deadlineContext(true)
		payload, closed, err := c.stream.Receive(ctx)
		cancel()
		if err != nil {
			return 0, deadlineError(ctx, err)
		}
		if len(payload) == 0 || closed {
			if len(payload) == 0 {
				return 0, io.EOF
			}
		}
		c.readBuffer = payload
	}
	n := copy(target, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

func (c *SecureConn) Write(payload []byte) (int, error) {
	if c == nil || c.stream == nil {
		return 0, net.ErrClosed
	}
	if len(payload) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > secureConnChunk {
			chunk = chunk[:secureConnChunk]
		}
		ctx, cancel := c.deadlineContext(false)
		err := c.stream.Send(ctx, chunk, false)
		cancel()
		if err != nil {
			return written, deadlineError(ctx, err)
		}
		written += len(chunk)
		payload = payload[len(chunk):]
	}
	return written, nil
}

func (c *SecureConn) Close() error {
	if c == nil || c.stream == nil {
		return nil
	}
	return c.stream.Close()
}

// CloseWrite sends an authenticated end-of-stream record without closing the
// receive direction or the multiplexed carrier stream.
func (c *SecureConn) CloseWrite() error {
	if c == nil || c.stream == nil {
		return net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	ctx, cancel := c.deadlineContext(false)
	err := c.stream.Send(ctx, nil, true)
	cancel()
	return deadlineError(ctx, err)
}

func (c *SecureConn) LocalAddr() net.Addr  { return c.local }
func (c *SecureConn) RemoteAddr() net.Addr { return c.remote }

func (c *SecureConn) SetDeadline(value time.Time) error {
	if c == nil || c.stream == nil {
		return net.ErrClosed
	}
	c.deadlineMu.Lock()
	c.readDeadline, c.writeDeadline = value, value
	c.deadlineMu.Unlock()
	return nil
}

func (c *SecureConn) SetReadDeadline(value time.Time) error {
	if c == nil || c.stream == nil {
		return net.ErrClosed
	}
	c.deadlineMu.Lock()
	c.readDeadline = value
	c.deadlineMu.Unlock()
	return nil
}

func (c *SecureConn) SetWriteDeadline(value time.Time) error {
	if c == nil || c.stream == nil {
		return net.ErrClosed
	}
	c.deadlineMu.Lock()
	c.writeDeadline = value
	c.deadlineMu.Unlock()
	return nil
}

func (c *SecureConn) deadlineContext(read bool) (context.Context, context.CancelFunc) {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	c.deadlineMu.RUnlock()
	if deadline.IsZero() {
		return context.WithCancel(context.Background())
	}
	return context.WithDeadline(context.Background(), deadline)
}

func deadlineError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.Join(os.ErrDeadlineExceeded, err)
	}
	return err
}

type secureAddr string

func (secureAddr) Network() string  { return "paperboat-peer" }
func (a secureAddr) String() string { return string(a) }

var _ net.Conn = (*SecureConn)(nil)
var _ interface{ CloseWrite() error } = (*SecureConn)(nil)
