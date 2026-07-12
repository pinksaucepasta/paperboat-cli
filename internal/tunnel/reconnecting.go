package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

type ReconnectFunc func(context.Context) (Conn, error)

var ErrWriteUncertain = errors.New("terminal write outcome is uncertain")
var ErrTransportLost = errors.New("terminal transport lost")

type transportFailureMarker interface {
	MarkTransportLost(error)
}

// ReconnectingConn supervises unexpected transport loss while one session
// loop retains ownership of stdin. Failed writes are never replayed.
type ReconnectingConn struct {
	ctx        context.Context
	mu         sync.RWMutex
	current    Conn
	available  chan struct{}
	reconnect  ReconnectFunc
	maxRetries int
	delay      time.Duration
	out        chan []byte
	done       chan reconnectResult
	closed     chan struct{}
	closeOnce  sync.Once
	pending    []byte
}

type reconnectResult struct {
	code int
	err  error
}

func NewReconnectingConn(ctx context.Context, initial Conn, maxRetries int, delay time.Duration, reconnect ReconnectFunc) *ReconnectingConn {
	available := make(chan struct{})
	close(available)
	c := &ReconnectingConn{ctx: ctx, current: initial, available: available, reconnect: reconnect, maxRetries: maxRetries, delay: delay, out: make(chan []byte, 64), done: make(chan reconnectResult, 1), closed: make(chan struct{})}
	go c.supervise(initial)
	return c
}

func (c *ReconnectingConn) supervise(conn Conn) {
	defer close(c.out)
	for {
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			buf := make([]byte, 32*1024)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					b := append([]byte(nil), buf[:n]...)
					select {
					case c.out <- b:
					case <-c.closed:
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		code, err := conn.Wait()
		_ = conn.Close()
		<-readDone
		if err == nil || !errors.Is(err, ErrTransportLost) || c.reconnect == nil || c.maxRetries <= 0 {
			c.done <- reconnectResult{code, err}
			return
		}
		c.setUnavailable(conn)
		reconnected := false
		for attempt := 0; attempt < c.maxRetries; attempt++ {
			if waitErr := c.waitDelay(); waitErr != nil {
				c.done <- reconnectResult{130, nil}
				return
			}
			next, dialErr := c.reconnect(c.ctx)
			if dialErr != nil {
				err = errors.Join(err, dialErr)
				continue
			}
			if next == nil {
				err = errors.Join(err, errors.New("reconnect returned no connection"))
				continue
			}
			select {
			case <-c.closed:
				_ = next.Close()
				c.done <- reconnectResult{130, nil}
				return
			default:
			}
			conn = next
			c.setCurrent(next)
			reconnected = true
			break
		}
		if !reconnected {
			c.done <- reconnectResult{1, err}
			return
		}
	}
}

func (c *ReconnectingConn) setUnavailable(conn Conn) {
	c.mu.Lock()
	if c.current == conn {
		c.current = nil
		c.available = make(chan struct{})
	}
	c.mu.Unlock()
}
func (c *ReconnectingConn) setCurrent(conn Conn) {
	c.mu.Lock()
	c.current = conn
	ch := c.available
	c.mu.Unlock()
	close(ch)
}
func (c *ReconnectingConn) waitCurrent(ctx context.Context) (Conn, error) {
	for {
		c.mu.RLock()
		conn, ch := c.current, c.available
		c.mu.RUnlock()
		if conn != nil {
			return conn, nil
		}
		select {
		case <-ch:
		case <-c.closed:
			return nil, io.ErrClosedPipe
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
func (c *ReconnectingConn) waitDelay() error {
	timer := time.NewTimer(c.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-c.closed:
		return io.ErrClosedPipe
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}
func (c *ReconnectingConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	b, ok := <-c.out
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n < len(b) {
		c.pending = append(c.pending, b[n:]...)
	}
	return n, nil
}
func (c *ReconnectingConn) Write(p []byte) (int, error) {
	conn, err := c.waitCurrent(c.ctx)
	if err != nil {
		return 0, err
	}
	n, writeErr := conn.Write(p)
	if writeErr != nil {
		if c.maxRetries <= 0 || c.reconnect == nil {
			return n, writeErr
		}
		c.setUnavailable(conn)
		if marker, ok := conn.(transportFailureMarker); ok {
			marker.MarkTransportLost(writeErr)
		} else {
			_ = conn.Close()
		}
		return n, errors.Join(ErrWriteUncertain, writeErr)
	}
	return n, nil
}
func (c *ReconnectingConn) Resize(r, col uint16) error {
	conn, err := c.waitCurrent(c.ctx)
	if err != nil {
		return err
	}
	return conn.Resize(r, col)
}
func (c *ReconnectingConn) CloseWrite() error {
	conn, err := c.waitCurrent(c.ctx)
	if err != nil {
		return err
	}
	if h, ok := conn.(InputHalfCloser); ok {
		return h.CloseWrite()
	}
	return nil
}
func (c *ReconnectingConn) Wait() (int, error) { r := <-c.done; return r.code, r.err }
func (c *ReconnectingConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.RLock()
		conn := c.current
		c.mu.RUnlock()
		if conn != nil {
			err = conn.Close()
		}
	})
	return err
}
