package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type closeTrackingConn struct {
	*reconnectTestConn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error { c.closed.Store(true); return nil }

type reconnectTestConn struct {
	*bytes.Reader
	code   int
	err    error
	writes bytes.Buffer
}

func (c *reconnectTestConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (*reconnectTestConn) Close() error                  { return nil }
func (*reconnectTestConn) Resize(uint16, uint16) error   { return nil }
func (c *reconnectTestConn) Wait() (int, error)          { return c.code, c.err }

func TestReconnectingConnReattachesWithoutReplayingInput(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader([]byte("before")), err: ErrTransportLost}
	second := &reconnectTestConn{Reader: bytes.NewReader([]byte("after")), code: 7}
	reconnects := 0
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) { reconnects++; return second, nil })
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.Wait()
	if err != nil || code != 7 || string(got) != "beforeafter" || reconnects != 1 {
		t.Fatalf("code=%d err=%v output=%q reconnects=%d", code, err, got, reconnects)
	}
	if first.writes.Len() != 0 || second.writes.Len() != 0 {
		t.Fatal("reconnect replayed terminal input")
	}
}

func TestReconnectingConnBoundsFailures(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	c := NewReconnectingConn(context.Background(), first, 1, time.Millisecond, func(context.Context) (Conn, error) { return nil, errors.New("still offline") })
	_, _ = io.ReadAll(c)
	code, err := c.Wait()
	if err == nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestReconnectingConnDoesNotRetryTerminalFailure(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: errors.New("remote command failed")}
	reconnects := 0
	c := NewReconnectingConn(context.Background(), first, 2, 0, func(context.Context) (Conn, error) {
		reconnects++
		return nil, errors.New("should not reconnect")
	})
	_, err := c.Wait()
	if err == nil || err.Error() != "remote command failed" || reconnects != 0 {
		t.Fatalf("err=%v reconnects=%d", err, reconnects)
	}
}

func TestReconnectingConnRejectsLateReconnectAfterClose(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	replacement := &closeTrackingConn{reconnectTestConn: &reconnectTestConn{Reader: bytes.NewReader(nil)}}
	started := make(chan struct{})
	release := make(chan struct{})
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) {
		close(started)
		<-release
		return replacement, nil
	})
	<-started
	_ = c.Close()
	close(release)
	done := make(chan struct{})
	go func() { _, _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait hung after a late reconnect")
	}
	if !replacement.closed.Load() {
		t.Fatal("late reconnect result was not closed")
	}
}

type writeRaceConn struct{ wait chan error }

func (*writeRaceConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *writeRaceConn) Write([]byte) (int, error) {
	return 0, ErrTransportLost
}
func (c *writeRaceConn) Close() error {
	select {
	case c.wait <- nil:
	default:
	}
	return nil
}
func (c *writeRaceConn) MarkTransportLost(error) {
	select {
	case c.wait <- ErrTransportLost:
	default:
	}
}
func (*writeRaceConn) Resize(uint16, uint16) error { return nil }
func (c *writeRaceConn) Wait() (int, error)        { return 1, <-c.wait }

func TestReconnectingConnCoordinatesWriteFailureWithReconnect(t *testing.T) {
	first := &writeRaceConn{wait: make(chan error, 1)}
	second := &reconnectTestConn{Reader: bytes.NewReader(nil)}
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) { return second, nil })
	if _, err := c.Write([]byte("uncertain")); !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("err=%v", err)
	}
	if _, err := c.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if second.writes.String() != "next" {
		t.Fatalf("replayed writes=%q", second.writes.String())
	}
	_ = c.Close()
}
