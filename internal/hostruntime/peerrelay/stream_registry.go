package peerrelay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/resumablestream"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
)

const resumableWindow = 512 << 10

type logicalStreamKey struct {
	principal, operation, consumer, stream string
}

type logicalStream struct {
	header streamauth.Header
	conn   *resumablestream.Conn
}

type streamRegistry struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	items  map[logicalStreamKey]*logicalStream
}

func newStreamRegistry() *streamRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	return &streamRegistry{ctx: ctx, cancel: cancel, items: make(map[logicalStreamKey]*logicalStream)}
}

// Attach transfers ownership of carrier to one logical application stream.
// The handler is invoked exactly once; reattachments only replace its carrier.
func (r *streamRegistry) Attach(principal string, header streamauth.Header, carrier net.Conn, handler StreamHandler, activities ...*transportActivity) error {
	if r == nil || principal == "" || carrier == nil || handler == nil || !header.Resumable {
		return ErrStreamDispatch
	}
	key := logicalStreamKey{principal: principal, operation: header.OperationID, consumer: header.Consumer, stream: header.StreamID}
	var requestedActivity *transportActivity
	if len(activities) > 0 {
		requestedActivity = activities[0]
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	entry := r.items[key]
	if entry != nil && (entry.header.MaximumBytes != header.MaximumBytes || entry.header.DeadlineUnix != header.DeadlineUnix) {
		r.mu.Unlock()
		return ErrStreamDispatch
	}
	created := false
	if entry == nil {
		connection, err := resumablestream.New(r.ctx, resumablestream.Config{WindowBytes: resumableWindow, Role: resumablestream.RoleResponder, Identity: resumablestream.StreamIdentity{Principal: principal, OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
		if err != nil {
			r.mu.Unlock()
			return err
		}
		entry = &logicalStream{header: header, conn: connection}
		r.items[key] = entry
		created = true
		go func() {
			bounded := &boundedConn{Conn: connection, remaining: header.MaximumBytes}
			slog.Info("peer logical stream handler starting", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID)
			handlerErr := handler(r.ctx, header, bounded)
			slog.Info("peer logical stream handler finished", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID, "error", handlerErr)
			_ = connection.CloseWrite()
			drainCtx, cancelDrain := context.WithTimeout(r.ctx, 5*time.Second)
			_ = connection.WaitWriteClosed(drainCtx)
			cancelDrain()
			_ = bounded.Close()
			r.mu.Lock()
			if r.items[key] == entry {
				delete(r.items, key)
			}
			r.mu.Unlock()
		}()
	}
	if requestedActivity != nil {
		requestedActivity.Open()
		carrier = &activityConn{Conn: carrier, release: requestedActivity.Close}
	}
	r.mu.Unlock()
	acceptCtx, cancelAccept := context.WithDeadline(r.ctx, time.Unix(header.DeadlineUnix, 0))
	err := entry.conn.AcceptCarrier(acceptCtx, carrier)
	cancelAccept()
	if err != nil {
		_ = carrier.Close()
		if created {
			_ = entry.conn.Close()
			r.mu.Lock()
			if r.items[key] == entry {
				delete(r.items, key)
			}
			r.mu.Unlock()
		}
		return errors.Join(ErrStreamDispatch, err)
	}
	slog.Info("peer logical stream carrier attached", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID)
	return nil
}

// activityConn binds an attempt lifetime to one physical carrier. Recovery
// standbys and the active carrier may belong to different attempts, so the
// logical stream must retain both until resumablestream detaches each carrier.
type activityConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *activityConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (r *streamRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	items := r.items
	r.items = make(map[logicalStreamKey]*logicalStream)
	r.mu.Unlock()
	r.cancel()
	var result error
	for _, entry := range items {
		result = errors.Join(result, entry.conn.Close())
	}
	return result
}
