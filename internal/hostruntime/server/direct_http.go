package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
)

func ServeHTTPConnection(ctx context.Context, connection net.Conn, handler http.Handler) error {
	if ctx == nil || connection == nil || handler == nil {
		return ErrInvalidConfiguration
	}
	tracked := &trackedHTTPConn{Conn: connection, closed: make(chan struct{})}
	listener := &singleHTTPListener{ctx: ctx, connection: tracked}
	server := &http.Server{Handler: handler, BaseContext: func(net.Listener) context.Context { return ctx }}
	stop := context.AfterFunc(ctx, func() { _ = tracked.Close() })
	err := server.Serve(listener)
	stop()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

type trackedHTTPConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *trackedHTTPConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type singleHTTPListener struct {
	ctx        context.Context
	connection *trackedHTTPConn
	once       sync.Once
	accepted   bool
}

func (l *singleHTTPListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.connection, nil
	}
	select {
	case <-l.connection.closed:
		return nil, net.ErrClosed
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *singleHTTPListener) Close() error {
	l.once.Do(func() { _ = l.connection.Close() })
	return nil
}

func (l *singleHTTPListener) Addr() net.Addr { return l.connection.LocalAddr() }
