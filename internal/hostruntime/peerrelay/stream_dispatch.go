package peerrelay

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
)

var ErrStreamDispatch = errors.New("peer stream dispatch failed")

type StreamAuthorizer func(context.Context, streamauth.Header) (server.Authorization, error)
type StreamHandler func(context.Context, streamauth.Header, net.Conn) error

// CredentialStreamAuthorizer adapts the existing application credential
// verifier to the reusable transport header. It deliberately performs no new
// authorization; the canonical protocol capability and operation binding are
// selected here and verified by the existing host authorizer.
func CredentialStreamAuthorizer(factory server.AuthorizerFactory) StreamAuthorizer {
	return func(ctx context.Context, header streamauth.Header) (server.Authorization, error) {
		if factory == nil {
			return server.Authorization{}, ErrStreamDispatch
		}
		authorizer, err := factory(header.Credential)
		if err != nil || authorizer == nil {
			return server.Authorization{}, errors.Join(ErrStreamDispatch, err)
		}
		if closer, ok := authorizer.(server.AuthorizationCloser); ok {
			defer closer.CloseAuthorization()
		}
		capability := map[string]string{"terminal": "terminal.v1", "exec": "exec.v1", "ssh": "ssh.v1", "private_preview": "preview.launch.v1", "codex": "codex.connect.v1"}[header.Consumer]
		if capability == "" {
			return server.Authorization{}, ErrStreamDispatch
		}
		authorization, err := authorizer.Authorize(ctx, protocol.Frame{Type: "request", RequestID: header.StreamID, Version: protocol.ProtocolVersion, OperationID: header.OperationID, Capability: capability})
		if err != nil {
			return server.Authorization{}, errors.Join(ErrStreamDispatch, err)
		}
		return authorization, nil
	}
}

// DispatchAuthorizedStream validates the canonical stream header before any
// application handler receives the connection. The handler gets a bounded
// connection and cannot exceed the grant's byte limit in either direction.
func DispatchAuthorizedStream(ctx context.Context, encoded []byte, conn net.Conn, authorize StreamAuthorizer, handler StreamHandler) error {
	if ctx == nil || conn == nil || authorize == nil || handler == nil {
		return ErrStreamDispatch
	}
	header, err := streamauth.Parse(encoded, time.Now().UTC())
	if err != nil {
		_ = conn.Close()
		return errors.Join(ErrStreamDispatch, err)
	}
	return DispatchParsedStream(ctx, header, conn, authorize, handler)
}

func DispatchParsedStream(ctx context.Context, header streamauth.Header, conn net.Conn, authorize StreamAuthorizer, handler StreamHandler) error {
	if ctx == nil || conn == nil || authorize == nil || handler == nil || header.Validate(time.Now().UTC()) != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return ErrStreamDispatch
	}
	if _, err := authorize(ctx, header); err != nil {
		_ = conn.Close()
		return errors.Join(ErrStreamDispatch, err)
	}
	bounded := &boundedConn{Conn: conn, remaining: header.MaximumBytes}
	defer bounded.Close()
	return handler(ctx, header, bounded)
}

type boundedConn struct {
	net.Conn
	remaining uint64
	closed    atomic.Bool
}

func (c *boundedConn) Read(data []byte) (int, error) {
	if c == nil || c.Conn == nil || c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(data) == 0 {
		return 0, nil
	}
	limit := uint64(len(data))
	if limit > c.remaining {
		limit = c.remaining
	}
	if limit == 0 {
		return 0, ErrStreamDispatch
	}
	count, err := c.Conn.Read(data[:limit])
	c.remaining -= uint64(count)
	return count, err
}

func (c *boundedConn) Write(data []byte) (int, error) {
	if c == nil || c.Conn == nil || c.closed.Load() {
		return 0, net.ErrClosed
	}
	if uint64(len(data)) > c.remaining {
		return 0, ErrStreamDispatch
	}
	count, err := c.Conn.Write(data)
	c.remaining -= uint64(count)
	return count, err
}

func (c *boundedConn) CloseWrite() error {
	if c == nil || c.Conn == nil || c.closed.Load() {
		return net.ErrClosed
	}
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return ErrStreamDispatch
}

func (c *boundedConn) Close() error {
	if c == nil || c.Conn == nil || c.closed.Swap(true) {
		return nil
	}
	return c.Conn.Close()
}
