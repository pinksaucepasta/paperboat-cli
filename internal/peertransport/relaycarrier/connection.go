// Package relaycarrier owns bounded relay QUIC and WSS connection streams.
package relaycarrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/wsscarrier"
)

var (
	ErrInvalid = errors.New("invalid relay carrier configuration")
	ErrClosed  = errors.New("relay carrier closed")
	ErrLimit   = errors.New("relay carrier stream limit reached")
)

type Config struct {
	MaximumStreams       int
	AcceptBacklog        int
	StreamWindow         uint32
	ConnectionWriteLimit time.Duration
	StreamOpenLimit      time.Duration
	StreamCloseLimit     time.Duration
}

func DevelopmentConfig() Config {
	return Config{MaximumStreams: 64, AcceptBacklog: 16, StreamWindow: 256 << 10, ConnectionWriteLimit: 10 * time.Second, StreamOpenLimit: 10 * time.Second, StreamCloseLimit: 5 * time.Second}
}

func (c Config) valid() bool {
	return c.MaximumStreams > 0 && c.MaximumStreams <= 1024 && c.AcceptBacklog > 0 && c.AcceptBacklog <= c.MaximumStreams && c.StreamWindow >= 64<<10 && c.StreamWindow <= 16<<20 && c.ConnectionWriteLimit > 0 && c.ConnectionWriteLimit <= time.Minute && c.StreamOpenLimit > 0 && c.StreamOpenLimit <= time.Minute && c.StreamCloseLimit > 0 && c.StreamCloseLimit <= time.Minute
}

type streamMux interface {
	Open(context.Context) (io.ReadWriteCloser, error)
	Accept(context.Context) (io.ReadWriteCloser, error)
	Close() error
}

type admissionStreamMux interface {
	OpenHandle(context.Context, [16]byte) (io.ReadWriteCloser, error)
	AcceptHandle(context.Context, [16]byte) (io.ReadWriteCloser, error)
}

type Connection struct {
	mux     streamMux
	permits chan struct{}
	done    chan struct{}
	once    sync.Once
	err     error
	carrier relaynoise.Carrier
	pto     func() uint32
}

func NewRelayQUIC(session *peerquic.Session, config Config) (*Connection, error) {
	if session == nil || session.Connection == nil || !config.valid() {
		return nil, ErrInvalid
	}
	connection := newConnection(&quicMux{session: session}, config)
	connection.carrier = relaynoise.CarrierRelayQUIC
	connection.pto = session.PTOCount
	return connection, nil
}

func (c *Connection) ptoCount() uint32 {
	if c == nil || c.pto == nil {
		return 0
	}
	return c.pto()
}

func (c *Connection) Carrier() relaynoise.Carrier {
	if c == nil {
		return 0
	}
	return c.carrier
}

func NewWSSClient(conn *wsscarrier.Conn, config Config) (*Connection, error) {
	return newWSS(conn, config, true)
}

func NewWSSServer(conn *wsscarrier.Conn, config Config) (*Connection, error) {
	return newWSS(conn, config, false)
}

func newWSS(conn net.Conn, config Config, client bool) (*Connection, error) {
	if nilNetConn(conn) || !config.valid() {
		return nil, ErrInvalid
	}
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.LogOutput = io.Discard
	yamuxConfig.AcceptBacklog = config.AcceptBacklog
	yamuxConfig.EnableKeepAlive = false
	yamuxConfig.ConnectionWriteTimeout = config.ConnectionWriteLimit
	yamuxConfig.MaxStreamWindowSize = config.StreamWindow
	yamuxConfig.StreamOpenTimeout = config.StreamOpenLimit
	yamuxConfig.StreamCloseTimeout = config.StreamCloseLimit
	var session *yamux.Session
	var err error
	if client {
		session, err = yamux.Client(conn, yamuxConfig)
	} else {
		session, err = yamux.Server(conn, yamuxConfig)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	connection := newConnection(&yamuxMux{session: session}, config)
	connection.carrier = relaynoise.CarrierWSS
	return connection, nil
}

func newConnection(mux streamMux, config Config) *Connection {
	return &Connection{mux: mux, permits: make(chan struct{}, config.MaximumStreams), done: make(chan struct{})}
}

func (c *Connection) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return c.stream(ctx, c.mux.Open)
}

func (c *Connection) AcceptStream(ctx context.Context) (io.ReadWriteCloser, error) {
	stream, err := c.stream(ctx, c.mux.Accept)
	if err != nil && ctx != nil && ctx.Err() != nil {
		_ = c.Close()
	}
	return stream, err
}

func (c *Connection) openHandle(ctx context.Context, handle [16]byte, accept bool) (io.ReadWriteCloser, error) {
	if c == nil || c.mux == nil || ctx == nil || allZeroHandle(handle) {
		return nil, ErrInvalid
	}
	admission, ok := c.mux.(admissionStreamMux)
	if !ok {
		if accept {
			return c.AcceptStream(ctx)
		}
		return c.OpenStream(ctx)
	}
	operation := admission.OpenHandle
	if accept {
		operation = admission.AcceptHandle
	}
	return c.stream(ctx, func(ctx context.Context) (io.ReadWriteCloser, error) { return operation(ctx, handle) })
}

func (c *Connection) stream(ctx context.Context, operation func(context.Context) (io.ReadWriteCloser, error)) (io.ReadWriteCloser, error) {
	if c == nil || c.mux == nil || ctx == nil {
		return nil, ErrInvalid
	}
	select {
	case c.permits <- struct{}{}:
	case <-c.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrLimit
	}
	stream, err := operation(ctx)
	if err != nil {
		<-c.permits
		if c.closed() {
			return nil, ErrClosed
		}
		return nil, err
	}
	return &ownedStream{ReadWriteCloser: stream, release: func() { <-c.permits }}, nil
}

func (c *Connection) State() connectionmanager.State {
	if c == nil || c.closed() {
		return connectionmanager.StateFailed
	}
	return connectionmanager.StateTrusted
}

func (c *Connection) Close() error {
	if c == nil || c.mux == nil {
		return nil
	}
	c.once.Do(func() {
		close(c.done)
		c.err = c.mux.Close()
		slog.Info("relay carrier closed", "carrier", c.carrier, "pto_count", c.ptoCount(), "error", c.err)
	})
	return c.err
}

func (c *Connection) closed() bool {
	if c == nil || c.done == nil {
		return true
	}
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

type ownedStream struct {
	io.ReadWriteCloser
	once    sync.Once
	release func()
}

func (s *ownedStream) SetReadDeadline(deadline time.Time) error {
	stream, ok := s.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return relaynoise.ErrProtocol
	}
	return stream.SetReadDeadline(deadline)
}

func (s *ownedStream) SetWriteDeadline(deadline time.Time) error {
	stream, ok := s.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return relaynoise.ErrProtocol
	}
	return stream.SetWriteDeadline(deadline)
}

func (s *ownedStream) Close() error {
	if s == nil || s.ReadWriteCloser == nil {
		return nil
	}
	err := s.ReadWriteCloser.Close()
	s.once.Do(s.release)
	return err
}

type quicMux struct{ session *peerquic.Session }

func (m *quicMux) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return m.session.Connection.OpenStreamSync(ctx)
}
func (m *quicMux) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	return m.session.Connection.AcceptStream(ctx)
}
func (m *quicMux) Close() error { return m.session.Close() }

type yamuxMux struct {
	session *yamux.Session

	acceptMu      sync.Mutex
	acceptStarted bool
	acceptErr     error
	waiters       map[[16]byte][]chan yamuxAcceptResult
	pending       map[[16]byte][]*yamux.Stream
}

type yamuxAcceptResult struct {
	stream *yamux.Stream
	err    error
}

func (m *yamuxMux) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return m.run(ctx, m.session.OpenStream, false)
}
func (m *yamuxMux) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	return m.run(ctx, m.session.AcceptStream, true)
}
func (m *yamuxMux) Close() error { return m.session.Close() }

func (m *yamuxMux) OpenHandle(ctx context.Context, handle [16]byte) (io.ReadWriteCloser, error) {
	if m == nil || m.session == nil || ctx == nil || allZeroHandle(handle) {
		return nil, ErrInvalid
	}
	stream, err := m.run(ctx, m.session.OpenStream, false)
	if err != nil {
		return nil, err
	}
	yamuxStream, ok := stream.(*yamux.Stream)
	if !ok {
		_ = stream.Close()
		return nil, ErrInvalid
	}
	if err := writeYamuxHandle(ctx, yamuxStream, handle); err != nil {
		return nil, errors.Join(err, yamuxStream.Close())
	}
	return yamuxStream, nil
}

func (m *yamuxMux) AcceptHandle(ctx context.Context, handle [16]byte) (io.ReadWriteCloser, error) {
	if m == nil || m.session == nil || ctx == nil || allZeroHandle(handle) {
		return nil, ErrInvalid
	}
	waiter := make(chan yamuxAcceptResult, 1)
	m.acceptMu.Lock()
	if streams := m.pending[handle]; len(streams) > 0 {
		stream := streams[0]
		if len(streams) == 1 {
			delete(m.pending, handle)
		} else {
			m.pending[handle] = streams[1:]
		}
		m.acceptMu.Unlock()
		return stream, nil
	}
	if m.acceptErr != nil {
		err := m.acceptErr
		m.acceptMu.Unlock()
		return nil, err
	}
	if m.waiters == nil {
		m.waiters = make(map[[16]byte][]chan yamuxAcceptResult)
	}
	m.waiters[handle] = append(m.waiters[handle], waiter)
	if !m.acceptStarted {
		m.acceptStarted = true
		go m.dispatchHandledStreams()
	}
	m.acceptMu.Unlock()

	select {
	case result := <-waiter:
		return result.stream, result.err
	case <-ctx.Done():
		m.acceptMu.Lock()
		waiters := m.waiters[handle]
		for index, candidate := range waiters {
			if candidate == waiter {
				waiters = append(waiters[:index], waiters[index+1:]...)
				break
			}
		}
		if len(waiters) == 0 {
			delete(m.waiters, handle)
		} else {
			m.waiters[handle] = waiters
		}
		m.acceptMu.Unlock()
		return nil, ctx.Err()
	}
}

func (m *yamuxMux) dispatchHandledStreams() {
	for {
		stream, err := m.session.AcceptStream()
		if err != nil {
			slog.Info("relay yamux handled accept stopped", "error", err)
			m.failHandledAccepts(err)
			return
		}
		var handle [16]byte
		if _, err := io.ReadFull(stream, handle[:]); err != nil || allZeroHandle(handle) {
			_ = stream.Close()
			continue
		}
		m.acceptMu.Lock()
		waiters := m.waiters[handle]
		if len(waiters) > 0 {
			waiter := waiters[0]
			if len(waiters) == 1 {
				delete(m.waiters, handle)
			} else {
				m.waiters[handle] = waiters[1:]
			}
			m.acceptMu.Unlock()
			waiter <- yamuxAcceptResult{stream: stream}
			continue
		}
		if m.pending == nil {
			m.pending = make(map[[16]byte][]*yamux.Stream)
		}
		m.pending[handle] = append(m.pending[handle], stream)
		m.acceptMu.Unlock()
	}
}

func (m *yamuxMux) failHandledAccepts(err error) {
	m.acceptMu.Lock()
	m.acceptErr = err
	waiters := m.waiters
	pending := m.pending
	m.waiters = nil
	m.pending = nil
	m.acceptMu.Unlock()
	for _, values := range waiters {
		for _, waiter := range values {
			waiter <- yamuxAcceptResult{err: err}
		}
	}
	for _, streams := range pending {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}
}

func writeYamuxHandle(ctx context.Context, stream *yamux.Stream, handle [16]byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.SetWriteDeadline(time.Now()) })
	_, err := io.CopyN(stream, bytes.NewReader(handle[:]), int64(len(handle)))
	stop()
	clearErr := stream.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), err, clearErr)
	}
	return errors.Join(err, clearErr)
}

func (m *yamuxMux) run(ctx context.Context, operation func() (*yamux.Stream, error), closeOnCancel bool) (io.ReadWriteCloser, error) {
	result := make(chan struct {
		stream *yamux.Stream
		err    error
	}, 1)
	go func() {
		stream, err := operation()
		result <- struct {
			stream *yamux.Stream
			err    error
		}{stream: stream, err: err}
	}()
	select {
	case value := <-result:
		return value.stream, value.err
	case <-ctx.Done():
		if closeOnCancel {
			slog.Info("relay yamux accept context canceled; closing session", "error", ctx.Err())
			_ = m.session.Close()
			<-result
			return nil, ctx.Err()
		}
		go func() {
			value := <-result
			if value.stream != nil {
				_ = value.stream.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func nilNetConn(conn net.Conn) bool {
	if conn == nil {
		return true
	}
	value := reflect.ValueOf(conn)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

var _ connectionmanager.Connection = (*Connection)(nil)
