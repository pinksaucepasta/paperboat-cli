package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

// Data-carrier limits are deliberately small.  They bound both the number of
// streams which can hold a connection permit and the number of stream opens
// waiting for a peer acknowledgement.
const (
	defaultDataCarrierStreams      = 64
	defaultDataCarrierBacklog      = 16
	defaultDataCarrierQueue        = 16
	defaultDataCarrierWindow       = 256 << 10
	defaultDataCarrierKeepalive    = 30 * time.Second
	defaultDataCarrierWriteLimit   = 10 * time.Second
	defaultDataCarrierOpenLimit    = 10 * time.Second
	defaultDataCarrierCloseLimit   = 5 * time.Second
	defaultDataCarrierMaxCarriers  = 2
	maxDataCarrierStreams          = 1024
	maxDataCarrierBacklog          = 1024
	maxDataCarrierQueue            = 1024
	maxDataCarrierWindow           = 16 << 20
	maxDataCarrierKeepalive        = time.Hour
	maxDataCarrierOperationTimeout = time.Minute
)

var (
	ErrInvalidDataCarrierConfig = errors.New("invalid data carrier configuration")
	ErrDataCarrierClosed        = errors.New("data carrier closed")
	ErrDataCarrierDraining      = errors.New("data carrier draining")
	ErrDataCarrierLimit         = errors.New("data carrier stream limit reached")
	ErrDataCarrierUnavailable   = errors.New("data carrier unavailable")
	ErrDataCarrierControlOpen   = errors.New("data carrier control stream already open")
	ErrDataCarrierAdmission     = errors.New("data carrier stream admission rejected")
)

// StreamOpen is the canonical connector-v1 per-stream admission metadata.
// It deliberately contains no bearer or reusable credential bytes.
type StreamOpen = connectorprotocol.StreamOpen

// DataCarrierIdentity is the authenticated control-session identity bound to
// every data-stream preface.  The carrier owner must obtain it from the
// connector-v1 control session; this package never authenticates bearer data.
type DataCarrierIdentity struct {
	AccountID   string
	HostID      string
	TunnelID    string
	ConnectorID string
	SessionID   string
	// SessionGeneration is the server-issued connector lease/credential
	// generation. It is distinct from process and configuration generations and
	// is required by stable-host update fencing.
	SessionGeneration uint64
	ProcessGeneration uint64
	Generation        uint64
}

func (i DataCarrierIdentity) validate() error {
	if connectorprotocol.ValidateIdentifier(i.AccountID) != nil || connectorprotocol.ValidateIdentifier(i.HostID) != nil || connectorprotocol.ValidateIdentifier(i.TunnelID) != nil || connectorprotocol.ValidateIdentifier(i.ConnectorID) != nil || connectorprotocol.ValidateIdentifier(i.SessionID) != nil || i.ProcessGeneration == 0 || i.Generation == 0 {
		return ErrInvalidDataCarrierConfig
	}
	return nil
}

func (i DataCarrierIdentity) matches(open StreamOpen) bool {
	return open.AccountID == i.AccountID && open.TunnelID == i.TunnelID && open.ConnectorID == i.ConnectorID && open.SessionID == i.SessionID && open.ProcessGeneration == i.ProcessGeneration && open.Generation == i.Generation
}

// DataCarrierAdmission is evaluated after the canonical stream-open preface
// has been decoded and exact session identity has matched.  The route owner
// remains responsible for route revision and request admission.
type DataCarrierAdmission struct {
	Identity  DataCarrierIdentity
	Authorize func(context.Context, StreamOpen) error
}

func (a DataCarrierAdmission) validate() error {
	if err := a.Identity.validate(); err != nil || a.Authorize == nil {
		return ErrInvalidDataCarrierConfig
	}
	return nil
}

// DataCarrierConfig controls one authenticated multiplexed carrier.  The
// carrier does not perform authentication or admission itself; callers must
// establish those boundaries before passing the link to this package.
type DataCarrierConfig struct {
	MaximumStreams       int
	AcceptBacklog        int
	QueueDepth           int
	StreamWindow         uint32
	KeepAliveInterval    time.Duration
	ConnectionWriteLimit time.Duration
	StreamOpenLimit      time.Duration
	StreamCloseLimit     time.Duration
}

func DefaultDataCarrierConfig() DataCarrierConfig {
	return DataCarrierConfig{
		MaximumStreams:       defaultDataCarrierStreams,
		AcceptBacklog:        defaultDataCarrierBacklog,
		QueueDepth:           defaultDataCarrierQueue,
		StreamWindow:         defaultDataCarrierWindow,
		KeepAliveInterval:    defaultDataCarrierKeepalive,
		ConnectionWriteLimit: defaultDataCarrierWriteLimit,
		StreamOpenLimit:      defaultDataCarrierOpenLimit,
		StreamCloseLimit:     defaultDataCarrierCloseLimit,
	}
}

func (c DataCarrierConfig) withDefaults() DataCarrierConfig {
	d := DefaultDataCarrierConfig()
	if c.MaximumStreams == 0 {
		c.MaximumStreams = d.MaximumStreams
	}
	if c.AcceptBacklog == 0 {
		c.AcceptBacklog = d.AcceptBacklog
	}
	if c.QueueDepth == 0 {
		c.QueueDepth = d.QueueDepth
	}
	if c.StreamWindow == 0 {
		c.StreamWindow = d.StreamWindow
	}
	if c.KeepAliveInterval == 0 {
		c.KeepAliveInterval = d.KeepAliveInterval
	}
	if c.ConnectionWriteLimit == 0 {
		c.ConnectionWriteLimit = d.ConnectionWriteLimit
	}
	if c.StreamOpenLimit == 0 {
		c.StreamOpenLimit = d.StreamOpenLimit
	}
	if c.StreamCloseLimit == 0 {
		c.StreamCloseLimit = d.StreamCloseLimit
	}
	return c
}

func (c DataCarrierConfig) Validate() error {
	c = c.withDefaults()
	if c.MaximumStreams <= 0 || c.MaximumStreams > maxDataCarrierStreams {
		return fmt.Errorf("%w: maximum streams must be in [1,%d]", ErrInvalidDataCarrierConfig, maxDataCarrierStreams)
	}
	if c.AcceptBacklog <= 0 || c.AcceptBacklog > maxDataCarrierBacklog || c.AcceptBacklog > c.MaximumStreams {
		return fmt.Errorf("%w: accept backlog must be in [1,%d] and no greater than maximum streams", ErrInvalidDataCarrierConfig, maxDataCarrierBacklog)
	}
	if c.QueueDepth <= 0 || c.QueueDepth > maxDataCarrierQueue {
		return fmt.Errorf("%w: queue depth must be in [1,%d]", ErrInvalidDataCarrierConfig, maxDataCarrierQueue)
	}
	if c.StreamWindow < defaultDataCarrierWindow || c.StreamWindow > maxDataCarrierWindow {
		return fmt.Errorf("%w: stream window must be in [%d,%d]", ErrInvalidDataCarrierConfig, defaultDataCarrierWindow, maxDataCarrierWindow)
	}
	if c.KeepAliveInterval <= 0 || c.KeepAliveInterval > maxDataCarrierKeepalive {
		return fmt.Errorf("%w: keepalive interval must be in (0,%s]", ErrInvalidDataCarrierConfig, maxDataCarrierKeepalive)
	}
	if !validDataCarrierTimeout(c.ConnectionWriteLimit) || !validDataCarrierTimeout(c.StreamOpenLimit) || !validDataCarrierTimeout(c.StreamCloseLimit) {
		return fmt.Errorf("%w: operation limits must be in (0,%s]", ErrInvalidDataCarrierConfig, maxDataCarrierOperationTimeout)
	}
	return nil
}

func validDataCarrierTimeout(timeout time.Duration) bool {
	return timeout > 0 && timeout <= maxDataCarrierOperationTimeout
}

// DataCarrierState describes the lifecycle of one carrier.  A carrier is
// usable as soon as its yamux session has been built.  Client pools additionally
// perform a Ping round trip before publishing Ready.
type DataCarrierState string

const (
	DataCarrierReady   DataCarrierState = "ready"
	DataCarrierClosed  DataCarrierState = "closed"
	DataCarrierUnknown DataCarrierState = "unknown"
)

var nextDataCarrierID atomic.Uint64

// DataCarrierStreamLink is the bounded byte stream exposed by one carrier
// stream. TCP links use yamux streams; QUIC links use native bidirectional
// streams directly.
type DataCarrierStreamLink interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// DataCarrierSession is the transport-specific multiplexing boundary. The
// TCP implementation wraps one TLS connection in yamux, while QUIC maps each
// operation to an independent native QUIC bidirectional stream.
type DataCarrierSession interface {
	OpenStream(context.Context) (DataCarrierStreamLink, error)
	AcceptStream(context.Context) (DataCarrierStreamLink, error)
	Ping(context.Context) error
	Close() error
	CloseChan() <-chan struct{}
}

// DataCarrier owns one transport-native session and its bounded stream
// permits.
type DataCarrier struct {
	id        string
	ctx       context.Context
	session   DataCarrierSession
	config    DataCarrierConfig
	identity  DataCarrierIdentity
	admission *DataCarrierAdmission
	permits   chan struct{}
	openings  chan struct{}
	accepted  chan dataCarrierAcceptResult
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	active    atomic.Int64
}

type dataCarrierAcceptResult struct {
	stream *DataCarrierStream
	open   StreamOpen
	err    error
}

func NewDataCarrierClient(ctx context.Context, link io.ReadWriteCloser, config DataCarrierConfig, identity ...DataCarrierIdentity) (*DataCarrier, error) {
	if len(identity) > 1 {
		return nil, ErrInvalidDataCarrierConfig
	}
	var bound DataCarrierIdentity
	if len(identity) == 1 {
		bound = identity[0]
		if err := bound.validate(); err != nil {
			return nil, err
		}
	}
	return newDataCarrier(ctx, link, config, true, bound, nil)
}

// NewDataCarrierClientWithSession constructs a client on a transport-native
// session, such as a QUIC connection. The session owns all stream creation,
// acceptance, keepalive, and closure semantics.
func NewDataCarrierClientWithSession(ctx context.Context, session DataCarrierSession, config DataCarrierConfig, identity ...DataCarrierIdentity) (*DataCarrier, error) {
	if len(identity) > 1 {
		return nil, ErrInvalidDataCarrierConfig
	}
	var bound DataCarrierIdentity
	if len(identity) == 1 {
		bound = identity[0]
		if err := bound.validate(); err != nil {
			return nil, err
		}
	}
	return newDataCarrierWithSession(ctx, session, config, bound, nil)
}

func NewDataCarrierServer(ctx context.Context, link io.ReadWriteCloser, config DataCarrierConfig, admission ...DataCarrierAdmission) (*DataCarrier, error) {
	if len(admission) != 1 {
		return nil, ErrInvalidDataCarrierConfig
	}
	var bound *DataCarrierAdmission
	if len(admission) == 1 {
		if err := admission[0].validate(); err != nil {
			return nil, err
		}
		bound = &admission[0]
	}
	return newDataCarrier(ctx, link, config, false, DataCarrierIdentity{}, bound)
}

// NewDataCarrierServerWithSession constructs a server on a transport-native
// session. Admission remains mandatory so an authenticated control-session
// identity and route owner are always present before bytes are exposed.
func NewDataCarrierServerWithSession(ctx context.Context, session DataCarrierSession, config DataCarrierConfig, admission ...DataCarrierAdmission) (*DataCarrier, error) {
	if len(admission) != 1 || session == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	if err := admission[0].validate(); err != nil {
		return nil, err
	}
	return newDataCarrierWithSession(ctx, session, config, DataCarrierIdentity{}, &admission[0])
}

func newDataCarrier(ctx context.Context, link io.ReadWriteCloser, config DataCarrierConfig, client bool, identity DataCarrierIdentity, admission *DataCarrierAdmission) (*DataCarrier, error) {
	if ctx == nil || link == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	session, err := newYamuxDataCarrierSession(link, config, client)
	if err != nil {
		_ = link.Close()
		return nil, err
	}
	return newDataCarrierWithSession(ctx, session, config, identity, admission)
}

func newDataCarrierWithSession(ctx context.Context, session DataCarrierSession, config DataCarrierConfig, identity DataCarrierIdentity, admission *DataCarrierAdmission) (*DataCarrier, error) {
	if ctx == nil || session == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	c := &DataCarrier{
		id:        fmt.Sprintf("carrier-%d", nextDataCarrierID.Add(1)),
		ctx:       ctx,
		session:   session,
		config:    config,
		identity:  identity,
		admission: admission,
		permits:   make(chan struct{}, config.MaximumStreams),
		openings:  make(chan struct{}, config.QueueDepth),
		accepted:  make(chan dataCarrierAcceptResult, config.QueueDepth),
		done:      make(chan struct{}),
	}
	go c.watch(ctx)
	go c.acceptLoop()
	return c, nil
}

type yamuxDataCarrierSession struct {
	session *yamux.Session
}

func newYamuxDataCarrierSession(link io.ReadWriteCloser, config DataCarrierConfig, client bool) (DataCarrierSession, error) {
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.LogOutput = io.Discard
	yamuxConfig.AcceptBacklog = config.AcceptBacklog
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = config.KeepAliveInterval
	yamuxConfig.ConnectionWriteTimeout = config.ConnectionWriteLimit
	yamuxConfig.MaxStreamWindowSize = config.StreamWindow
	yamuxConfig.StreamOpenTimeout = config.StreamOpenLimit
	yamuxConfig.StreamCloseTimeout = config.StreamCloseLimit
	var (
		session *yamux.Session
		err     error
	)
	if client {
		session, err = yamux.Client(link, yamuxConfig)
	} else {
		session, err = yamux.Server(link, yamuxConfig)
	}
	if err != nil {
		return nil, err
	}
	return &yamuxDataCarrierSession{session: session}, nil
}

func (s *yamuxDataCarrierSession) OpenStream(ctx context.Context) (DataCarrierStreamLink, error) {
	if s == nil || s.session == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	result := make(chan struct {
		stream *yamux.Stream
		err    error
	}, 1)
	go func() {
		stream, err := s.session.OpenStream()
		result <- struct {
			stream *yamux.Stream
			err    error
		}{stream: stream, err: err}
	}()
	select {
	case opened := <-result:
		return opened.stream, opened.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.session.CloseChan():
		return nil, ErrDataCarrierClosed
	}
}

func (s *yamuxDataCarrierSession) AcceptStream(ctx context.Context) (DataCarrierStreamLink, error) {
	if s == nil || s.session == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	result := make(chan struct {
		stream *yamux.Stream
		err    error
	}, 1)
	go func() {
		stream, err := s.session.AcceptStream()
		result <- struct {
			stream *yamux.Stream
			err    error
		}{stream: stream, err: err}
	}()
	select {
	case opened := <-result:
		return opened.stream, opened.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.session.CloseChan():
		return nil, ErrDataCarrierClosed
	}
}

func (s *yamuxDataCarrierSession) Ping(ctx context.Context) error {
	if s == nil || s.session == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.session.Ping()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.session.CloseChan():
		return ErrDataCarrierClosed
	}
}

func (s *yamuxDataCarrierSession) Close() error {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Close()
}

func (s *yamuxDataCarrierSession) CloseChan() <-chan struct{} {
	if s == nil || s.session == nil {
		return closedDataCarrierChannel()
	}
	return s.session.CloseChan()
}

func (c *DataCarrier) watch(ctx context.Context) {
	select {
	case <-ctx.Done():
		c.shutdown(ctx.Err())
	case <-c.session.CloseChan():
		c.shutdown(ErrDataCarrierClosed)
	}
}

func (c *DataCarrier) acceptLoop() {
	defer close(c.accepted)
	for {
		raw, err := c.session.AcceptStream(c.ctx)
		if err != nil {
			if !c.closed() {
				c.shutdown(err)
			}
			return
		}
		select {
		case c.permits <- struct{}{}:
			c.active.Add(1)
		case <-c.done:
			_ = raw.Close()
			return
		}
		var open StreamOpen
		if c.admission != nil {
			admissionContext, cancel := context.WithTimeout(context.Background(), c.config.StreamOpenLimit)
			deadline := time.Now().Add(c.config.StreamOpenLimit)
			if err := raw.SetReadDeadline(deadline); err != nil {
				cancel()
				_ = raw.Close()
				c.releasePermit()
				c.publishAccepted(dataCarrierAcceptResult{err: ErrDataCarrierAdmission})
				continue
			}
			open, err = connectorprotocol.ReadStreamOpen(raw)
			_ = raw.SetReadDeadline(time.Time{})
			if err == nil && !c.admission.Identity.matches(open) {
				err = ErrDataCarrierAdmission
			}
			if err == nil {
				err = c.admission.Authorize(admissionContext, open)
				if err != nil {
					err = fmt.Errorf("%w: %v", ErrDataCarrierAdmission, err)
				}
			}
			cancel()
			if err != nil {
				_ = raw.Close()
				c.releasePermit()
				c.publishAccepted(dataCarrierAcceptResult{err: err})
				continue
			}
		}
		stream := c.wrapStream(raw, context.Background(), nil)
		stream.Open = open
		select {
		case c.accepted <- dataCarrierAcceptResult{stream: stream, open: open}:
		case <-c.done:
			_ = stream.Close()
			return
		}
	}
}

func (c *DataCarrier) publishAccepted(result dataCarrierAcceptResult) {
	select {
	case c.accepted <- result:
	case <-c.done:
		if result.stream != nil {
			_ = result.stream.Close()
		}
	}
}

func (c *DataCarrier) ID() string {
	if c == nil {
		return ""
	}
	return c.id
}

// Identity returns the authenticated control-session identity bound to this
// carrier. HostID is intentionally local metadata and is never repeated in
// the per-stream wire preface.
func (c *DataCarrier) Identity() DataCarrierIdentity {
	if c == nil {
		return DataCarrierIdentity{}
	}
	return c.identity
}

func (c *DataCarrier) State() DataCarrierState {
	if c == nil || c.closed() {
		return DataCarrierClosed
	}
	return DataCarrierReady
}

func (c *DataCarrier) ActiveStreams() int {
	if c == nil || c.closed() {
		return 0
	}
	active := c.active.Load()
	if active <= 0 {
		return 0
	}
	return int(active)
}

func (c *DataCarrier) Done() <-chan struct{} {
	if c == nil {
		return closedDataCarrierChannel()
	}
	return c.done
}

func (c *DataCarrier) Ping(ctx context.Context) error {
	if c == nil || c.session == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	if c.closed() {
		return ErrDataCarrierClosed
	}
	err := c.session.Ping(ctx)
	if err != nil && c.closed() {
		return ErrDataCarrierClosed
	}
	return err
}

func (c *DataCarrier) OpenStream(ctx context.Context, open ...StreamOpen) (io.ReadWriteCloser, error) {
	if len(open) > 1 {
		return nil, ErrInvalidDataCarrierConfig
	}
	var metadata *StreamOpen
	if len(open) == 1 {
		if err := open[0].Validate(); err != nil {
			return nil, err
		}
		if c == nil || c.identity.AccountID == "" || !c.identity.matches(open[0]) {
			return nil, ErrDataCarrierAdmission
		}
		metadata = &open[0]
	}
	return c.openStreamWithMetadata(ctx, nil, metadata)
}

// OpenControlStream reserves one ordinary carrier stream for the already
// authenticated connector-v1 control session.  Control frames are owned by
// the protocol package and therefore have no data-stream preface.
func (c *DataCarrier) OpenControlStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return c.openStream(ctx, nil)
}

func (c *DataCarrier) openStream(ctx context.Context, onClose func()) (io.ReadWriteCloser, error) {
	return c.openStreamWithMetadata(ctx, onClose, nil)
}

func (c *DataCarrier) openStreamWithMetadata(ctx context.Context, onClose func(), open *StreamOpen) (io.ReadWriteCloser, error) {
	if c == nil || c.session == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	if open != nil {
		if err := open.Validate(); err != nil {
			return nil, err
		}
		if c.identity.AccountID == "" || !c.identity.matches(*open) {
			return nil, ErrDataCarrierAdmission
		}
	}
	if c.closed() {
		return nil, ErrDataCarrierClosed
	}
	select {
	case c.permits <- struct{}{}:
		c.active.Add(1)
	case <-c.done:
		return nil, ErrDataCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrDataCarrierLimit
	}
	select {
	case c.openings <- struct{}{}:
	case <-c.done:
		c.releasePermit()
		return nil, ErrDataCarrierClosed
	case <-ctx.Done():
		c.releasePermit()
		return nil, ctx.Err()
	}
	result := make(chan dataCarrierOpenResult, 1)
	go func() {
		raw, err := c.session.OpenStream(ctx)
		result <- dataCarrierOpenResult{stream: raw, err: err}
	}()
	select {
	case opened := <-result:
		<-c.openings
		if opened.err != nil {
			c.releasePermit()
			if c.closed() {
				return nil, ErrDataCarrierClosed
			}
			return nil, opened.err
		}
		if err := ctx.Err(); err != nil {
			_ = opened.stream.Close()
			c.releasePermit()
			return nil, err
		}
		if open != nil {
			if err := writeDataCarrierStreamOpen(ctx, opened.stream, *open, c.config.StreamOpenLimit); err != nil {
				_ = opened.stream.Close()
				c.releasePermit()
				return nil, err
			}
		}
		if open != nil {
			stream := c.wrapStream(opened.stream, ctx, onClose, *open)
			return stream, nil
		}
		stream := c.wrapStream(opened.stream, ctx, onClose)
		return stream, nil
	case <-c.done:
		go c.finishCanceledOpen(result)
		return nil, ErrDataCarrierClosed
	case <-ctx.Done():
		go c.finishCanceledOpen(result)
		return nil, ctx.Err()
	}
}

type dataCarrierOpenResult struct {
	stream DataCarrierStreamLink
	err    error
}

func (c *DataCarrier) finishCanceledOpen(result <-chan dataCarrierOpenResult) {
	opened := <-result
	<-c.openings
	if opened.stream != nil {
		_ = opened.stream.Close()
	}
	c.releasePermit()
}

func (c *DataCarrier) AcceptStream(ctx context.Context) (*DataCarrierStream, StreamOpen, error) {
	if c == nil || ctx == nil {
		return nil, StreamOpen{}, ErrInvalidDataCarrierConfig
	}
	if c.closed() {
		return nil, StreamOpen{}, ErrDataCarrierClosed
	}
	select {
	case result, ok := <-c.accepted:
		if !ok {
			return nil, StreamOpen{}, ErrDataCarrierClosed
		}
		return result.stream, result.open, result.err
	case <-c.done:
		return nil, StreamOpen{}, ErrDataCarrierClosed
	case <-ctx.Done():
		return nil, StreamOpen{}, ctx.Err()
	}
}

func writeDataCarrierStreamOpen(ctx context.Context, stream DataCarrierStreamLink, open StreamOpen, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := connectorprotocol.WriteStreamOpen(stream, open)
	_ = stream.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return ctx.Err()
}

func (c *DataCarrier) wrapStream(raw DataCarrierStreamLink, ctx context.Context, onClose func(), open ...StreamOpen) *DataCarrierStream {
	stream := &DataCarrierStream{raw: raw, release: c.releasePermit, onClose: onClose}
	if len(open) > 0 {
		stream.Open = open[0]
	}
	if ctx != nil && ctx != context.Background() {
		stream.cancelMu.Lock()
		stream.stopCancel = context.AfterFunc(ctx, func() { _ = stream.Close() })
		stream.cancelMu.Unlock()
	}
	return stream
}

func (c *DataCarrier) releasePermit() {
	if !c.closed() {
		c.active.Add(-1)
	}
	select {
	case <-c.permits:
	default:
	}
}

func (c *DataCarrier) shutdown(err error) {
	c.closeOnce.Do(func() {
		c.closeErr = err
		close(c.done)
		_ = c.session.Close()
	})
}

func (c *DataCarrier) Close() error {
	if c == nil {
		return nil
	}
	c.shutdown(nil)
	return c.closeErr
}

func (c *DataCarrier) closed() bool {
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

func closedDataCarrierChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// DataCarrierStream owns one stream permit.  Closing it is required even
// after receiving EOF so the carrier can admit another stream.
type DataCarrierStream struct {
	raw        DataCarrierStreamLink
	Open       StreamOpen
	release    func()
	onClose    func()
	cancelMu   sync.Mutex
	stopCancel func() bool
	closeOnce  sync.Once
	closeErr   error
}

func (s *DataCarrierStream) Read(p []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrDataCarrierClosed
	}
	return s.raw.Read(p)
}

func (s *DataCarrierStream) Write(p []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrDataCarrierClosed
	}
	return s.raw.Write(p)
}

func (s *DataCarrierStream) Close() error {
	if s == nil || s.raw == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancelMu.Lock()
		stopCancel := s.stopCancel
		s.cancelMu.Unlock()
		if stopCancel != nil {
			stopCancel()
		}
		s.closeErr = s.raw.Close()
		if s.release != nil {
			s.release()
		}
		if s.onClose != nil {
			s.onClose()
		}
	})
	return s.closeErr
}

func (s *DataCarrierStream) StreamID() uint32 {
	if s == nil || s.raw == nil {
		return 0
	}
	if identified, ok := s.raw.(interface{ StreamID() uint32 }); ok {
		return identified.StreamID()
	}
	return 0
}

func (s *DataCarrierStream) SetDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrDataCarrierClosed
	}
	return s.raw.SetDeadline(deadline)
}

func (s *DataCarrierStream) SetReadDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrDataCarrierClosed
	}
	return s.raw.SetReadDeadline(deadline)
}

func (s *DataCarrierStream) SetWriteDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrDataCarrierClosed
	}
	return s.raw.SetWriteDeadline(deadline)
}

// TransportDialError lets a dialer make fallback eligibility explicit.  A
// plain net.Error is also eligible, except context cancellation/deadlines,
// which must never silently switch transports.
type TransportDialError struct {
	Transport Transport
	Err       error
	Fallback  bool
}

func (e *TransportDialError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s carrier dial: %v", e.Transport, e.Err)
}

func (e *TransportDialError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func transportFallbackAllowed(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var dialErr *TransportDialError
	if errors.As(err, &dialErr) {
		return dialErr.Fallback
	}
	var networkErr net.Error
	return errors.As(err, &networkErr)
}

type DataCarrierPoolConfig struct {
	MaximumCarriers int
	QueueDepth      int
	Preferred       Transport
	Fallback        Transport
	SingleTransport bool
	EdgeID          string
	FailureDomains  []string
	Session         DataCarrierIdentity
	Carrier         DataCarrierConfig
}

func DefaultDataCarrierPoolConfig() DataCarrierPoolConfig {
	return DataCarrierPoolConfig{
		MaximumCarriers: defaultDataCarrierMaxCarriers,
		QueueDepth:      defaultDataCarrierQueue,
		Preferred:       QUIC,
		Fallback:        TCPMux,
		EdgeID:          "edge",
		FailureDomains:  []string{"domain-a", "domain-b"},
		Session:         DataCarrierIdentity{AccountID: "account", HostID: "host-a", TunnelID: "tunnel", ConnectorID: "connector", SessionID: "session", ProcessGeneration: 1, Generation: 1},
		Carrier:         DefaultDataCarrierConfig(),
	}
}

func (c DataCarrierPoolConfig) withDefaults() DataCarrierPoolConfig {
	d := DefaultDataCarrierPoolConfig()
	if c.MaximumCarriers == 0 {
		c.MaximumCarriers = d.MaximumCarriers
	}
	if c.QueueDepth == 0 {
		c.QueueDepth = d.QueueDepth
	}
	if c.Preferred == "" || c.Preferred == Auto {
		c.Preferred = d.Preferred
	}
	if c.Fallback == "" || c.Fallback == Auto {
		c.Fallback = d.Fallback
	}
	if c.EdgeID == "" {
		c.EdgeID = d.EdgeID
	}
	if len(c.FailureDomains) == 0 {
		c.FailureDomains = append([]string(nil), d.FailureDomains...)
	}
	c.Carrier = c.Carrier.withDefaults()
	return c
}

func (c DataCarrierPoolConfig) Validate() error {
	c = c.withDefaults()
	if c.MaximumCarriers <= 0 || c.MaximumCarriers > 16 {
		return fmt.Errorf("%w: maximum carriers must be in [1,16]", ErrInvalidDataCarrierConfig)
	}
	if c.QueueDepth <= 0 || c.QueueDepth > maxDataCarrierQueue {
		return fmt.Errorf("%w: pool queue depth must be in [1,%d]", ErrInvalidDataCarrierConfig, maxDataCarrierQueue)
	}
	if c.Preferred != QUIC && c.Preferred != TCPMux {
		return fmt.Errorf("%w: preferred transport must be quic or tcp mux", ErrInvalidDataCarrierConfig)
	}
	if c.Fallback != QUIC && c.Fallback != TCPMux {
		return fmt.Errorf("%w: fallback transport must be quic or tcp mux", ErrInvalidDataCarrierConfig)
	}
	if c.Preferred == c.Fallback && !c.SingleTransport {
		return fmt.Errorf("%w: equal preferred and fallback require single transport", ErrInvalidDataCarrierConfig)
	}
	if c.SingleTransport && c.Preferred != c.Fallback {
		return fmt.Errorf("%w: single transport requires equal preferred and fallback", ErrInvalidDataCarrierConfig)
	}
	if !validDataCarrierIdentifier(c.EdgeID, 128) {
		return fmt.Errorf("%w: edge identity is required", ErrInvalidDataCarrierConfig)
	}
	if len(c.FailureDomains) < c.MaximumCarriers {
		return fmt.Errorf("%w: one failure domain is required per carrier slot", ErrInvalidDataCarrierConfig)
	}
	if err := c.Session.validate(); err != nil {
		return fmt.Errorf("%w: authenticated session identity is required", ErrInvalidDataCarrierConfig)
	}
	seenDomains := make(map[string]struct{}, len(c.FailureDomains))
	for _, domain := range c.FailureDomains {
		if !validDataCarrierIdentifier(domain, 128) {
			return fmt.Errorf("%w: failure domain is required", ErrInvalidDataCarrierConfig)
		}
		if _, exists := seenDomains[domain]; exists {
			return fmt.Errorf("%w: failure domains must be distinct", ErrInvalidDataCarrierConfig)
		}
		seenDomains[domain] = struct{}{}
	}
	if err := c.Carrier.Validate(); err != nil {
		return err
	}
	return nil
}

func validDataCarrierIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// DataCarrierDialRequest binds each dial attempt to a configured edge and
// failure domain.  A dialer must not silently reuse a different slot or
// domain, because the pool uses those identities for failover diagnostics.
type DataCarrierDialRequest struct {
	Transport     Transport
	Slot          int
	Attempt       int
	EdgeID        string
	FailureDomain string
	Identity      DataCarrierIdentity
}

// DataCarrierDialResult records the identity actually reached by a dialer.
// The pool rejects a result which does not match its request. Production
// dialers must populate PeerIdentity from the verified TLS/QUIC peer binding.
type DataCarrierDialResult struct {
	Link          io.ReadWriteCloser
	Session       DataCarrierSession
	PeerIdentity  DataCarrierIdentity
	Transport     Transport
	EdgeID        string
	FailureDomain string
}

type DataCarrierDialer func(context.Context, DataCarrierDialRequest) (DataCarrierDialResult, error)

type DataCarrierPoolState string

const (
	DataCarrierPoolDisconnected DataCarrierPoolState = "disconnected"
	DataCarrierPoolConnecting   DataCarrierPoolState = "connecting"
	DataCarrierPoolReady        DataCarrierPoolState = "ready"
	DataCarrierPoolDraining     DataCarrierPoolState = "draining"
	DataCarrierPoolClosed       DataCarrierPoolState = "closed"
)

type DataCarrierInfo struct {
	ID            string
	Identity      DataCarrierIdentity
	Transport     Transport
	EdgeID        string
	FailureDomain string
	Slot          int
	Attempt       int
	ActiveStreams int
	State         DataCarrierState
}

type pooledDataCarrier struct {
	transport     Transport
	edgeID        string
	failureDomain string
	slot          int
	attempt       int
	carrier       *DataCarrier
}

// DataCarrierPool maintains a small set of independently dialed carriers.
// Connect publishes Ready only after at least one preferred/fallback carrier
// has completed a yamux Ping round trip.
type DataCarrierPool struct {
	ctx    context.Context
	cancel context.CancelFunc
	dial   DataCarrierDialer
	config DataCarrierPoolConfig
	queue  chan struct{}
	done   chan struct{}
	ready  chan struct{}

	connectMu      sync.Mutex
	mu             sync.RWMutex
	state          DataCarrierPoolState
	selected       Transport
	carriers       []*pooledDataCarrier
	readyOnce      sync.Once
	closeOnce      sync.Once
	control        *DataCarrierStream
	controlOpening bool
}

// Identity returns a copy of the exact authenticated session binding used by
// every carrier in this pool. It never exposes credential material.
func (p *DataCarrierPool) Identity() (DataCarrierIdentity, bool) {
	if p == nil {
		return DataCarrierIdentity{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.state == DataCarrierPoolClosed || p.config.Session.validate() != nil {
		return DataCarrierIdentity{}, false
	}
	return p.config.Session, true
}

func NewDataCarrierPool(ctx context.Context, config DataCarrierPoolConfig, dialer DataCarrierDialer) (*DataCarrierPool, error) {
	if ctx == nil || dialer == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	poolCtx, cancel := context.WithCancel(ctx)
	return &DataCarrierPool{
		ctx:    poolCtx,
		cancel: cancel,
		dial:   dialer,
		config: config,
		queue:  make(chan struct{}, config.QueueDepth),
		done:   make(chan struct{}),
		ready:  make(chan struct{}),
		state:  DataCarrierPoolDisconnected,
	}, nil
}

func (p *DataCarrierPool) Connect(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.connectMu.Lock()
	defer p.connectMu.Unlock()
	p.mu.Lock()
	if p.state == DataCarrierPoolClosed {
		p.mu.Unlock()
		return ErrDataCarrierClosed
	}
	if p.state == DataCarrierPoolDraining {
		p.mu.Unlock()
		return ErrDataCarrierDraining
	}
	p.state = DataCarrierPoolConnecting
	p.mu.Unlock()

	var errs []error
	for {
		p.mu.RLock()
		slot := p.nextSlotLocked()
		remaining := p.config.MaximumCarriers - len(p.carriers)
		p.mu.RUnlock()
		if remaining <= 0 {
			break
		}
		result, transport, attempt, err := p.dialWithFallback(ctx, slot)
		if err != nil {
			errs = append(errs, err)
			break
		}
		var carrier *DataCarrier
		if result.Session != nil {
			carrier, err = NewDataCarrierClientWithSession(p.ctx, result.Session, p.config.Carrier, p.config.Session)
		} else {
			carrier, err = NewDataCarrierClient(p.ctx, result.Link, p.config.Carrier, p.config.Session)
		}
		if err != nil {
			if result.Session != nil {
				_ = result.Session.Close()
			} else if result.Link != nil {
				_ = result.Link.Close()
			}
			errs = append(errs, err)
			break
		}
		pingCtx, cancel := context.WithTimeout(ctx, p.config.Carrier.ConnectionWriteLimit)
		err = carrier.Ping(pingCtx)
		cancel()
		if err != nil {
			_ = carrier.Close()
			errs = append(errs, err)
			break
		}
		p.mu.Lock()
		if p.state == DataCarrierPoolClosed {
			p.mu.Unlock()
			_ = carrier.Close()
			return ErrDataCarrierClosed
		}
		p.carriers = append(p.carriers, &pooledDataCarrier{transport: transport, edgeID: result.EdgeID, failureDomain: result.FailureDomain, slot: slot, attempt: attempt, carrier: carrier})
		if p.selected == "" {
			p.selected = transport
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	if len(p.carriers) > 0 {
		p.state = DataCarrierPoolReady
		p.readyOnce.Do(func() { close(p.ready) })
	} else if p.state != DataCarrierPoolClosed {
		p.state = DataCarrierPoolDisconnected
	}
	state := p.state
	p.mu.Unlock()
	if state == DataCarrierPoolReady {
		return nil
	}
	if len(errs) == 0 {
		return ErrDataCarrierUnavailable
	}
	return errors.Join(errs...)
}

func (p *DataCarrierPool) nextSlotLocked() int {
	for slot := 0; slot < p.config.MaximumCarriers; slot++ {
		used := false
		for _, pooled := range p.carriers {
			if pooled != nil && pooled.slot == slot {
				used = true
				break
			}
		}
		if !used {
			return slot
		}
	}
	return p.config.MaximumCarriers
}

func (p *DataCarrierPool) dialWithFallback(ctx context.Context, slot int) (DataCarrierDialResult, Transport, int, error) {
	preferred := p.config.Preferred
	preferredRequest := DataCarrierDialRequest{Transport: preferred, Slot: slot, Attempt: 1, EdgeID: p.config.EdgeID, FailureDomain: p.config.FailureDomains[slot], Identity: p.config.Session}
	result, err := p.dial(ctx, preferredRequest)
	if err == nil {
		if err := validateDataCarrierDialResult(preferredRequest, result); err != nil {
			return DataCarrierDialResult{}, preferred, 1, err
		}
		return result, preferred, 1, nil
	}
	if p.config.Fallback == preferred || !transportFallbackAllowed(err) {
		return DataCarrierDialResult{}, preferred, 1, &TransportDialError{Transport: preferred, Err: err, Fallback: false}
	}
	fallbackRequest := DataCarrierDialRequest{Transport: p.config.Fallback, Slot: slot, Attempt: 2, EdgeID: p.config.EdgeID, FailureDomain: p.config.FailureDomains[slot], Identity: p.config.Session}
	fallbackResult, fallbackErr := p.dial(ctx, fallbackRequest)
	if fallbackErr == nil {
		if err := validateDataCarrierDialResult(fallbackRequest, fallbackResult); err != nil {
			return DataCarrierDialResult{}, p.config.Fallback, 2, err
		}
		return fallbackResult, p.config.Fallback, 2, nil
	}
	return DataCarrierDialResult{}, preferred, 1, errors.Join(
		&TransportDialError{Transport: preferred, Err: err, Fallback: true},
		&TransportDialError{Transport: p.config.Fallback, Err: fallbackErr, Fallback: false},
	)
}

func validateDataCarrierDialResult(request DataCarrierDialRequest, result DataCarrierDialResult) error {
	if (result.Link == nil) == (result.Session == nil) || result.Transport != request.Transport || result.EdgeID != request.EdgeID || result.FailureDomain != request.FailureDomain || result.PeerIdentity != request.Identity {
		if result.Link != nil {
			_ = result.Link.Close()
		}
		if result.Session != nil {
			_ = result.Session.Close()
		}
		return fmt.Errorf("%w: dial result identity does not match slot %d attempt %d", ErrInvalidDataCarrierConfig, request.Slot, request.Attempt)
	}
	return nil
}

func (p *DataCarrierPool) Ready() <-chan struct{} {
	if p == nil {
		return closedDataCarrierChannel()
	}
	return p.ready
}

func (p *DataCarrierPool) State() DataCarrierPoolState {
	if p == nil {
		return DataCarrierPoolClosed
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *DataCarrierPool) SelectedTransport() (Transport, bool) {
	if p == nil {
		return "", false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.selected, p.selected != ""
}

func (p *DataCarrierPool) Snapshot() []DataCarrierInfo {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]DataCarrierInfo, 0, len(p.carriers))
	for _, pooled := range p.carriers {
		if pooled == nil || pooled.carrier == nil {
			continue
		}
		result = append(result, DataCarrierInfo{ID: pooled.carrier.ID(), Identity: pooled.carrier.Identity(), Transport: pooled.transport, EdgeID: pooled.edgeID, FailureDomain: pooled.failureDomain, Slot: pooled.slot, Attempt: pooled.attempt, ActiveStreams: pooled.carrier.ActiveStreams(), State: pooled.carrier.State()})
	}
	return result
}

func (p *DataCarrierPool) OpenStream(ctx context.Context, open ...StreamOpen) (io.ReadWriteCloser, error) {
	if len(open) > 1 {
		return nil, ErrInvalidDataCarrierConfig
	}
	var metadata *StreamOpen
	if len(open) == 1 {
		metadata = &open[0]
	}
	return p.openStream(ctx, false, metadata)
}

func (p *DataCarrierPool) OpenControlStream(ctx context.Context) (io.ReadWriteCloser, error) {
	if p == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	p.mu.Lock()
	if p.control != nil || p.controlOpening {
		p.mu.Unlock()
		return nil, ErrDataCarrierControlOpen
	}
	p.controlOpening = true
	p.mu.Unlock()
	stream, err := p.openStream(ctx, true, nil)
	if err != nil {
		p.mu.Lock()
		p.controlOpening = false
		p.mu.Unlock()
		return nil, err
	}
	p.mu.Lock()
	if p.control != nil {
		p.controlOpening = false
		p.mu.Unlock()
		_ = stream.Close()
		return nil, ErrDataCarrierControlOpen
	}
	control, ok := stream.(*DataCarrierStream)
	if !ok {
		p.mu.Unlock()
		_ = stream.Close()
		return nil, ErrDataCarrierUnavailable
	}
	p.control = control
	p.controlOpening = false
	p.mu.Unlock()
	return control, nil
}

func (p *DataCarrierPool) openStream(ctx context.Context, control bool, open *StreamOpen) (io.ReadWriteCloser, error) {
	if p == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()
	if state == DataCarrierPoolDraining {
		return nil, ErrDataCarrierDraining
	}
	if state == DataCarrierPoolClosed {
		return nil, ErrDataCarrierClosed
	}
	select {
	case p.queue <- struct{}{}:
		defer func() { <-p.queue }()
	case <-p.done:
		return nil, ErrDataCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := p.ensureConnected(ctx); err != nil {
		return nil, err
	}
	for {
		p.removeClosed()
		p.mu.RLock()
		carriers := append([]*pooledDataCarrier(nil), p.carriers...)
		p.mu.RUnlock()
		if len(carriers) == 0 {
			return nil, ErrDataCarrierUnavailable
		}
		if control {
			// Keep the control stream on the selected carrier.  This gives
			// control ownership a stable diagnostic and leaves other carriers
			// available for data streams.
			selected, ok := p.SelectedTransport()
			if !ok {
				return nil, ErrDataCarrierUnavailable
			}
			for _, pooled := range carriers {
				if pooled.transport == selected {
					return pooled.carrier.openStreamWithMetadata(ctx, p.clearControl, nil)
				}
			}
			return nil, ErrDataCarrierUnavailable
		}
		// Pick the least-loaded carrier.  Sorting is unnecessary because the
		// list is small; preserving list order makes selection deterministic.
		var selected *pooledDataCarrier
		for _, pooled := range carriers {
			if pooled.carrier.State() == DataCarrierClosed {
				continue
			}
			if selected == nil || pooled.carrier.ActiveStreams() < selected.carrier.ActiveStreams() {
				selected = pooled
			}
		}
		if selected == nil {
			if err := p.ensureConnected(ctx); err != nil {
				return nil, err
			}
			continue
		}
		stream, err := selected.carrier.openStreamWithMetadata(ctx, nil, open)
		if err == nil {
			return stream, nil
		}
		if errors.Is(err, ErrDataCarrierClosed) {
			p.removeClosed()
			continue
		}
		return nil, err
	}
}

// AcceptStream waits for an edge-opened data stream on any healthy carrier.
// Each carrier gets one bounded waiter, and cancellation tears down the
// unselected waiters without closing healthy sessions.
func (p *DataCarrierPool) AcceptStream(ctx context.Context) (*DataCarrierStream, StreamOpen, error) {
	if p == nil || ctx == nil {
		return nil, StreamOpen{}, ErrInvalidDataCarrierConfig
	}
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()
	if state == DataCarrierPoolDraining {
		return nil, StreamOpen{}, ErrDataCarrierDraining
	}
	if state == DataCarrierPoolClosed {
		return nil, StreamOpen{}, ErrDataCarrierClosed
	}
	if err := p.ensureConnected(ctx); err != nil {
		return nil, StreamOpen{}, err
	}
	p.removeClosed()
	p.mu.RLock()
	carriers := append([]*pooledDataCarrier(nil), p.carriers...)
	p.mu.RUnlock()
	if len(carriers) == 0 {
		return nil, StreamOpen{}, ErrDataCarrierUnavailable
	}
	waitContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dataCarrierAcceptResult, len(carriers))
	for _, pooled := range carriers {
		go func(carrier *DataCarrier) {
			stream, open, err := carrier.AcceptStream(waitContext)
			results <- dataCarrierAcceptResult{stream: stream, open: open, err: err}
		}(pooled.carrier)
	}
	var lastErr error
	for range carriers {
		select {
		case result := <-results:
			if result.err == nil && result.stream != nil {
				return result.stream, result.open, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			return nil, StreamOpen{}, ctx.Err()
		case <-p.done:
			return nil, StreamOpen{}, ErrDataCarrierClosed
		}
	}
	if lastErr == nil {
		lastErr = ErrDataCarrierUnavailable
	}
	return nil, StreamOpen{}, lastErr
}

func (p *DataCarrierPool) clearControl() {
	p.mu.Lock()
	p.control = nil
	p.mu.Unlock()
}

func (p *DataCarrierPool) ensureConnected(ctx context.Context) error {
	p.removeClosed()
	p.mu.RLock()
	count := len(p.carriers)
	state := p.state
	p.mu.RUnlock()
	if count > 0 && state == DataCarrierPoolReady {
		return nil
	}
	return p.Connect(ctx)
}

func (p *DataCarrierPool) removeClosed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.carriers[:0]
	for _, pooled := range p.carriers {
		if pooled != nil && pooled.carrier != nil && pooled.carrier.State() != DataCarrierClosed {
			kept = append(kept, pooled)
		}
	}
	p.carriers = kept
	if len(kept) == 0 {
		if p.state == DataCarrierPoolReady {
			p.state = DataCarrierPoolDisconnected
		}
		p.selected = ""
		return
	}
	selectedPresent := false
	for _, pooled := range kept {
		if pooled.transport == p.selected {
			selectedPresent = true
			break
		}
	}
	if !selectedPresent {
		p.selected = kept[0].transport
	}
}

// BeginDrain atomically closes stream admission without waiting for existing
// streams or closing their underlying carriers. It is idempotent and fences a
// concurrent Connect so a stale dial completion cannot reopen admission.
func (p *DataCarrierPool) BeginDrain() error {
	if p == nil {
		return ErrInvalidDataCarrierConfig
	}
	p.connectMu.Lock()
	defer p.connectMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == DataCarrierPoolClosed || p.state == DataCarrierPoolDraining {
		return nil
	}
	p.state = DataCarrierPoolDraining
	return nil
}

// ActiveStreams returns the bounded aggregate stream count across the exact
// authenticated carrier generation owned by this pool.
func (p *DataCarrierPool) ActiveStreams() int { return p.totalActive() }

func (p *DataCarrierPool) Drain(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	if err := p.BeginDrain(); err != nil {
		return err
	}
	for {
		p.removeClosed()
		if p.totalActive() == 0 {
			return p.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return nil
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (p *DataCarrierPool) totalActive() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, pooled := range p.carriers {
		if pooled != nil && pooled.carrier != nil {
			total += pooled.carrier.ActiveStreams()
		}
	}
	return total
}

func (p *DataCarrierPool) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.state = DataCarrierPoolClosed
		carriers := append([]*pooledDataCarrier(nil), p.carriers...)
		p.mu.Unlock()
		close(p.done)
		p.cancel()
		p.readyOnce.Do(func() { close(p.ready) })
		for _, pooled := range carriers {
			if pooled != nil && pooled.carrier != nil {
				_ = pooled.carrier.Close()
			}
		}
	})
	return nil
}
