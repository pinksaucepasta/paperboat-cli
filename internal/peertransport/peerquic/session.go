// Package peerquic owns native Paperboat QUIC over an ICE-nominated path.
package peerquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/fixedpacket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const ALPN = "paperboat-peer-v1"

type Class uint8

const (
	ClassInteractive Class = iota + 1
	ClassPreview
	ClassTransfer
)

type SessionConfig struct {
	Class             Class
	KeepAlivePeriod   time.Duration
	MaxIdleTimeout    time.Duration
	InitialPacketSize uint16
}

func DevelopmentSessionConfig(class Class) SessionConfig {
	return SessionConfig{
		Class: class, KeepAlivePeriod: 3 * time.Second,
		MaxIdleTimeout: 2 * time.Minute, InitialPacketSize: 1200,
	}
}

func (c SessionConfig) WithKeepAlive(period time.Duration) (SessionConfig, error) {
	c.KeepAlivePeriod = period
	if err := c.validate(); err != nil {
		return SessionConfig{}, err
	}
	return c, nil
}

func (c SessionConfig) WithInitialPacketSize(size uint16) (SessionConfig, error) {
	c.InitialPacketSize = size
	if err := c.validate(); err != nil {
		return SessionConfig{}, err
	}
	return c, nil
}

func (c SessionConfig) validate() error {
	if !validClass(c.Class) || c.KeepAlivePeriod <= 0 || c.MaxIdleTimeout <= 2*c.KeepAlivePeriod || c.InitialPacketSize < 1200 {
		return errors.New("invalid peer QUIC session configuration")
	}
	return nil
}

type Session struct {
	Connection *quic.Conn
	transport  *quic.Transport
	pto        *ptoTrace
	closeOnce  sync.Once
	closeErr   error
}

func Dial(ctx context.Context, iceConn net.Conn, tlsConfig *tls.Config, class Class) (*Session, error) {
	return DialConfigured(ctx, iceConn, tlsConfig, DevelopmentSessionConfig(class))
}

func DialConfigured(ctx context.Context, iceConn net.Conn, tlsConfig *tls.Config, sessionConfig SessionConfig) (*Session, error) {
	if err := sessionConfig.validate(); err != nil {
		return nil, err
	}
	if err := validateClientTLS(tlsConfig); err != nil {
		return nil, err
	}
	return dial(ctx, iceConn, tlsConfig, quicConfig(sessionConfig))
}

// DialProbe creates a probe-only connection with automatic keepalives disabled
// so an idle interval measures the network mapping rather than QUIC traffic.
func DialProbe(ctx context.Context, iceConn net.Conn, tlsConfig *tls.Config, maximumIdle time.Duration) (*Session, error) {
	if err := validateClientTLS(tlsConfig); err != nil || maximumIdle <= 0 {
		if err == nil {
			err = errors.New("probe maximum idle must be positive")
		}
		return nil, err
	}
	return dial(ctx, iceConn, tlsConfig, probeConfig(maximumIdle))
}

func dial(ctx context.Context, iceConn net.Conn, tlsConfig *tls.Config, quicConfig *quic.Config) (*Session, error) {
	packetConn, err := fixedpacket.New(iceConn)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 8, DisableVersionNegotiationPackets: true}
	pto := newPTOTrace()
	configured := quicConfig.Clone()
	configured.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return pto }
	connection, err := transport.Dial(ctx, packetConn.RemoteAddr(), tlsConfig.Clone(), configured)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("dial peer QUIC: %w", err)
	}
	return &Session{Connection: connection, transport: transport, pto: pto}, nil
}

type Listener struct {
	listener  *quic.Listener
	transport *quic.Transport
	pto       *ptoTrace
	closeOnce sync.Once
	closeErr  error
}

func Listen(iceConn net.Conn, tlsConfig *tls.Config, class Class) (*Listener, error) {
	return ListenConfigured(iceConn, tlsConfig, DevelopmentSessionConfig(class))
}

func ListenConfigured(iceConn net.Conn, tlsConfig *tls.Config, sessionConfig SessionConfig) (*Listener, error) {
	if err := sessionConfig.validate(); err != nil {
		return nil, err
	}
	if err := validateServerTLS(tlsConfig); err != nil {
		return nil, err
	}
	return listen(iceConn, tlsConfig, quicConfig(sessionConfig))
}

// ListenProbe accepts only probe-control streams and sends no automatic
// keepalive packets during the measured idle period.
func ListenProbe(iceConn net.Conn, tlsConfig *tls.Config, maximumIdle time.Duration) (*Listener, error) {
	if err := validateServerTLS(tlsConfig); err != nil || maximumIdle <= 0 {
		if err == nil {
			err = errors.New("probe maximum idle must be positive")
		}
		return nil, err
	}
	return listen(iceConn, tlsConfig, probeConfig(maximumIdle))
}

func listen(iceConn net.Conn, tlsConfig *tls.Config, quicConfig *quic.Config) (*Listener, error) {
	started := time.Now()
	timing := map[string]int64{}
	defer func() {
		diagnosticlog.TryInfo("peer QUIC listener timing", "milestones_us", timing, "elapsed_us", time.Since(started).Microseconds())
	}()
	packetConn, err := fixedpacket.New(iceConn)
	if err != nil {
		return nil, err
	}
	timing["packet_adapter_ready"] = time.Since(started).Microseconds()
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 8, DisableVersionNegotiationPackets: true}
	pto := newPTOTrace()
	configured := quicConfig.Clone()
	configured.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return pto }
	listener, err := transport.Listen(tlsConfig.Clone(), configured)
	timing["transport_listen_returned"] = time.Since(started).Microseconds()
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("listen peer QUIC: %w", err)
	}
	return &Listener{listener: listener, transport: transport, pto: pto}, nil
}

func probeConfig(maximumIdle time.Duration) *quic.Config {
	probeSession := DevelopmentSessionConfig(ClassInteractive)
	probeSession.MaxIdleTimeout = maximumIdle
	result := quicConfig(probeSession)
	result.KeepAlivePeriod = 0
	result.MaxIncomingStreams = 3
	return result
}

func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	connection, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept peer QUIC: %w", err)
	}
	return &Session{Connection: connection, pto: l.pto}, nil
}

func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closeErr = errors.Join(l.transport.Conn.Close(), l.listener.Close(), l.transport.Close())
	})
	return l.closeErr
}

func (s *Session) Close() error {
	if s == nil || s.Connection == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var packetErr, transportErr error
		// Send QUIC's authenticated close while the packet transport is still
		// writable. Closing the ICE/UDP socket first strands the peer until its
		// idle timeout, which leaks host-side carriers after the final lease.
		// quic-go's CloseWithError waits for the connection context to finish.
		// Initiate it asynchronously and bound the flush wait so carrier cleanup
		// cannot stall on a peer that is already unreachable.
		connectionDone := make(chan error, 1)
		go func() { connectionDone <- s.Connection.CloseWithError(0, "") }()
		var connectionErr error
		select {
		case connectionErr = <-connectionDone:
		case <-time.After(250 * time.Millisecond):
			// Transport.Close below forcefully completes the QUIC connection;
			// timeout here is an expected bounded-cleanup outcome, not an
			// application failure.
			connectionErr = nil
		}
		if s.transport != nil {
			transportErr = s.transport.Close()
			packetErr = s.transport.Conn.Close()
		}
		s.closeErr = errors.Join(connectionErr, packetErr, transportErr)
	})
	return s.closeErr
}

func (s *Session) PTOCount() uint32 {
	if s == nil || s.pto == nil {
		return 0
	}
	return s.pto.total.Load()
}

// PTOChanged reports RFC 9002 probe-timeout progress without polling. The
// notification is edge-triggered; PTOCount is the authoritative total.
func (s *Session) PTOChanged() <-chan struct{} {
	if s == nil || s.pto == nil {
		return nil
	}
	return s.pto.changed
}

type ptoTrace struct {
	current atomic.Uint32
	total   atomic.Uint32
	changed chan struct{}
}

func newPTOTrace() *ptoTrace { return &ptoTrace{changed: make(chan struct{}, 1)} }

func (*ptoTrace) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }
func (t *ptoTrace) AddProducer() qlogwriter.Recorder { return (*ptoRecorder)(t) }

type ptoRecorder ptoTrace

func (r *ptoRecorder) RecordEvent(event qlogwriter.Event) {
	updated, ok := event.(qlog.PTOCountUpdated)
	if !ok {
		if pointer, pointerOK := event.(*qlog.PTOCountUpdated); pointerOK {
			updated, ok = *pointer, true
		}
	}
	if !ok {
		return
	}
	previous := r.current.Swap(updated.PTOCount)
	if updated.PTOCount > previous {
		r.total.Add(updated.PTOCount - previous)
		if r.changed != nil {
			select {
			case r.changed <- struct{}{}:
			default:
			}
		}
	}
}

func (*ptoRecorder) Close() error { return nil }

func config(class Class) *quic.Config {
	return quicConfig(DevelopmentSessionConfig(class))
}

func quicConfig(sessionConfig SessionConfig) *quic.Config {
	maximumStreams := int64(64)
	maximumUniStreams := int64(-1)
	switch sessionConfig.Class {
	case ClassPreview:
		maximumStreams = 128
		// HTTP/3 owns control and QPACK unidirectional streams after
		// authenticated preview admission.
		maximumUniStreams = 16
	case ClassTransfer:
		maximumStreams = 16
	case ClassInteractive:
	default:
		maximumStreams = -1
	}
	return &quic.Config{
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 sessionConfig.MaxIdleTimeout,
		KeepAlivePeriod:                sessionConfig.KeepAlivePeriod,
		InitialPacketSize:              sessionConfig.InitialPacketSize,
		DisablePathMTUDiscovery:        false,
		MaxIncomingStreams:             maximumStreams,
		MaxIncomingUniStreams:          maximumUniStreams,
		Allow0RTT:                      false,
		EnableDatagrams:                false,
		InitialStreamReceiveWindow:     256 << 10,
		MaxStreamReceiveWindow:         4 << 20,
		InitialConnectionReceiveWindow: 512 << 10,
		MaxConnectionReceiveWindow:     16 << 20,
	}
}

func validClass(class Class) bool {
	return class == ClassInteractive || class == ClassPreview || class == ClassTransfer
}

func validateClientTLS(config *tls.Config) error {
	if err := validateCommonTLS(config); err != nil {
		return err
	}
	if !config.InsecureSkipVerify || config.VerifyConnection == nil || config.RootCAs != nil || len(config.Certificates) != 1 {
		return errors.New("peer QUIC client requires endpoint-certificate verification")
	}
	return nil
}

func validateServerTLS(config *tls.Config) error {
	if err := validateCommonTLS(config); err != nil {
		return err
	}
	if !config.InsecureSkipVerify || config.VerifyConnection == nil || len(config.Certificates) != 1 || config.ClientCAs != nil || config.ClientAuth != tls.RequireAnyClientCert {
		return errors.New("peer QUIC server requires endpoint-certificate verification")
	}
	return nil
}

func validateCommonTLS(config *tls.Config) error {
	if config == nil || config.MinVersion != tls.VersionTLS13 || config.MaxVersion != 0 && config.MaxVersion != tls.VersionTLS13 {
		return errors.New("peer QUIC requires TLS 1.3")
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != ALPN {
		return errors.New("peer QUIC requires the Paperboat v1 ALPN")
	}
	return nil
}
