package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
)

// DataCarrierALPN identifies the authenticated connector-v1 carrier
// handshake. TLS verification remains the caller's trust boundary; this
// package rejects an unverified or non-mutual configuration before dialing.
const DataCarrierALPN = "paperboat.connector.v1"

// DataCarrierPeerBinding maps the verified peer certificate to the exact
// connector-v1 control-session identity expected by the caller. A trusted
// certificate alone is not authorization to claim another host, tunnel, or
// generation.
type DataCarrierPeerBinding func(tls.ConnectionState) (DataCarrierIdentity, error)

var (
	ErrInvalidDataCarrierEndpoint = errors.New("invalid data carrier endpoint configuration")
	ErrDataCarrierTLS             = errors.New("data carrier TLS authentication failed")
)

// DataCarrierEndpointConfig describes one real network endpoint. A TLS
// configuration is required for both transports and must authenticate both
// peers. The caller may use RootCAs/ClientCAs or a custom VerifyConnection
// policy such as the endpointidentity package.
type DataCarrierEndpointConfig struct {
	Address          string
	TLS              *tls.Config
	PeerBinding      DataCarrierPeerBinding
	ExpectedIdentity DataCarrierIdentity
}

func (c DataCarrierEndpointConfig) validateClient() error {
	if strings.TrimSpace(c.Address) == "" || c.TLS == nil || c.PeerBinding == nil {
		return ErrInvalidDataCarrierEndpoint
	}
	if err := validateTLSConfig(c.TLS, false); err != nil {
		return err
	}
	if c.ExpectedIdentity != (DataCarrierIdentity{}) {
		if err := c.ExpectedIdentity.validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateTLSConfig(base *tls.Config, server bool) error {
	if base == nil {
		return ErrInvalidDataCarrierEndpoint
	}
	config := base.Clone()
	if config.MinVersion != 0 && config.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("%w: TLS 1.3 or newer is required", ErrDataCarrierTLS)
	}
	if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return fmt.Errorf("%w: TLS 1.3 is required", ErrDataCarrierTLS)
	}
	if server {
		if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
			return fmt.Errorf("%w: server certificate is required", ErrDataCarrierTLS)
		}
		if config.ClientAuth < tls.RequireAnyClientCert || config.ClientAuth == tls.VerifyClientCertIfGiven {
			return fmt.Errorf("%w: mutual client authentication is required", ErrDataCarrierTLS)
		}
		if config.ClientAuth != tls.RequireAndVerifyClientCert && config.VerifyConnection == nil && config.VerifyPeerCertificate == nil {
			return fmt.Errorf("%w: client certificate verification is required", ErrDataCarrierTLS)
		}
		return nil
	}
	if len(config.Certificates) == 0 && config.GetClientCertificate == nil {
		return fmt.Errorf("%w: client certificate is required", ErrDataCarrierTLS)
	}
	if config.InsecureSkipVerify && config.VerifyConnection == nil && config.VerifyPeerCertificate == nil {
		return fmt.Errorf("%w: insecure server verification is not allowed", ErrDataCarrierTLS)
	}
	return nil
}

func clientTLSConfig(base *tls.Config, address string) (*tls.Config, error) {
	if err := validateTLSConfig(base, false); err != nil {
		return nil, err
	}
	config := base.Clone()
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS13
	}
	if config.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			config.ServerName = host
		} else {
			config.ServerName = address
		}
	}
	config.NextProtos = appendALPN(config.NextProtos)
	return config, nil
}

func appendALPN(protocols []string) []string {
	_ = protocols
	return []string{DataCarrierALPN}
}

func bindPeer(endpoint DataCarrierEndpointConfig, state tls.ConnectionState) (DataCarrierIdentity, error) {
	if endpoint.PeerBinding == nil {
		return DataCarrierIdentity{}, fmt.Errorf("%w: peer binding is required", ErrDataCarrierTLS)
	}
	identity, err := endpoint.PeerBinding(state)
	if err != nil {
		return DataCarrierIdentity{}, fmt.Errorf("%w: peer binding rejected: %v", ErrDataCarrierTLS, err)
	}
	if err := identity.validate(); err != nil {
		return DataCarrierIdentity{}, fmt.Errorf("%w: peer binding returned invalid identity", ErrDataCarrierTLS)
	}
	if endpoint.ExpectedIdentity != (DataCarrierIdentity{}) && identity != endpoint.ExpectedIdentity {
		return DataCarrierIdentity{}, fmt.Errorf("%w: peer identity does not match expected session", ErrDataCarrierTLS)
	}
	return identity, nil
}

// DialTCPMux establishes a mutually authenticated TLS TCP carrier. The
// returned link is ready for NewDataCarrierClient and therefore uses one
// yamux session for independently opened data streams.
func DialTCPMux(ctx context.Context, endpoint DataCarrierEndpointConfig) (io.ReadWriteCloser, error) {
	connection, _, err := dialTCPMux(ctx, endpoint)
	return connection, err
}

func dialTCPMux(ctx context.Context, endpoint DataCarrierEndpointConfig) (io.ReadWriteCloser, DataCarrierIdentity, error) {
	if ctx == nil {
		return nil, DataCarrierIdentity{}, ErrInvalidDataCarrierEndpoint
	}
	if err := endpoint.validateClient(); err != nil {
		return nil, DataCarrierIdentity{}, err
	}
	tlsConfig, err := clientTLSConfig(endpoint.TLS, endpoint.Address)
	if err != nil {
		return nil, DataCarrierIdentity{}, err
	}
	dialer := tls.Dialer{Config: tlsConfig}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, DataCarrierIdentity{}, fmt.Errorf("%w: TCP carrier dial: %w", ErrDataCarrierTLS, err)
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		_ = connection.Close()
		return nil, DataCarrierIdentity{}, fmt.Errorf("%w: TCP dial did not return TLS", ErrDataCarrierTLS)
	}
	state := tlsConnection.ConnectionState()
	if state.NegotiatedProtocol != DataCarrierALPN {
		_ = connection.Close()
		return nil, DataCarrierIdentity{}, fmt.Errorf("%w: negotiated ALPN %q", ErrDataCarrierTLS, state.NegotiatedProtocol)
	}
	identity, err := bindPeer(endpoint, state)
	if err != nil {
		_ = connection.Close()
		return nil, DataCarrierIdentity{}, err
	}
	return connection, identity, nil
}

// DialQUIC establishes a mutually authenticated QUIC connection. Each
// DataCarrierSession stream operation maps directly to an independent native
// QUIC bidirectional stream, so unrelated requests do not share a byte-level
// head-of-line queue.
func DialQUIC(ctx context.Context, endpoint DataCarrierEndpointConfig) (DataCarrierSession, error) {
	session, _, err := dialQUIC(ctx, endpoint)
	return session, err
}

func dialQUIC(ctx context.Context, endpoint DataCarrierEndpointConfig) (DataCarrierSession, DataCarrierIdentity, error) {
	if ctx == nil {
		return nil, DataCarrierIdentity{}, ErrInvalidDataCarrierEndpoint
	}
	if err := endpoint.validateClient(); err != nil {
		return nil, DataCarrierIdentity{}, err
	}
	tlsConfig, err := clientTLSConfig(endpoint.TLS, endpoint.Address)
	if err != nil {
		return nil, DataCarrierIdentity{}, err
	}
	connection, err := quic.DialAddr(ctx, endpoint.Address, tlsConfig, defaultQUICConfig())
	if err != nil {
		return nil, DataCarrierIdentity{}, fmt.Errorf("%w: QUIC carrier dial: %w", ErrDataCarrierTLS, err)
	}
	state := connection.ConnectionState().TLS
	if state.NegotiatedProtocol != DataCarrierALPN {
		_ = connection.CloseWithError(0, "invalid carrier ALPN")
		return nil, DataCarrierIdentity{}, fmt.Errorf("%w: negotiated ALPN %q", ErrDataCarrierTLS, state.NegotiatedProtocol)
	}
	identity, err := bindPeer(endpoint, state)
	if err != nil {
		_ = connection.CloseWithError(0, "peer binding rejected")
		return nil, DataCarrierIdentity{}, err
	}
	return newQUICDataCarrierSession(connection), identity, nil
}

// NewTCPMuxDialer adapts DialTCPMux to the pool's slot/attempt-bound dialer.
func NewTCPMuxDialer(endpoint DataCarrierEndpointConfig) DataCarrierDialer {
	return func(ctx context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		if request.Transport != TCPMux {
			return DataCarrierDialResult{}, &TransportDialError{Transport: request.Transport, Err: ErrInvalidDataCarrierEndpoint, Fallback: false}
		}
		link, peerIdentity, err := dialTCPMux(ctx, endpoint)
		if err != nil {
			return DataCarrierDialResult{}, newTransportDialError(TCPMux, err)
		}
		if request.Identity != (DataCarrierIdentity{}) && peerIdentity != request.Identity {
			_ = link.Close()
			return DataCarrierDialResult{}, &TransportDialError{Transport: TCPMux, Err: ErrDataCarrierAdmission, Fallback: false}
		}
		return DataCarrierDialResult{Link: link, PeerIdentity: peerIdentity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
}

// NewQUICDialer adapts DialQUIC to the pool's slot/attempt-bound dialer.
func NewQUICDialer(endpoint DataCarrierEndpointConfig) DataCarrierDialer {
	return func(ctx context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		if request.Transport != QUIC {
			return DataCarrierDialResult{}, &TransportDialError{Transport: request.Transport, Err: ErrInvalidDataCarrierEndpoint, Fallback: false}
		}
		session, peerIdentity, err := dialQUIC(ctx, endpoint)
		if err != nil {
			return DataCarrierDialResult{}, newTransportDialError(QUIC, err)
		}
		if request.Identity != (DataCarrierIdentity{}) && peerIdentity != request.Identity {
			_ = session.Close()
			return DataCarrierDialResult{}, &TransportDialError{Transport: QUIC, Err: ErrDataCarrierAdmission, Fallback: true}
		}
		return DataCarrierDialResult{Session: session, PeerIdentity: peerIdentity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
}

// NetworkDialerConfig configures the two supported pool transports.
//
// NewNetworkDialer routes the two supported pool transports to their real
// endpoint. It intentionally has no TCP-dedicated or implicit transport path.
type NetworkDialerConfig struct {
	TCPMux DataCarrierEndpointConfig
	QUIC   DataCarrierEndpointConfig
}

func NewNetworkDialer(config NetworkDialerConfig) DataCarrierDialer {
	return func(ctx context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		var (
			link    io.ReadWriteCloser
			session DataCarrierSession
			err     error
		)
		switch request.Transport {
		case TCPMux:
			var peerIdentity DataCarrierIdentity
			link, peerIdentity, err = dialTCPMux(ctx, config.TCPMux)
			if err == nil {
				if request.Identity != (DataCarrierIdentity{}) && peerIdentity != request.Identity {
					_ = link.Close()
					return DataCarrierDialResult{}, newTransportDialError(TCPMux, ErrDataCarrierAdmission)
				}
				return DataCarrierDialResult{Link: link, PeerIdentity: peerIdentity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
			}
		case QUIC:
			var peerIdentity DataCarrierIdentity
			session, peerIdentity, err = dialQUIC(ctx, config.QUIC)
			if err == nil {
				if request.Identity != (DataCarrierIdentity{}) && peerIdentity != request.Identity {
					_ = session.Close()
					return DataCarrierDialResult{}, newTransportDialError(QUIC, ErrDataCarrierAdmission)
				}
				return DataCarrierDialResult{Session: session, PeerIdentity: peerIdentity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
			}
		default:
			err = ErrInvalidDataCarrierEndpoint
		}
		if err != nil {
			return DataCarrierDialResult{}, newTransportDialError(request.Transport, err)
		}
		return DataCarrierDialResult{}, ErrInvalidDataCarrierEndpoint
	}
}

func newTransportDialError(transport Transport, err error) *TransportDialError {
	return &TransportDialError{Transport: transport, Err: err, Fallback: dataCarrierDialFallbackEligible(err)}
}

// dataCarrierDialFallbackEligible classifies only failures that are safe to
// retry on the other transport.  Authentication, admission, endpoint, and
// protocol errors are terminal even when their text mentions a network
// operation.  A context deadline is also terminal because the caller's
// overall operation has expired.
func dataCarrierDialFallbackEligible(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrInvalidDataCarrierEndpoint) || errors.Is(err, ErrDataCarrierAdmission) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func defaultQUICConfig() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 30 * time.Second, MaxIncomingStreams: 16, MaxIncomingUniStreams: 0}
}

type quicDataCarrierSession struct {
	connection *quic.Conn
	done       chan struct{}
	once       sync.Once
	err        error
}

func newQUICDataCarrierSession(connection *quic.Conn) DataCarrierSession {
	return &quicDataCarrierSession{connection: connection, done: make(chan struct{})}
}

func (s *quicDataCarrierSession) OpenStream(ctx context.Context) (DataCarrierStreamLink, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierEndpoint
	}
	stream, err := s.connection.OpenStreamSync(ctx)
	if err != nil {
		if s.closed() {
			return nil, ErrDataCarrierClosed
		}
		return nil, err
	}
	return stream, nil
}

func (s *quicDataCarrierSession) AcceptStream(ctx context.Context) (DataCarrierStreamLink, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierEndpoint
	}
	stream, err := s.connection.AcceptStream(ctx)
	if err != nil {
		if s.closed() {
			return nil, ErrDataCarrierClosed
		}
		return nil, err
	}
	return stream, nil
}

func (s *quicDataCarrierSession) Ping(ctx context.Context) error {
	if s == nil || s.connection == nil || ctx == nil {
		return ErrInvalidDataCarrierEndpoint
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrDataCarrierClosed
	case <-s.connection.HandshakeComplete():
		return nil
	case <-s.connection.Context().Done():
		return ErrDataCarrierClosed
	}
}

func (s *quicDataCarrierSession) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.done)
		if s.connection != nil {
			s.err = s.connection.CloseWithError(0, "carrier closed")
		}
	})
	return s.err
}

func (s *quicDataCarrierSession) CloseChan() <-chan struct{} {
	if s == nil {
		return closedDataCarrierChannel()
	}
	return s.done
}

func (s *quicDataCarrierSession) closed() bool {
	if s == nil || s.done == nil {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
