package relaycarrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const relayQUICCloseGrace = time.Second

var relayQUICRequestPreface = [...]byte{'P', 'B', 'R', 'Q', 1}

type QUICDialConfig struct {
	URL               string
	Credential        string
	EndpointID        string
	Role              string
	StreamHandle      [16]byte
	TLS               *tls.Config
	HTTPClient        *http.Client
	Lifetime          context.Context
	MaximumDeadline   time.Duration
	Carrier           Config
	InitialPacketSize uint16
}

// DialQUIC creates a relay carrier whose logical streams are independent
// full-duplex HTTP/3 requests admitted by their Noise stream handle.
func DialQUIC(ctx context.Context, config QUICDialConfig) (*Connection, error) {
	parsed, err := url.Parse(config.URL)
	if config.InitialPacketSize == 0 {
		config.InitialPacketSize = 1200
	}
	if ctx == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "/v1/peer-relay" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !compactCredential(config.Credential) || !boundedAttachmentID(config.EndpointID) || config.Role != "initiator" && config.Role != "responder" || allZeroHandle(config.StreamHandle) || config.TLS == nil || config.TLS.MinVersion < tls.VersionTLS13 || config.MaximumDeadline <= 0 || config.MaximumDeadline > 24*time.Hour || config.InitialPacketSize < 1200 || config.InitialPacketSize > 1500 || !config.Carrier.valid() {
		return nil, ErrInvalid
	}
	lifetime := config.Lifetime
	if lifetime == nil {
		lifetime = context.Background()
	}
	ownerCtx, cancel := context.WithCancel(lifetime)
	client := config.HTTPClient
	var closeTransport func() error
	if client == nil {
		transport := &http3.Transport{
			TLSClientConfig: config.TLS.Clone(),
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout:    10 * time.Second,
				MaxIdleTimeout:          config.MaximumDeadline,
				KeepAlivePeriod:         15 * time.Second,
				DisablePathMTUDiscovery: true,
				InitialPacketSize:       config.InitialPacketSize,
			},
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 << 10,
		}
		client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
		closeTransport = transport.Close
	}
	attachment := &relayQUICMux{ctx: ownerCtx, cancel: cancel, client: client, url: config.URL, credential: config.Credential, endpointID: config.EndpointID, role: config.Role, closeTransport: closeTransport}
	// The relay attachment is a persistent full-duplex HTTP/3 request. Setup
	// cancellation must abort dialing, but once admitted the request belongs to
	// the carrier lifetime rather than the path race that created it.
	openCtx, cancelOpen := context.WithCancel(ownerCtx)
	stopSetupCancel := context.AfterFunc(ctx, cancelOpen)
	base, err := attachment.open(openCtx, config.StreamHandle)
	if !stopSetupCancel() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		cancelOpen()
		_ = attachment.Close()
		return nil, err
	}
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.LogOutput = io.Discard
	yamuxConfig.AcceptBacklog = config.Carrier.AcceptBacklog
	yamuxConfig.EnableKeepAlive = false
	yamuxConfig.ConnectionWriteTimeout = config.Carrier.ConnectionWriteLimit
	yamuxConfig.MaxStreamWindowSize = config.Carrier.StreamWindow
	yamuxConfig.StreamOpenTimeout = config.Carrier.StreamOpenLimit
	yamuxConfig.StreamCloseTimeout = config.Carrier.StreamCloseLimit
	var session *yamux.Session
	if config.Role == "initiator" {
		session, err = yamux.Client(base, yamuxConfig)
	} else {
		session, err = yamux.Server(base, yamuxConfig)
	}
	if err != nil {
		_ = base.Close()
		_ = attachment.Close()
		return nil, err
	}
	connection := newConnection(&relayQUICPersistentMux{yamuxMux: yamuxMux{session: session}, attachment: attachment}, config.Carrier)
	connection.carrier = relaynoise.CarrierRelayQUIC
	return connection, nil
}

type relayQUICPersistentMux struct {
	yamuxMux
	attachment *relayQUICMux
}

func (m *relayQUICPersistentMux) Close() error {
	if m == nil {
		return nil
	}
	return errors.Join(m.yamuxMux.Close(), m.attachment.Close())
}

type relayQUICMux struct {
	ctx            context.Context
	cancel         context.CancelFunc
	client         *http.Client
	url            string
	credential     string
	endpointID     string
	role           string
	closeTransport func() error
	once           sync.Once
	err            error
}

type relayQUICOutcome struct {
	response *http.Response
	err      error
}

func (m *relayQUICMux) Open(context.Context) (io.ReadWriteCloser, error) {
	return nil, ErrInvalid
}

func (m *relayQUICMux) Accept(context.Context) (io.ReadWriteCloser, error) {
	return nil, ErrInvalid
}

func (m *relayQUICMux) OpenHandle(ctx context.Context, handle [16]byte) (io.ReadWriteCloser, error) {
	return m.open(ctx, handle)
}

func (m *relayQUICMux) AcceptHandle(ctx context.Context, handle [16]byte) (io.ReadWriteCloser, error) {
	return m.open(ctx, handle)
}

func (m *relayQUICMux) open(ctx context.Context, handle [16]byte) (io.ReadWriteCloser, error) {
	if m == nil || ctx == nil || allZeroHandle(handle) {
		return nil, ErrInvalid
	}
	streamCtx, cancel := context.WithCancel(m.ctx)
	reader, writer := io.Pipe()
	requestBody := io.MultiReader(bytes.NewReader(relayQUICRequestPreface[:]), reader)
	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, m.url, requestBody)
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+m.credential)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Paperboat-Relay-Carrier", "HTTP/3.0")
	request.Header.Set("X-Paperboat-Stream-Handle", base64.RawURLEncoding.EncodeToString(handle[:]))
	request.Header.Set("X-Paperboat-Endpoint-Id", m.endpointID)
	request.Header.Set("X-Paperboat-Relay-Role", m.role)
	result := make(chan relayQUICOutcome, 1)
	go func() {
		response, requestErr := m.client.Do(request)
		result <- relayQUICOutcome{response: response, err: requestErr}
	}()
	stop := context.AfterFunc(ctx, cancel)
	body := &pendingRelayQUICBody{result: result, cancel: cancel, stop: stop}
	return &relayQUICStream{reader: body, writer: writer, cancel: cancel}, nil
}

type pendingRelayQUICBody struct {
	result <-chan relayQUICOutcome
	cancel context.CancelFunc
	stop   func() bool
	once   sync.Once
	body   io.ReadCloser
	err    error
}

func (b *pendingRelayQUICBody) Read(target []byte) (int, error) {
	b.once.Do(func() {
		value := <-b.result
		if b.stop != nil {
			b.stop()
		}
		b.body, b.err = value.responseBody()
	})
	if b.err != nil {
		return 0, b.err
	}
	return b.body.Read(target)
}

func (b *pendingRelayQUICBody) Close() error {
	if b == nil {
		return nil
	}
	b.cancel()
	b.once.Do(func() {
		value := <-b.result
		if b.stop != nil {
			b.stop()
		}
		b.body, b.err = value.responseBody()
	})
	if b.body != nil {
		return b.body.Close()
	}
	return b.err
}

func (o relayQUICOutcome) responseBody() (io.ReadCloser, error) {
	if o.err == nil && o.response != nil && o.response.StatusCode == http.StatusOK && o.response.ProtoMajor == 3 {
		return o.response.Body, nil
	}
	if o.response != nil && o.response.Body != nil {
		_ = o.response.Body.Close()
	}
	if o.err != nil {
		return nil, o.err
	}
	class := connectionmanager.FailureProtocol
	if o.response != nil {
		switch o.response.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			class = connectionmanager.FailureTransient
		case http.StatusUnauthorized, http.StatusForbidden:
			class = connectionmanager.FailureAuthentication
		}
	}
	return nil, &connectionmanager.Failure{Class: class, Path: connectionmanager.PathRelayQUIC, Cause: ErrInvalid}
}

func (m *relayQUICMux) Close() error {
	if m == nil {
		return nil
	}
	m.once.Do(func() {
		m.cancel()
		if m.closeTransport != nil {
			m.err = m.closeTransport()
		}
	})
	return m.err
}

type relayQUICStream struct {
	reader        io.ReadCloser
	writer        *io.PipeWriter
	cancel        context.CancelFunc
	once          sync.Once
	err           error
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
	writeTimer    *time.Timer
	readActive    bool
	writeActive   bool
	readTimedOut  bool
	writeTimedOut bool
}

func (s *relayQUICStream) Read(target []byte) (int, error) {
	s.beginDeadlineOperation(true)
	read, err := s.reader.Read(target)
	return read, s.finishDeadlineOperation(true, err)
}

func (s *relayQUICStream) Write(value []byte) (int, error) {
	s.beginDeadlineOperation(false)
	written, err := s.writer.Write(value)
	return written, s.finishDeadlineOperation(false, err)
}

func (s *relayQUICStream) SetReadDeadline(deadline time.Time) error {
	s.setDeadline(true, deadline)
	return nil
}

func (s *relayQUICStream) SetWriteDeadline(deadline time.Time) error {
	s.setDeadline(false, deadline)
	return nil
}

func (s *relayQUICStream) setDeadline(read bool, deadline time.Time) {
	s.deadlineMu.Lock()
	deadlineTarget, timer, active := &s.writeDeadline, &s.writeTimer, s.writeActive
	if read {
		deadlineTarget, timer, active = &s.readDeadline, &s.readTimer, s.readActive
	}
	*deadlineTarget = deadline
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if active && !deadline.IsZero() {
		*timer = time.AfterFunc(time.Until(deadline), func() { s.expireDeadline(read) })
	}
	s.deadlineMu.Unlock()
}

func (s *relayQUICStream) beginDeadlineOperation(read bool) {
	s.deadlineMu.Lock()
	deadline, timer := s.writeDeadline, &s.writeTimer
	if read {
		deadline, timer = s.readDeadline, &s.readTimer
		s.readActive, s.readTimedOut = true, false
	} else {
		s.writeActive, s.writeTimedOut = true, false
	}
	if !deadline.IsZero() {
		*timer = time.AfterFunc(time.Until(deadline), func() { s.expireDeadline(read) })
	}
	s.deadlineMu.Unlock()
}

func (s *relayQUICStream) expireDeadline(read bool) {
	s.deadlineMu.Lock()
	active := s.writeActive
	if read {
		active = s.readActive
		s.readTimedOut = active
	} else {
		s.writeTimedOut = active
	}
	s.deadlineMu.Unlock()
	if active {
		s.cancel()
	}
}

func (s *relayQUICStream) finishDeadlineOperation(read bool, err error) error {
	s.deadlineMu.Lock()
	timer, timedOut := &s.writeTimer, s.writeTimedOut
	if read {
		timer, timedOut = &s.readTimer, s.readTimedOut
		s.readActive = false
	} else {
		s.writeActive = false
	}
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	s.deadlineMu.Unlock()
	if timedOut {
		return errors.Join(os.ErrDeadlineExceeded, err)
	}
	return err
}

func (s *relayQUICStream) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		// Closing the request body sends FIN. Drain the response through its FIN
		// before canceling so already-written peer bytes are not reset. A bounded
		// grace still prevents pool retirement from hanging on an abandoned peer.
		writerErr := s.writer.Close()
		cancelTimer := time.AfterFunc(relayQUICCloseGrace, s.cancel)
		_, drainErr := io.Copy(io.Discard, s.reader)
		cancelTimer.Stop()
		s.cancel()
		s.err = errors.Join(writerErr, drainErr, s.reader.Close())
	})
	return s.err
}
