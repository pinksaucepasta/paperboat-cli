package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const publicPreviewRelayPath = "/v1/public-preview-relay"

var publicPreviewRelayPreface = [...]byte{'P', 'B', 'P', 'R', 1}

const publicPreviewStartupMarker byte = 0

type PublicPreviewProtocol string

const (
	PublicPreviewHTTP3 PublicPreviewProtocol = "http3"
	PublicPreviewHTTP2 PublicPreviewProtocol = "http2"
)

type PublicPreviewTransportError struct {
	Protocol PublicPreviewProtocol
	Cause    error
}

func (e *PublicPreviewTransportError) Error() string {
	return fmt.Sprintf("public preview relay %s: %v", e.Protocol, e.Cause)
}
func (e *PublicPreviewTransportError) Unwrap() error { return e.Cause }

type PublicPreviewDialerConfig struct {
	HTTP3       http.RoundTripper
	HTTP2       http.RoundTripper
	DialTimeout time.Duration
}

type PublicPreviewDialer struct{ config PublicPreviewDialerConfig }

func NewPublicPreviewDialer(config PublicPreviewDialerConfig) (*PublicPreviewDialer, error) {
	if config.DialTimeout == 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.DialTimeout <= 0 {
		return nil, ErrAdmissionInvalid
	}
	if config.HTTP3 == nil {
		config.HTTP3 = &http3.Transport{
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(32)},
			QUICConfig:             &quic.Config{HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second, DisablePathMTUDiscovery: true, InitialPacketSize: 1200},
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 << 10,
		}
	}
	if config.HTTP2 == nil {
		config.HTTP2 = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(32)}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	}
	return &PublicPreviewDialer{config: config}, nil
}

func (d *PublicPreviewDialer) Dial(ctx context.Context, _ Transport, value Admission) (Connection, error) {
	if ctx == nil || !validRelayHTTPEndpoint(value.RelayHTTPEndpoint) || len(value.Routes) != 1 || value.Routes[0].Kind != "preview_public_https_wss" || value.Routes[0].LocalTarget.Host != "127.0.0.1" && value.Routes[0].LocalTarget.Host != "::1" || value.Routes[0].LocalTarget.Port == 0 {
		return nil, ErrAdmissionInvalid
	}
	stream, protocol, err := d.attach(ctx, value, PublicPreviewHTTP3, d.config.HTTP3)
	if err != nil {
		if !publicPreviewFallbackEligible(err) {
			return nil, err
		}
		slog.Warn("public preview HTTP/3 unavailable; using HTTP/2", "error", err)
		stream, protocol, err = d.attach(ctx, value, PublicPreviewHTTP2, d.config.HTTP2)
		if err != nil {
			return nil, err
		}
	}
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 10 * time.Second
	config.ConnectionWriteTimeout = 10 * time.Second
	mux, err := yamux.Client(stream, config)
	if err != nil {
		_ = stream.Close()
		return nil, &PublicPreviewTransportError{Protocol: protocol, Cause: err}
	}
	connection := &publicPreviewConnection{stream: stream, mux: mux, target: net.JoinHostPort(value.Routes[0].LocalTarget.Host, strconv.Itoa(int(value.Routes[0].LocalTarget.Port))), protocol: protocol, done: make(chan error, 1), closed: make(chan struct{})}
	go connection.serve()
	return connection, nil
}

func (d *PublicPreviewDialer) attach(ctx context.Context, value Admission, protocol PublicPreviewProtocol, transport http.RoundTripper) (io.ReadWriteCloser, PublicPreviewProtocol, error) {
	payload, err := publicPreviewAdmission(value)
	if err != nil {
		return nil, protocol, err
	}
	reader, writer := io.Pipe()
	startup := append(append([]byte(nil), publicPreviewRelayPreface[:]...), publicPreviewStartupMarker)
	requestBody := io.MultiReader(bytes.NewReader(startup), reader)
	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	endpoint, _ := url.Parse(value.RelayHTTPEndpoint)
	endpoint.Path = publicPreviewRelayPath
	request, _ := http.NewRequestWithContext(carrierCtx, http.MethodPost, endpoint.String(), requestBody)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Paperboat-Relay-Carrier", string(map[PublicPreviewProtocol]string{PublicPreviewHTTP3: "HTTP/3.0", PublicPreviewHTTP2: "HTTP/2.0"}[protocol]))
	request.Header.Set("X-Paperboat-Connector-Admission", base64.RawURLEncoding.EncodeToString(payload))
	type roundTripResult struct {
		response *http.Response
		err      error
	}
	results := make(chan roundTripResult, 1)
	go func() {
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAdmissionInvalid }}
		response, roundTripErr := client.Do(request)
		results <- roundTripResult{response, roundTripErr}
	}()
	timer := time.NewTimer(d.config.DialTimeout)
	defer timer.Stop()
	var response *http.Response
	select {
	case result := <-results:
		response, err = result.response, result.err
	case <-ctx.Done():
		cancelCarrier()
		_ = writer.CloseWithError(ctx.Err())
		return nil, protocol, &PublicPreviewTransportError{Protocol: protocol, Cause: ctx.Err()}
	case <-timer.C:
		cancelCarrier()
		_ = writer.CloseWithError(context.DeadlineExceeded)
		return nil, protocol, &PublicPreviewTransportError{Protocol: protocol, Cause: context.DeadlineExceeded}
	}
	if err != nil {
		cancelCarrier()
		_ = writer.CloseWithError(err)
		return nil, protocol, &PublicPreviewTransportError{Protocol: protocol, Cause: err}
	}
	if response == nil {
		err = errors.New("public preview relay returned no response")
		cancelCarrier()
		_ = writer.CloseWithError(err)
		return nil, protocol, &PublicPreviewTransportError{Protocol: protocol, Cause: err}
	}
	if response.StatusCode != http.StatusOK {
		cancelCarrier()
		_ = response.Body.Close()
		_ = writer.CloseWithError(ErrAdmissionInvalid)
		return nil, protocol, errors.Join(ErrAdmissionInvalid, fmt.Errorf("public preview relay status %d", response.StatusCode))
	}
	return &publicPreviewHTTPStream{reader: response.Body, writer: writer, cancel: cancelCarrier}, protocol, nil
}

func publicPreviewAdmission(value Admission) ([]byte, error) {
	document := struct {
		OperationID string         `json:"operation_id"`
		Credential  string         `json:"credential"`
		Environment string         `json:"environment_id"`
		Machine     string         `json:"machine_id"`
		Connector   string         `json:"connector_id"`
		Generation  uint64         `json:"connector_generation"`
		EdgePool    string         `json:"edge_pool"`
		EdgeNode    string         `json:"edge_node_id"`
		Routes      []RouteHandoff `json:"routes"`
	}{value.OperationID, value.Credential, value.EnvironmentID, value.MachineID, value.ConnectorID, value.Generation, value.EdgePool, value.EdgeNodeID, value.Routes}
	payload, err := json.Marshal(document)
	if err != nil || len(payload) > 64<<10 {
		return nil, errors.Join(ErrAdmissionInvalid, err)
	}
	return payload, nil
}

func publicPreviewFallbackEligible(err error) bool {
	var transportErr *PublicPreviewTransportError
	if !errors.As(err, &transportErr) || transportErr.Protocol != PublicPreviewHTTP3 || errors.Is(transportErr.Cause, context.Canceled) {
		return false
	}
	var networkError net.Error
	return errors.As(transportErr.Cause, &networkError) || errors.Is(transportErr.Cause, os.ErrDeadlineExceeded)
}

type publicPreviewHTTPStream struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
}

func (s *publicPreviewHTTPStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *publicPreviewHTTPStream) Write(p []byte) (int, error) { return s.writer.Write(p) }
func (s *publicPreviewHTTPStream) Close() error {
	var err error
	s.once.Do(func() { s.cancel(); err = errors.Join(s.writer.Close(), s.reader.Close()) })
	return err
}

type publicPreviewConnection struct {
	stream   io.ReadWriteCloser
	mux      *yamux.Session
	target   string
	protocol PublicPreviewProtocol
	done     chan error
	closed   chan struct{}
	once     sync.Once
}

func (c *publicPreviewConnection) serve() {
	var result error
	defer func() { c.done <- result; close(c.done) }()
	for {
		stream, err := c.mux.AcceptStream()
		if err != nil {
			result = err
			return
		}
		go c.forward(stream)
	}
}

func (c *publicPreviewConnection) forward(stream net.Conn) {
	target, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", c.target)
	if err != nil {
		_ = stream.Close()
		return
	}
	copyBidirectional(stream, target)
}

func copyBidirectional(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyOne(left, right)
	go copyOne(right, left)
	wg.Wait()
	_ = left.Close()
	_ = right.Close()
}

func (c *publicPreviewConnection) Retire() error                   { return c.Close() }
func (c *publicPreviewConnection) Drain(ctx context.Context) error { return c.Close() }
func (c *publicPreviewConnection) Close() error {
	c.once.Do(func() { close(c.closed); _ = c.mux.Close(); _ = c.stream.Close() })
	return nil
}
func (c *publicPreviewConnection) Done() <-chan error { return c.done }
func (c *publicPreviewConnection) SelectedTransport() Transport {
	if c.protocol == PublicPreviewHTTP3 {
		return QUIC
	}
	return TCPMux
}
