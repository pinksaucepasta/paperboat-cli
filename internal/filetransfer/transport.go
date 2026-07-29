package filetransfer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Transport string

const (
	TransportH3 Transport = "h3"
	TransportH2 Transport = "h2"
)

type TransportError struct {
	Transport Transport
	Cause     error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("file transfer %s transport: %v", e.Transport, e.Cause)
}
func (e *TransportError) Unwrap() error { return e.Cause }

type TransportSelectorConfig struct {
	H3           http.RoundTripper
	H2           http.RoundTripper
	Stagger      time.Duration
	Cooldown     time.Duration
	ProbeTimeout time.Duration
	Now          func() time.Time
}
type routeChoice struct {
	transport Transport
	retryH3At time.Time
}
type TransportSelector struct {
	config TransportSelectorConfig
	mu     sync.Mutex
	routes map[string]routeChoice
}

func NewTransportSelector(config TransportSelectorConfig) (*TransportSelector, error) {
	if config.Stagger == 0 {
		config.Stagger = 250 * time.Millisecond
	}
	if config.Cooldown == 0 {
		config.Cooldown = 5 * time.Minute
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = 5 * time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.H3 == nil {
		config.H3 = &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(32)}, QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 15 * time.Second}, MaxResponseHeaderBytes: 32 << 10}
	}
	if config.H2 == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		config.H2 = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(32)}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second, ExpectContinueTimeout: time.Second, IdleConnTimeout: 90 * time.Second, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, MaxResponseHeaderBytes: 32 << 10}
	}
	if config.Stagger < 0 || config.Cooldown <= 0 || config.ProbeTimeout <= 0 {
		return nil, errors.New("invalid file transfer transport configuration")
	}
	return &TransportSelector{config: config, routes: make(map[string]routeChoice)}, nil
}

func (s *TransportSelector) Probe(ctx context.Context, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("invalid file transfer endpoint")
	}
	_, err = s.selectTransport(ctx, u)
	return err
}

func (s *TransportSelector) RoundTrip(request *http.Request) (*http.Response, error) {
	choice, err := s.selectTransport(request.Context(), request.URL)
	if err != nil {
		return nil, err
	}
	transport := s.transport(choice)
	response, err := transport.RoundTrip(request)
	if err == nil {
		return response, nil
	}
	if choice == TransportH3 && fallbackEligibleTransportError(err) {
		s.setChoice(authority(request.URL), routeChoice{transport: TransportH2, retryH3At: s.config.Now().Add(s.config.Cooldown)})
	}
	return nil, &TransportError{Transport: choice, Cause: err}
}

func (s *TransportSelector) selectTransport(ctx context.Context, u *url.URL) (Transport, error) {
	host := authority(u)
	now := s.config.Now()
	s.mu.Lock()
	choice, ok := s.routes[host]
	s.mu.Unlock()
	if ok && (choice.transport == TransportH3 || choice.transport == TransportH2 && now.Before(choice.retryH3At)) {
		return choice.transport, nil
	}
	probe := *u
	probe.Path = "/healthz"
	probe.RawPath = ""
	probe.RawQuery = ""
	probe.Fragment = ""
	probeCtx, cancel := context.WithTimeout(ctx, s.config.ProbeTimeout)
	defer cancel()
	type result struct {
		transport Transport
		response  *http.Response
		err       error
	}
	results := make(chan result, 2)
	start := func(transport Transport) {
		go func() {
			request, _ := http.NewRequestWithContext(probeCtx, http.MethodHead, probe.String(), nil)
			response, err := s.transport(transport).RoundTrip(request)
			results <- result{transport, response, err}
		}()
	}
	start(TransportH3)
	timer := time.NewTimer(s.config.Stagger)
	defer timer.Stop()
	startedH2 := false
	var firstErr error
	for received := 0; received < 2; {
		select {
		case <-probeCtx.Done():
			if firstErr != nil {
				return "", errors.Join(firstErr, probeCtx.Err())
			}
			return "", probeCtx.Err()
		case <-timer.C:
			if !startedH2 {
				startedH2 = true
				start(TransportH2)
			}
		case result := <-results:
			received++
			if result.response != nil {
				_ = result.response.Body.Close()
				selected := routeChoice{transport: result.transport}
				if result.transport == TransportH2 {
					selected.retryH3At = now.Add(s.config.Cooldown)
				}
				s.setChoice(host, selected)
				cancel()
				return result.transport, nil
			}
			wrapped := &TransportError{Transport: result.transport, Cause: result.err}
			if result.transport == TransportH3 && !fallbackEligibleTransportError(result.err) {
				cancel()
				return "", wrapped
			}
			firstErr = errors.Join(firstErr, wrapped)
			if !startedH2 {
				startedH2 = true
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				start(TransportH2)
			}
			if received == 2 {
				return "", firstErr
			}
		}
	}
	return "", firstErr
}

func (s *TransportSelector) transport(value Transport) http.RoundTripper {
	if value == TransportH3 {
		return s.config.H3
	}
	return s.config.H2
}
func (s *TransportSelector) setChoice(host string, choice routeChoice) {
	s.mu.Lock()
	s.routes[host] = choice
	s.mu.Unlock()
}
func authority(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}

func fallbackEligibleTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var network net.Error
	if errors.As(err, &network) {
		return true
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return true
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func (s *TransportSelector) Close() error {
	var result error
	if closer, ok := s.config.H3.(io.Closer); ok {
		result = errors.Join(result, closer.Close())
	}
	if closer, ok := s.config.H2.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return result
}
