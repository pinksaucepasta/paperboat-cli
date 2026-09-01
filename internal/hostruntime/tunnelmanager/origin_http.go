package tunnelmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"golang.org/x/net/http2"
)

var ErrOriginRequestInvalid = errors.New("invalid origin HTTP request")

// OriginHTTPTransport forwards one already edge-normalized request to its
// route origin. Public Host and TLS SNI are independent: Host is preserved by
// default or explicitly overridden, while SNI comes only from tls_server_name
// or the origin address. Paperboat-internal and hop-by-hop headers never cross
// this final trust boundary.
type OriginHTTPTransport struct {
	Dialer                   OriginDialer
	TLS                      OriginTLSProvider
	AllowInsecureDevelopment bool
	Observe                  func(OriginProbeObservation)

	mu         sync.Mutex
	transports map[string]originRoundTripper
	closed     bool
}

type originRoundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

func (t *OriginHTTPTransport) RoundTrip(ctx context.Context, route hoststate.TunnelConfigRoute, request *http.Request) (*http.Response, error) {
	if ctx == nil || request == nil || request.URL == nil || route.Protocol != "http" || route.DesiredState != "active" {
		return nil, ErrOriginRequestInvalid
	}
	switch route.OriginScheme {
	case "http", "h2c", "https", "unix":
	default:
		return nil, ErrOriginRequestInvalid
	}
	if route.ConnectTimeoutMs < 100 || route.IdleTimeoutMs < 1000 {
		return nil, ErrOriginRequestInvalid
	}
	transport, err := t.transportFor(ctx, route)
	if err != nil {
		return nil, err
	}
	out := request.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = route.OriginScheme
	if route.OriginScheme == "h2c" || route.OriginScheme == "unix" {
		out.URL.Scheme = "http"
	}
	out.URL.Host = route.OriginAddress
	if route.OriginScheme == "unix" {
		out.URL.Host = "paperboat-origin.invalid"
	}
	if route.HostOverride != nil {
		out.Host = *route.HostOverride
	} else if !route.PreserveHost {
		out.Host = route.OriginAddress
	}
	sanitizeOriginHeaders(out.Header)
	response, err := transport.RoundTrip(out)
	if err != nil {
		return nil, errors.Join(ErrOriginUnavailable, err)
	}
	return response, nil
}

func (t *OriginHTTPTransport) transportFor(ctx context.Context, route hoststate.TunnelConfigRoute) (originRoundTripper, error) {
	if t == nil {
		return nil, ErrInvalidConfig
	}
	key := originTransportKey(route)
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrOriginUnavailable
	}
	if transport := t.transports[key]; transport != nil {
		t.mu.Unlock()
		return transport, nil
	}
	t.mu.Unlock()
	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: time.Duration(route.ConnectTimeoutMs) * time.Millisecond, KeepAlive: 30 * time.Second}
	}
	var transport originRoundTripper
	standard := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     route.OriginScheme == "https",
		DisableCompression:    true,
		IdleConnTimeout:       time.Duration(route.IdleTimeoutMs) * time.Millisecond,
		TLSHandshakeTimeout:   time.Duration(route.ConnectTimeoutMs) * time.Millisecond,
		ExpectContinueTimeout: time.Second,
		MaxIdleConnsPerHost:   2,
	}
	if route.OriginScheme == "unix" {
		standard.DialContext = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, "unix", route.OriginAddress)
		}
	}
	if route.OriginScheme == "https" {
		prober := NetworkOriginProber{TLS: t.TLS, AllowInsecureDevelopment: t.AllowInsecureDevelopment, Observe: t.Observe}
		if route.TLSVerification == "insecure_development" {
			if !t.AllowInsecureDevelopment || t.Observe == nil {
				return nil, ErrInvalidConfig
			}
			t.Observe(OriginProbeObservation{RouteID: route.ID, Code: OriginProbeInsecureDevelopment})
		}
		tlsConfig, err := prober.originTLSConfig(ctx, route)
		if err != nil {
			return nil, errors.Join(ErrOriginUnavailable, err)
		}
		standard.TLSClientConfig = tlsConfig
	}
	transport = standard
	if route.OriginScheme == "h2c" {
		transport = &http2.Transport{AllowHTTP: true, DialTLSContext: func(dialCtx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(dialCtx, network, route.OriginAddress)
		}}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		transport.CloseIdleConnections()
		return nil, ErrOriginUnavailable
	}
	if current := t.transports[key]; current != nil {
		transport.CloseIdleConnections()
		return current, nil
	}
	if t.transports == nil {
		t.transports = make(map[string]originRoundTripper)
	}
	t.transports[key] = transport
	return transport, nil
}

func originTransportKey(route hoststate.TunnelConfigRoute) string {
	field := func(value *string) string {
		if value == nil {
			return "-"
		}
		return *value
	}
	return strings.Join([]string{route.ID, route.OriginScheme, route.OriginAddress, strconv.FormatBool(route.PreserveHost), field(route.HostOverride), route.TLSVerification, field(route.TLSServerName), field(route.CAReference), field(route.MTLSCredentialReference), strconv.FormatInt(int64(route.ConnectTimeoutMs), 10), strconv.FormatInt(int64(route.IdleTimeoutMs), 10)}, "\x00")
}

func (t *OriginHTTPTransport) newGeneration() *OriginHTTPTransport {
	if t == nil {
		return nil
	}
	return &OriginHTTPTransport{Dialer: t.Dialer, TLS: t.TLS, AllowInsecureDevelopment: t.AllowInsecureDevelopment, Observe: t.Observe, transports: make(map[string]originRoundTripper)}
}

func (t *OriginHTTPTransport) CloseIdleConnections() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	transports := t.transports
	t.transports = nil
	t.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func sanitizeOriginHeaders(header http.Header) {
	if header == nil {
		return
	}
	connectionTokens := strings.Split(header.Get("Connection"), ",")
	for _, token := range connectionTokens {
		if token = strings.TrimSpace(token); token != "" {
			header.Del(token)
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-paperboat-") {
			header.Del(name)
		}
	}
}
