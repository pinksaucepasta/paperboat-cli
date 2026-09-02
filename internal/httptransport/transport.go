// Package httptransport owns common HTTPS and WSS connection policy.
package httptransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
)

type ProxyFailure uint8

const (
	ProxyInvalid ProxyFailure = iota + 1
	ProxyAuthenticationRequired
	ProxyAutomaticConfigurationUnsupported
)

type ProxyError struct {
	Failure ProxyFailure
	Cause   error
}

func (e *ProxyError) Error() string {
	if e == nil {
		return "HTTP proxy failure"
	}
	switch e.Failure {
	case ProxyInvalid:
		return "HTTP proxy configuration is invalid"
	case ProxyAuthenticationRequired:
		return "HTTP proxy authentication is required"
	case ProxyAutomaticConfigurationUnsupported:
		return "automatic HTTP proxy configuration is unsupported; configure an explicit credential-free proxy"
	default:
		return "HTTP proxy failure"
	}
}
func (e *ProxyError) Unwrap() error { return e.Cause }

type ProxySnapshot struct {
	HTTPProxy          string
	HTTPSProxy         string
	NoProxy            string
	ExcludeSimpleHosts bool
	PACOnly            bool
	Generation         uint64
}

type ProxySource interface {
	Snapshot(context.Context) (ProxySnapshot, error)
}

type Config struct {
	TLSConfig              *tls.Config
	ProxySource            ProxySource
	DialContext            func(context.Context, string, string) (net.Conn, error)
	DialTLSContext         func(context.Context, string, string) (net.Conn, error)
	ForceAttemptHTTP2      bool
	DialTimeout            time.Duration
	KeepAlive              time.Duration
	TLSHandshakeTimeout    time.Duration
	ResponseHeaderTimeout  time.Duration
	ExpectContinueTimeout  time.Duration
	IdleConnTimeout        time.Duration
	MaxIdleConns           int
	MaxConnsPerHost        int
	MaxIdleConnsPerHost    int
	MaxResponseHeaderBytes int64
}

func DevelopmentConfig() Config {
	return Config{ProxySource: DefaultProxySource(), ForceAttemptHTTP2: true, DialTimeout: 5 * time.Second, KeepAlive: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second, ExpectContinueTimeout: time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 32, MaxConnsPerHost: 16, MaxIdleConnsPerHost: 8, MaxResponseHeaderBytes: 32 << 10}
}

// Default returns an independently owned transport with development policy.
func Default() *Transport {
	return &Transport{config: DevelopmentConfig()}
}

type Transport struct {
	config Config
	mu     sync.Mutex
	key    string
	base   *http.Transport
}

func New(config Config) (*Transport, error) {
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if config.ProxySource == nil {
		config.ProxySource = EnvironmentProxySource{}
	}
	if config.DialTimeout <= 0 || config.KeepAlive <= 0 || config.TLSHandshakeTimeout <= 0 || config.ResponseHeaderTimeout <= 0 || config.ExpectContinueTimeout <= 0 || config.IdleConnTimeout <= 0 || config.MaxIdleConns < 1 || config.MaxConnsPerHost < 1 || config.MaxIdleConnsPerHost < 1 || config.MaxIdleConnsPerHost > config.MaxConnsPerHost || config.MaxIdleConnsPerHost > config.MaxIdleConns || config.MaxResponseHeaderBytes < 1024 || config.MaxResponseHeaderBytes > 1<<20 {
		return nil, errors.New("invalid HTTP transport configuration")
	}
	return &Transport{config: config}, nil
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || request == nil {
		return nil, errors.New("invalid HTTP transport request")
	}
	snapshot, err := t.config.ProxySource.Snapshot(request.Context())
	if err != nil {
		return nil, err
	}
	base, err := t.transport(snapshot)
	if err != nil {
		return nil, err
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusProxyAuthRequired {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		_ = response.Body.Close()
		return nil, &ProxyError{Failure: ProxyAuthenticationRequired}
	}
	return response, nil
}

func (t *Transport) transport(snapshot ProxySnapshot) (*http.Transport, error) {
	proxy, key, err := proxyFunction(snapshot)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	if t.base != nil && t.key == key {
		base := t.base
		t.mu.Unlock()
		return base, nil
	}
	dialContext := t.config.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: t.config.DialTimeout, KeepAlive: t.config.KeepAlive}).DialContext
	}
	base := &http.Transport{Proxy: proxy, DialContext: dialContext, DialTLSContext: t.config.DialTLSContext, ForceAttemptHTTP2: t.config.ForceAttemptHTTP2, TLSClientConfig: t.config.TLSConfig.Clone(), TLSHandshakeTimeout: t.config.TLSHandshakeTimeout, ResponseHeaderTimeout: t.config.ResponseHeaderTimeout, ExpectContinueTimeout: t.config.ExpectContinueTimeout, IdleConnTimeout: t.config.IdleConnTimeout, MaxIdleConns: t.config.MaxIdleConns, MaxConnsPerHost: t.config.MaxConnsPerHost, MaxIdleConnsPerHost: t.config.MaxIdleConnsPerHost, MaxResponseHeaderBytes: t.config.MaxResponseHeaderBytes,
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
			if response.StatusCode == http.StatusProxyAuthRequired {
				return &ProxyError{Failure: ProxyAuthenticationRequired}
			}
			return nil
		},
	}
	previous := t.base
	t.base, t.key = base, key
	t.mu.Unlock()
	if previous != nil {
		previous.CloseIdleConnections()
	}
	return base, nil
}

func (t *Transport) CloseIdleConnections() {
	if t == nil {
		return
	}
	t.mu.Lock()
	base := t.base
	t.mu.Unlock()
	if base != nil {
		base.CloseIdleConnections()
	}
}

func proxyFunction(snapshot ProxySnapshot) (func(*http.Request) (*url.URL, error), string, error) {
	if snapshot.PACOnly && snapshot.HTTPProxy == "" && snapshot.HTTPSProxy == "" {
		if snapshot.NoProxy == "" {
			return nil, "", &ProxyError{Failure: ProxyAutomaticConfigurationUnsupported}
		}
		// Paperboat never evaluates PAC scripts. It may still connect directly
		// to an administrator-declared NO_PROXY control-plane host while the
		// operating system routes private preview names through Paperboat's own
		// PAC. Every other destination remains fail-closed.
		bypass := (&httpproxy.Config{HTTPProxy: "http://127.0.0.1:1", HTTPSProxy: "http://127.0.0.1:1", NoProxy: snapshot.NoProxy}).ProxyFunc()
		proxy := func(request *http.Request) (*url.URL, error) {
			selected, err := bypass(request.URL)
			if err != nil {
				return nil, &ProxyError{Failure: ProxyInvalid, Cause: err}
			}
			if selected == nil {
				return nil, nil
			}
			return nil, &ProxyError{Failure: ProxyAutomaticConfigurationUnsupported}
		}
		return proxy, fmt.Sprintf("%d\x00pac-only\x00%s", snapshot.Generation, snapshot.NoProxy), nil
	}
	for _, raw := range []string{snapshot.HTTPProxy, snapshot.HTTPSProxy} {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, "", &ProxyError{Failure: ProxyInvalid}
		}
	}
	config := &httpproxy.Config{HTTPProxy: snapshot.HTTPProxy, HTTPSProxy: snapshot.HTTPSProxy, NoProxy: snapshot.NoProxy}
	selectProxy := config.ProxyFunc()
	proxy := func(request *http.Request) (*url.URL, error) {
		if snapshot.ExcludeSimpleHosts {
			host := request.URL.Hostname()
			if host != "" && !strings.Contains(host, ".") && net.ParseIP(host) == nil {
				return nil, nil
			}
		}
		value, err := selectProxy(request.URL)
		if err != nil {
			return nil, &ProxyError{Failure: ProxyInvalid, Cause: err}
		}
		return value, nil
	}
	key := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%t", snapshot.Generation, snapshot.HTTPProxy, snapshot.HTTPSProxy, snapshot.NoProxy, snapshot.ExcludeSimpleHosts)
	return proxy, key, nil
}

func ResolveProxy(ctx context.Context, source ProxySource, target *url.URL) (ProxySnapshot, *url.URL, error) {
	if source == nil || target == nil || target.Hostname() == "" {
		return ProxySnapshot{}, nil, errors.New("invalid HTTP proxy resolution")
	}
	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		return ProxySnapshot{}, nil, err
	}
	proxy, _, err := proxyFunction(snapshot)
	if err != nil {
		return ProxySnapshot{}, nil, err
	}
	request := &http.Request{URL: target}
	value, err := proxy(request)
	return snapshot, value, err
}

type EnvironmentProxySource struct{ LookupEnv func(string) (string, bool) }

type AdministratorProxySource struct{ LookupEnv func(string) (string, bool) }

type PriorityProxySource struct {
	Administrator ProxySource
	Environment   ProxySource
	System        ProxySource
}

func DefaultProxySource() ProxySource {
	return PriorityProxySource{Administrator: AdministratorProxySource{}, Environment: EnvironmentProxySource{}, System: NativeSystemProxySource{}}
}

func (s PriorityProxySource) Snapshot(ctx context.Context) (ProxySnapshot, error) {
	administrator := ProxySnapshot{}
	var err error
	if s.Administrator != nil {
		administrator, err = s.Administrator.Snapshot(ctx)
		if err != nil {
			return ProxySnapshot{}, err
		}
		if administrator.HTTPProxy != "" || administrator.HTTPSProxy != "" || administrator.PACOnly {
			return administrator, nil
		}
	}
	environment := ProxySnapshot{}
	if s.Environment != nil {
		environment, err = s.Environment.Snapshot(ctx)
		if err != nil {
			return ProxySnapshot{}, err
		}
		if proxyConfigured(environment) {
			return environment, nil
		}
	}
	if s.System == nil {
		return environment, nil
	}
	system, err := s.System.Snapshot(ctx)
	if err != nil {
		return ProxySnapshot{}, err
	}
	if environment.NoProxy != "" {
		system.NoProxy = appendNoProxy(system.NoProxy, environment.NoProxy)
	}
	if administrator.NoProxy != "" {
		system.NoProxy = appendNoProxy(system.NoProxy, administrator.NoProxy)
	}
	return system, nil
}

func proxyConfigured(snapshot ProxySnapshot) bool {
	return snapshot.HTTPProxy != "" || snapshot.HTTPSProxy != "" || snapshot.PACOnly
}

func appendNoProxy(current, added string) string {
	if current == "" {
		return added
	}
	if added == "" {
		return current
	}
	return current + "," + added
}

func (s EnvironmentProxySource) Snapshot(context.Context) (ProxySnapshot, error) {
	lookup := s.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	first := func(names ...string) string {
		for _, name := range names {
			if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	return ProxySnapshot{HTTPProxy: first("HTTP_PROXY", "http_proxy"), HTTPSProxy: first("HTTPS_PROXY", "https_proxy"), NoProxy: first("NO_PROXY", "no_proxy")}, nil
}

func (s AdministratorProxySource) Snapshot(context.Context) (ProxySnapshot, error) {
	lookup := s.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	value := func(name string) string {
		result, _ := lookup(name)
		return strings.TrimSpace(result)
	}
	return ProxySnapshot{
		HTTPProxy:  value("PAPERBOAT_HTTP_PROXY"),
		HTTPSProxy: value("PAPERBOAT_HTTPS_PROXY"),
		NoProxy:    value("PAPERBOAT_NO_PROXY"),
	}, nil
}

type StaticProxySource struct{ Value ProxySnapshot }

func (s StaticProxySource) Snapshot(context.Context) (ProxySnapshot, error) { return s.Value, nil }

// ValidateProxySnapshot rejects proxy policy that cannot be used safely before
// a service begins accepting work.
func ValidateProxySnapshot(snapshot ProxySnapshot) error {
	_, _, err := proxyFunction(snapshot)
	return err
}

var _ http.RoundTripper = (*Transport)(nil)
