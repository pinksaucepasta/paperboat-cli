package httptransport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

var (
	ErrLoopbackRequired = errors.New("HTTP endpoint must use a literal loopback address")
	ErrLoopbackRedirect = errors.New("loopback HTTP redirects are forbidden")
)

// NewLoopbackClient returns a proxy-free client that can dial only literal
// loopback addresses. It is the shared transport for local hostd and worker
// control endpoints, which must never follow administrator, environment, or
// network proxy configuration.
func NewLoopbackClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 5*time.Minute {
		return nil, errors.New("invalid loopback HTTP timeout")
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrLoopbackRequired
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrLoopbackRequired
		}
		return dialer.DialContext(ctx, network, address)
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           4,
		MaxConnsPerHost:        4,
		MaxIdleConnsPerHost:    2,
		MaxResponseHeaderBytes: 32 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrLoopbackRedirect
		},
	}, nil
}
