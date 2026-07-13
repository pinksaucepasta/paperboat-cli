package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultRequestTimeout      = 30 * time.Second
	defaultTLSHandshakeTimeout = 5 * time.Second
	tlsHandshakeAttempts       = 3
)

func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	return &http.Client{
		Timeout: defaultRequestTimeout,
		Transport: &tlsHandshakeRetryTransport{
			base:     transport,
			attempts: tlsHandshakeAttempts,
		},
	}
}

// tlsHandshakeRetryTransport retries only failures that happen before an HTTP
// request is sent. Ambiguous transport failures are returned immediately so
// credential-rotating and other mutation requests are never replayed.
type tlsHandshakeRetryTransport struct {
	base     http.RoundTripper
	attempts int
}

func (t *tlsHandshakeRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := t.attempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		request, err := requestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}
		resp, err := t.base.RoundTrip(request)
		if err == nil || !retryableTransportError(request, err) || attempt == attempts-1 {
			return resp, err
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
		}
	}
	panic("unreachable")
}

func requestForAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 0 || req.Body == nil {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("cannot retry TLS handshake: request body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Body = body
	return clone, nil
}

func isTLSHandshakeTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() &&
		strings.Contains(strings.ToLower(err.Error()), "tls handshake timeout")
}

func retryableTransportError(req *http.Request, err error) bool {
	if isTLSHandshakeTimeout(err) {
		return true
	}
	// A response-header timeout is safe to retry for read-only requests. It is
	// deliberately excluded for POST/PUT/PATCH because the server may have
	// already applied the mutation before the response was lost.
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() &&
		strings.Contains(strings.ToLower(err.Error()), "awaiting headers")
}
