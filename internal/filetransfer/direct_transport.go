package filetransfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const directProgressTimeout = 3 * time.Second

type directFallbackTransport struct {
	direct   http.RoundTripper
	relay    http.RoundTripper
	timeout  time.Duration
	mu       sync.RWMutex
	fallback bool
	closed   bool
}

func newDirectFallbackTransport(direct, relay http.RoundTripper) (http.RoundTripper, error) {
	if direct == nil || relay == nil {
		return nil, errors.New("direct file transfer requires direct and relay transports")
	}
	return &directFallbackTransport{direct: direct, relay: relay, timeout: directProgressTimeout}, nil
}

func (t *directFallbackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.RLock()
	fallback := t.fallback
	t.mu.RUnlock()
	if fallback {
		return t.relay.RoundTrip(request)
	}
	ctx, cancel := context.WithTimeout(request.Context(), t.timeout)
	response, err := t.direct.RoundTrip(request.Clone(ctx))
	cancel()
	if err == nil {
		return response, nil
	}
	if !fallbackEligibleTransportError(err) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	t.mu.Lock()
	t.fallback = true
	closeDirect := !t.closed
	t.closed = true
	t.mu.Unlock()
	if closeDirect {
		_ = closeRoundTripper(t.direct)
	}
	return nil, &TransportError{Transport: "direct", Cause: err}
}

func (t *directFallbackTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	return closeRoundTripper(t.direct)
}

func closeRoundTripper(transport http.RoundTripper) error {
	if closer, ok := transport.(io.Closer); ok {
		return closer.Close()
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

func (t *directFallbackTransport) CloseIdleConnections() {
	if closer, ok := t.direct.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	if closer, ok := t.relay.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
