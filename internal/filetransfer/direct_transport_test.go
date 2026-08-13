package filetransfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closingRoundTripper struct {
	calls  atomic.Int32
	closed atomic.Bool
	closes atomic.Int32
	trip   func(*http.Request) (*http.Response, error)
}

func (t *closingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return t.trip(request)
}
func (t *closingRoundTripper) Close() error {
	t.closes.Add(1)
	t.closed.Store(true)
	return nil
}

func TestDirectTransferFallsBackAfterReachabilityFailure(t *testing.T) {
	direct := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, networkFailure() }}
	relay := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(&emptyReader{}), Header: make(http.Header)}, nil
	}}
	transport, err := newDirectFallbackTransport(direct, relay)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://machine.test/v1/file-transfers/id", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("direct reachability failure was hidden")
	}
	if !direct.closed.Load() {
		t.Fatal("failed direct transport remained open after sticky fallback")
	}
	response, err := transport.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusNoContent || direct.calls.Load() != 1 || relay.calls.Load() != 1 {
		t.Fatalf("response=%v error=%v direct=%d relay=%d", response, err, direct.calls.Load(), relay.calls.Load())
	}
	if err := transport.(io.Closer).Close(); err != nil || !direct.closed.Load() {
		t.Fatalf("close error=%v closed=%v", err, direct.closed.Load())
	}
	if direct.closes.Load() != 1 {
		t.Fatalf("direct transport closed %d times", direct.closes.Load())
	}
}

func TestConcurrentDirectFailuresCloseOwnedTransportOnce(t *testing.T) {
	direct := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, networkFailure() }}
	relay := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, networkFailure() }}
	transport, err := newDirectFallbackTransport(direct, relay)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://machine.test/v1/file-transfers/id", nil)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = transport.RoundTrip(request)
		}()
	}
	workers.Wait()
	if direct.closes.Load() != 1 {
		t.Fatalf("direct transport closed %d times", direct.closes.Load())
	}
}

func TestDirectTransferProtocolFailureDoesNotDowngrade(t *testing.T) {
	direct := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, errors.New("invalid direct response") }}
	relay := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, nil }}
	transport, _ := newDirectFallbackTransport(direct, relay)
	request, _ := http.NewRequest(http.MethodGet, "https://machine.test/v1/file-transfers/id", nil)
	for range 2 {
		if _, err := transport.RoundTrip(request); err == nil {
			t.Fatal("direct protocol failure was hidden")
		}
	}
	if direct.calls.Load() != 2 || relay.calls.Load() != 0 {
		t.Fatalf("direct=%d relay=%d", direct.calls.Load(), relay.calls.Load())
	}
}

func TestDirectTransferNoProgressFallsBack(t *testing.T) {
	direct := &closingRoundTripper{trip: func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}}
	relay := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(&emptyReader{}), Header: make(http.Header)}, nil
	}}
	transport, _ := newDirectFallbackTransport(direct, relay)
	transport.(*directFallbackTransport).timeout = 10 * time.Millisecond
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://machine.test/v1/file-transfers/id", nil)
	started := time.Now()
	if _, err := transport.RoundTrip(request); err == nil || time.Since(started) > time.Second {
		t.Fatalf("error=%v elapsed=%s", err, time.Since(started))
	}
	if _, err := transport.RoundTrip(request); err != nil || relay.calls.Load() != 1 {
		t.Fatalf("relay error=%v calls=%d", err, relay.calls.Load())
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
