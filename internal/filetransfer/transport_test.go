package filetransfer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
func response(request *http.Request, status int) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}
}
func networkFailure() error {
	return &net.OpError{Op: "dial", Net: "udp", Err: errors.New("unreachable")}
}

func TestTransportProbeKeepsH3ForEveryHTTPStatus(t *testing.T) {
	h3Calls, h2Calls := 0, 0
	selector, err := NewTransportSelector(TransportSelectorConfig{H3: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		h3Calls++
		return response(request, http.StatusServiceUnavailable), nil
	}), H2: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		h2Calls++
		return response(request, http.StatusOK), nil
	}), Stagger: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.Probe(context.Background(), "https://route.example/v1/file-transfers"); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://route.example/v1/file-transfers/ft_1", nil)
	got, err := selector.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Body.Close()
	if h3Calls != 2 || h2Calls != 0 {
		t.Fatalf("h3=%d h2=%d", h3Calls, h2Calls)
	}
}

func TestTransportProbeFallsBackOnlyAfterH3NetworkFailure(t *testing.T) {
	h3Calls, h2Calls := 0, 0
	selector, _ := NewTransportSelector(TransportSelectorConfig{H3: roundTripFunc(func(*http.Request) (*http.Response, error) { h3Calls++; return nil, networkFailure() }), H2: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		h2Calls++
		return response(request, http.StatusOK), nil
	}), Stagger: time.Hour})
	if err := selector.Probe(context.Background(), "https://route.example/v1/file-transfers"); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodHead, "https://route.example/v1/file-transfers/ft_1/content", nil)
	got, err := selector.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Body.Close()
	if h3Calls != 1 || h2Calls != 2 {
		t.Fatalf("h3=%d h2=%d", h3Calls, h2Calls)
	}
}

func TestTransportFailureSwitchesSameRouteToH2ForOffsetConfirmation(t *testing.T) {
	var mu sync.Mutex
	h3Calls, h2Calls := 0, 0
	h3 := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		h3Calls++
		if h3Calls == 1 {
			return response(request, http.StatusOK), nil
		}
		return nil, networkFailure()
	})
	h2 := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		h2Calls++
		return response(request, http.StatusNoContent), nil
	})
	selector, _ := NewTransportSelector(TransportSelectorConfig{H3: h3, H2: h2, Stagger: time.Hour})
	if err := selector.Probe(context.Background(), "https://route.example/v1/file-transfers"); err != nil {
		t.Fatal(err)
	}
	patch, _ := http.NewRequest(http.MethodPatch, "https://route.example/v1/file-transfers/ft_1/content", strings.NewReader("chunk"))
	if _, err := selector.RoundTrip(patch); err == nil {
		t.Fatal("expected uncertain H3 failure")
	}
	head, _ := http.NewRequest(http.MethodHead, "https://route.example/v1/file-transfers/ft_1/content", nil)
	got, err := selector.RoundTrip(head)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Body.Close()
	if h3Calls != 2 || h2Calls != 1 {
		t.Fatalf("h3=%d h2=%d", h3Calls, h2Calls)
	}
}

func TestTransportRetriesH3AfterCooldown(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h3Healthy := false
	h3Calls, h2Calls := 0, 0
	selector, _ := NewTransportSelector(TransportSelectorConfig{H3: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		h3Calls++
		if !h3Healthy {
			return nil, networkFailure()
		}
		return response(request, http.StatusOK), nil
	}), H2: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		h2Calls++
		return response(request, http.StatusOK), nil
	}), Stagger: time.Hour, Cooldown: time.Minute, Now: func() time.Time { return now }})
	if err := selector.Probe(context.Background(), "https://route.example/v1/file-transfers"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	h3Healthy = true
	request, _ := http.NewRequest(http.MethodGet, "https://route.example/v1/file-transfers/ft_1", nil)
	got, err := selector.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Body.Close()
	if h3Calls != 3 || h2Calls != 1 {
		t.Fatalf("h3=%d h2=%d", h3Calls, h2Calls)
	}
}
