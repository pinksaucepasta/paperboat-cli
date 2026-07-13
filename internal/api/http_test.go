package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type timeoutError string

func (e timeoutError) Error() string { return string(e) }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTLSHandshakeRetryTransportRetriesReplayableRequest(t *testing.T) {
	var calls int
	var bodies []string
	transport := &tlsHandshakeRetryTransport{
		attempts: 3,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, string(body))
			if calls == 1 {
				return nil, timeoutError("net/http: TLS handshake timeout")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://paperboat.example/api/auth/token/refresh", bytes.NewBufferString("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if strings.Join(bodies, ",") != "payload,payload" {
		t.Fatalf("bodies = %q", bodies)
	}
}

func TestTLSHandshakeRetryTransportDoesNotRetryAmbiguousError(t *testing.T) {
	want := errors.New("connection reset by peer")
	var calls int
	transport := &tlsHandshakeRetryTransport{
		attempts: 3,
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, want
		}),
	}
	req, err := http.NewRequest(http.MethodGet, "https://paperboat.example/api/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.RoundTrip(req)
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestTLSHandshakeRetryTransportRetriesGETHeaderTimeout(t *testing.T) {
	var calls int
	transport := &tlsHandshakeRetryTransport{
		attempts: 2,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return nil, timeoutError("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodGet, "https://paperboat.example/api/projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestTLSHandshakeRetryTransportDoesNotRetryPOSTHeaderTimeout(t *testing.T) {
	var calls int
	transport := &tlsHandshakeRetryTransport{
		attempts: 2,
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, timeoutError("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "https://paperboat.example/api/auth/token/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.RoundTrip(req)
	if err == nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d; want one attempt", err, calls)
	}
}
