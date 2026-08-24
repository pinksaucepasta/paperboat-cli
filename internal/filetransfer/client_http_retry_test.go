package filetransfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestRetryJSONRequestRetriesTransientGatewayStatuses(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			const (
				body      = `{"batch_id":"fb_restart"}`
				operation = "ft_create_restart"
			)
			calls := 0
			client := NewClient("https://route.example/v1/file-transfers", Auth{Token: "token"}, testBinding(), &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Header.Get("X-Paperboat-Operation-ID") != operation || request.Header.Get("X-Paperboat-Request-ID") != operation {
					t.Errorf("call %d operation headers changed: %#v", calls, request.Header)
				}
				gotBody, err := io.ReadAll(request.Body)
				if err != nil {
					t.Errorf("call %d read body: %v", calls, err)
				} else if string(gotBody) != body {
					t.Errorf("call %d body=%q", calls, gotBody)
				}
				if calls == 1 {
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("private edge failure detail")), Request: request}, nil
				}
				return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"batch_id":"fb_restart","transfers":[]}`)), Request: request}, nil
			})})
			client.retryWait = func(context.Context, int) error { return nil }

			var batch Batch
			if err := client.retryJSONRequest(context.Background(), http.MethodPost, client.Endpoint, operation, "application/json", 0, []byte(body), &batch); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || batch.BatchID != "fb_restart" {
				t.Fatalf("calls=%d batch=%#v", calls, batch)
			}
		})
	}
}

func TestRetryJSONRequestDoesNotRetryOtherHTTPStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusUnprocessableEntity,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusNotImplemented,
	} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			client := NewClient("https://route.example/v1/file-transfers", Auth{Token: "token"}, testBinding(), &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"code":"route_invalid","message":"private edge failure detail","requestId":"req_public","retryable":false}`)),
					Request:    request,
				}, nil
			})})
			client.retryWait = func(context.Context, int) error {
				t.Fatal("non-transient HTTP status entered retry backoff")
				return nil
			}

			err := client.retryJSONRequest(context.Background(), http.MethodPost, client.Endpoint, "ft_create_permanent", "application/json", 0, []byte(`{}`), &Batch{})
			var responseErr *Error
			if !errors.As(err, &responseErr) {
				t.Fatalf("error type=%T error=%v", err, err)
			}
			want := "file transfer failed: route_invalid (HTTP " + strconv.Itoa(status) + " " + http.StatusText(status) + ")"
			if calls != 1 || responseErr.StatusCode != status || responseErr.Code != "route_invalid" || err.Error() != want || strings.Contains(err.Error(), "private edge failure detail") {
				t.Fatalf("calls=%d status=%d code=%q error=%q", calls, responseErr.StatusCode, responseErr.Code, err)
			}
		})
	}
}

func TestRetryJSONRequestHonorsCancellationDuringBackoff(t *testing.T) {
	calls := 0
	client := NewClient("https://route.example/v1/file-transfers", Auth{Token: "token"}, testBinding(), &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})})
	ctx, cancel := context.WithCancel(context.Background())
	client.retryWait = func(retryCtx context.Context, attempt int) error {
		if attempt != 0 {
			t.Fatalf("attempt=%d", attempt)
		}
		cancel()
		return retryCtx.Err()
	}

	err := client.retryJSONRequest(ctx, http.MethodPost, client.Endpoint, "ft_create_cancel", "application/json", 0, []byte(`{}`), &Batch{})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}

func TestRetryJSONRequestReportsFinalTransientStatusAtRecoveryBoundary(t *testing.T) {
	calls := 0
	client := NewClient("https://route.example/v1/file-transfers", Auth{Token: "token"}, testBinding(), &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		status := http.StatusBadGateway
		body := `{"code":"storage_unavailable","message":"private first failure detail","requestId":"req_first","retryable":true}`
		if calls == 2 {
			status = http.StatusGatewayTimeout
			body = `{"code":"edge_unavailable","message":"private final failure detail","requestId":"req_final","retryable":true}`
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})})
	client.retryWait = func(_ context.Context, attempt int) error {
		if attempt == 0 {
			return nil
		}
		return context.DeadlineExceeded
	}

	err := client.retryJSONRequest(context.Background(), http.MethodPost, client.Endpoint, "ft_create_boundary", "application/json", 0, []byte(`{}`), &Batch{})
	var responseErr *Error
	if !errors.As(err, &responseErr) {
		t.Fatalf("error type=%T error=%v", err, err)
	}
	want := "file transfer failed: edge_unavailable (HTTP 504 Gateway Timeout)"
	if calls != 2 || responseErr.StatusCode != http.StatusGatewayTimeout || responseErr.Code != "edge_unavailable" || responseErr.RequestID != "req_final" || !responseErr.Retryable || err.Error() != want || strings.Contains(err.Error(), "private final failure detail") {
		t.Fatalf("calls=%d decoded=%#v error=%q", calls, responseErr, err)
	}
}

func TestDecodeErrorRejectsUnsafeResultCodeAndBodyMessage(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Body:       io.NopCloser(strings.NewReader("{\"code\":\"unsafe detail!\",\"message\":\"private edge failure detail\"}")),
	}
	err := decodeError(response)
	var responseErr *Error
	if !errors.As(err, &responseErr) {
		t.Fatalf("error type=%T", err)
	}
	want := "file transfer failed: http_error (HTTP 503 Service Unavailable)"
	if responseErr.Code != "http_error" || responseErr.Message != "" || err.Error() != want || strings.Contains(err.Error(), "private edge failure detail") {
		t.Fatalf("decoded=%#v error=%q", responseErr, err)
	}
}
