package httptransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoopbackClientRejectsNonLoopbackDial(t *testing.T) {
	client, err := NewLoopbackClient(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://192.0.2.1:8080/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if !errors.Is(err, ErrLoopbackRequired) {
		t.Fatalf("non-loopback error = %v", err)
	}
}

func TestLoopbackClientDisablesProxyAndRedirects(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:8080")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect" {
			http.Redirect(writer, request, "/ready", http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewLoopbackClient(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL + "/redirect")
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, ErrLoopbackRedirect) {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestLoopbackClientRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 6 * time.Minute} {
		if _, err := NewLoopbackClient(timeout); err == nil {
			t.Fatalf("timeout %s accepted", timeout)
		}
	}
}
