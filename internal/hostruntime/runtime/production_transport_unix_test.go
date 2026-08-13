//go:build darwin || linux

package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

func TestProductionTransportAdministratorProxyTakesPrecedence(t *testing.T) {
	administrator := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "administrator")
	}))
	defer administrator.Close()
	environment := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "environment")
	}))
	defer environment.Close()

	values := map[string]string{
		"PAPERBOAT_HTTP_PROXY": administrator.URL,
		"HTTP_PROXY":           environment.URL,
	}
	transport, err := productionTransport("", func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://control.invalid/resource", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "administrator" {
		t.Fatalf("body=%q", body)
	}
}

func TestProductionTransportRejectsUnsafeAdministratorProxyAtStartup(t *testing.T) {
	for name, value := range map[string]string{
		"credentials": "http://operator:secret@proxy.test",
		"scheme":      "socks5://proxy.test",
		"path":        "http://proxy.test/path",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := productionTransport("", func(key string) string {
				if key == "PAPERBOAT_HTTPS_PROXY" {
					return value
				}
				return ""
			})
			var proxyErr *httptransport.ProxyError
			if !errors.Is(err, ErrProductionInvalid) || !errors.As(err, &proxyErr) || proxyErr.Failure != httptransport.ProxyInvalid {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestProductionTransportRequiresEnvironmentReader(t *testing.T) {
	if _, err := productionTransport("", nil); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("err=%v", err)
	}
}
