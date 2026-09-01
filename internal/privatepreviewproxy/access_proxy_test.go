package privatepreviewproxy

import (
	"bufio"
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

type accessTestSource struct {
	mu       sync.Mutex
	routes   []AccessRoute
	snapshot error
	open     error
	hosts    []string
}

func (s *accessTestSource) Snapshot(context.Context) ([]AccessRoute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AccessRoute(nil), s.routes...), s.snapshot
}

func (s *accessTestSource) Open(_ context.Context, host string) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	s.hosts = append(s.hosts, host)
	err := s.open
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func TestAccessProxyPACIsNarrowAndContainsNoCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &accessTestSource{routes: []AccessRoute{
		{MatchType: AccessMatchOneLabelWildcard, WildcardSuffix: "private.example.test"},
		{MatchType: AccessMatchExact, Hostname: "ONE.private.example.test"},
	}}
	proxy, err := StartAccessProxy(ctx, AccessProxyConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	response, err := http.Get(proxy.PACURL)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, body, readErr)
	}
	text := string(body)
	for _, required := range []string{"one.private.example.test", "dnsDomainLevels(host)", "PROXY 127.0.0.1:", "return 'DIRECT'"} {
		if !strings.Contains(text, required) {
			t.Fatalf("PAC missing %q: %s", required, text)
		}
	}
	for _, forbidden := range []string{"Bearer", "cookie", "token", "secret"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("PAC contains forbidden %q: %s", forbidden, text)
		}
	}
}

func TestAccessProxyConnectUsesExactHostAndStreamsBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &accessTestSource{routes: []AccessRoute{{MatchType: AccessMatchExact, Hostname: "private.example.test"}}}
	proxy, err := StartAccessProxy(ctx, AccessProxyConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	connection, err := net.Dial("tcp4", proxy.ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "CONNECT private.example.test:443 HTTP/1.1\r\nHost: private.example.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if _, err := connection.Write([]byte("tls-canary")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len("tls-canary"))
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "tls-canary" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	source.mu.Lock()
	hosts := append([]string(nil), source.hosts...)
	source.mu.Unlock()
	if len(hosts) != 1 || hosts[0] != "private.example.test" {
		t.Fatalf("opened hosts=%v", hosts)
	}
}

func TestAccessProxyMapsAuthenticationAuthorizationAndAvailability(t *testing.T) {
	tests := []struct {
		name   string
		routes []AccessRoute
		err    error
		status int
	}{
		{name: "authentication", routes: []AccessRoute{{Hostname: "private.example.test"}}, err: ErrAccessAuthentication, status: http.StatusUnauthorized},
		{name: "authorization", routes: []AccessRoute{{Hostname: "private.example.test"}}, err: ErrAccessForbidden, status: http.StatusForbidden},
		{name: "unavailable", routes: []AccessRoute{{Hostname: "private.example.test"}}, err: ErrAccessTemporarilyUnavailable, status: http.StatusServiceUnavailable},
		{name: "not listed", routes: []AccessRoute{{Hostname: "other.example.test"}}, status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := &accessTestSource{routes: test.routes, open: test.err}
			proxy, err := StartAccessProxy(ctx, AccessProxyConfig{Source: source})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			request, _ := http.NewRequest(http.MethodConnect, "http://"+proxy.ProxyAddress, nil)
			request.Host = "private.example.test:443"
			response, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status=%d want=%d", response.StatusCode, test.status)
			}
		})
	}
}

func TestAccessProxyRejectsBrowserCredentialsAndRecursiveWildcard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &accessTestSource{routes: []AccessRoute{{MatchType: AccessMatchOneLabelWildcard, WildcardSuffix: "private.example.test"}}}
	proxy, err := StartAccessProxy(ctx, AccessProxyConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	credentialRequest, _ := http.NewRequest(http.MethodConnect, "http://"+proxy.ProxyAddress, nil)
	credentialRequest.Host = "one.private.example.test:443"
	credentialRequest.Header.Set("Proxy-Authorization", "Bearer browser-secret")
	credentialResponse, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(credentialRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = credentialResponse.Body.Close()
	if credentialResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("credential status=%d", credentialResponse.StatusCode)
	}

	recursiveRequest, _ := http.NewRequest(http.MethodConnect, "http://"+proxy.ProxyAddress, nil)
	recursiveRequest.Host = "two.one.private.example.test:443"
	recursiveResponse, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(recursiveRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = recursiveResponse.Body.Close()
	if recursiveResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("recursive wildcard status=%d", recursiveResponse.StatusCode)
	}
}

func TestAccessProxyCancellationClosesHijackedStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &accessTestSource{routes: []AccessRoute{{Hostname: "private.example.test"}}}
	proxy, err := StartAccessProxy(ctx, AccessProxyConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp4", proxy.ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(connection, "CONNECT private.example.test:443 HTTP/1.1\r\nHost: private.example.test:443\r\n\r\n")
	reader := bufio.NewReader(connection)
	if _, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect}); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("hijacked browser connection remained open after hostd cancellation")
	}
	_ = connection.Close()
	if err := proxy.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeAccessRoutesRejectsCatchAllAndUnsafeHosts(t *testing.T) {
	for _, routes := range [][]AccessRoute{
		{{MatchType: "catch_all", Hostname: "example.test"}},
		{{Hostname: "127.0.0.1"}},
		{{Hostname: "private.example.test:443"}},
		{{MatchType: AccessMatchOneLabelWildcard, WildcardSuffix: "localhost"}},
	} {
		if _, err := normalizeAccessRoutes(routes, 10); !errors.Is(err, ErrAccessProxyInvalid) {
			t.Fatalf("routes=%+v error=%v", routes, err)
		}
	}
}

func TestNormalizeAccessRoutesRejectsNormalizedDuplicates(t *testing.T) {
	for _, routes := range [][]AccessRoute{
		{{MatchType: AccessMatchExact, Hostname: "BÜCHER.example"}, {MatchType: AccessMatchExact, Hostname: "xn--bcher-kva.example"}},
		{{MatchType: AccessMatchExact, Hostname: "same.example.test"}, {MatchType: AccessMatchManagedExact, Hostname: "same.example.test"}},
		{{MatchType: AccessMatchOneLabelWildcard, Hostname: "*.private.example.test"}, {MatchType: AccessMatchOneLabelWildcard, WildcardSuffix: "private.example.test"}},
	} {
		if _, err := normalizeAccessRoutes(routes, 10); !errors.Is(err, ErrAccessProxyInvalid) {
			t.Fatalf("duplicate routes=%+v error=%v", routes, err)
		}
	}
}
