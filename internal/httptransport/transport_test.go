package httptransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestProxySnapshotSelectionAndNoProxy(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.test:8080")
	_, key, err := proxyFunction(ProxySnapshot{HTTPProxy: proxyURL.String(), HTTPSProxy: proxyURL.String(), NoProxy: "direct.test", Generation: 2})
	if err != nil || key == "" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	selectProxy, _, _ := proxyFunction(ProxySnapshot{HTTPProxy: proxyURL.String(), HTTPSProxy: proxyURL.String(), NoProxy: "direct.test"})
	request := func(raw string) *http.Request { value, _ := http.NewRequest(http.MethodGet, raw, nil); return value }
	if got, err := selectProxy(request("https://remote.test")); err != nil || got.String() != proxyURL.String() {
		t.Fatalf("proxy=%v err=%v", got, err)
	}
	if got, err := selectProxy(request("https://direct.test")); err != nil || got != nil {
		t.Fatalf("proxy=%v err=%v", got, err)
	}
}

func TestProxyPolicyRejectsCredentialsMalformedAndPACOnly(t *testing.T) {
	for name, snapshot := range map[string]ProxySnapshot{
		"credentials": {HTTPSProxy: "http://user:secret@proxy.test"},
		"scheme":      {HTTPSProxy: "socks5://proxy.test"},
		"path":        {HTTPSProxy: "http://proxy.test/path"},
		"pac":         {PACOnly: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := proxyFunction(snapshot)
			var proxyErr *ProxyError
			if !errors.As(err, &proxyErr) {
				t.Fatalf("err=%v", err)
			}
			if name == "pac" && proxyErr.Failure != ProxyAutomaticConfigurationUnsupported {
				t.Fatalf("failure=%d", proxyErr.Failure)
			}
		})
	}
}

func TestValidateProxySnapshotUsesTransportPolicy(t *testing.T) {
	if err := ValidateProxySnapshot(ProxySnapshot{HTTPSProxy: "http://proxy.test:8443", NoProxy: "direct.test"}); err != nil {
		t.Fatal(err)
	}
	var proxyErr *ProxyError
	if err := ValidateProxySnapshot(ProxySnapshot{HTTPSProxy: "http://user:secret@proxy.test"}); !errors.As(err, &proxyErr) || proxyErr.Failure != ProxyInvalid {
		t.Fatalf("err=%v", err)
	}
}

func TestTransportReturnsTypedProxyAuthenticationFailure(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusProxyAuthRequired) }))
	defer proxy.Close()
	config := DevelopmentConfig()
	config.ProxySource = StaticProxySource{Value: ProxySnapshot{HTTPProxy: proxy.URL}}
	transport, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://remote.test/resource", nil)
	_, err = transport.RoundTrip(request)
	var proxyErr *ProxyError
	if !errors.As(err, &proxyErr) || proxyErr.Failure != ProxyAuthenticationRequired {
		t.Fatalf("err=%v", err)
	}
}

func TestTransportSupportsHTTPSConnectAndTypesConnect407(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "through-connect") }))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	port := targetURL.Port()
	targetURL.Host = net.JoinHostPort("target.test", port)
	proxy := connectProxy(t, http.StatusOK, target.Listener.Addr().String())
	defer proxy.Close()
	config := DevelopmentConfig()
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // test server certificate
	config.ProxySource = StaticProxySource{Value: ProxySnapshot{HTTPSProxy: proxy.URL}}
	transport, _ := New(config)
	response, err := (&http.Client{Transport: transport}).Get(targetURL.String())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(data) != "through-connect" {
		t.Fatalf("body=%q", data)
	}

	rejecting := connectProxy(t, http.StatusProxyAuthRequired, "")
	defer rejecting.Close()
	config.ProxySource = StaticProxySource{Value: ProxySnapshot{HTTPSProxy: rejecting.URL}}
	transport, _ = New(config)
	_, err = (&http.Client{Transport: transport}).Get(targetURL.String())
	var proxyErr *ProxyError
	if !errors.As(err, &proxyErr) || proxyErr.Failure != ProxyAuthenticationRequired {
		t.Fatalf("err=%v", err)
	}
}

func TestTransportReplacesIdlePoolWhenProxyGenerationChanges(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "first") }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "second") }))
	defer second.Close()
	source := &mutableProxySource{snapshot: ProxySnapshot{HTTPProxy: first.URL, Generation: 1}}
	config := DevelopmentConfig()
	config.ProxySource = source
	transport, _ := New(config)
	client := &http.Client{Transport: transport}
	read := func() string {
		response, err := client.Get("http://remote.test/value")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return string(data)
	}
	if got := read(); got != "first" {
		t.Fatal(got)
	}
	source.set(ProxySnapshot{HTTPProxy: second.URL, Generation: 2})
	if got := read(); got != "second" {
		t.Fatal(got)
	}
}

func TestTransportCancellationBoundsDial(t *testing.T) {
	config := DevelopmentConfig()
	started := make(chan struct{})
	config.ProxySource = StaticProxySource{}
	config.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	transport, _ := New(config)
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://remote.test", nil)
	done := make(chan error, 1)
	go func() { _, err := transport.RoundTrip(request); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestEnvironmentProxySourceReadsEachSnapshot(t *testing.T) {
	values := map[string]string{"HTTPS_PROXY": "http://first.test", "NO_PROXY": "direct.test"}
	source := EnvironmentProxySource{LookupEnv: func(name string) (string, bool) { value, ok := values[name]; return value, ok }}
	first, _ := source.Snapshot(context.Background())
	values["HTTPS_PROXY"] = "http://second.test"
	second, _ := source.Snapshot(context.Background())
	if first.HTTPSProxy == second.HTTPSProxy || second.NoProxy != "direct.test" {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestAdministratorProxySourceReadsOnlyPaperboatNamespace(t *testing.T) {
	values := map[string]string{
		"PAPERBOAT_HTTP_PROXY":  " http://administrator.test:8080 ",
		"PAPERBOAT_HTTPS_PROXY": "https://administrator.test:8443",
		"PAPERBOAT_NO_PROXY":    "direct.test",
		"HTTPS_PROXY":           "http://environment.test",
	}
	snapshot, err := (AdministratorProxySource{LookupEnv: func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}}).Snapshot(context.Background())
	if err != nil || snapshot.HTTPProxy != "http://administrator.test:8080" || snapshot.HTTPSProxy != "https://administrator.test:8443" || snapshot.NoProxy != "direct.test" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
}

func TestDefaultProxySourceIncludesAdministratorPolicy(t *testing.T) {
	source, ok := DefaultProxySource().(PriorityProxySource)
	if !ok {
		t.Fatalf("source=%T", DefaultProxySource())
	}
	if _, ok := source.Administrator.(AdministratorProxySource); !ok {
		t.Fatalf("administrator=%T", source.Administrator)
	}
}

func TestPriorityProxySourceAndBypassComposition(t *testing.T) {
	source := PriorityProxySource{
		Administrator: StaticProxySource{Value: ProxySnapshot{NoProxy: "admin.test"}},
		Environment:   StaticProxySource{Value: ProxySnapshot{NoProxy: "env.test"}},
		System:        StaticProxySource{Value: ProxySnapshot{HTTPSProxy: "http://system.test", NoProxy: "system.test"}},
	}
	snapshot, err := source.Snapshot(context.Background())
	if err != nil || snapshot.HTTPSProxy != "http://system.test" || snapshot.NoProxy != "system.test,env.test,admin.test" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	source.Environment = StaticProxySource{Value: ProxySnapshot{HTTPSProxy: "http://environment.test"}}
	snapshot, _ = source.Snapshot(context.Background())
	if snapshot.HTTPSProxy != "http://environment.test" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	source.Administrator = StaticProxySource{Value: ProxySnapshot{HTTPSProxy: "http://administrator.test"}}
	snapshot, _ = source.Snapshot(context.Background())
	if snapshot.HTTPSProxy != "http://administrator.test" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestProxyExcludesSimpleSystemHosts(t *testing.T) {
	selectProxy, _, err := proxyFunction(ProxySnapshot{HTTPSProxy: "http://proxy.test", ExcludeSimpleHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://intranet/resource", nil)
	if value, err := selectProxy(request); err != nil || value != nil {
		t.Fatalf("proxy=%v err=%v", value, err)
	}
	request, _ = http.NewRequest(http.MethodGet, "https://intranet.test/resource", nil)
	if value, err := selectProxy(request); err != nil || value == nil {
		t.Fatalf("proxy=%v err=%v", value, err)
	}
}

func TestNativeSystemProxySnapshotIsSafe(t *testing.T) {
	snapshot, err := (NativeSystemProxySource{}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _, policyErr := proxyFunction(snapshot)
	var proxyErr *ProxyError
	if policyErr != nil && (!errors.As(policyErr, &proxyErr) || proxyErr.Failure != ProxyAutomaticConfigurationUnsupported) {
		t.Fatalf("snapshot rejected: %v", policyErr)
	}
}

type mutableProxySource struct {
	mu       sync.Mutex
	snapshot ProxySnapshot
}

func (s *mutableProxySource) Snapshot(context.Context) (ProxySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, nil
}
func (s *mutableProxySource) set(value ProxySnapshot) { s.mu.Lock(); s.snapshot = value; s.mu.Unlock() }

func connectProxy(t *testing.T, status int, targetAddress string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			writer.WriteHeader(status)
			return
		}
		target, err := net.Dial("tcp", targetAddress)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			_ = target.Close()
			t.Error("proxy response is not hijackable")
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			_ = target.Close()
			t.Error(err)
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(target, client); _ = target.Close() }()
		_, _ = io.Copy(client, target)
		_ = client.Close()
	}))
}

func TestDevelopmentTransportConfigIsBounded(t *testing.T) {
	config := DevelopmentConfig()
	if config.MaxConnsPerHost < 1 || config.MaxIdleConnsPerHost > config.MaxConnsPerHost || config.TLSHandshakeTimeout > 10*time.Second {
		t.Fatalf("config=%+v", config)
	}
}
