package preview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

type privateTCPAccessTestProxy struct {
	mu     sync.Mutex
	closed int
	rawURL string
}

func (p *privateTCPAccessTestProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed++
	return nil
}
func (p *privateTCPAccessTestProxy) AccessURL() string { return p.rawURL }

func newPrivateTCPAccessTestManager(t *testing.T, maximum int, resolve func(context.Context, string) (string, string, error), start func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error)) (*PrivateTCPAccessManager, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	counter := 0
	manager, err := NewPrivateTCPAccessManager(PrivateTCPAccessManagerConfig{ControlToken: "local-token", RunContext: ctx, MaximumActive: maximum, resolve: resolve, start: start, newID: func() (string, error) { counter++; return "id_" + string(rune('0'+counter)), nil }})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = manager.Close() })
	return manager, cancel
}

func privateTCPAccessRequest(t *testing.T, manager http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	manager.ServeHTTP(recorder, request)
	return recorder
}
func validPrivateTCPAccessBody(selector string) string {
	raw, _ := json.Marshal(privateTCPAccessRequestDocument{Schema: PrivateTCPAccessSchema, Kind: "private_tcp_access_request", Selector: selector, ListenAddress: "127.0.0.1:0"})
	return string(raw)
}

func TestPrivateTCPAccessManagerAuthorizesBeforePublishingAndDeleteIsReplaySafe(t *testing.T) {
	proxy := &privateTCPAccessTestProxy{rawURL: "http://127.0.0.1:24001"}
	resolved := false
	manager, _ := newPrivateTCPAccessTestManager(t, 2, func(_ context.Context, selector string) (string, string, error) {
		resolved = true
		if selector != "tun_1" {
			t.Fatalf("selector=%q", selector)
		}
		return "route_tcp_1", "tun_1", nil
	}, func(_ context.Context, request PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
		if !resolved {
			t.Fatal("listener started before route authorization")
		}
		if request.RouteID != "route_tcp_1" || request.ListenPort != 0 || request.MaximumConnections != 128 {
			t.Fatalf("request=%#v", request)
		}
		return proxy, nil
	})
	response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, secret := range []string{"local-token", "grant", "credential", "secret"} {
		if strings.Contains(strings.ToLower(body), secret) {
			t.Fatalf("secret output=%s", body)
		}
	}
	var session privateTCPAccessResponseDocument
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.RouteID != "route_tcp_1" || session.ListenAddress != "127.0.0.1:24001" {
		t.Fatalf("session=%#v", session)
	}
	for i := 0; i < 2; i++ {
		deleted := privateTCPAccessRequest(t, manager, http.MethodDelete, "/v1/private-tcp-access/"+session.ID, "local-token", "")
		if deleted.Code != http.StatusNoContent {
			t.Fatalf("delete %d status=%d", i, deleted.Code)
		}
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.closed != 1 {
		t.Fatalf("closed=%d", proxy.closed)
	}
}

func TestPrivateTCPAccessManagerMapsMissingAmbiguousStaleAndBindFailure(t *testing.T) {
	tests := []struct {
		name                 string
		resolveErr, startErr error
		url                  string
		status               int
		code                 string
	}{
		{"missing", ErrPrivateTCPAccessNotFound, nil, "", http.StatusForbidden, "access_forbidden"},
		{"ambiguous", ErrPrivateTCPAccessUnavailable, nil, "", http.StatusServiceUnavailable, "runtime_unavailable"},
		{"stale", nil, privatepreviewproxy.ErrAccessForbidden, "", http.StatusForbidden, "access_forbidden"},
		{"bind", nil, nil, "http://0.0.0.0:22000", http.StatusServiceUnavailable, "runtime_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, _ := newPrivateTCPAccessTestManager(t, 1, func(context.Context, string) (string, string, error) {
				if test.resolveErr != nil {
					return "", "", test.resolveErr
				}
				return "route_1", "tun_1", nil
			}, func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
				if test.startErr != nil {
					return nil, test.startErr
				}
				return &privateTCPAccessTestProxy{rawURL: test.url}, nil
			})
			response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1"))
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPrivateTCPAccessManagerCapacityAuthenticationAndStrictBody(t *testing.T) {
	manager, _ := newPrivateTCPAccessTestManager(t, 1, func(context.Context, string) (string, string, error) { return "route_1", "tun_1", nil }, func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
		return &privateTCPAccessTestProxy{rawURL: "http://127.0.0.1:22000"}, nil
	})
	if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "", validPrivateTCPAccessBody("tun_1")); response.Code != http.StatusUnauthorized {
		t.Fatalf("auth status=%d", response.Code)
	}
	duplicate := `{"schema":"paperboat.private-tcp-access/v1","schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access_request","selector":"tun_1","listen_address":"127.0.0.1:0"}`
	if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", duplicate); response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate status=%d", response.Code)
	}
	if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", strings.Repeat("x", privateTCPAccessBodyLimit+1)); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d", response.Code)
	}
	if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1")); response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1")); response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "capacity_exhausted") {
		t.Fatalf("capacity status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPrivateTCPAccessManagerShutdownClosesEverySessionAndRejectsNew(t *testing.T) {
	var proxies []*privateTCPAccessTestProxy
	manager, cancel := newPrivateTCPAccessTestManager(t, 3, func(context.Context, string) (string, string, error) { return "route_1", "tun_1", nil }, func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
		proxy := &privateTCPAccessTestProxy{rawURL: "http://127.0.0.1:22000"}
		proxies = append(proxies, proxy)
		return proxy, nil
	})
	for i := 0; i < 2; i++ {
		if response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1")); response.Code != http.StatusCreated {
			t.Fatalf("status=%d", response.Code)
		}
	}
	cancel()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	for _, proxy := range proxies {
		if proxy.closed != 1 {
			t.Fatalf("closed=%d", proxy.closed)
		}
	}
	response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", validPrivateTCPAccessBody("tun_1"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestPrivateTCPAccessManagerRejectsNonLoopbackAndUnknownFields(t *testing.T) {
	manager, _ := newPrivateTCPAccessTestManager(t, 1, func(context.Context, string) (string, string, error) { return "route_1", "tun_1", nil }, func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
		return nil, errors.New("must not run")
	})
	for _, body := range []string{`{"schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access_request","selector":"tun_1","listen_address":"0.0.0.0:9000"}`, `{"schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access_request","selector":"tun_1","listen_address":"127.0.0.1:0","grant":"secret"}`} {
		response := privateTCPAccessRequest(t, manager, http.MethodPost, "/v1/private-tcp-access", "local-token", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestResolvePrivateTCPAdmissionSupportsExactIDsAndNames(t *testing.T) {
	admissions := []accessorAdmission{
		{ResourceKind: "tunnel", Protocol: "private_tcp", ResourceID: "tun_1", TunnelID: "tun_1", TunnelName: "payments", RouteID: "route_tcp_1", RouteName: "postgres"},
		{ResourceKind: "tunnel", Protocol: "http", ResourceID: "tun_1", TunnelID: "tun_1", TunnelName: "payments", RouteID: "route_http_1", RouteName: "web"},
	}
	for _, selector := range []string{"tun_1", "route_tcp_1", "payments", "postgres", "  postgres  "} {
		selected, err := resolvePrivateTCPAdmission(admissions, selector)
		if err != nil || selected.RouteID != "route_tcp_1" || selected.TunnelID != "tun_1" {
			t.Fatalf("selector %q selected=%#v err=%v", selector, selected, err)
		}
	}
}

func TestResolvePrivateTCPAdmissionRejectsAmbiguousAndUnavailableNames(t *testing.T) {
	admissions := []accessorAdmission{
		{ResourceKind: "tunnel", Protocol: "private_tcp", ResourceID: "tun_1", TunnelID: "tun_1", TunnelName: "payments", RouteID: "route_tcp_1", RouteName: "database"},
		{ResourceKind: "tunnel", Protocol: "private_tcp", ResourceID: "tun_2", TunnelID: "tun_2", TunnelName: "analytics", RouteID: "route_tcp_2", RouteName: "database"},
	}
	if _, err := resolvePrivateTCPAdmission(admissions, "database"); !errors.Is(err, ErrPrivateTCPAccessUnavailable) {
		t.Fatalf("ambiguous name error=%v", err)
	}
	if _, err := resolvePrivateTCPAdmission(admissions, "missing"); !errors.Is(err, ErrPrivateTCPAccessNotFound) {
		t.Fatalf("missing name error=%v", err)
	}
	if _, err := resolvePrivateTCPAdmission(admissions, "bad/name"); !errors.Is(err, ErrPrivateTCPAccessInvalid) {
		t.Fatalf("invalid name error=%v", err)
	}
	for _, selector := range []string{"Payment", "pay", "páyments"} {
		if _, err := resolvePrivateTCPAdmission(admissions, selector); !errors.Is(err, ErrPrivateTCPAccessNotFound) {
			t.Fatalf("confusable selector %q error=%v", selector, err)
		}
	}
}

func TestResolvePrivateTCPAdmissionRejectsNameCollidingWithAnotherRouteID(t *testing.T) {
	admissions := []accessorAdmission{
		{ResourceKind: "tunnel", Protocol: "private_tcp", ResourceID: "tun_1", TunnelID: "tun_1", TunnelName: "payments", RouteID: "route_tcp_1", RouteName: "route_tcp_2"},
		{ResourceKind: "tunnel", Protocol: "private_tcp", ResourceID: "tun_2", TunnelID: "tun_2", TunnelName: "analytics", RouteID: "route_tcp_2", RouteName: "postgres"},
	}
	if _, err := resolvePrivateTCPAdmission(admissions, "route_tcp_2"); !errors.Is(err, ErrPrivateTCPAccessUnavailable) {
		t.Fatalf("name-to-ID collision error=%v", err)
	}
	admissions[1].TunnelName = "payments"
	if _, err := resolvePrivateTCPAdmission(admissions, "payments"); !errors.Is(err, ErrPrivateTCPAccessUnavailable) {
		t.Fatalf("duplicate tunnel name error=%v", err)
	}
}
