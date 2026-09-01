package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type fakeAccessTunnelRuntime struct {
	mu       sync.Mutex
	started  int
	released int
	session  accessTunnelSession
	startErr error
}

func (f *fakeAccessTunnelRuntime) Start(_ context.Context, selector, listen string) (accessTunnelSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	if f.startErr != nil {
		return accessTunnelSession{}, f.startErr
	}
	out := f.session
	if out.Schema == "" {
		out = accessTunnelSession{Schema: accessTunnelSchema, Kind: "private_tcp_access", ID: "access_1", TunnelID: "tun_1", RouteID: "route_tcp_1", ListenAddress: "127.0.0.1:24000"}
	}
	return out, nil
}
func (f *fakeAccessTunnelRuntime) Release(context.Context, accessTunnelSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
	return nil
}

func withAccessTunnelRuntime(t *testing.T, runtime accessTunnelRuntime) {
	t.Helper()
	old := accessTunnelRuntimeForCommand
	accessTunnelRuntimeForCommand = func() (accessTunnelRuntime, error) { return runtime, nil }
	t.Cleanup(func() { accessTunnelRuntimeForCommand = old })
}

func TestAccessTunnelCommandCancelsAndCleansUpWithoutSecrets(t *testing.T) {
	runtime := &fakeAccessTunnelRuntime{}
	withAccessTunnelRuntime(t, runtime)
	ctx, cancel := context.WithCancel(context.Background())
	output := &cancelAfterWrite{cancel: cancel}
	command := accessTunnelCobraCommandV1()
	command.SetContext(ctx)
	command.SetOut(output)
	command.SetArgs([]string{"tun_1", "--json"})
	err := command.Execute()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.started != 1 || runtime.released != 1 {
		t.Fatalf("started=%d released=%d", runtime.started, runtime.released)
	}
	lower := strings.ToLower(output.String())
	for _, forbidden := range []string{"grant", "token", "secret", "credential"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("unsafe output=%s", output.String())
		}
	}
}

func TestAccessTunnelCommandRejectsNonLiteralLoopbackBeforeRuntime(t *testing.T) {
	runtime := &fakeAccessTunnelRuntime{}
	withAccessTunnelRuntime(t, runtime)
	for _, listen := range []string{"localhost:0", "0.0.0.0:9000", "192.168.1.2:9000", "127.0.0.1:http"} {
		command := accessTunnelCobraCommandV1()
		command.SetArgs([]string{"tun_1", "--listen", listen})
		if err := command.Execute(); !errors.Is(err, ErrAccessTunnelInvalid) {
			t.Fatalf("listen=%q error=%v", listen, err)
		}
	}
	if runtime.started != 0 {
		t.Fatalf("started=%d", runtime.started)
	}
}

func TestLocalAccessTunnelClientMapsAuthenticationAuthorizationAndAvailability(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{{http.StatusUnauthorized, ErrAccessTunnelAuthentication}, {http.StatusForbidden, ErrAccessTunnelForbidden}, {http.StatusServiceUnavailable, ErrAccessTunnelUnavailable}, {http.StatusNotFound, ErrAccessTunnelRuntimeRPCUnavailable}} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer local-token" {
					t.Fatal("missing local token")
				}
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			client := &localAccessTunnelClient{base: base, token: "local-token", client: server.Client()}
			_, err := client.Start(context.Background(), "tun_1", "127.0.0.1:0")
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLocalAccessTunnelClientStrictlyBoundsAndDecodesResponse(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"duplicate", `{"schema":"paperboat.private-tcp-access/v1","schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access","id":"access_1","tunnel_id":"tun_1","route_id":"route_1","listen_address":"127.0.0.1:24000"}`},
		{"unknown", `{"schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access","id":"access_1","tunnel_id":"tun_1","route_id":"route_1","listen_address":"127.0.0.1:24000","grant":"must-not-appear"}`},
		{"oversized", strings.Repeat("x", accessTunnelResponseLimit+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			client := &localAccessTunnelClient{base: base, token: "local-token", client: server.Client()}
			if _, err := client.Start(context.Background(), "tun_1", "127.0.0.1:0"); !errors.Is(err, ErrAccessTunnelInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLocalAccessTunnelClientAcceptsSafeBoundSessionAndRelease(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["selector"] != "route_tcp_1" || body["listen_address"] != "127.0.0.1:0" {
			t.Fatalf("body=%#v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schema":"paperboat.private-tcp-access/v1","kind":"private_tcp_access","id":"access_1","tunnel_id":"tun_1","route_id":"route_tcp_1","listen_address":"127.0.0.1:24000"}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := &localAccessTunnelClient{base: base, token: "local-token", client: server.Client()}
	session, err := client.Start(context.Background(), "route_tcp_1", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Release(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestAccessTunnelHumanOutputIsCanonicalSafeEndpoint(t *testing.T) {
	runtime := &fakeAccessTunnelRuntime{}
	withAccessTunnelRuntime(t, runtime)
	ctx, cancel := context.WithCancel(context.Background())
	output := &cancelAfterWrite{cancel: cancel}
	command := accessTunnelCobraCommandV1()
	command.SetContext(ctx)
	command.SetOut(output)
	command.SetArgs([]string{"tun_1"})
	_ = command.Execute()
	if got := output.String(); got != "Private access for route route_tcp_1 is listening on 127.0.0.1:24000\n" {
		t.Fatalf("output=%q", got)
	}
}
