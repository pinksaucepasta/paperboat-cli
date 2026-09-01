package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/spf13/cobra"
)

func TestParsePreviewTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		scheme  string
		address string
		invalid bool
	}{
		{name: "port", input: "3000", scheme: "http", address: "127.0.0.1:3000"},
		{name: "http URL", input: "http://localhost:3000", scheme: "http", address: "localhost:3000"},
		{name: "https IPv6 URL", input: "https://[::1]:8443", scheme: "https", address: "[::1]:8443"},
		{name: "h2c URL", input: "h2c://127.0.0.1:8080", scheme: "h2c", address: "127.0.0.1:8080"},
		{name: "tcp URL", input: "tcp://relay.example.test:9000", scheme: "tcp", address: "relay.example.test:9000"},
		{name: "Unix URL", input: "unix:///run/my-app.sock", scheme: "unix", address: "/run/my-app.sock"},
		{name: "absolute Unix path", input: "/tmp/my-app.sock", scheme: "unix", address: "/tmp/my-app.sock"},
		{name: "zero port", input: "0", invalid: true},
		{name: "too large port", input: "65536", invalid: true},
		{name: "relative path", input: "./app.sock", invalid: true},
		{name: "URL missing port", input: "http://localhost", invalid: true},
		{name: "URL path", input: "http://localhost:3000/health", invalid: true},
		{name: "URL userinfo", input: "http://user:password@localhost:3000", invalid: true},
		{name: "URL query", input: "http://localhost:3000?token=secret", invalid: true},
		{name: "unsupported scheme", input: "ftp://localhost:21", invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parsePreviewTarget(test.input)
			if test.invalid {
				if err == nil || !errors.Is(err, ErrPreviewInvalidTarget) {
					t.Fatalf("error = %v, want ErrPreviewInvalidTarget", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Scheme != test.scheme || got.Address != test.address {
				t.Fatalf("target = %#v, want scheme=%q address=%q", got, test.scheme, test.address)
			}
		})
	}
}

func TestPreviewCommandSurfaceAndHelp(t *testing.T) {
	root := newRootCommand()
	previewCommand, remaining, err := root.Find([]string{"preview"})
	if err != nil || len(remaining) != 0 || previewCommand == root {
		t.Fatalf("preview lookup command=%v remaining=%v err=%v", previewCommand, remaining, err)
	}
	for _, child := range []string{"list", "stop"} {
		entry, remaining, err := root.Find([]string{"preview", child})
		if err != nil || len(remaining) != 0 || entry == root {
			t.Fatalf("preview %s lookup command=%v remaining=%v err=%v", child, entry, remaining, err)
		}
	}
	for _, removed := range []string{"create", "revoke", "serve", "previews"} {
		entry, remaining, err := root.Find(strings.Fields(removed))
		if err != nil || entry != root || len(remaining) != 1 {
			t.Fatalf("removed command %q is discoverable: command=%v remaining=%v err=%v", removed, entry, remaining, err)
		}
	}
	for _, flagName := range []string{"private", "duration", "domain", "json"} {
		if previewCommand.Flags().Lookup(flagName) == nil {
			t.Fatalf("preview missing --%s", flagName)
		}
	}
	for _, removed := range []string{"public", "name", "machine", "indefinite", "detach", "listen-port"} {
		if previewCommand.Flags().Lookup(removed) != nil {
			t.Fatalf("preview exposes removed --%s", removed)
		}
	}

	var help bytes.Buffer
	helpRoot := newRootCommand()
	helpRoot.SetOut(&help)
	helpRoot.SetErr(&help)
	helpRoot.SetArgs([]string{"preview", "--help"})
	if err := helpRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := help.String()
	for _, want := range []string{"pb preview <port|url|path>", "--private", "--duration", "--domain", "--json", "list", "stop"} {
		if !strings.Contains(text, want) {
			t.Fatalf("help missing %q: %s", want, text)
		}
	}
	for _, removed := range []string{"--public", "--name", "create", "revoke"} {
		if strings.Contains(text, removed) {
			t.Fatalf("help contains removed %q: %s", removed, text)
		}
	}

	stop, _, err := root.Find([]string{"preview", "stop"})
	if err != nil || stop.ValidArgsFunction == nil {
		t.Fatalf("preview stop completion missing: command=%v err=%v", stop, err)
	}
}

func TestPreviewForegroundPublishesCanonicalResourceOnlyAfterReadiness(t *testing.T) {
	var requestsMu sync.Mutex
	var requests []string
	server := newPreviewCommandServer(t, func(r *http.Request, body map[string]any) (any, string, int) {
		requestsMu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		requestsMu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case http.MethodPost + " /v1/previews":
			target, ok := body["target"].(map[string]any)
			if !ok || target["scheme"] != "http" || target["address"] != "127.0.0.1:3000" {
				t.Fatalf("create target = %#v", body["target"])
			}
			if body["access_mode"] != "public" {
				t.Fatalf("create access_mode = %#v", body["access_mode"])
			}
			return previewCommandLease("prv_cli_1", "device_cli", body["owner_session_id"].(string), "http", "127.0.0.1:3000", "connecting"), `"ptv1:preview_lease:cHJ2X2NsaV8x:1"`, http.StatusOK
		case http.MethodDelete + " /v1/previews/prv_cli_1":
			value := previewCommandLease("prv_cli_1", "device_cli", "session_unused", "http", "127.0.0.1:3000", "stopped")
			value["allocation_state"] = "released"
			value["edge_state"] = "down"
			return value, `"ptv1:preview_lease:cHJ2X2NsaV8x:2"`, http.StatusOK
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, "", http.StatusNotFound
		}
	})
	defer server.Close()

	client := api.New(server.URL, config.Credential{AccessToken: "test-token"}, server.Client())
	previousClient := previewClientForCommand
	previousMachine := previewMachineID
	previousCarrier := newPreviewCarrier
	t.Cleanup(func() {
		previewClientForCommand = previousClient
		previewMachineID = previousMachine
		newPreviewCarrier = previousCarrier
	})
	previewClientForCommand = func(*cobra.Command) (*api.Client, error) { return client, nil }
	previewMachineID = func() (string, error) { return "device_cli", nil }
	carrier := &cliPreviewCarrier{ready: make(chan struct{})}
	newPreviewCarrier = func(context.Context, preview.LeaseTarget, string, string) (preview.Carrier, error) {
		return carrier, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := previewCobraCommandV1()
	var output lockedPreviewWriter
	command.SetOut(&output)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"3000", "--json"})
	result := make(chan error, 1)
	go func() { result <- command.ExecuteContext(ctx) }()
	select {
	case <-carrier.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("carrier did not receive the lease")
	}
	deadline := time.After(2 * time.Second)
	for output.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("preview command did not publish output after readiness")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	var resource api.PreviewLease
	outputBytes := output.Bytes()
	if err := json.Unmarshal(outputBytes, &resource); err != nil {
		t.Fatalf("JSON output = %q: %v", string(outputBytes), err)
	}
	if resource.Schema != api.PreviewTunnelSchemaV1 || resource.Kind != "preview_lease" || resource.State != "ready" || resource.Endpoint == "" || resource.Target.Address != "127.0.0.1:3000" {
		t.Fatalf("resource = %#v", resource)
	}
	if strings.Contains(output.String(), "credential") || strings.Contains(output.String(), "token") {
		t.Fatalf("JSON output contains secret-bearing field: %s", string(outputBytes))
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("preview command did not stop after context cancellation")
	}
	requestsMu.Lock()
	gotRequests := append([]string(nil), requests...)
	requestsMu.Unlock()
	if strings.Join(gotRequests, ",") != "POST /v1/previews,DELETE /v1/previews/prv_cli_1" {
		t.Fatalf("requests = %v", gotRequests)
	}
}

func TestPreviewForegroundProductionOwnerLeaseBindsCreateAndReleasesOnExit(t *testing.T) {
	apiServer := newPreviewCommandServer(t, func(r *http.Request, body map[string]any) (any, string, int) {
		switch r.Method + " " + r.URL.Path {
		case http.MethodPost + " /v1/previews":
			owner, ok := body["owner_session_id"].(string)
			if !ok || !strings.HasPrefix(owner, "owner_") {
				t.Fatalf("create was not bound to a hostd-minted owner session: %#v", body["owner_session_id"])
			}
			return previewCommandLease("prv_owner_1", "device_cli", owner, "http", "127.0.0.1:3000", "connecting"), `"ptv1:preview_lease:cHJ2X293bmVyXzE:1"`, http.StatusOK
		case http.MethodDelete + " /v1/previews/prv_owner_1":
			value := previewCommandLease("prv_owner_1", "device_cli", "session_unused", "http", "127.0.0.1:3000", "stopped")
			value["allocation_state"], value["edge_state"] = "released", "down"
			return value, `"ptv1:preview_lease:cHJ2X293bmVyXzE:2"`, http.StatusOK
		default:
			t.Fatalf("unexpected API request %s %s", r.Method, r.URL.Path)
			return nil, "", http.StatusNotFound
		}
	})
	defer apiServer.Close()
	runtimeDone := make(chan struct{})
	registry, err := preview.NewRuntimeOwnerSessionRegistry(preview.RuntimeOwnerSessionRegistryConfig{MachineID: "device_cli", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler := &recordingOwnerLeaseHandler{}
	ownerManager, err := preview.NewOwnerSessionLeaseManager(preview.OwnerSessionLeaseManagerConfig{MachineID: "device_cli", ControlToken: "control_secret", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler.next = ownerManager
	ownerServer := httptest.NewServer(ownerHandler)
	defer ownerServer.Close()
	ownerClient, err := preview.NewLocalOwnerSessionClient(ownerServer.URL, "control_secret", ownerServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	apiClient := api.New(apiServer.URL, config.Credential{AccessToken: "test-token"}, apiServer.Client())
	carrier := &productionOwnerLeaseCarrier{ready: make(chan struct{}), owner: make(chan string, 1)}
	previousClient := previewClientForCommand
	previousMachine := previewMachineID
	previousCarrier := newPreviewCarrier
	previousOwnerClient := previewOwnerSessionClientForCommand
	t.Cleanup(func() {
		previewClientForCommand = previousClient
		previewMachineID = previousMachine
		newPreviewCarrier = previousCarrier
		previewOwnerSessionClientForCommand = previousOwnerClient
		_ = ownerManager.Close()
	})
	previewClientForCommand = func(*cobra.Command) (*api.Client, error) { return apiClient, nil }
	previewMachineID = func() (string, error) { return "device_cli", nil }
	newPreviewCarrier = func(_ context.Context, _ preview.LeaseTarget, _, ownerID string) (preview.Carrier, error) {
		if ownerID != "" {
			t.Fatalf("production carrier received a CLI-generated owner ID %q", ownerID)
		}
		return carrier, nil
	}
	previewOwnerSessionClientForCommand = func() (*preview.LocalOwnerSessionClient, error) { return ownerClient, nil }

	ctx, cancel := context.WithCancel(context.Background())
	command := previewCobraCommandV1()
	var output lockedPreviewWriter
	command.SetOut(&output)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"3000"})
	done := make(chan error, 1)
	go func() { done <- command.ExecuteContext(ctx) }()
	var ownerID string
	select {
	case ownerID = <-carrier.owner:
	case <-time.After(2 * time.Second):
		t.Fatal("production carrier did not receive hostd owner session")
	}
	if ownerID == "" || !strings.HasPrefix(ownerID, "owner_") {
		t.Fatalf("owner session = %q", ownerID)
	}
	select {
	case <-carrier.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("production carrier did not report readiness")
	}
	outputDeadline := time.After(2 * time.Second)
	for output.Len() == 0 {
		select {
		case <-outputDeadline:
			t.Fatal("preview command did not publish output")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("preview command result=%v local_calls=%v", err, ownerHandler.methods())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preview command did not stop")
	}
	if ownerHandler.count(http.MethodPost) != 1 || ownerHandler.count(http.MethodDelete) != 1 {
		t.Fatalf("local owner lease calls = %v", ownerHandler.methods())
	}
}

func TestPreviewForegroundProductionOwnerLeaseFailureCancelsAndReleases(t *testing.T) {
	apiServer := newPreviewCommandServer(t, func(r *http.Request, _ map[string]any) (any, string, int) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/previews" {
			return map[string]any{"error": map[string]string{"code": "preview_unavailable"}}, "", http.StatusServiceUnavailable
		}
		t.Fatalf("unexpected API request %s %s", r.Method, r.URL.Path)
		return nil, "", http.StatusNotFound
	})
	defer apiServer.Close()
	runtimeDone := make(chan struct{})
	registry, err := preview.NewRuntimeOwnerSessionRegistry(preview.RuntimeOwnerSessionRegistryConfig{MachineID: "device_cli", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler := &recordingOwnerLeaseHandler{}
	ownerManager, err := preview.NewOwnerSessionLeaseManager(preview.OwnerSessionLeaseManagerConfig{MachineID: "device_cli", ControlToken: "control_secret", Registry: registry, TTL: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler.next = ownerManager
	ownerServer := httptest.NewServer(ownerHandler)
	defer ownerServer.Close()
	ownerClient, err := preview.NewLocalOwnerSessionClient(ownerServer.URL, "control_secret", ownerServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	apiClient := api.New(apiServer.URL, config.Credential{AccessToken: "test-token"}, apiServer.Client())
	carrier := &productionOwnerLeaseCarrier{ready: make(chan struct{}), owner: make(chan string, 1)}
	previousClient := previewClientForCommand
	previousMachine := previewMachineID
	previousCarrier := newPreviewCarrier
	previousOwnerClient := previewOwnerSessionClientForCommand
	t.Cleanup(func() {
		previewClientForCommand = previousClient
		previewMachineID = previousMachine
		newPreviewCarrier = previousCarrier
		previewOwnerSessionClientForCommand = previousOwnerClient
		_ = ownerManager.Close()
	})
	previewClientForCommand = func(*cobra.Command) (*api.Client, error) { return apiClient, nil }
	previewMachineID = func() (string, error) { return "device_cli", nil }
	newPreviewCarrier = func(context.Context, preview.LeaseTarget, string, string) (preview.Carrier, error) {
		return carrier, nil
	}
	previewOwnerSessionClientForCommand = func() (*preview.LocalOwnerSessionClient, error) { return ownerClient, nil }
	command := previewCobraCommandV1()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"3000"})
	if err := command.ExecuteContext(context.Background()); err == nil {
		t.Fatal("preview create unexpectedly succeeded")
	}
	if ownerHandler.count(http.MethodPost) != 1 || ownerHandler.count(http.MethodDelete) != 1 {
		t.Fatalf("local owner lease calls = %v", ownerHandler.methods())
	}
}

func TestPreviewForegroundProductionOwnerLeaseHeartbeatFailureCancels(t *testing.T) {
	apiServer := newPreviewCommandServer(t, func(r *http.Request, body map[string]any) (any, string, int) {
		switch r.Method + " " + r.URL.Path {
		case http.MethodPost + " /v1/previews":
			owner := body["owner_session_id"].(string)
			return previewCommandLease("prv_owner_2", "device_cli", owner, "http", "127.0.0.1:3000", "connecting"), `"ptv1:preview_lease:cHJ2X293bmVyXzI:1"`, http.StatusOK
		case http.MethodDelete + " /v1/previews/prv_owner_2":
			value := previewCommandLease("prv_owner_2", "device_cli", "session_unused", "http", "127.0.0.1:3000", "stopped")
			value["allocation_state"], value["edge_state"] = "released", "down"
			return value, `"ptv1:preview_lease:cHJ2X293bmVyXzI:2"`, http.StatusOK
		default:
			t.Fatalf("unexpected API request %s %s", r.Method, r.URL.Path)
			return nil, "", http.StatusNotFound
		}
	})
	defer apiServer.Close()
	runtimeDone := make(chan struct{})
	registry, err := preview.NewRuntimeOwnerSessionRegistry(preview.RuntimeOwnerSessionRegistryConfig{MachineID: "device_cli", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler := &recordingOwnerLeaseHandler{}
	ownerManager, err := preview.NewOwnerSessionLeaseManager(preview.OwnerSessionLeaseManagerConfig{MachineID: "device_cli", ControlToken: "control_secret", Registry: registry, TTL: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ownerHandler.next = ownerManager
	ownerServer := httptest.NewServer(ownerHandler)
	defer ownerServer.Close()
	baseTransport := ownerServer.Client().Transport
	failTransport := &failOwnerHeartbeatTransport{base: baseTransport}
	ownerClient, err := preview.NewLocalOwnerSessionClient(ownerServer.URL, "control_secret", &http.Client{Transport: failTransport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	apiClient := api.New(apiServer.URL, config.Credential{AccessToken: "test-token"}, apiServer.Client())
	carrier := &productionOwnerLeaseCarrier{ready: make(chan struct{}), owner: make(chan string, 1)}
	previousClient := previewClientForCommand
	previousMachine := previewMachineID
	previousCarrier := newPreviewCarrier
	previousOwnerClient := previewOwnerSessionClientForCommand
	t.Cleanup(func() {
		previewClientForCommand = previousClient
		previewMachineID = previousMachine
		newPreviewCarrier = previousCarrier
		previewOwnerSessionClientForCommand = previousOwnerClient
		_ = ownerManager.Close()
	})
	previewClientForCommand = func(*cobra.Command) (*api.Client, error) { return apiClient, nil }
	previewMachineID = func() (string, error) { return "device_cli", nil }
	newPreviewCarrier = func(context.Context, preview.LeaseTarget, string, string) (preview.Carrier, error) {
		return carrier, nil
	}
	previewOwnerSessionClientForCommand = func() (*preview.LocalOwnerSessionClient, error) { return ownerClient, nil }
	command := previewCobraCommandV1()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"3000"})
	started := make(chan error, 1)
	go func() { started <- command.ExecuteContext(context.Background()) }()
	select {
	case <-carrier.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("preview did not become ready before heartbeat failure")
	}
	select {
	case err := <-started:
		if !errors.Is(err, ErrPreviewOwnerSessionUnavailable) {
			t.Fatalf("heartbeat result = %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("heartbeat failure did not cancel preview; calls=%v transport_puts=%d", ownerHandler.methods(), failTransport.putsCount())
	}
	if failTransport.putsCount() == 0 || ownerHandler.count(http.MethodDelete) != 1 {
		t.Fatalf("local owner lease calls = %v transport_puts=%d", ownerHandler.methods(), failTransport.putsCount())
	}
}

func TestPreviewListAndStopUseCanonicalLeaseClient(t *testing.T) {
	server := newPreviewCommandServer(t, func(r *http.Request, _ map[string]any) (any, string, int) {
		lease := previewCommandLease("prv_cli_2", "device_cli", "session_cli", "https", "localhost:8443", "ready")
		switch r.Method + " " + r.URL.Path {
		case http.MethodGet + " /v1/previews":
			if r.URL.Query().Get("limit") != "100" {
				t.Fatalf("list limit = %q", r.URL.Query().Get("limit"))
			}
			return map[string]any{"items": []any{lease}, "next_cursor": ""}, "", http.StatusOK
		case http.MethodGet + " /v1/previews/prv_cli_2":
			return lease, `"ptv1:preview_lease:cHJ2X2NsaV8y:1"`, http.StatusOK
		case http.MethodDelete + " /v1/previews/prv_cli_2":
			lease["state"] = "stopped"
			lease["allocation_state"] = "released"
			lease["edge_state"] = "down"
			return lease, `"ptv1:preview_lease:cHJ2X2NsaV8y:2"`, http.StatusOK
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, "", http.StatusNotFound
		}
	})
	defer server.Close()
	client := api.New(server.URL, config.Credential{AccessToken: "test-token"}, server.Client())
	previous := previewClientForCommand
	t.Cleanup(func() { previewClientForCommand = previous })
	previewClientForCommand = func(*cobra.Command) (*api.Client, error) { return client, nil }

	list := previewCobraCommandV1()
	var listOutput bytes.Buffer
	list.SetOut(&listOutput)
	list.SetErr(io.Discard)
	list.SetArgs([]string{"list", "--json"})
	if err := list.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var page api.PreviewLeasePage
	if err := json.Unmarshal(listOutput.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != "prv_cli_2" {
		t.Fatalf("list output=%q page=%#v err=%v", listOutput.String(), page, err)
	}

	stop := previewCobraCommandV1()
	var stopOutput bytes.Buffer
	stop.SetOut(&stopOutput)
	stop.SetErr(io.Discard)
	stop.SetArgs([]string{"stop", "prv_cli_2", "--json"})
	if err := stop.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var stopped api.PreviewLease
	if err := json.Unmarshal(stopOutput.Bytes(), &stopped); err != nil || stopped.State != "stopped" {
		t.Fatalf("stop output=%q lease=%#v err=%v", stopOutput.String(), stopped, err)
	}
}

type cliPreviewCarrier struct {
	ready chan struct{}
	once  sync.Once
}

type productionOwnerLeaseCarrier struct {
	ready chan struct{}
	owner chan string
	once  sync.Once
}

func (*productionOwnerLeaseCarrier) NeedsOwnerSessionLease() bool { return true }

func (c *productionOwnerLeaseCarrier) Run(ctx context.Context, lease preview.Lease, ready func(preview.Lease) error) error {
	select {
	case c.owner <- lease.OwnerSessionID:
	default:
	}
	lease.State, lease.AllocationState, lease.EdgeState, lease.OriginState = "ready", "ready", "ready", "ready"
	if err := ready(lease); err != nil {
		return err
	}
	c.once.Do(func() { close(c.ready) })
	<-ctx.Done()
	return nil
}

func (*productionOwnerLeaseCarrier) Close(context.Context) error { return nil }

type recordingOwnerLeaseHandler struct {
	next     http.Handler
	mu       sync.Mutex
	requests []string
}

func (h *recordingOwnerLeaseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests = append(h.requests, r.Method)
	h.mu.Unlock()
	h.next.ServeHTTP(w, r)
}

func (h *recordingOwnerLeaseHandler) count(method string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, got := range h.requests {
		if got == method {
			count++
		}
	}
	return count
}

func (h *recordingOwnerLeaseHandler) methods() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.requests...)
}

type failOwnerHeartbeatTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	puts int
}

func (t *failOwnerHeartbeatTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut {
		t.mu.Lock()
		t.puts++
		t.mu.Unlock()
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"code":"owner_session_lost"}}`)), Request: r}, nil
	}
	return t.base.RoundTrip(r)
}

func (t *failOwnerHeartbeatTransport) putsCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.puts
}

func (c *cliPreviewCarrier) Run(ctx context.Context, lease preview.Lease, ready func(preview.Lease) error) error {
	lease.State, lease.AllocationState, lease.EdgeState, lease.OriginState = "ready", "ready", "ready", "ready"
	if err := ready(lease); err != nil {
		return err
	}
	c.once.Do(func() { close(c.ready) })
	<-ctx.Done()
	return nil
}

func (*cliPreviewCarrier) Close(context.Context) error { return nil }

type lockedPreviewWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedPreviewWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(value)
}

func (w *lockedPreviewWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

func (w *lockedPreviewWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *lockedPreviewWriter) String() string {
	return string(w.Bytes())
}

func newPreviewCommandServer(t *testing.T, handler func(*http.Request, map[string]any) (any, string, int)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode %s %s request: %v", r.Method, r.URL.Path, err)
			}
		}
		data, etag, status := handler(r, body)
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/previews" {
			w.Header().Set("X-Paperboat-Operation-ID", "operation_preview_cli_1")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if data != nil {
			if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		}
	}))
}

func previewCommandLease(id, device, session, scheme, address, state string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"schema": api.PreviewTunnelSchemaV1, "kind": "preview_lease", "id": id, "account_id": "acct_cli", "actor_id": "actor_cli",
		"owner_device_id": device, "owner_session_id": session, "target": map[string]string{"scheme": scheme, "address": address},
		"access_mode": "public", "persistent": false, "endpoint": "https://quiet-river-7.preview.example.test", "lease_deadline": now.Add(time.Hour),
		"state": state, "allocation_state": map[bool]string{true: "ready", false: "pending"}[state == "ready"], "edge_state": map[bool]string{true: "ready", false: "pending"}[state == "ready"],
		"origin_state": map[bool]string{true: "ready", false: "unknown"}[state == "ready"], "created_at": now, "last_renewed_at": now,
	}
}
