package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/spf13/cobra"
)

func TestPreviewCommandDomainsUsesCanonicalRequestAndSafeProjection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var mu sync.Mutex
	var createDomains []string
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()

		var body struct {
			OwnerSessionID string   `json:"owner_session_id"`
			Domains        []string `json:"domains"`
		}
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode %s %s: %v", r.Method, r.URL.Path, err)
			}
		}

		var value map[string]any
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/previews":
			createDomains = append([]string(nil), body.Domains...)
			value = previewDomainCommandLease(now, "connecting", body.OwnerSessionID)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/previews/prv_domains":
			value = previewDomainCommandLease(now, "ready", "session_cli")
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/previews/prv_domains":
			value = previewDomainCommandLease(now, "stopped", "session_cli")
			value["allocation_state"], value["edge_state"] = "released", "down"
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2X2RvbWFpbnM:1"`)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/previews" {
			w.Header().Set("X-Paperboat-Operation-ID", "operation_preview_domains")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
	}))
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
	command.SetArgs([]string{"3000", "--domain", "BÜCHER.Example.", "--domain", "APP.Example.com.", "--json"})
	result := make(chan error, 1)
	go func() { result <- command.ExecuteContext(ctx) }()

	select {
	case <-carrier.ready:
	case <-time.After(2 * time.Second):
		select {
		case err := <-result:
			t.Fatalf("carrier did not report readiness; command error: %v", err)
		default:
			t.Fatal("carrier did not report readiness")
		}
	}
	deadline := time.After(2 * time.Second)
	for output.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("preview command did not publish JSON")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	var lease api.PreviewLease
	if err := json.Unmarshal(output.Bytes(), &lease); err != nil {
		t.Fatalf("JSON output = %q: %v", output.String(), err)
	}
	if lease.ID != "prv_domains" || lease.State != "ready" || lease.Endpoint == "" || len(lease.Domains) != 2 {
		t.Fatalf("lease projection = %#v", lease)
	}
	if got := []string{lease.Domains[0].Hostname, lease.Domains[1].Hostname}; !reflect.DeepEqual(got, []string{"app.example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("domain projection = %#v", got)
	}
	if lease.Domains[0].TargetKind != "preview_lease" || lease.Domains[0].PreviewID != lease.ID || lease.Domains[0].Instructions == nil {
		t.Fatalf("domain binding = %#v", lease.Domains[0])
	}
	if bytes.Contains(output.Bytes(), []byte("token")) || bytes.Contains(output.Bytes(), []byte("private_key")) {
		t.Fatalf("JSON output contains a secret-bearing field: %s", output.String())
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("preview command did not stop")
	}
	mu.Lock()
	gotRequests := append([]string(nil), requests...)
	gotCreateDomains := append([]string(nil), createDomains...)
	mu.Unlock()
	if !reflect.DeepEqual(gotCreateDomains, []string{"app.example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("create domains = %#v", gotCreateDomains)
	}
	if len(gotRequests) < 3 || gotRequests[0] != "POST /v1/previews" || gotRequests[1] != "GET /v1/previews/prv_domains" {
		t.Fatalf("API request sequence = %#v", gotRequests)
	}
}

func previewDomainCommandLease(now time.Time, state, ownerSessionID string) map[string]any {
	lease := map[string]any{
		"schema": api.PreviewTunnelSchemaV1, "kind": "preview_lease", "id": "prv_domains", "account_id": "acct_cli", "actor_id": "actor_cli",
		"owner_device_id": "device_cli", "owner_session_id": ownerSessionID,
		"target": map[string]string{"scheme": "http", "address": "127.0.0.1:3000"}, "access_mode": "public", "persistent": false,
		"endpoint": "https://preview-domain.preview.example.test", "lease_deadline": now.Add(time.Hour), "user_deadline": nil,
		"state": state, "allocation_state": "pending", "edge_state": "pending", "origin_state": "unknown",
		"created_at": now, "last_renewed_at": now,
	}
	if state == "ready" {
		lease["allocation_state"], lease["edge_state"], lease["origin_state"] = "ready", "ready", "ready"
	}
	lease["domains"] = []map[string]any{
		{
			"id": "domain_app", "target_kind": "preview_lease", "preview_id": "prv_domains", "hostname": "app.example.com", "match_type": "exact", "state": "ready",
			"dns":         map[string]any{"target": "domains.example.test", "observed_records": []string{"domains.example.test"}},
			"certificate": map[string]any{"state": "ready", "reference": "certificate_app", "expires_at": now.Add(30 * 24 * time.Hour)}, "generation": 1, "etag": `"domain_app:1"`,
			"instructions": map[string]any{
				"schema": api.PreviewTunnelSchemaV1, "kind": "dns_instructions", "target_kind": "preview_lease", "preview_id": "prv_domains", "domain_id": "domain_app", "hostname": "app.example.com", "provider": "generic",
				"records": []map[string]any{{"name": "_acme-challenge.app.example.com", "type": "CNAME", "value": "pb-app.challenge.example.test", "ttl": 300}}, "certificate_strategy": "delegated_dns01", "verification_state": "waiting_dns", "note": "Create this CNAME.",
			},
		},
		{
			"id": "domain_bucher", "target_kind": "preview_lease", "preview_id": "prv_domains", "hostname": "xn--bcher-kva.example", "match_type": "exact", "state": "ready",
			"dns": map[string]any{"target": "domains.example.test"}, "certificate": map[string]any{"state": "ready"}, "generation": 1, "etag": `"domain_bucher:1"`,
		},
	}
	return lease
}

func TestObservePreviewDomainsDoesNotReportReadyBeforeCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var mu sync.Mutex
	getCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/previews/prv_domains" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		mu.Lock()
		getCalls++
		call := getCalls
		mu.Unlock()
		value := previewDomainCommandLease(now, "ready", "session_cli")
		if call == 1 {
			value = previewDomainCommandLease(now, "connecting", "session_cli")
			domains := value["domains"].([]map[string]any)
			domains[0]["state"] = "waiting_dns"
			domains[0]["certificate"].(map[string]any)["state"] = "issuing"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2X2RvbWFpbnM:1"`)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
	}))
	defer server.Close()

	client := api.New(server.URL, config.Credential{AccessToken: "test-token"}, server.Client())
	writer := &previewDomainTestWriter{first: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		observePreviewDomains(context.Background(), client, "prv_domains", []string{"app.example.com"}, writer)
		close(done)
	}()
	select {
	case <-writer.first:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not publish the initial DNS state")
	}
	initial := writer.String()
	if !strings.Contains(initial, "state=waiting_dns") || strings.Contains(initial, "state=ready") {
		t.Fatalf("observer reported an unready domain as ready: %q", initial)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not stop after readiness")
	}
	final := writer.String()
	if strings.Index(final, "state=waiting_dns") >= strings.Index(final, "state=ready") {
		t.Fatalf("observer status order = %q", final)
	}
}

type previewDomainTestWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	once  sync.Once
	first chan struct{}
}

func (w *previewDomainTestWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(value)
	w.once.Do(func() { close(w.first) })
	return n, err
}

func (w *previewDomainTestWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
