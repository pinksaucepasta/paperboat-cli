package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestNormalizePreviewDomainsCanonicalizesIDNAAndOrdering(t *testing.T) {
	got, err := NormalizePreviewDomains([]string{"*.BÜCHER.Example.", "EXAMPLE.COM.", "app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.xn--bcher-kva.example", "app.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %#v, want %#v", got, want)
	}
	for _, test := range []struct {
		name  string
		input []string
		isErr error
	}{
		{name: "normalized duplicate", input: []string{"Example.com", "example.com."}, isErr: ErrPreviewLeaseInvalid},
		{name: "recursive wildcard", input: []string{"*.*.example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "wildcard not first label", input: []string{"app.*.example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "ip literal", input: []string{"127.0.0.1"}, isErr: ErrPreviewLeaseInvalid},
		{name: "local name", input: []string{"localhost"}, isErr: ErrPreviewLeaseInvalid},
		{name: "underscore label", input: []string{"app_name.example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "surrounding whitespace", input: []string{" app.example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "unicode whitespace", input: []string{"app.\u00a0example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "unicode control", input: []string{"app.\u007f.example.com"}, isErr: ErrPreviewLeaseInvalid},
		{name: "too many", input: []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com", "g.example.com", "h.example.com", "i.example.com"}, isErr: ErrPreviewLeaseInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizePreviewDomains(test.input); !errors.Is(err, test.isErr) {
				t.Fatalf("error = %v, want %v", err, test.isErr)
			}
		})
	}
}

func TestPreviewLeaseIdempotencyKeyIsStrictAndBounded(t *testing.T) {
	valid := "preview_01ABCxyz-_.~"
	if err := validatePreviewLeaseIdempotencyKey(valid); err != nil {
		t.Fatalf("valid key error = %v", err)
	}
	for _, value := range []string{
		"", " key", "key ", "key\tvalue", "key\u00a0value", "key\u007fvalue",
		strings.Repeat("k", 257),
	} {
		if err := validatePreviewLeaseIdempotencyKey(value); err == nil {
			t.Fatalf("key %q was accepted", value)
		}
	}
}

func TestCreatePreviewLeaseSendsOrderedDomainsAndSafeSummaries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	lease := PreviewLease{
		Schema: PreviewTunnelSchemaV1, Kind: "preview_lease", ID: "prv_domains", AccountID: "acct_1", ActorID: "actor_1",
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"},
		AccessMode: "public", Endpoint: "https://preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "connecting",
		AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: now, LastRenewedAt: now,
		Domains: []PreviewDomainSummary{{
			ID: "dom_1", TargetKind: "preview_lease", PreviewID: "prv_domains", Hostname: "app.example.com", MatchType: "exact", State: "waiting_dns",
			DNS: PreviewDomainDNS{Target: "domains.example.test"}, Certificate: PreviewDomainCertificate{State: "not_requested"}, Generation: 1, ETag: `"dom_1:1"`,
			Instructions: &PreviewDNSInstructions{
				Schema: PreviewTunnelSchemaV1, Kind: "dns_instructions", TargetKind: "preview_lease", PreviewID: "prv_domains", DomainID: "dom_1", Hostname: "app.example.com", Provider: "generic",
				Records: []PreviewDNSRecord{{Name: "_acme-challenge.app.example.com", Type: "CNAME", Value: "pb-1.challenge.example.test", TTL: 300}}, CertificateStrategy: "delegated_dns01", VerificationState: "waiting_dns", Note: "Add this CNAME.",
			},
		}, {
			ID: "dom_2", TargetKind: "preview_lease", PreviewID: "prv_domains", Hostname: "example.com", MatchType: "exact", State: "waiting_dns",
			DNS: PreviewDomainDNS{Target: "domains.example.test"}, Certificate: PreviewDomainCertificate{State: "not_requested"}, Generation: 1, ETag: `"dom_2:1"`,
		}},
	}
	var request PreviewLeaseCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/previews" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2X2RvbWFpbnM:1"`)
		w.Header().Set("X-Paperboat-Operation-ID", "op_domains")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": lease})
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{AccessToken: "access-token"}, server.Client())
	got, err := client.CreatePreviewLease(context.Background(), PreviewLeaseCreateRequest{
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, Domains: []string{"EXAMPLE.COM.", "app.example.com"},
	}, "create-domains")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(request.Domains, []string{"app.example.com", "example.com"}) {
		t.Fatalf("request domains = %#v", request.Domains)
	}
	if len(got.Domains) != 2 || got.Domains[0].TargetKind != "preview_lease" || got.Domains[0].PreviewID != got.ID || got.Domains[0].Instructions == nil {
		t.Fatalf("lease domains = %#v", got.Domains)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(strings.ToLower(string(encoded)), "token") || strings.Contains(strings.ToLower(string(encoded)), "private_key") {
		t.Fatalf("lease projection contains secret material: %s", encoded)
	}
}

func TestPreviewLeaseRejectsMixedDomainTargetBinding(t *testing.T) {
	now := time.Now().UTC()
	lease := PreviewLease{
		Schema: PreviewTunnelSchemaV1, Kind: "preview_lease", ID: "prv_1", AccountID: "acct_1", ActorID: "actor_1", OwnerDeviceID: "device_1", OwnerSessionID: "session_1",
		Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public", Endpoint: "https://preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "ready", AllocationState: "ready", EdgeState: "ready", OriginState: "ready", CreatedAt: now, LastRenewedAt: now,
		Domains: []PreviewDomainSummary{{ID: "dom_1", TargetKind: "tunnel_route", PreviewID: "prv_1", Hostname: "app.example.com", MatchType: "exact", State: "ready", DNS: PreviewDomainDNS{Target: "dns.example.test"}, Certificate: PreviewDomainCertificate{State: "ready"}, Generation: 1, ETag: `"dom_1:1"`}},
	}
	if err := validatePreviewLease(lease); !errors.Is(err, ErrPreviewLeaseInvalid) {
		t.Fatalf("error = %v, want ErrPreviewLeaseInvalid", err)
	}
}
