package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestPreviewLeaseClientFollowsCreateOperationAndUsesETags(t *testing.T) {
	now := time.Now().UTC()
	lease := PreviewLease{
		Schema: PreviewTunnelSchemaV1, Kind: "preview_lease", ID: "prv_1", AccountID: "acct_1", ActorID: "actor_1",
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"},
		AccessMode: "public", Persistent: false, Endpoint: "https://quiet-river-7.preview.example.test",
		LeaseDeadline: now.Add(time.Hour), State: "connecting", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown",
		CreatedAt: now, LastRenewedAt: now,
	}
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q, want identity for strong ETag preservation", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/previews":
			if r.Header.Get("Idempotency-Key") != "create-key" {
				t.Errorf("create idempotency key = %q", r.Header.Get("Idempotency-Key"))
			}
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if domains, ok := body["domains"]; !ok || string(domains) != "[]" {
				t.Errorf("create domains = %s, present=%v; want explicit []", domains, ok)
			}
			w.Header().Set("X-Paperboat-Operation-ID", "op_1")
			writePreviewLeaseEnvelope(t, w, PreviewLeaseOperation{Schema: PreviewTunnelSchemaV1, Kind: "operation", ID: "op_1", ResourceKind: "preview_lease", ResourceID: "prv_1", Phase: "connecting", State: "running", Progress: 50, CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/previews/prv_1":
			w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2XzE:1"`)
			writePreviewLeaseEnvelope(t, w, lease)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/previews/prv_1/lease/renew":
			if r.Header.Get("If-Match") != `"ptv1:preview_lease:cHJ2XzE:1"` || r.Header.Get("Idempotency-Key") == "" {
				t.Errorf("renew headers = %#v", r.Header)
			}
			lease.State, lease.AllocationState, lease.EdgeState, lease.OriginState = "ready", "ready", "ready", "ready"
			lease.LastRenewedAt = time.Now().UTC()
			w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2XzE:2"`)
			writePreviewLeaseEnvelope(t, w, lease)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/previews/prv_1":
			if r.Header.Get("If-Match") != `"ptv1:preview_lease:cHJ2XzE:2"` || r.Header.Get("Idempotency-Key") == "" {
				t.Errorf("stop headers = %#v", r.Header)
			}
			lease.State, lease.AllocationState, lease.EdgeState = "stopped", "released", "down"
			w.Header().Set("ETag", `"ptv1:preview_lease:cHJ2XzE:3"`)
			writePreviewLeaseEnvelope(t, w, lease)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{AccessToken: "access-token"}, server.Client())
	created, err := client.CreatePreviewLease(context.Background(), PreviewLeaseCreateRequest{
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"},
	}, "create-key")
	if err != nil {
		t.Fatal(err)
	}
	if created.ETag != `"ptv1:preview_lease:cHJ2XzE:1"` || created.ID != "prv_1" || created.CreateOperationID != "op_1" {
		t.Fatalf("created lease = %#v", created)
	}
	renewed, err := client.RenewPreviewLease(context.Background(), created, "session_1", "renew-key")
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ETag != `"ptv1:preview_lease:cHJ2XzE:2"` || renewed.State != "ready" {
		t.Fatalf("renewed lease = %#v", renewed)
	}
	stopped, err := client.StopPreviewLease(context.Background(), renewed, "stop-key")
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != "stopped" || stopped.ETag != `"ptv1:preview_lease:cHJ2XzE:3"` {
		t.Fatalf("stopped lease = %#v", stopped)
	}
	if strings.Join(methods, ",") != "POST /v1/previews,GET /v1/previews/prv_1,POST /v1/previews/prv_1/lease/renew,DELETE /v1/previews/prv_1" {
		t.Fatalf("methods = %v", methods)
	}
}

func TestPreviewLeaseClientRejectsUnsafeResource(t *testing.T) {
	client := New("https://api.example.test", config.Credential{}, nil)
	if _, err := client.CreatePreviewLease(context.Background(), PreviewLeaseCreateRequest{
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: PreviewLeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, ExpiresAt: func() *time.Time { value := time.Now().Add(-time.Minute); return &value }(),
	}, "create-key"); !errors.Is(err, ErrPreviewLeaseInvalid) {
		t.Fatalf("past deadline error = %v", err)
	}
	unsafe := PreviewLease{
		Schema: PreviewTunnelSchemaV1, Kind: "preview_lease", ID: "prv_1", AccountID: "acct_1", OwnerDeviceID: "device_1", OwnerSessionID: "session_1",
		AccessMode: "public", Endpoint: "http://unsafe.example.test", LeaseDeadline: time.Now().Add(time.Hour), ETag: `"etag"`,
	}
	if err := validatePreviewLease(unsafe); !errors.Is(err, ErrPreviewLeaseInvalid) {
		t.Fatalf("unsafe endpoint error = %v", err)
	}
}

func writePreviewLeaseEnvelope(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{"data": value}); err != nil {
		t.Fatal(err)
	}
}
