package telemetry

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	runtimehealth "github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	runtimeobs "github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

func TestHealthProjectionMatchesCanonicalShapeAndFixedDimensions(t *testing.T) {
	checked := time.Date(2026, 8, 31, 4, 5, 6, 123000000, time.FixedZone("IST", 19800))
	resource, err := NewHealthResource(HealthProjectionInput{
		ResourceKind:  "tunnel",
		ResourceID:    "tunnel_01",
		CorrelationID: "cor_01",
		Snapshot: runtimehealth.Snapshot{
			Live:      true,
			Version:   "2026.08.31.0",
			CheckedAt: checked,
			Capabilities: map[string]runtimehealth.Capability{
				"edge.v1":   {State: runtimehealth.Ready},
				"origin.v1": {State: runtimehealth.Degraded, Reason: "connection refused"},
				"dns.v1":    {State: runtimehealth.Unavailable, Reason: "timeout"},
			},
		},
		Summary:      "Origin is unavailable. Authorization: Bearer secret-value",
		OverallCode:  "dns_unavailable",
		Retrying:     true,
		NextRetryAt:  checked.Add(time.Minute),
		RepairAction: "Retry the health check.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := resource.Validate(); err != nil {
		t.Fatal(err)
	}
	if resource.Schema != ContractSchemaV1 || resource.Kind != "health" || !resource.Since.Equal(checked.UTC()) {
		t.Fatalf("resource = %#v", resource)
	}
	if resource.Dimensions.Service.Status != StatusReady || resource.Dimensions.Edge.Status != StatusReady {
		t.Fatalf("service/edge = %#v/%#v", resource.Dimensions.Service, resource.Dimensions.Edge)
	}
	if resource.Dimensions.Origin.Status != StatusDegraded || resource.Dimensions.DNS.Status != StatusDown {
		t.Fatalf("origin/dns = %#v/%#v", resource.Dimensions.Origin, resource.Dimensions.DNS)
	}
	if resource.Dimensions.Config.Status != StatusNotApplicable || resource.Dimensions.Config.Code != "not_applicable" {
		t.Fatalf("missing config capability = %#v", resource.Dimensions.Config)
	}
	body, err := resource.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "kind", "resource_kind", "resource_id", "overall_code", "dimensions", "summary", "since", "retrying", "next_retry_at", "repair_action", "correlation_id"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("canonical field %q missing: %s", key, body)
		}
	}
	if len(decoded) != 12 || strings.Contains(string(body), "broken_since") || strings.Contains(string(body), "capabilities") || strings.Contains(string(body), "secret-value") {
		t.Fatalf("non-canonical or unsafe fields in %s", body)
	}
}

func TestHealthProjectionRequiresEnvelopeIdentity(t *testing.T) {
	snapshot := runtimehealth.Snapshot{Live: true, CheckedAt: time.Now().UTC()}
	if _, err := ProjectHealth(snapshot, "tunnel", "tunnel_01", ""); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("missing correlation error = %v", err)
	}
	if _, err := ProjectHealth(snapshot, "unknown", "tunnel_01", "cor_01"); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("bad resource kind error = %v", err)
	}
	if _, err := ProjectHealth(runtimehealth.Snapshot{Live: true}, "tunnel", "tunnel_01", "cor_01"); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("missing checked time error = %v", err)
	}
}

func TestCanonicalEventRequiresDurableIDAndCursorAndCopiesSafeMetadata(t *testing.T) {
	metadata := map[string]any{"generation": int64(3), "nested": map[string]any{"note": "safe"}}
	event, err := NewCanonicalEvent(CanonicalEventInput{
		ID:            "event_01",
		Cursor:        "cursor_0001",
		EventType:     "connector.attached",
		ResourceKind:  "connector",
		ResourceID:    "connector_01",
		OccurredAt:    time.Date(2026, 8, 31, 4, 5, 6, 0, time.UTC),
		ActorType:     "host",
		ActorID:       "host_01",
		CorrelationID: "cor_01",
		SafeMetadata:  metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata["generation"] = "changed"
	metadata["nested"].(map[string]any)["note"] = "changed"
	if event.SafeMetadata["generation"] != int64(3) || event.SafeMetadata["nested"].(map[string]any)["note"] != "safe" {
		t.Fatalf("metadata was not copied: %#v", event.SafeMetadata)
	}
	body, err := event.JSON()
	if err != nil || !json.Valid(body) {
		t.Fatalf("event JSON: %s, %v", body, err)
	}
	if _, err := NewCanonicalEvent(CanonicalEventInput{Cursor: "cursor_01", EventType: "connector.attached", ResourceKind: "connector", ResourceID: "connector_01", OccurredAt: time.Now(), ActorType: "host", ActorID: "host_01", CorrelationID: "cor_01"}); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("missing durable event ID error = %v", err)
	}
	if _, err := NewCanonicalEvent(CanonicalEventInput{ID: "event_01", EventType: "connector.attached", ResourceKind: "connector", ResourceID: "connector_01", OccurredAt: time.Now(), ActorType: "host", ActorID: "host_01", CorrelationID: "cor_01"}); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("missing durable cursor error = %v", err)
	}
	if _, err := NewCanonicalEvent(CanonicalEventInput{ID: "event_01", Cursor: "cursor_01", EventType: "connector.attached", ResourceKind: "connector", ResourceID: "connector_01", OccurredAt: time.Now(), ActorType: "host", ActorID: "host_01", CorrelationID: "cor_01", SafeMetadata: map[string]any{"access_token": "secret"}}); !errors.Is(err, ErrCanonicalMetadata) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe metadata error = %v", err)
	}
}

func TestProjectRuntimeEventRequiresEnvelopeAndMapsBoundedFields(t *testing.T) {
	runtimeEvent := runtimeobs.Event{Component: "route", Operation: "activate", Result: "ok", ErrorCode: "", CorrelationID: "cor_01", ResourceID: "route_01", Duration: 1500 * time.Millisecond, Bytes: 7, Generation: 4}
	if _, err := ProjectEvent(runtimeEvent, CanonicalEventInput{EventType: "route.activated", ResourceKind: "route", ResourceID: "route_01", OccurredAt: time.Now(), ActorType: "system", ActorID: "system_01", CorrelationID: "cor_01"}); !errors.Is(err, ErrCanonicalEnvelope) {
		t.Fatalf("missing ID/cursor error = %v", err)
	}
	event, err := ProjectEvent(runtimeEvent, CanonicalEventInput{ID: "event_02", Cursor: "cursor_0002", EventType: "route.activated", ResourceKind: "route", ResourceID: "route_01", OccurredAt: time.Now(), ActorType: "system", ActorID: "system_01", CorrelationID: "cor_01"})
	if err != nil {
		t.Fatal(err)
	}
	if event.SafeMetadata["component"] != "route" || event.SafeMetadata["operation"] != "activate" || event.SafeMetadata["generation"] != uint64(4) {
		t.Fatalf("runtime metadata = %#v", event.SafeMetadata)
	}
}

func TestCanonicalMetadataBoundsAndRedaction(t *testing.T) {
	secret := "Authorization: Bearer abc123 https://user:pass@example.test"
	event, err := NewCanonicalEvent(CanonicalEventInput{ID: "event_03", Cursor: "cursor_0003", EventType: "access.denied", ResourceKind: "connector", ResourceID: "connector_01", OccurredAt: time.Now(), ActorType: "edge", ActorID: "edge_01", CorrelationID: "cor_01", SafeMetadata: map[string]any{"message": secret}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := event.JSON()
	if strings.Contains(string(encoded), "abc123") || strings.Contains(string(encoded), "user:pass") {
		t.Fatalf("secret leaked in metadata: %s", encoded)
	}
	tooMany := make(map[string]any, 65)
	for index := 0; index < 65; index++ {
		tooMany["key_"+string(rune('a'+index%26))+string(rune('0'+index/26))] = true
	}
	if _, err := NewCanonicalEvent(CanonicalEventInput{ID: "event_04", Cursor: "cursor_0004", EventType: "access.denied", ResourceKind: "connector", ResourceID: "connector_01", OccurredAt: time.Now(), ActorType: "edge", ActorID: "edge_01", CorrelationID: "cor_01", SafeMetadata: tooMany}); !errors.Is(err, ErrCanonicalMetadata) {
		t.Fatalf("metadata overflow error = %v", err)
	}
}
