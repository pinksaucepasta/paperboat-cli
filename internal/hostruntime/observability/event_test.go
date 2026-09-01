package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEventInput() EventInput {
	return EventInput{
		At:            time.Date(2026, 8, 31, 1, 2, 3, 456000000, time.FixedZone("offset", 19800)),
		Severity:      SeverityWarn,
		Component:     DimensionRoute,
		Name:          "route_transition",
		Code:          "route_stale",
		Outcome:       OutcomeStateChange,
		Message:       "Route assignment is stale.",
		CorrelationID: "corr_event_1",
		IDs:           SafeIDs{AccountID: "account_01", TunnelID: "tunnel_01", RouteID: "route_02", ConnectorID: "connector_03", ResourceID: "resource_04", SessionID: "session_05", ProcessID: "process_06", ConfigID: "config_07"},
		Generations:   Generations{Config: 4, Route: 5, Assignment: 6, Process: 7, Session: 8},
		Retry:         RetryScheduled,
		NextRetryAt:   time.Date(2026, 8, 31, 1, 3, 3, 456000000, time.FixedZone("offset", 19800)),
	}
}

func TestEventJSONAndConstructionRedaction(t *testing.T) {
	event, err := NewEvent(testEventInput())
	if err != nil {
		t.Fatal(err)
	}
	body, err := event.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) || !strings.Contains(string(body), `"schema":"paperboat.edge_event.v1"`) || !strings.Contains(string(body), `"resource_id":"resource_04"`) {
		t.Fatalf("event JSON = %s", body)
	}
	unsafe := testEventInput()
	unsafe.Message = "Authorization: Bearer secret-token customer.example.com https://alice:password@example.com /Users/alice/private route_customer123"
	event, err = NewEvent(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = event.JSON()
	for _, value := range []string{"secret-token", "customer.example.com", "alice", "route_customer123"} {
		if strings.Contains(string(body), value) {
			t.Fatalf("unsafe value %q in %s", value, body)
		}
	}
	if !strings.Contains(string(body), RedactedValue) {
		t.Fatalf("redaction missing in %s", body)
	}
}

func TestEventLogIsBoundedNonblockingAndCopyIsolated(t *testing.T) {
	log, err := NewEventLogWithQueue(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	input := testEventInput()
	input.Message = "event"
	input.Retry = RetryNone
	input.NextRetryAt = time.Time{}
	for range 100 {
		if _, err := log.Record(input); err != nil {
			t.Fatal(err)
		}
	}
	if len(log.Snapshot()) > 2 || log.DroppedEvents() == 0 {
		t.Fatalf("events=%d drops=%d", len(log.Snapshot()), log.DroppedEvents())
	}
	events := log.Snapshot()
	if len(events) > 0 {
		events[0].IDs = SafeIDs{TunnelID: "tunnel_mutated"}
		if strings.Contains(string(mustEventJSON(t, log.Snapshot()[0])), "tunnel_mutated") {
			t.Fatal("snapshot mutation changed retained event")
		}
	}
	if _, _, err := log.TryRecord(EventInput{}); err == nil {
		t.Fatal("invalid event was accepted")
	}
}

func TestEventLogConcurrentClose(t *testing.T) {
	log, err := NewEventLogWithQueue(64, 64)
	if err != nil {
		t.Fatal(err)
	}
	input := testEventInput()
	input.Message = "event"
	input.Retry = RetryNone
	input.NextRetryAt = time.Time{}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 32 {
				_, _ = log.Record(input)
			}
		}()
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
	if len(log.queue) != 0 {
		t.Fatalf("queued events remain: %d", len(log.queue))
	}
}

func TestEventLogFlushHonorsCancellation(t *testing.T) {
	log, err := NewEventLog(2)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := log.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Flush error = %v", err)
	}
}

func TestLoggerRedactsCanonicalMessage(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(slog.New(slog.NewJSONHandler(&output, nil)))
	if err != nil {
		t.Fatal(err)
	}
	event := testEventInput()
	event.Message = "token=secret-token"
	constructed, err := NewEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(context.Background(), constructed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "secret-token") || !strings.Contains(output.String(), RedactedValue) {
		t.Fatalf("logger output = %s", output.String())
	}
}

func mustEventJSON(t *testing.T, event Event) []byte {
	t.Helper()
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
