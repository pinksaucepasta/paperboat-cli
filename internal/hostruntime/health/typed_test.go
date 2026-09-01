package health

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTypedHealthSnapshotIsDeterministicAndCopyIsolated(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 456789000, time.FixedZone("offset", 19800))
	tracker, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	first := tracker.Snapshot()
	second := tracker.Snapshot()
	firstJSON, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) || first.ETag != second.ETag || first.Schema != "paperboat.health/v1" {
		t.Fatalf("unstable snapshot: %s / %s", firstJSON, secondJSON)
	}
	first.Dimensions.Service.BrokenSince = timePtr(time.Unix(1, 0))
	if tracker.Snapshot().Dimensions.Service.BrokenSince != nil {
		t.Fatal("snapshot mutation changed tracker state")
	}
	if !json.Valid(firstJSON) {
		t.Fatal("snapshot is not valid JSON")
	}
}

func TestTypedHealthTracksRetryRecoverySuppressionAndRedaction(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(HealthUpdate{Dimension: DimensionRoute, Status: StatusDegraded, Code: "route_stale", Summary: "token=secret customer.example.com route_customer123", RepairAction: "Wait for a fresh route.", CorrelationID: "corr_health_1", Retry: RetryScheduled, NextRetryAt: at.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	first := tracker.Snapshot()
	brokenSince := first.Dimensions.Route.BrokenSince
	if brokenSince == nil || first.Overall.Dimension != DimensionRoute || first.Dimensions.Route.Retry != RetryScheduled {
		t.Fatalf("first state = %#v", first)
	}
	if strings.Contains(first.Dimensions.Route.Summary, "secret") || strings.Contains(first.Dimensions.Route.Summary, "customer.example.com") || strings.Contains(first.Dimensions.Route.Summary, "route_customer123") {
		t.Fatalf("unsafe summary = %q", first.Dimensions.Route.Summary)
	}
	at = at.Add(time.Minute)
	if err := tracker.Update(HealthUpdate{Dimension: DimensionRoute, Status: StatusDown, Code: "route_down", Summary: "Route is unavailable.", RepairAction: "Restore route.", CorrelationID: "corr_health_2", Retry: RetryWaitForChange}); err != nil {
		t.Fatal(err)
	}
	second := tracker.Snapshot()
	if second.Dimensions.Route.BrokenSince == nil || !second.Dimensions.Route.BrokenSince.Equal(*brokenSince) || !second.Dimensions.Route.Since.Equal(at) {
		t.Fatalf("broken transition = %#v", second.Dimensions.Route)
	}
	at = at.Add(time.Minute)
	if err := tracker.Update(HealthUpdate{Dimension: DimensionRoute, Status: StatusReady, Code: "ready", Summary: "Route is ready.", RepairAction: "No action is required.", Retry: RetryNone}); err != nil {
		t.Fatal(err)
	}
	if got := tracker.Snapshot().Dimensions.Route.BrokenSince; got != nil {
		t.Fatal("recovery retained broken_since")
	}
	at = at.Add(time.Minute)
	if err := tracker.Update(HealthUpdate{Dimension: DimensionService, Status: StatusDown, Code: "service_down", Summary: "Service is unavailable.", RepairAction: "Restart the host.", Retry: RetryWaitForChange}); err != nil {
		t.Fatal(err)
	}
	suppressed := tracker.Snapshot()
	if suppressed.Dimensions.Route.SuppressedBy != DimensionService || suppressed.Overall.Dimension != DimensionService {
		t.Fatalf("suppression = %#v", suppressed)
	}
	if alert, ok := suppressed.AlertFor(DimensionService); !ok || alert.BrokenSince == nil {
		t.Fatalf("alert = %#v, %v", alert, ok)
	}
}

func TestTypedHealthConcurrentSnapshots(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			for iteration := 0; iteration < 50; iteration++ {
				dimension := dimensionOrder[(index+iteration)%len(dimensionOrder)]
				if err := tracker.Update(HealthUpdate{Dimension: dimension, Status: StatusReady, Code: "ready", Summary: "Ready.", RepairAction: "No action is required.", Retry: RetryNone}); err != nil {
					t.Errorf("Update: %v", err)
					return
				}
				body, err := tracker.Snapshot().JSON()
				if err != nil || !json.Valid(body) {
					t.Errorf("invalid snapshot: %s (%v)", body, err)
					return
				}
			}
		}(worker)
	}
	group.Wait()
}

func TestTypedHealthRejectsInvalidRetryAndClock(t *testing.T) {
	tracker, err := NewHealthTracker(func() time.Time { return time.Time{} })
	if errorCodeOf(err) != ErrorInvalidTime || tracker != nil {
		t.Fatalf("invalid clock = %#v, %v", tracker, err)
	}
	tracker, err = NewHealthTracker(func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	err = tracker.Update(HealthUpdate{Dimension: DimensionService, Status: StatusReady, Code: "ready", Summary: "Ready.", RepairAction: "No action is required.", Retry: RetryScheduled})
	if errorCodeOf(err) != ErrorInvalidRetry {
		t.Fatalf("invalid retry = %v", err)
	}
}

func timePtr(value time.Time) *time.Time { return &value }

func errorCodeOf(err error) ErrorCode {
	if typed, ok := err.(*Error); ok {
		return typed.Code
	}
	return ""
}
