package observability

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
)

func TestLifecycleMetricsUseFixedLabelsAndHealthProjection(t *testing.T) {
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker, err := health.NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordHealth(tracker.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordHealthTransition(health.DimensionService, health.StatusUnknown, health.StatusReady); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"download", "verify", "stage", "activate", "health_gate", "rollback", "quarantine"} {
		if err := registry.RecordUpdatePhase(phase, "success"); err != nil {
			t.Fatalf("phase %s: %v", phase, err)
		}
	}
	for _, check := range []string{"state", "credential", "clock", "dns", "edge", "transport", "config", "origin", "resource"} {
		if err := registry.RecordDoctorCheck(check, "ok"); err != nil {
			t.Fatalf("check %s: %v", check, err)
		}
	}
	if err := registry.SetServiceUptime(at, at.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordServiceRestart("upgrade"); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordWatchdogFailure("timeout"); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetCrashLoop(true); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordDoctorCheck("resource_123", "ok"); err == nil {
		t.Fatal("accepted unbounded doctor label")
	}
	if err := registry.RecordUpdatePhase("download", "customer_result"); err == nil {
		t.Fatal("accepted unbounded update outcome")
	}
	if err := registry.SetCrashLoop(false); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, sample := range registry.Snapshot() {
		if sample.Name == MetricHealthDimension {
			seen[sample.Labels["dimension"]] = true
		}
	}
	if len(seen) != len(health.Dimensions()) {
		t.Fatalf("health dimensions = %v", seen)
	}
}
