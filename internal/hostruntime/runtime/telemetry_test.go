package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

type telemetryClock struct{ now time.Time }

func (c telemetryClock) Now() time.Time { return c.now }

func newTelemetryConfig(t *testing.T, now time.Time, components []Component, tracker *health.HealthTracker, metrics *observability.Registry, events *observability.EventLog) Config {
	t.Helper()
	return Config{
		Version:         "runtime-test",
		Components:      components,
		ShutdownTimeout: time.Second,
		Clock:           telemetryClock{now: now},
		HealthTracker:   tracker,
		Metrics:         metrics,
		EventLog:        events,
		CorrelationID:   "correlation_runtime_test",
	}
}

func newTelemetrySinks(t *testing.T, now time.Time) (*health.HealthTracker, *observability.Registry, *observability.EventLog) {
	t.Helper()
	tracker, err := health.NewHealthTracker(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := observability.NewRegistry(observability.DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	events, err := observability.NewEventLog(32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	return tracker, metrics, events
}

func TestRuntimeTelemetryLifecycleIsTypedAndExactlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 9, 10, 0, time.UTC)
	tracker, metrics, events := newTelemetrySinks(t, now)
	component := Component{Capability: "service", Required: true, Service: &service{name: "service", recorder: &recorder{}}}
	runtime, err := NewRuntime(newTelemetryConfig(t, now, []Component{component}, tracker, metrics, events))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := runtime.TypedHealth().Dimensions.Service
	if started.Status != health.StatusReady || started.Code != "ready" || started.CorrelationID != "correlation_runtime_test" {
		t.Fatalf("typed start health=%#v", started)
	}
	if got := events.Snapshot(); len(got) != 1 || got[0].Name != lifecycleStart || got[0].Code != "ready" || got[0].Outcome != observability.OutcomeStateChange {
		t.Fatalf("start events=%#v", got)
	}
	if got := events.Snapshot()[0]; got.IDs.ResourceID != "resource_service" || got.IDs.SessionID != "session_runtime" || got.IDs.ProcessID != "process_runtime" || got.IDs.ConfigID != "config_runtime-test" {
		t.Fatalf("event identity=%#v", got.IDs)
	}
	if got := metricValue(metrics.Snapshot(), "paperboat_runtime_operations_total", map[string]string{"component": "service", "result": "ok"}); got != 1 {
		t.Fatalf("start operations metric=%v", got)
	}

	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopped := runtime.TypedHealth().Dimensions.Service
	if stopped.Status != health.StatusNotApplicable || stopped.Code != "stopped" {
		t.Fatalf("typed shutdown health=%#v", stopped)
	}
	if got := events.Snapshot(); len(got) != 2 || got[1].Name != lifecycleShutdown || got[1].Code != "stopped" {
		t.Fatalf("shutdown events=%#v", got)
	}
	if got := metricValue(metrics.Snapshot(), "paperboat_runtime_operations_total", map[string]string{"component": "service", "result": "ok"}); got != 2 {
		t.Fatalf("lifecycle operations metric=%v", got)
	}
	if got := metricValue(metrics.Snapshot(), observability.MetricServiceUptime, nil); got != 0 {
		// The injected clock makes the runtime duration exactly zero. The
		// presence check below distinguishes an absent series from zero.
		t.Fatalf("uptime metric=%v", got)
	}
	if !hasMetric(metrics.Snapshot(), observability.MetricServiceUptime, nil) {
		t.Fatal("service uptime metric was not recorded")
	}
}

func TestRuntimeTelemetryOptionalAndRequiredFailuresStaySafe(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 9, 10, 0, time.UTC)
	t.Run("optional", func(t *testing.T) {
		tracker, metrics, events := newTelemetrySinks(t, now)
		failure := errors.New("offline token=super-secret https://private.example.test")
		component := Component{Capability: "edge", Required: false, Service: &service{name: "edge", recorder: &recorder{}, startErr: failure}}
		runtime, err := NewRuntime(newTelemetryConfig(t, now, []Component{component}, tracker, metrics, events))
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		state := runtime.TypedHealth().Dimensions.Edge
		if state.Status != health.StatusDegraded || state.Code != "start_failed" || state.Retry != health.RetryScheduled {
			t.Fatalf("optional health=%#v", state)
		}
		got := events.Snapshot()
		if len(got) != 1 || got[0].Outcome != observability.OutcomeFailed || got[0].Severity != observability.SeverityError {
			t.Fatalf("optional events=%#v", got)
		}
		body, marshalErr := got[0].JSON()
		if marshalErr != nil || strings.Contains(string(body), "super-secret") || strings.Contains(string(body), "private.example") {
			t.Fatalf("unsafe event=%s err=%v", body, marshalErr)
		}
	})

	t.Run("required rollback", func(t *testing.T) {
		tracker, metrics, events := newTelemetrySinks(t, now)
		recorder := &recorder{}
		failure := errors.New("required component secret")
		components := []Component{
			{Capability: "service", Required: true, Service: &service{name: "service", recorder: recorder}},
			{Capability: "edge", Required: true, Service: &service{name: "edge", recorder: recorder, startErr: failure}},
		}
		runtime, err := NewRuntime(newTelemetryConfig(t, now, components, tracker, metrics, events))
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Start(context.Background()); err == nil {
			t.Fatal("expected required start failure")
		}
		if runtime.State() != Failed {
			t.Fatalf("state=%s", runtime.State())
		}
		if got := runtime.TypedHealth().Dimensions.Edge; got.Status != health.StatusDown || got.Code != "start_failed" {
			t.Fatalf("required health=%#v", got)
		}
		if got := runtime.TypedHealth().Dimensions.Service; got.Status != health.StatusDown || got.Code != "start_failed" {
			t.Fatalf("rollback health=%#v", got)
		}
		got := events.Snapshot()
		if len(got) != 3 || got[0].Code != "ready" || got[1].Code != "start_failed" || got[2].Name != lifecycleRollback || got[2].Code != "stopped" {
			t.Fatalf("rollback events=%#v", got)
		}
		if got := metricValue(metrics.Snapshot(), observability.MetricUpdateOperations, map[string]string{"phase": "rollback", "outcome": "success"}); got != 1 {
			t.Fatalf("rollback metric=%v", got)
		}
	})
}

func TestRuntimeTelemetryShutdownCancellationUsesStableCode(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 9, 10, 0, time.UTC)
	tracker, metrics, events := newTelemetrySinks(t, now)
	component := Component{Capability: "service", Required: true, Service: &service{name: "service", recorder: &recorder{}, shutdownErr: context.Canceled}}
	runtime, err := NewRuntime(newTelemetryConfig(t, now, []Component{component}, tracker, metrics, events))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Shutdown(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown error=%v", err)
	}
	state := runtime.TypedHealth().Dimensions.Service
	if state.Status != health.StatusDegraded || state.Code != "shutdown_canceled" || state.Retry != health.RetryScheduled {
		t.Fatalf("shutdown health=%#v", state)
	}
	got := events.Snapshot()
	if len(got) != 2 || got[1].Outcome != observability.OutcomeCanceled || got[1].Code != "shutdown_canceled" {
		t.Fatalf("shutdown events=%#v", got)
	}
	body, marshalErr := got[1].JSON()
	if marshalErr != nil || strings.Contains(string(body), "context canceled") {
		t.Fatalf("raw error leaked: %s err=%v", body, marshalErr)
	}
	if got := metricValue(metrics.Snapshot(), "paperboat_runtime_operations_total", map[string]string{"component": "service", "result": "canceled"}); got != 1 {
		t.Fatalf("cancellation metric=%v", got)
	}
}

func metricValue(series []observability.Series, name string, labels map[string]string) float64 {
	for _, item := range series {
		if item.Name == name && labelsEqual(item.Labels, labels) {
			return item.Value
		}
	}
	return 0
}

func hasMetric(series []observability.Series, name string, labels map[string]string) bool {
	for _, item := range series {
		if item.Name == name && labelsEqual(item.Labels, labels) {
			return true
		}
	}
	return false
}

func labelsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
