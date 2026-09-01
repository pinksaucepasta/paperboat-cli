//go:build darwin || linux || windows

package runtime

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

func TestHostDiagnosticsIsLoopbackBoundedAndDeterministic(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	tracker, err := health.NewHealthTracker(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(health.HealthUpdate{
		Dimension: health.DimensionService, Status: health.StatusReady, Code: "ready",
		Summary: "Runtime is ready at /Users/alice and https://runtime.example.test.", RepairAction: "No action is required.",
		CorrelationID: "corr_test", Retry: health.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}
	metrics, err := observability.NewRegistry(observability.DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Record("paperboat_runtime_connector_retries_total", 2, map[string]string{"transport": "tcp_mux", "result": "connected"}); err != nil {
		t.Fatal(err)
	}
	events, err := observability.NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	if _, err := events.Record(observability.EventInput{
		At: now, Severity: observability.SeverityInfo, Component: observability.DimensionService,
		Name: "runtime_ready", Code: "ready", Outcome: observability.OutcomeStateChange,
		Message: "Runtime is ready.", CorrelationID: "corr_test",
		Generations: observability.Generations{Config: 3}, Retry: observability.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	healthSource := &runtimeHealthSource{}
	registerHostLivenessAndDiagnostics(mux, healthSource, tracker, metrics, events)

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	first := httptest.NewRecorder()
	mux.ServeHTTP(first, request)
	if first.Code != http.StatusOK || first.Header().Get("Content-Type") != "application/json" || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("diagnostics response code=%d headers=%v body=%q", first.Code, first.Header(), first.Body.String())
	}
	var diagnostics HostDiagnostics
	if err := json.Unmarshal(first.Body.Bytes(), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if diagnostics.Schema != HostDiagnosticsSchemaV1 || diagnostics.Health.Schema != health.HealthSchemaV1 || len(diagnostics.Metrics) != 1 || len(diagnostics.Events) != 1 || diagnostics.Events[0].Generations.Config != 3 {
		t.Fatalf("diagnostics=%#v", diagnostics)
	}
	if !bytes.Contains(first.Body.Bytes(), []byte(`"name":"paperboat_runtime_connector_retries_total"`)) || bytes.Contains(first.Body.Bytes(), []byte(`"Name"`)) {
		t.Fatalf("metrics are not canonical JSON: %s", first.Body.Bytes())
	}
	second := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	mux.ServeHTTP(second, request)
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("diagnostics are not deterministic:\nfirst=%s\nsecond=%s", first.Body.Bytes(), second.Body.Bytes())
	}
	for _, secret := range []string{"/Users/alice", "Bearer local-secret", "runtime.example.test"} {
		if bytes.Contains(first.Body.Bytes(), []byte(secret)) {
			t.Fatalf("diagnostics leaked %q: %s", secret, first.Body.Bytes())
		}
	}

	for _, test := range []struct {
		name   string
		remote string
		method string
		path   string
		want   int
	}{
		{name: "non-loopback", remote: "192.0.2.1:43210", method: http.MethodGet, path: "/diagnostics", want: http.StatusForbidden},
		{name: "query", remote: "127.0.0.1:43210", method: http.MethodGet, path: "/diagnostics?verbose=true", want: http.StatusNotFound},
		{name: "method", remote: "127.0.0.1:43210", method: http.MethodPost, path: "/diagnostics", want: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://127.0.0.1"+test.path, nil)
			request.RemoteAddr = test.remote
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}

	liveness := httptest.NewRecorder()
	livenessRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
	mux.ServeHTTP(liveness, livenessRequest)
	if liveness.Code != http.StatusOK || liveness.Body.String() != `{"live":true}` {
		t.Fatalf("liveness=%d %q", liveness.Code, liveness.Body.String())
	}
}

func TestHostDiagnosticsAbsentWhenOptionalSourcesAreNil(t *testing.T) {
	mux := http.NewServeMux()
	registerHostLivenessAndDiagnostics(mux, &runtimeHealthSource{}, nil, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestHostDiagnosticsEventLimitIsBounded(t *testing.T) {
	events, err := observability.NewEventLog(hostDiagnosticsMaximumEvents + 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	at := time.Unix(101, 0).UTC()
	for index := 0; index < hostDiagnosticsMaximumEvents+32; index++ {
		if _, err := events.Record(observability.EventInput{
			At: at.Add(time.Duration(index) * time.Second), Severity: observability.SeverityInfo,
			Component: observability.DimensionService, Name: "runtime_ready", Code: "ready",
			Outcome: observability.OutcomeSuccess, Message: "ready", CorrelationID: "corr_test",
			Retry: observability.RetryNone,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerHostLivenessAndDiagnostics(mux, &runtimeHealthSource{}, nil, nil, events)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var diagnostics HostDiagnostics
	if err := json.NewDecoder(response.Body).Decode(&diagnostics); err != nil {
		t.Fatal(err)
	}
	if len(diagnostics.Events) != hostDiagnosticsMaximumEvents {
		t.Fatalf("events=%d, want %d", len(diagnostics.Events), hostDiagnosticsMaximumEvents)
	}
}

func TestHostDiagnosticsSourceSnapshotDoesNotExposeLegacyHealth(t *testing.T) {
	tracker, err := health.NewHealthTracker(func() time.Time { return time.Unix(1, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	source := hostDiagnosticsSource{healthTracker: tracker}
	if got := source.healthTracker.Snapshot(); got.Schema != health.HealthSchemaV1 {
		t.Fatalf("typed health schema=%q", got.Schema)
	}
	if strings.Contains(string(mustJSON(t, source.healthTracker.Snapshot())), "workloads") {
		t.Fatal("typed health unexpectedly contains legacy workload data")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
