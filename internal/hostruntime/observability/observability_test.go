package observability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

func TestMetricsHandlerRendersDeterministicPrometheusText(t *testing.T) {
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Record("paperboat_runtime_restart_total", 4, nil); err != nil {
		t.Fatal(err)
	}
	if err := registry.Record("paperboat_runtime_connector_retries_total", 1, map[string]string{"result": "failed", "transport": "none"}); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", recorder.Code, recorder.Header())
	}
	want := "paperboat_runtime_connector_retries_total{result=\"failed\",transport=\"none\"} 1\npaperboat_runtime_restart_total 4\n"
	if body := recorder.Body.String(); body != want || !strings.Contains(recorder.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("body=%q content-type=%q", body, recorder.Header().Get("Content-Type"))
	}
}

func TestLoggerAcceptsOnlySafeStructuredFields(t *testing.T) {
	var output bytes.Buffer
	logger, _ := NewLogger(slog.New(slog.NewJSONHandler(&output, nil)))
	event := Event{Component: "session", Operation: "attach", Result: "ok", CorrelationID: "req_123", ResourceID: "ses_123", Duration: time.Second, Bytes: 10}
	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	encoded := output.String()
	if !strings.Contains(encoded, `"msg":"runtime_event"`) || strings.Contains(encoded, "terminal bytes") {
		t.Fatalf("log=%s", encoded)
	}
	event.ResourceID = "Bearer secret token"
	if err := logger.Log(context.Background(), event); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(output.String(), "secret token") {
		t.Fatal("unsafe value entered log")
	}
}

func TestMetricsRejectUnknownLabelsAndBoundSeries(t *testing.T) {
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"component": "session", "result": "ok"}
	if err := registry.Record("paperboat_runtime_operations_total", 1, labels); err != nil {
		t.Fatal(err)
	}
	if err := registry.Record("paperboat_runtime_operations_total", 2, labels); err != nil {
		t.Fatal(err)
	}
	if got := registry.Snapshot(); len(got) != 1 || got[0].Value != 3 {
		t.Fatalf("series=%#v", got)
	}
	if err := registry.Record("paperboat_runtime_operations_total", 1, map[string]string{"component": "session", "result": "customer_id"}); !errors.Is(err, ErrInvalidLabels) {
		t.Fatalf("err=%v", err)
	}
	if err := registry.Record("dynamic_customer_metric", 1, nil); !errors.Is(err, ErrUnknownMetric) {
		t.Fatalf("err=%v", err)
	}
}

func TestDefaultMetricVocabularyHasFixedCardinality(t *testing.T) {
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct {
		name   string
		labels map[string]string
	}{
		{"paperboat_runtime_operations_total", map[string]string{"component": "session", "result": "replayed"}},
		{"paperboat_runtime_connector_retries_total", map[string]string{"transport": "quic", "result": "connected"}},
		{"paperboat_runtime_connector_retries_total", map[string]string{"transport": "tcp_dedicated", "result": "connected"}},
		{"paperboat_runtime_connector_retries_total", map[string]string{"transport": "tcp_mux", "result": "connected"}},
		{"paperboat_runtime_network_changes_total", map[string]string{"reason": "default_route", "action": "rebind"}},
		{"paperboat_runtime_network_generation", nil},
		{"paperboat_runtime_terminal_events_total", map[string]string{"event": "slow_consumer"}},
		{"paperboat_runtime_delivery_total", map[string]string{"kind": "preview", "result": "failed"}},
		{"paperboat_runtime_cleanup_total", map[string]string{"kind": "upload", "result": "preserved"}},
		{"paperboat_runtime_serve_events_total", map[string]string{"event": "lease_loss", "result": "expired"}},
	}
	for _, metric := range valid {
		if err := registry.Record(metric.name, 1, metric.labels); err != nil {
			t.Fatalf("metric=%s err=%v", metric.name, err)
		}
	}
	if len(registry.Snapshot()) != len(valid) {
		t.Fatalf("series=%#v", registry.Snapshot())
	}
	if err := registry.Record("paperboat_runtime_delivery_total", 1, map[string]string{"kind": "customer_123", "result": "failed"}); !errors.Is(err, ErrInvalidLabels) {
		t.Fatalf("unbounded label err=%v", err)
	}
	if err := registry.Record("paperboat_runtime_network_changes_total", 1, map[string]string{"reason": "en0", "action": "rebind"}); !errors.Is(err, ErrInvalidLabels) {
		t.Fatalf("network identity label err=%v", err)
	}
}

func TestServeLatencyIsPrometheusHistogram(t *testing.T) {
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"stage": "readiness", "owner": "detached", "result": "ok"}
	if err := registry.Record("paperboat_runtime_serve_latency_seconds", 0.2, labels); err != nil {
		t.Fatal(err)
	}
	if err := registry.Record("paperboat_runtime_serve_latency_seconds", 2, labels); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{"paperboat_runtime_serve_latency_seconds_bucket", "le=\"0.5\"", "paperboat_runtime_serve_latency_seconds_sum", "paperboat_runtime_serve_latency_seconds_count"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, body)
		}
	}
}

func TestTerminalCompressionMetricsUseOnlyBoundedLabels(t *testing.T) {
	_, _ = protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 1, Data: []byte("ok")}, nil)
	_, _ = protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: protocol.TerminalStdout, StreamID: 1, Data: bytes.Repeat([]byte("agent output\r\n"), 200)}, nil)
	registry, err := NewRegistry(DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	foundRaw, foundZstd, foundBytes := false, false, false
	for _, series := range registry.Snapshot() {
		switch series.Name {
		case "paperboat_runtime_terminal_compression_frames_total":
			if len(series.Labels) != 2 {
				t.Fatalf("labels=%v", series.Labels)
			}
			foundRaw = foundRaw || series.Labels["encoding"] == "raw" && series.Labels["decision"] == "small" && series.Value > 0
			foundZstd = foundZstd || series.Labels["encoding"] == "zstd" && series.Labels["decision"] == "compressed" && series.Value > 0
		case "paperboat_runtime_terminal_compression_bytes_total":
			foundBytes = foundBytes || series.Labels["kind"] == "encoded" && series.Value > 0
		}
	}
	if !foundRaw || !foundZstd || !foundBytes {
		t.Fatalf("raw=%v zstd=%v bytes=%v", foundRaw, foundZstd, foundBytes)
	}
}

func TestDiagnosticsAreBoundedAndRejectPrivateFields(t *testing.T) {
	checked := time.Now().UTC()
	snapshot := health.Snapshot{Live: true, Version: "1.0.0", CheckedAt: checked, Capabilities: map[string]health.Capability{"terminal.v1": {State: health.Ready}}}
	encoded, err := BuildDiagnostics("1.0.0", "byod", snapshot, map[string]uint64{"attachment_bytes": 2}, []string{"req_1"}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/Users/") {
		t.Fatalf("diagnostics=%s", encoded)
	}
	if _, err := BuildDiagnostics("1.0.0", "byod", snapshot, map[string]uint64{"private_path": 1}, nil, 4096); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("err=%v", err)
	}
	if _, err := BuildDiagnostics("1.0.0", "byod", snapshot, nil, nil, 8); !errors.Is(err, ErrDiagnosticLimit) {
		t.Fatalf("err=%v", err)
	}
}
