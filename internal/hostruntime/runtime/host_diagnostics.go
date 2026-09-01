//go:build darwin || linux || windows

package runtime

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

// HostDiagnosticsPath is intentionally outside the versioned /v1 API. It is
// a local operator endpoint owned by the stable host daemon, not a browser or
// control-plane surface.
const HostDiagnosticsPath = "/diagnostics"

const (
	HostDiagnosticsSchemaV1   = "paperboat.host-diagnostics/v1"
	HostDiagnosticsMaxBytes   = 1 << 20
	HostDiagnosticsMaxEvents  = 256
	HostDiagnosticsMaxMetrics = 4096
	hostDiagnosticsSchemaV1   = HostDiagnosticsSchemaV1
	// Registry and EventLog are bounded independently, but keep a response cap
	// as a final guard against future changes to either implementation.
	hostDiagnosticsMaximumEvents  = HostDiagnosticsMaxEvents
	hostDiagnosticsMaximumMetrics = HostDiagnosticsMaxMetrics
	hostDiagnosticsMaximumBytes   = HostDiagnosticsMaxBytes
)

// HostDiagnostics is the safe, typed projection used by the local operator
// endpoint. Its fields are intentionally limited to typed health, fixed-label
// metrics, and construction-time-redacted events.
type HostDiagnostics struct {
	Schema        string                 `json:"schema"`
	Health        health.HealthSnapshot  `json:"health"`
	Metrics       []observability.Series `json:"metrics"`
	Events        []observability.Event  `json:"events"`
	DroppedEvents uint64                 `json:"dropped_events"`
}

type hostDiagnosticsMetric struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
}

// MarshalJSON gives Registry's in-process Series the same lower-case wire
// shape as the rest of the diagnostics contract without changing the shared
// observability package's legacy representation.
func (diagnostics HostDiagnostics) MarshalJSON() ([]byte, error) {
	metrics := make([]hostDiagnosticsMetric, 0, len(diagnostics.Metrics))
	for _, series := range diagnostics.Metrics {
		labels := make(map[string]string, len(series.Labels))
		for key, value := range series.Labels {
			labels[key] = value
		}
		metrics = append(metrics, hostDiagnosticsMetric{Name: series.Name, Labels: labels, Value: series.Value})
	}
	events := diagnostics.Events
	if events == nil {
		events = []observability.Event{}
	}
	return json.Marshal(struct {
		Schema        string                  `json:"schema"`
		Health        health.HealthSnapshot   `json:"health"`
		Metrics       []hostDiagnosticsMetric `json:"metrics"`
		Events        []observability.Event   `json:"events"`
		DroppedEvents uint64                  `json:"dropped_events"`
	}{
		Schema: diagnostics.Schema, Health: diagnostics.Health, Metrics: metrics,
		Events: events, DroppedEvents: diagnostics.DroppedEvents,
	})
}

type hostDiagnosticsSource struct {
	health        *runtimeHealthSource
	healthTracker *health.HealthTracker
	metrics       *observability.Registry
	events        *observability.EventLog
}

// registerHostLivenessAndDiagnostics installs the minimal liveness contract
// and, only when an optional typed telemetry source exists, the richer local
// diagnostics contract. The caller binds HTTPService to literal loopback.
func registerHostLivenessAndDiagnostics(mux *http.ServeMux, healthSource *runtimeHealthSource, tracker *health.HealthTracker, metrics *observability.Registry, events *observability.EventLog) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/healthz", hostLivenessHandler)
	if tracker == nil && metrics == nil && events == nil {
		return
	}
	mux.Handle(HostDiagnosticsPath, hostDiagnosticsHandler{source: hostDiagnosticsSource{
		health:        healthSource,
		healthTracker: tracker,
		metrics:       metrics,
		events:        events,
	}})
}

func hostLivenessHandler(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodGet {
		if writer != nil {
			writer.Header().Set("Allow", http.MethodGet)
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	// Keep liveness deliberately independent of mutable workload and health
	// state. Reaching the handler proves that the stable daemon is serving.
	_, _ = io.WriteString(writer, `{"live":true}`)
}

type hostDiagnosticsHandler struct {
	source hostDiagnosticsSource
}

func (handler hostDiagnosticsHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || !hostDiagnosticsLoopback(request) {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if request.URL == nil || request.URL.Path != HostDiagnosticsPath || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	metrics := []observability.Series{}
	if handler.source.metrics != nil {
		metrics = handler.source.metrics.Snapshot()
		if len(metrics) > hostDiagnosticsMaximumMetrics {
			metrics = metrics[:hostDiagnosticsMaximumMetrics]
		}
	}
	events := []observability.Event{}
	droppedEvents := uint64(0)
	if handler.source.events != nil {
		events = handler.source.events.Snapshot()
		if len(events) > hostDiagnosticsMaximumEvents {
			events = events[len(events)-hostDiagnosticsMaximumEvents:]
		}
		droppedEvents = handler.source.events.DroppedEvents()
	}
	healthSnapshot := health.HealthSnapshot{}
	if handler.source.health != nil {
		healthSnapshot = handler.source.health.TypedSnapshot()
	}
	if healthSnapshot.Schema == "" && handler.source.healthTracker != nil {
		healthSnapshot = handler.source.healthTracker.Snapshot()
	}

	body, err := json.Marshal(HostDiagnostics{
		Schema:        hostDiagnosticsSchemaV1,
		Health:        healthSnapshot,
		Metrics:       metrics,
		Events:        events,
		DroppedEvents: droppedEvents,
	})
	if err != nil || len(body) > hostDiagnosticsMaximumBytes {
		writeHostDiagnosticsUnavailable(writer)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func writeHostDiagnosticsUnavailable(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(writer, `{"error":"diagnostics_unavailable"}`)
}

func hostDiagnosticsLoopback(request *http.Request) bool {
	if request == nil {
		return false
	}
	remoteAddress := strings.TrimSpace(request.RemoteAddr)
	if remoteAddress == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// TypedSnapshot reads the optional shared typed health state without exposing
// the legacy health registry used by /healthz and existing API handlers.
func (s *runtimeHealthSource) TypedSnapshot() health.HealthSnapshot {
	if s == nil {
		return health.HealthSnapshot{}
	}
	s.mu.RLock()
	runtime := s.runtime
	s.mu.RUnlock()
	if runtime == nil {
		return health.HealthSnapshot{}
	}
	return runtime.TypedHealth()
}

var _ http.Handler = hostDiagnosticsHandler{}
