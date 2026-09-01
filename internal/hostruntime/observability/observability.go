package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

var (
	ErrUnsafeValue     = errors.New("unsafe observability value")
	ErrUnknownMetric   = errors.New("unknown metric")
	ErrInvalidLabels   = errors.New("invalid metric labels")
	ErrDiagnosticLimit = errors.New("diagnostic size limit")
)

type Event struct {
	// Canonical event envelope. These fields are intentionally the same shape
	// as server and edge telemetry so host events can be forwarded unchanged.
	Schema        string        `json:"schema"`
	At            time.Time     `json:"at"`
	Severity      EventSeverity `json:"severity"`
	Component     Dimension     `json:"component"`
	Name          string        `json:"name"`
	Code          string        `json:"code"`
	Outcome       EventOutcome  `json:"outcome"`
	Message       string        `json:"message"`
	CorrelationID string        `json:"correlation_id"`
	IDs           SafeIDs       `json:"ids"`
	Generations   Generations   `json:"generations"`
	Retry         RetryDecision `json:"retry"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`

	// Legacy runtime logger projection. They remain part of the in-process
	// value for existing callers, but are excluded from canonical JSON.
	Operation  string        `json:"-"`
	Result     string        `json:"-"`
	ErrorCode  string        `json:"-"`
	ResourceID string        `json:"-"`
	Duration   time.Duration `json:"-"`
	Bytes      uint64        `json:"-"`
	Count      uint64        `json:"-"`
	MachineID  string        `json:"-"`
	State      string        `json:"-"`
	Role       string        `json:"-"`
	Generation uint64        `json:"-"`
}
type Logger struct{ logger *slog.Logger }

func NewLogger(logger *slog.Logger) (*Logger, error) {
	if logger == nil {
		return nil, ErrUnsafeValue
	}
	return &Logger{logger: logger}, nil
}
func (l *Logger) Log(ctx context.Context, event Event) error {
	component := string(event.Component)
	operation := event.Operation
	if operation == "" {
		operation = event.Name
	}
	result := event.Result
	if result == "" {
		result = string(event.Outcome)
	}
	errorCode := event.ErrorCode
	if errorCode == "" {
		errorCode = event.Code
	}
	if component == "" || operation == "" || result == "" {
		return ErrUnsafeValue
	}
	for _, value := range []string{component, operation, result, errorCode, event.CorrelationID, event.ResourceID, event.MachineID, event.State, event.Role} {
		if value != "" && !safeValue(value) {
			return ErrUnsafeValue
		}
	}
	if !validSafeIDs(event.IDs) {
		return ErrUnsafeValue
	}
	message := event.Message
	if message != "" {
		var err error
		message, err = safeBoundedString(message, maximumMessageBytes, false)
		if err != nil {
			return ErrUnsafeValue
		}
	}
	attributes := []any{"component", component, "operation", operation, "result", result, "duration_ms", event.Duration.Milliseconds(), "bytes", event.Bytes, "count", event.Count}
	if errorCode != "" {
		attributes = append(attributes, "error_code", errorCode)
	}
	if event.CorrelationID != "" {
		attributes = append(attributes, "correlation_id", event.CorrelationID)
	}
	if event.ResourceID != "" {
		attributes = append(attributes, "resource_id", event.ResourceID)
	}
	if event.IDs.ResourceID != "" && event.ResourceID == "" {
		attributes = append(attributes, "resource_id", event.IDs.ResourceID)
	}
	if event.IDs.SessionID != "" {
		attributes = append(attributes, "session_id", event.IDs.SessionID)
	}
	if event.IDs.ProcessID != "" {
		attributes = append(attributes, "process_id", event.IDs.ProcessID)
	}
	if event.IDs.ConfigID != "" {
		attributes = append(attributes, "config_id", event.IDs.ConfigID)
	}
	if message != "" {
		attributes = append(attributes, "message", message)
	}
	if event.MachineID != "" {
		attributes = append(attributes, "machine_id", event.MachineID)
	}
	if event.State != "" {
		attributes = append(attributes, "state", event.State)
	}
	if event.Role != "" {
		attributes = append(attributes, "role", event.Role)
	}
	if event.Generation != 0 {
		attributes = append(attributes, "generation", event.Generation)
	}
	l.logger.InfoContext(ctx, "runtime_event", attributes...)
	return nil
}

type Kind string

const (
	Counter   Kind = "counter"
	Gauge     Kind = "gauge"
	Histogram Kind = "histogram"
)

const (
	MetricServiceUptime      = "paperboat_runtime_service_uptime_seconds"
	MetricServiceRestarts    = "paperboat_runtime_service_restarts_total"
	MetricWatchdogFailures   = "paperboat_runtime_watchdog_failures_total"
	MetricCrashLoop          = "paperboat_runtime_crash_loop"
	MetricHealthDimension    = "paperboat_runtime_health_dimension"
	MetricHealthTransitions  = "paperboat_runtime_health_transitions_total"
	MetricUpdateOperations   = "paperboat_runtime_update_operations_total"
	MetricDoctorChecks       = "paperboat_runtime_doctor_checks_total"
	MetricHealthProbeLatency = "paperboat_runtime_health_probe_latency_seconds"
	MetricStateEvidence      = "paperboat_runtime_state_evidence"
)

var (
	healthMetricDimensions = set("service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update")
	healthMetricStatuses   = set("unknown", "ready", "degraded", "down", "not_applicable")
	updateMetricPhases     = set("download", "verify", "stage", "activate", "health_gate", "rollback", "quarantine")
	updateMetricOutcomes   = set("success", "failed", "canceled")
	doctorMetricChecks     = set("state", "credential", "clock", "dns", "edge", "transport", "config", "origin", "resource")
	doctorMetricOutcomes   = set("ok", "degraded", "failed", "unknown")
)

type Descriptor struct {
	Name   string
	Kind   Kind
	Labels map[string]map[string]bool
}
type Series struct {
	Name   string
	Labels map[string]string
	Value  float64
}
type Registry struct {
	mu             sync.Mutex
	descriptors    map[string]Descriptor
	series         map[string]Series
	histograms     map[string]histogramSeries
	maxSeries      int
	terminalFrames [2]atomic.Uint64
	terminalBytes  [2]atomic.Uint64
	terminalNanos  [2]atomic.Uint64
}

type histogramSeries struct {
	Name    string
	Labels  map[string]string
	Count   uint64
	Sum     float64
	Buckets [9]uint64
}

var histogramBounds = [...]float64{0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, math.Inf(1)}

const (
	maximumMetricDescriptors = 128
	maximumMetricLabels      = 8
	maximumMetricLabelValues = 64
	maximumMetricSeries      = 4096
)

func NewRegistry(descriptors []Descriptor) (*Registry, error) {
	if len(descriptors) > maximumMetricDescriptors {
		return nil, ErrUnknownMetric
	}
	registry := &Registry{descriptors: make(map[string]Descriptor, len(descriptors)), series: make(map[string]Series), histograms: make(map[string]histogramSeries), maxSeries: maximumMetricSeries}
	for _, descriptor := range descriptors {
		if !safeMetricName(descriptor.Name) || descriptor.Kind != Counter && descriptor.Kind != Gauge && descriptor.Kind != Histogram || registry.descriptors[descriptor.Name].Name != "" {
			return nil, ErrUnknownMetric
		}
		if len(descriptor.Labels) > maximumMetricLabels {
			return nil, ErrInvalidLabels
		}
		for label, values := range descriptor.Labels {
			if !safeMetricName(label) || len(values) == 0 || len(values) > maximumMetricLabelValues {
				return nil, ErrInvalidLabels
			}
			for value := range values {
				if !safeValue(value) {
					return nil, ErrInvalidLabels
				}
			}
		}
		registry.descriptors[descriptor.Name] = cloneDescriptor(descriptor)
	}
	return registry, nil
}
func (r *Registry) Record(name string, value float64, labels map[string]string) error {
	if r == nil {
		return ErrUnknownMetric
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	descriptor, ok := r.descriptors[name]
	if !ok {
		return ErrUnknownMetric
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ErrInvalidLabels
	}
	if len(labels) != len(descriptor.Labels) {
		return ErrInvalidLabels
	}
	keys := make([]string, 0, len(labels))
	for label, labelValue := range labels {
		allowed, ok := descriptor.Labels[label]
		if !ok || !allowed[labelValue] {
			return ErrInvalidLabels
		}
		keys = append(keys, label)
	}
	sort.Strings(keys)
	var key strings.Builder
	key.WriteString(name)
	copied := make(map[string]string, len(labels))
	for _, label := range keys {
		key.WriteByte('|')
		key.WriteString(label)
		key.WriteByte('=')
		key.WriteString(labels[label])
		copied[label] = labels[label]
	}
	series := r.series[key.String()]
	if _, exists := r.series[key.String()]; !exists && len(r.series)+len(r.histograms) >= r.maxSeries {
		return ErrInvalidLabels
	}
	series.Name = name
	series.Labels = copied
	if descriptor.Kind == Histogram {
		if value < 0 {
			return ErrInvalidLabels
		}
		histogram := r.histograms[key.String()]
		if _, exists := r.histograms[key.String()]; !exists && len(r.series)+len(r.histograms) >= r.maxSeries {
			return ErrInvalidLabels
		}
		histogram.Name, histogram.Labels = name, copied
		if histogram.Count == ^uint64(0) || math.IsInf(histogram.Sum+value, 0) {
			return ErrInvalidLabels
		}
		histogram.Count++
		histogram.Sum += value
		for index, bound := range histogramBounds {
			if value <= bound {
				if histogram.Buckets[index] == ^uint64(0) {
					return ErrInvalidLabels
				}
				histogram.Buckets[index]++
			}
		}
		r.histograms[key.String()] = histogram
		return nil
	}
	if descriptor.Kind == Counter {
		if value < 0 {
			return ErrInvalidLabels
		}
		if math.IsInf(series.Value+value, 0) {
			return ErrInvalidLabels
		}
		series.Value += value
	} else {
		series.Value = value
	}
	r.series[key.String()] = series
	return nil
}
func (r *Registry) Snapshot() []Series {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Series, 0, len(r.series))
	for _, series := range r.series {
		copyLabels := make(map[string]string, len(series.Labels))
		for key, value := range series.Labels {
			copyLabels[key] = value
		}
		series.Labels = copyLabels
		result = append(result, series)
	}
	for _, histogram := range r.histograms {
		for index, bound := range histogramBounds {
			labels := make(map[string]string, len(histogram.Labels)+1)
			for key, value := range histogram.Labels {
				labels[key] = value
			}
			labels["le"] = "+Inf"
			if !math.IsInf(bound, 1) {
				labels["le"] = strconv.FormatFloat(bound, 'g', -1, 64)
			}
			result = append(result, Series{Name: histogram.Name + "_bucket", Labels: labels, Value: float64(histogram.Buckets[index])})
		}
		result = append(result,
			Series{Name: histogram.Name + "_sum", Labels: histogram.Labels, Value: histogram.Sum},
			Series{Name: histogram.Name + "_count", Labels: histogram.Labels, Value: float64(histogram.Count)},
		)
	}
	for index, stage := range []string{"socket_to_pty", "pty_to_socket"} {
		frames := r.terminalFrames[index].Load()
		if frames == 0 {
			continue
		}
		direction := []string{"input", "output"}[index]
		result = append(result,
			Series{Name: "paperboat_runtime_terminal_frames_total", Labels: map[string]string{"direction": direction}, Value: float64(frames)},
			Series{Name: "paperboat_runtime_terminal_bytes_total", Labels: map[string]string{"direction": direction}, Value: float64(r.terminalBytes[index].Load())},
			Series{Name: "paperboat_runtime_terminal_stage_nanoseconds_total", Labels: map[string]string{"stage": stage}, Value: float64(r.terminalNanos[index].Load())},
		)
	}
	compression := protocol.TerminalCompressionMetrics()
	if compression.SmallFrames+compression.InsufficientFrames+compression.CompressedFrames+compression.EncodeFailures+compression.DecodeFailures > 0 {
		result = append(result,
			Series{Name: "paperboat_runtime_terminal_compression_frames_total", Labels: map[string]string{"encoding": "raw", "decision": "small"}, Value: float64(compression.SmallFrames)},
			Series{Name: "paperboat_runtime_terminal_compression_frames_total", Labels: map[string]string{"encoding": "raw", "decision": "insufficient"}, Value: float64(compression.InsufficientFrames)},
			Series{Name: "paperboat_runtime_terminal_compression_frames_total", Labels: map[string]string{"encoding": "zstd", "decision": "compressed"}, Value: float64(compression.CompressedFrames)},
			Series{Name: "paperboat_runtime_terminal_compression_frames_total", Labels: map[string]string{"encoding": "raw", "decision": "failure"}, Value: float64(compression.EncodeFailures)},
			Series{Name: "paperboat_runtime_terminal_compression_bytes_total", Labels: map[string]string{"kind": "raw"}, Value: float64(compression.RawBytes)},
			Series{Name: "paperboat_runtime_terminal_compression_bytes_total", Labels: map[string]string{"kind": "encoded"}, Value: float64(compression.EncodedBytes)},
			Series{Name: "paperboat_runtime_terminal_compression_nanoseconds_total", Labels: map[string]string{"stage": "encode"}, Value: float64(compression.EncodeNanos)},
			Series{Name: "paperboat_runtime_terminal_compression_nanoseconds_total", Labels: map[string]string{"stage": "decode"}, Value: float64(compression.DecodeNanos)},
			Series{Name: "paperboat_runtime_terminal_compression_failures_total", Labels: map[string]string{"stage": "encode"}, Value: float64(compression.EncodeFailures)},
			Series{Name: "paperboat_runtime_terminal_compression_failures_total", Labels: map[string]string{"stage": "decode"}, Value: float64(compression.DecodeFailures)},
		)
	}
	sort.Slice(result, func(i, j int) bool { return seriesKey(result[i]) < seriesKey(result[j]) })
	return result
}

// RecordTerminalStage is allocation-free and lock-free for the terminal hot path.
func (r *Registry) RecordTerminalStage(stage string, duration time.Duration, bytes int) {
	if r == nil {
		return
	}
	index := -1
	switch stage {
	case "socket_to_pty":
		index = 0
	case "pty_to_socket":
		index = 1
	}
	if index < 0 || duration < 0 || bytes < 0 {
		return
	}
	r.terminalFrames[index].Add(1)
	r.terminalBytes[index].Add(uint64(bytes))
	r.terminalNanos[index].Add(uint64(duration))
}

func DefaultDescriptors() []Descriptor {
	return []Descriptor{
		{Name: "paperboat_runtime_operations_total", Kind: Counter, Labels: map[string]map[string]bool{"component": set("protocol", "auth", "session", "upload", "preview", "connector", "update", "service", "storage"), "result": set("ok", "replayed", "rejected", "conflict", "canceled", "deadline", "unavailable")}},
		{Name: "paperboat_runtime_active_resources", Kind: Gauge, Labels: map[string]map[string]bool{"kind": set("sessions", "attachments", "processes", "uploads", "previews", "connectors", "serves_foreground", "serves_detached")}},
		{Name: "paperboat_runtime_readiness", Kind: Gauge, Labels: map[string]map[string]bool{"capability": set("terminal", "upload", "preview", "health", "connector", "update"), "state": set("ready", "degraded", "unavailable")}},
		{Name: "paperboat_runtime_connector_retries_total", Kind: Counter, Labels: map[string]map[string]bool{"transport": set("quic", "tcp_dedicated", "tcp_mux", "none"), "result": set("connected", "failed", "replaced", "canceled")}},
		{Name: "paperboat_runtime_restart_total", Kind: Counter},
		{Name: MetricServiceUptime, Kind: Gauge},
		{Name: MetricServiceRestarts, Kind: Counter, Labels: map[string]map[string]bool{"reason": set("crash", "upgrade", "shutdown", "unknown")}},
		{Name: MetricWatchdogFailures, Kind: Counter, Labels: map[string]map[string]bool{"reason": set("timeout", "crash", "unhealthy", "unknown")}},
		{Name: MetricCrashLoop, Kind: Gauge},
		{Name: "paperboat_runtime_renewal_failures_total", Kind: Counter},
		{Name: "paperboat_runtime_connector_recovery_seconds", Kind: Gauge},
		{Name: "paperboat_runtime_network_changes_total", Kind: Counter, Labels: map[string]map[string]bool{"reason": set("default_route", "interface_address", "address_family", "proxy", "network_cost", "viability", "wake"), "action": set("observe", "rebind")}},
		{Name: "paperboat_runtime_network_generation", Kind: Gauge},
		{Name: "paperboat_runtime_update_rollbacks_total", Kind: Counter},
		{Name: MetricHealthDimension, Kind: Gauge, Labels: map[string]map[string]bool{"dimension": cloneSet(healthMetricDimensions), "status": cloneSet(healthMetricStatuses)}},
		{Name: MetricHealthTransitions, Kind: Counter, Labels: map[string]map[string]bool{"dimension": cloneSet(healthMetricDimensions), "from": cloneSet(healthMetricStatuses), "to": cloneSet(healthMetricStatuses)}},
		{Name: MetricUpdateOperations, Kind: Counter, Labels: map[string]map[string]bool{"phase": cloneSet(updateMetricPhases), "outcome": cloneSet(updateMetricOutcomes)}},
		{Name: MetricDoctorChecks, Kind: Counter, Labels: map[string]map[string]bool{"check": cloneSet(doctorMetricChecks), "outcome": cloneSet(doctorMetricOutcomes)}},
		{Name: MetricHealthProbeLatency, Kind: Histogram, Labels: map[string]map[string]bool{"dimension": cloneSet(healthMetricDimensions)}},
		{Name: MetricStateEvidence, Kind: Gauge, Labels: map[string]map[string]bool{"kind": cloneSet(doctorMetricChecks)}},
		{Name: "paperboat_runtime_terminal_events_total", Kind: Counter, Labels: map[string]map[string]bool{"event": set("replay_gap", "slow_consumer", "input_uncertain", "runtime_restart")}},
		{Name: "paperboat_runtime_terminal_persistence_failures_total", Kind: Counter},
		{Name: "paperboat_runtime_terminal_persistence_lag_bytes", Kind: Gauge},
		{Name: "paperboat_runtime_terminal_frames_total", Kind: Counter, Labels: map[string]map[string]bool{"direction": set("input", "output")}},
		{Name: "paperboat_runtime_terminal_bytes_total", Kind: Counter, Labels: map[string]map[string]bool{"direction": set("input", "output")}},
		{Name: "paperboat_runtime_terminal_stage_nanoseconds_total", Kind: Counter, Labels: map[string]map[string]bool{"stage": set("socket_to_pty", "pty_to_socket")}},
		{Name: "paperboat_runtime_terminal_compression_frames_total", Kind: Counter, Labels: map[string]map[string]bool{"encoding": set("raw", "zstd"), "decision": set("small", "insufficient", "compressed", "failure")}},
		{Name: "paperboat_runtime_terminal_compression_bytes_total", Kind: Counter, Labels: map[string]map[string]bool{"kind": set("raw", "encoded")}},
		{Name: "paperboat_runtime_terminal_compression_nanoseconds_total", Kind: Counter, Labels: map[string]map[string]bool{"stage": set("encode", "decode")}},
		{Name: "paperboat_runtime_terminal_compression_failures_total", Kind: Counter, Labels: map[string]map[string]bool{"stage": set("encode", "decode")}},
		{Name: "paperboat_runtime_delivery_total", Kind: Counter, Labels: map[string]map[string]bool{"kind": set("runtime", "preview"), "result": set("delivered", "failed", "canceled")}},
		{Name: "paperboat_runtime_cleanup_total", Kind: Counter, Labels: map[string]map[string]bool{"kind": set("upload", "update", "session"), "result": set("removed", "preserved", "failed")}},
		{Name: "paperboat_runtime_serve_events_total", Kind: Counter, Labels: map[string]map[string]bool{"event": set("selection", "validation", "listener_start", "listener_stop", "preview_registration", "readiness", "ownership_transfer", "lease_acquire", "lease_renew", "lease_release", "lease_loss", "restart", "source_invalidation", "revoke", "drain", "cleanup", "orphan_cleanup"), "result": set("ok", "failed", "canceled", "timeout", "expired", "removed", "preserved")}},
		{Name: "paperboat_runtime_serve_latency_seconds", Kind: Histogram, Labels: map[string]map[string]bool{"stage": set("selection", "validation", "readiness", "drain", "reconciliation"), "owner": set("foreground", "detached"), "result": set("ok", "failed", "canceled", "timeout")}},
	}
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		for _, series := range r.Snapshot() {
			_, _ = writer.Write([]byte(series.Name))
			if len(series.Labels) > 0 {
				_, _ = writer.Write([]byte("{"))
				keys := make([]string, 0, len(series.Labels))
				for key := range series.Labels {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for index, key := range keys {
					if index > 0 {
						_, _ = writer.Write([]byte(","))
					}
					_, _ = writer.Write([]byte(key + "=" + strconv.Quote(series.Labels[key])))
				}
				_, _ = writer.Write([]byte("}"))
			}
			_, _ = writer.Write([]byte(" " + strconv.FormatFloat(series.Value, 'g', -1, 64) + "\n"))
		}
	})
}

type Diagnostics struct {
	Version        string                       `json:"version"`
	Profile        string                       `json:"profile"`
	CheckedAt      time.Time                    `json:"checked_at"`
	Live           bool                         `json:"live"`
	Capabilities   map[string]health.Capability `json:"capabilities"`
	Queues         map[string]uint64            `json:"queues"`
	CorrelationIDs []string                     `json:"correlation_ids,omitempty"`
}

func BuildDiagnostics(version, profile string, snapshot health.Snapshot, queues map[string]uint64, correlationIDs []string, maxBytes int) ([]byte, error) {
	if !safeValue(version) || !safeValue(profile) || maxBytes < 1 {
		return nil, ErrUnsafeValue
	}
	allowedQueues := map[string]bool{"attachment_bytes": true, "cleanup_backlog": true, "connector_retries": true, "update_pending": true}
	copyQueues := make(map[string]uint64, len(queues))
	for key, value := range queues {
		if !allowedQueues[key] {
			return nil, ErrUnsafeValue
		}
		copyQueues[key] = value
	}
	ids := make([]string, 0, len(correlationIDs))
	for _, id := range correlationIDs {
		if !safeValue(id) {
			return nil, ErrUnsafeValue
		}
		ids = append(ids, id)
	}
	capabilities := make(map[string]health.Capability, len(snapshot.Capabilities))
	for name, capability := range snapshot.Capabilities {
		validState := capability.State == health.Ready || capability.State == health.Degraded || capability.State == health.Unavailable
		if !safeValue(name) || !validState || capability.Reason != "" && !safeValue(capability.Reason) {
			return nil, ErrUnsafeValue
		}
		capabilities[name] = capability
	}
	diagnostics := Diagnostics{Version: version, Profile: profile, CheckedAt: snapshot.CheckedAt, Live: snapshot.Live, Capabilities: capabilities, Queues: copyQueues, CorrelationIDs: ids}
	encoded, err := json.Marshal(diagnostics)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxBytes {
		return nil, ErrDiagnosticLimit
	}
	return encoded, nil
}

func safeValue(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character)) {
			return false
		}
	}
	return true
}
func safeMetricName(value string) bool {
	if !safeValue(value) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character == '_') {
			return false
		}
	}
	return true
}
func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func cloneSet(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for value, allowed := range values {
		result[value] = allowed
	}
	return result
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	result := descriptor
	result.Labels = make(map[string]map[string]bool, len(descriptor.Labels))
	for label, values := range descriptor.Labels {
		copied := make(map[string]bool, len(values))
		for value, allowed := range values {
			copied[value] = allowed
		}
		result.Labels[label] = copied
	}
	return result
}
func seriesKey(series Series) string {
	encoded, _ := json.Marshal(series.Labels)
	return fmt.Sprintf("%s:%s", series.Name, encoded)
}
