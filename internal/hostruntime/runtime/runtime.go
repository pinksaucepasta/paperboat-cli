package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

var (
	ErrInvalidConfiguration = errors.New("invalid runtime configuration")
	ErrInvalidState         = errors.New("invalid runtime state")
)

type Service interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}
type Component struct {
	Capability string
	Required   bool
	Service    Service
}
type Config struct {
	Version         string
	Components      []Component
	ShutdownTimeout time.Duration
	Clock           health.Clock

	// HealthTracker, Metrics, and EventLog are optional integration points for
	// the stable host telemetry contract. The legacy health registry remains
	// authoritative for existing callers, and these hooks are never allocated
	// implicitly so a nil configuration preserves the old behavior.
	HealthTracker *health.HealthTracker
	Metrics       *observability.Registry
	EventLog      *observability.EventLog
	CorrelationID string
}
type State string

const (
	New      State = "new"
	Starting State = "starting"
	Running  State = "running"
	Stopping State = "stopping"
	Stopped  State = "stopped"
	Failed   State = "failed"
)

type Runtime struct {
	opMu            sync.Mutex
	mu              sync.RWMutex
	config          Config
	state           State
	started         []Component
	health          *health.Registry
	typedHealth     *health.HealthTracker
	metrics         *observability.Registry
	eventLog        *observability.EventLog
	correlation     string
	typedComponents map[health.Dimension]map[string]componentHealthState
	typedSequence   uint64
	startedAt       time.Time
}

type componentHealthState struct {
	update   health.HealthUpdate
	sequence uint64
}

func stableCorrelationID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 128 {
		return "correlation_runtime"
	}
	validPrefix := false
	for _, prefix := range []string{"corr_", "cor_", "correlation_", "request_", "pb-"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			validPrefix = true
			break
		}
	}
	if !validPrefix {
		return "correlation_runtime"
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return "correlation_runtime"
		}
	}
	return value
}

func NewRuntime(config Config) (*Runtime, error) {
	if config.Version == "" || len(config.Components) == 0 {
		return nil, ErrInvalidConfiguration
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.ShutdownTimeout <= 0 {
		return nil, ErrInvalidConfiguration
	}
	seen := make(map[string]bool)
	capabilities := make([]string, 0, len(config.Components))
	for _, component := range config.Components {
		if component.Capability == "" || component.Service == nil || seen[component.Capability] {
			return nil, ErrInvalidConfiguration
		}
		seen[component.Capability] = true
		capabilities = append(capabilities, component.Capability)
	}
	return &Runtime{
		config:          config,
		state:           New,
		health:          health.New(config.Version, capabilities, config.Clock),
		typedHealth:     config.HealthTracker,
		metrics:         config.Metrics,
		eventLog:        config.EventLog,
		correlation:     stableCorrelationID(config.CorrelationID),
		typedComponents: make(map[health.Dimension]map[string]componentHealthState),
	}, nil
}

func (r *Runtime) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.mu.Lock()
	if r.state != New {
		r.mu.Unlock()
		return ErrInvalidState
	}
	r.state = Starting
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		r.recordLifecycle(Component{Capability: "service", Required: true}, lifecycleStart, "start_canceled", health.StatusDown, health.RetryWaitForChange, time.Time{}, observability.OutcomeCanceled, observability.SeverityWarn, "Runtime start was canceled.")
		r.mu.Lock()
		r.state = Failed
		r.mu.Unlock()
		r.health.SetLive(false)
		return err
	}
	for _, component := range r.config.Components {
		err := component.Service.Start(ctx)
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			cleanupErr := r.cleanupFailed(component)
			code, outcome, severity := lifecycleFailure(lifecycleStart, err)
			status := health.StatusDown
			if !component.Required {
				status = health.StatusDegraded
			}
			retry, nextRetry := lifecycleRetry(r.telemetryNow(), outcome)
			if !component.Required {
				r.health.Set(component.Capability, health.Unavailable, "start_failed", 0)
				r.recordLifecycle(component, lifecycleStart, code, status, retry, nextRetry, outcome, severity, "Component failed to start.")
				continue
			}
			r.health.Set(component.Capability, health.Unavailable, "start_failed", 0)
			r.recordLifecycle(component, lifecycleStart, code, status, retry, nextRetry, outcome, severity, "Required component failed to start.")
			r.updateServiceHealth(status, code, retry, nextRetry)
			rollbackErr := r.rollback()
			r.mu.Lock()
			r.state = Failed
			r.mu.Unlock()
			r.health.SetLive(false)
			return errors.Join(fmt.Errorf("start %s: %w", component.Capability, err), cleanupErr, rollbackErr)
		}
		r.started = append(r.started, component)
		r.health.Set(component.Capability, health.Ready, "", 0)
		r.recordLifecycle(component, lifecycleStart, "ready", health.StatusReady, health.RetryNone, time.Time{}, observability.OutcomeStateChange, observability.SeverityInfo, "Component started.")
	}
	r.mu.Lock()
	r.state = Running
	r.mu.Unlock()
	r.updateServiceHealth(health.StatusReady, "ready", health.RetryNone, time.Time{})
	r.startedAt = r.telemetryNow()
	if r.metrics != nil {
		_ = r.metrics.SetServiceUptime(r.startedAt, r.startedAt)
	}
	return nil
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.health.SetLive(false)
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.mu.Lock()
	if r.state == Stopped {
		r.mu.Unlock()
		return nil
	}
	if r.state != Running && r.state != Failed {
		r.mu.Unlock()
		return ErrInvalidState
	}
	r.state = Stopping
	r.mu.Unlock()
	shutdownCtx, cancel := context.WithTimeout(ctx, r.config.ShutdownTimeout)
	defer cancel()
	var result error
	for i := len(r.started) - 1; i >= 0; i-- {
		component := r.started[i]
		err := component.Service.Shutdown(shutdownCtx)
		if err == nil {
			err = shutdownCtx.Err()
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("shutdown %s: %w", component.Capability, err))
			r.health.Set(component.Capability, health.Degraded, "shutdown_failed", 0)
			code, outcome, severity := lifecycleFailure(lifecycleShutdown, err)
			retry, nextRetry := lifecycleRetry(r.telemetryNow(), outcome)
			r.recordLifecycle(component, lifecycleShutdown, code, health.StatusDegraded, retry, nextRetry, outcome, severity, "Component shutdown failed.")
		} else {
			r.health.Set(component.Capability, health.Unavailable, "stopped", 0)
			r.recordLifecycle(component, lifecycleShutdown, "stopped", health.StatusNotApplicable, health.RetryNone, time.Time{}, observability.OutcomeStateChange, observability.SeverityInfo, "Component stopped.")
		}
	}
	r.started = nil
	if result == nil {
		r.updateServiceHealth(health.StatusNotApplicable, "stopped", health.RetryNone, time.Time{})
	} else {
		code, outcome, _ := lifecycleFailure(lifecycleShutdown, result)
		retry, nextRetry := lifecycleRetry(r.telemetryNow(), outcome)
		r.updateServiceHealth(health.StatusDegraded, code, retry, nextRetry)
	}
	r.mu.Lock()
	r.state = Stopped
	r.mu.Unlock()
	if !r.startedAt.IsZero() && r.metrics != nil {
		_ = r.metrics.SetServiceUptime(r.startedAt, r.telemetryNow())
	}
	return result
}

func (r *Runtime) State() State            { r.mu.RLock(); defer r.mu.RUnlock(); return r.state }
func (r *Runtime) Health() health.Snapshot { return r.health.Snapshot() }

// TypedHealth returns the optional shared health contract. A zero snapshot is
// returned when the runtime was constructed without typed telemetry.
func (r *Runtime) TypedHealth() health.HealthSnapshot {
	if r == nil || r.typedHealth == nil {
		return health.HealthSnapshot{}
	}
	return r.typedHealth.Snapshot()
}

func (r *Runtime) rollback() error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ShutdownTimeout)
	defer cancel()
	var result error
	rollbackOutcome := "success"
	for i := len(r.started) - 1; i >= 0; i-- {
		component := r.started[i]
		err := component.Service.Shutdown(ctx)
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("rollback %s: %w", component.Capability, err))
			r.health.Set(component.Capability, health.Degraded, "rollback_failed", 0)
			code, outcome, severity := lifecycleFailure(lifecycleRollback, err)
			retry, nextRetry := lifecycleRetry(r.telemetryNow(), outcome)
			r.recordLifecycle(component, lifecycleRollback, code, health.StatusDegraded, retry, nextRetry, outcome, severity, "Component rollback failed.")
			if outcome == observability.OutcomeCanceled {
				rollbackOutcome = "canceled"
			}
		} else {
			r.health.Set(component.Capability, health.Unavailable, "stopped", 0)
			r.recordLifecycle(component, lifecycleRollback, "stopped", health.StatusNotApplicable, health.RetryNone, time.Time{}, observability.OutcomeStateChange, observability.SeverityInfo, "Component rolled back.")
		}
	}
	r.started = nil
	if r.metrics != nil {
		if result != nil && rollbackOutcome == "success" {
			rollbackOutcome = "failed"
		}
		_ = r.metrics.RecordUpdatePhase("rollback", rollbackOutcome)
	}
	return result
}

func (r *Runtime) cleanupFailed(component Component) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ShutdownTimeout)
	defer cancel()
	if err := component.Service.Shutdown(ctx); err != nil {
		return fmt.Errorf("cleanup failed start %s: %w", component.Capability, err)
	}
	return nil
}

const (
	lifecycleStart    = "component_start"
	lifecycleShutdown = "component_shutdown"
	lifecycleRollback = "component_rollback"
)

func lifecycleFailure(operation string, err error) (string, observability.EventOutcome, observability.EventSeverity) {
	prefix := strings.TrimPrefix(operation, "component_")
	if errors.Is(err, context.Canceled) {
		return prefix + "_canceled", observability.OutcomeCanceled, observability.SeverityWarn
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return prefix + "_deadline", observability.OutcomeCanceled, observability.SeverityWarn
	}
	return prefix + "_failed", observability.OutcomeFailed, observability.SeverityError
}

func lifecycleRetry(now time.Time, outcome observability.EventOutcome) (health.RetryDecision, time.Time) {
	if outcome == observability.OutcomeStateChange || outcome == observability.OutcomeSuccess {
		return health.RetryNone, time.Time{}
	}
	if now.IsZero() {
		return health.RetryWaitForChange, time.Time{}
	}
	return health.RetryScheduled, now.Add(time.Second)
}

func (r *Runtime) telemetryNow() time.Time {
	if r != nil && r.config.Clock != nil {
		if now := r.config.Clock.Now(); !now.IsZero() {
			return now.UTC().Round(0)
		}
	}
	return time.Now().UTC().Round(0)
}

func (r *Runtime) recordLifecycle(component Component, operation, code string, status health.HealthStatus, retry health.RetryDecision, nextRetry time.Time, outcome observability.EventOutcome, severity observability.EventSeverity, message string) {
	dimension := componentDimension(component.Capability)
	correlation := r.correlation
	if correlation == "" {
		correlation = "correlation_runtime"
	}
	r.updateTypedHealth(component.Capability, health.HealthUpdate{
		Dimension:     dimension,
		Status:        status,
		Code:          code,
		Summary:       message,
		RepairAction:  lifecycleRepairAction(status),
		CorrelationID: correlation,
		Retry:         retry,
		NextRetryAt:   nextRetry,
	})

	if r.metrics != nil {
		_ = r.metrics.Record("paperboat_runtime_operations_total", 1, map[string]string{
			"component": metricComponent(component.Capability),
			"result":    metricResult(outcome, code),
		})
	}
	if r.eventLog == nil {
		return
	}
	now := r.telemetryNow()
	_, _ = r.eventLog.Record(observability.EventInput{
		At:            now,
		Severity:      severity,
		Component:     string(dimension),
		Name:          operation,
		Code:          code,
		Outcome:       outcome,
		Message:       message,
		CorrelationID: correlation,
		IDs: observability.SafeIDs{
			ResourceID: resourceID(component.Capability),
			SessionID:  "session_runtime",
			ProcessID:  "process_runtime",
			ConfigID:   configID(r.config.Version),
		},
		Retry:       retry,
		NextRetryAt: nextRetry,
	})
}

func (r *Runtime) updateServiceHealth(status health.HealthStatus, code string, retry health.RetryDecision, nextRetry time.Time) {
	if r == nil {
		return
	}
	correlation := r.correlation
	if correlation == "" {
		correlation = "correlation_runtime"
	}
	r.updateTypedHealth("runtime_service", health.HealthUpdate{
		Dimension:     health.DimensionService,
		Status:        status,
		Code:          code,
		Summary:       "Host runtime service state changed.",
		RepairAction:  lifecycleRepairAction(status),
		CorrelationID: correlation,
		Retry:         retry,
		NextRetryAt:   nextRetry,
	})
}

func (r *Runtime) updateTypedHealth(capability string, update health.HealthUpdate) {
	if r == nil || r.typedHealth == nil {
		return
	}
	if r.typedComponents == nil {
		r.typedComponents = make(map[health.Dimension]map[string]componentHealthState)
	}
	components := r.typedComponents[update.Dimension]
	if components == nil {
		components = make(map[string]componentHealthState)
		r.typedComponents[update.Dimension] = components
	}
	r.typedSequence++
	components[capability] = componentHealthState{update: update, sequence: r.typedSequence}
	aggregate := aggregateHealthUpdate(components)
	previous := r.typedHealth.Snapshot().Dimensions.Get(update.Dimension)
	if err := r.typedHealth.Update(aggregate); err != nil {
		return
	}
	if r.metrics == nil {
		return
	}
	snapshot := r.typedHealth.Snapshot()
	current := snapshot.Dimensions.Get(update.Dimension)
	if previous.Status != current.Status || previous.Code != current.Code {
		_ = r.metrics.RecordHealthTransition(update.Dimension, previous.Status, current.Status)
	}
	_ = r.metrics.RecordHealth(snapshot)
}

func aggregateHealthUpdate(components map[string]componentHealthState) health.HealthUpdate {
	var selected componentHealthState
	selectedRank := -1
	for _, candidate := range components {
		rank := healthStatusRank(candidate.update.Status)
		if rank > selectedRank || rank == selectedRank && candidate.sequence > selected.sequence {
			selected = candidate
			selectedRank = rank
		}
	}
	return selected.update
}

func healthStatusRank(status health.HealthStatus) int {
	switch status {
	case health.StatusDown:
		return 5
	case health.StatusDegraded:
		return 4
	case health.StatusUnknown:
		return 3
	case health.StatusReady:
		return 2
	case health.StatusNotApplicable:
		return 1
	default:
		return 0
	}
}

func componentDimension(capability string) health.Dimension {
	normalized := strings.ToLower(strings.TrimSpace(capability))
	normalized = strings.NewReplacer(".", "_", "-", "_").Replace(normalized)
	switch {
	case normalized == "edge" || strings.Contains(normalized, "connector") || strings.Contains(normalized, "transport") || strings.Contains(normalized, "tunnel") || strings.Contains(normalized, "peer"):
		return health.DimensionEdge
	case normalized == "config" || strings.Contains(normalized, "config"):
		return health.DimensionConfig
	case normalized == "route" || strings.Contains(normalized, "route"):
		return health.DimensionRoute
	case normalized == "origin" || strings.Contains(normalized, "origin") || normalized == "target" || strings.Contains(normalized, "preview") || strings.Contains(normalized, "serve"):
		return health.DimensionOrigin
	case normalized == "dns" || strings.Contains(normalized, "dns"):
		return health.DimensionDNS
	case normalized == "certificate" || strings.Contains(normalized, "cert") || strings.Contains(normalized, "tls"):
		return health.DimensionCertificate
	case normalized == "access" || strings.Contains(normalized, "authoriz") || normalized == "auth" || strings.Contains(normalized, "admission"):
		return health.DimensionAccess
	case normalized == "update" || strings.Contains(normalized, "update"):
		return health.DimensionUpdate
	default:
		return health.DimensionService
	}
}

func lifecycleRepairAction(status health.HealthStatus) string {
	if status == health.StatusReady || status == health.StatusNotApplicable {
		return "No action is required."
	}
	return "Retry or restart the affected host component."
}

func metricComponent(capability string) string {
	normalized := strings.ToLower(strings.TrimSpace(capability))
	switch {
	case strings.Contains(normalized, "protocol"):
		return "protocol"
	case strings.Contains(normalized, "auth") || strings.Contains(normalized, "access") || strings.Contains(normalized, "admission"):
		return "auth"
	case strings.Contains(normalized, "session"):
		return "session"
	case strings.Contains(normalized, "upload") || strings.Contains(normalized, "transfer"):
		return "upload"
	case strings.Contains(normalized, "preview") || strings.Contains(normalized, "target") || strings.Contains(normalized, "serve"):
		return "preview"
	case strings.Contains(normalized, "connector") || strings.Contains(normalized, "edge") || strings.Contains(normalized, "transport") || strings.Contains(normalized, "tunnel") || strings.Contains(normalized, "peer"):
		return "connector"
	case strings.Contains(normalized, "update"):
		return "update"
	case strings.Contains(normalized, "storage"):
		return "storage"
	default:
		return "service"
	}
}

func metricResult(outcome observability.EventOutcome, code string) string {
	switch outcome {
	case observability.OutcomeCanceled:
		if strings.HasSuffix(code, "_deadline") {
			return "deadline"
		}
		return "canceled"
	case observability.OutcomeFailed, observability.OutcomeRejected:
		return "unavailable"
	default:
		return "ok"
	}
}

func opaqueIDPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
		if builder.Len() >= 64 {
			break
		}
	}
	part := strings.Trim(builder.String(), "_")
	if len(part) < 2 {
		part = "runtime"
	}
	return part
}

func resourceID(capability string) string { return "resource_" + opaqueIDPart(capability) }
func configID(version string) string      { return "config_" + opaqueIDPart(version) }
