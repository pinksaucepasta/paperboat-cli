package observability

import (
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
)

// RecordHealth publishes every canonical dimension with only fixed labels.
// Callers should invoke RecordHealthTransition when they have the previous
// status; snapshots intentionally do not retain transition history.
func (r *Registry) RecordHealth(snapshot health.HealthSnapshot) error {
	for _, dimension := range health.Dimensions() {
		state := snapshot.Dimensions.Get(dimension)
		if err := r.Record(MetricHealthDimension, 1, map[string]string{
			"dimension": string(dimension),
			"status":    statusValue(state.Status),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) RecordHealthTransition(dimension health.Dimension, from, to health.HealthStatus) error {
	return r.Record(MetricHealthTransitions, 1, map[string]string{
		"dimension": string(dimension),
		"from":      statusValue(from),
		"to":        statusValue(to),
	})
}

func (r *Registry) RecordHealthProbe(dimension health.Dimension, duration time.Duration) error {
	if duration < 0 {
		return ErrInvalidLabels
	}
	return r.Record(MetricHealthProbeLatency, duration.Seconds(), map[string]string{"dimension": string(dimension)})
}

func (r *Registry) RecordUpdatePhase(phase, outcome string) error {
	return r.Record(MetricUpdateOperations, 1, map[string]string{"phase": phase, "outcome": outcome})
}

func (r *Registry) RecordUpdateOperation(phase, outcome string) error {
	return r.RecordUpdatePhase(phase, outcome)
}

func (r *Registry) RecordDoctorCheck(check, outcome string) error {
	return r.Record(MetricDoctorChecks, 1, map[string]string{"check": check, "outcome": outcome})
}

func (r *Registry) RecordStateEvidence(kind string, value uint64) error {
	return r.Record(MetricStateEvidence, float64(value), map[string]string{"kind": kind})
}

func (r *Registry) SetServiceUptime(startedAt, now time.Time) error {
	if startedAt.IsZero() || now.IsZero() || now.Before(startedAt) {
		return ErrInvalidLabels
	}
	return r.Record(MetricServiceUptime, now.Sub(startedAt).Seconds(), nil)
}

func (r *Registry) RecordServiceRestart(reason string) error {
	return r.Record(MetricServiceRestarts, 1, map[string]string{"reason": reason})
}

func (r *Registry) RecordWatchdogFailure(reason string) error {
	return r.Record(MetricWatchdogFailures, 1, map[string]string{"reason": reason})
}

func (r *Registry) SetCrashLoop(active bool) error {
	var value float64
	if active {
		value = 1
	}
	return r.Record(MetricCrashLoop, value, nil)
}

func statusValue(status health.HealthStatus) string { return string(status) }
