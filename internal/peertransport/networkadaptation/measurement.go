package networkadaptation

import (
	"context"
	"errors"
	"time"
)

type ProbeResult struct {
	Reachable bool
	At        time.Time
}

// LifetimeProber owns an authenticated path and leaves it idle for the
// requested duration before testing whether the same mapping remains usable.
type LifetimeProber interface {
	ProbeAfterIdle(context.Context, time.Duration) (ProbeResult, error)
}

type MeasurementPolicy struct {
	IdleSteps       []time.Duration
	AttemptsPerStep int
	ResponseTimeout time.Duration
	TotalTimeout    time.Duration
}

func DevelopmentMeasurementPolicy() MeasurementPolicy {
	return MeasurementPolicy{
		IdleSteps:       []time.Duration{10 * time.Second, 30 * time.Second, time.Minute},
		AttemptsPerStep: 3,
		ResponseTimeout: 5 * time.Second,
		TotalTimeout:    7 * time.Minute,
	}
}

func (p MeasurementPolicy) validate() error {
	if len(p.IdleSteps) == 0 || len(p.IdleSteps) > 16 || p.AttemptsPerStep < 3 || p.AttemptsPerStep > 16 || p.ResponseTimeout <= 0 || p.TotalTimeout <= 0 {
		return ErrInvalid
	}
	var required time.Duration
	for index, idle := range p.IdleSteps {
		if idle <= 0 || index > 0 && idle <= p.IdleSteps[index-1] {
			return ErrInvalid
		}
		attemptBudget := idle + p.ResponseTimeout
		if attemptBudget <= idle || attemptBudget > time.Duration(1<<63-1)/time.Duration(p.AttemptsPerStep) {
			return ErrInvalid
		}
		stepBudget := attemptBudget * time.Duration(p.AttemptsPerStep)
		if required > time.Duration(1<<63-1)-stepBudget {
			return ErrInvalid
		}
		required += stepBudget
	}
	if required > p.TotalTimeout {
		return ErrInvalid
	}
	return nil
}

type Measurement struct {
	Attempts       int
	CompletedSteps int
	LowerBound     time.Duration
	FailedAt       time.Duration
}

type LifetimeMeasurer struct {
	policy MeasurementPolicy
	cache  *LifetimeCache
	prober LifetimeProber
}

func NewLifetimeMeasurer(policy MeasurementPolicy, cache *LifetimeCache, prober LifetimeProber) (*LifetimeMeasurer, error) {
	if err := policy.validate(); err != nil || cache == nil || prober == nil {
		return nil, ErrInvalid
	}
	return &LifetimeMeasurer{policy: policy, cache: cache, prober: prober}, nil
}

func (m *LifetimeMeasurer) Measure(ctx context.Context, fingerprint Fingerprint) (Measurement, error) {
	if m == nil || ctx == nil || !fingerprint.valid() {
		return Measurement{}, ErrInvalid
	}
	measurementCtx, cancel := context.WithTimeout(ctx, m.policy.TotalTimeout)
	defer cancel()
	var measurement Measurement
	var previous time.Time
	for _, idle := range m.policy.IdleSteps {
		for range m.policy.AttemptsPerStep {
			attemptCtx, attemptCancel := context.WithTimeout(measurementCtx, idle+m.policy.ResponseTimeout)
			result, err := m.prober.ProbeAfterIdle(attemptCtx, idle)
			attemptCancel()
			measurement.Attempts++
			if err != nil {
				return measurement, err
			}
			if err := measurementCtx.Err(); err != nil {
				return measurement, err
			}
			if result.At.IsZero() || !previous.IsZero() && !result.At.After(previous) {
				return measurement, ErrInvalid
			}
			previous = result.At
			if !result.Reachable {
				if err := m.cache.RecordFailure(fingerprint, idle, result.At); err != nil {
					return measurement, err
				}
				measurement.FailedAt = idle
				return measurement, nil
			}
			if err := m.cache.RecordSuccess(fingerprint, idle, result.At); err != nil {
				return measurement, err
			}
		}
		measurement.CompletedSteps++
		measurement.LowerBound = idle
	}
	return measurement, nil
}

func IsMeasurementCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
