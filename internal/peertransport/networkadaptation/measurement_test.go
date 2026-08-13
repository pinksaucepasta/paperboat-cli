package networkadaptation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type scriptedProbe struct {
	mu      sync.Mutex
	results []ProbeResult
	errors  []error
	idles   []time.Duration
	probe   func(context.Context, time.Duration) (ProbeResult, error)
}

func (p *scriptedProbe) ProbeAfterIdle(ctx context.Context, idle time.Duration) (ProbeResult, error) {
	p.mu.Lock()
	p.idles = append(p.idles, idle)
	probe := p.probe
	if probe != nil {
		p.mu.Unlock()
		return probe(ctx, idle)
	}
	index := len(p.idles) - 1
	var result ProbeResult
	var err error
	if index < len(p.results) {
		result = p.results[index]
	}
	if index < len(p.errors) {
		err = p.errors[index]
	}
	p.mu.Unlock()
	return result, err
}

func measurementPolicy() MeasurementPolicy {
	return MeasurementPolicy{
		IdleSteps:       []time.Duration{time.Second, 2 * time.Second},
		AttemptsPerStep: 3,
		ResponseTimeout: time.Second,
		TotalTimeout:    15 * time.Second,
	}
}

func newMeasurementCache(t *testing.T) *LifetimeCache {
	t.Helper()
	policy := DevelopmentLifetimePolicy()
	policy.MinimumSampleInterval = time.Millisecond
	policy.JitterFraction = 0
	cache, err := NewLifetimeCache(policy, fixedRandom{})
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func TestMeasurerRecordsCompletedStepsAndDrivesDecision(t *testing.T) {
	base := time.Unix(10_000, 0)
	results := make([]ProbeResult, 6)
	for index := range results {
		results[index] = ProbeResult{Reachable: true, At: base.Add(time.Duration(index) * time.Second)}
	}
	cache := newMeasurementCache(t)
	prober := &scriptedProbe{results: results}
	measurer, err := NewLifetimeMeasurer(measurementPolicy(), cache, prober)
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := measurer.Measure(context.Background(), testFingerprint(10))
	if err != nil {
		t.Fatal(err)
	}
	if measurement.Attempts != 6 || measurement.CompletedSteps != 2 || measurement.LowerBound != 2*time.Second || measurement.FailedAt != 0 {
		t.Fatalf("measurement = %+v", measurement)
	}
	decision, err := cache.Keepalive(testFingerprint(10), base.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Evidence != 6 || decision.LowerBound != 2*time.Second {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestMeasurerStopsAtFirstAuthoritativeFailure(t *testing.T) {
	base := time.Unix(20_000, 0)
	results := []ProbeResult{
		{Reachable: true, At: base},
		{Reachable: true, At: base.Add(time.Second)},
		{Reachable: true, At: base.Add(2 * time.Second)},
		{Reachable: false, At: base.Add(3 * time.Second)},
	}
	cache := newMeasurementCache(t)
	prober := &scriptedProbe{results: results}
	measurer, _ := NewLifetimeMeasurer(measurementPolicy(), cache, prober)
	measurement, err := measurer.Measure(context.Background(), testFingerprint(11))
	if err != nil {
		t.Fatal(err)
	}
	if measurement.Attempts != 4 || measurement.CompletedSteps != 1 || measurement.LowerBound != time.Second || measurement.FailedAt != 2*time.Second {
		t.Fatalf("measurement = %+v", measurement)
	}
	if len(prober.idles) != 4 {
		t.Fatalf("probe count = %d", len(prober.idles))
	}
}

func TestMeasurerDoesNotTurnTransportErrorIntoFailureEvidence(t *testing.T) {
	want := errors.New("peer authentication failed")
	base := time.Unix(30_000, 0)
	cache := newMeasurementCache(t)
	prober := &scriptedProbe{results: []ProbeResult{{Reachable: true, At: base}}, errors: []error{want}}
	measurer, _ := NewLifetimeMeasurer(measurementPolicy(), cache, prober)
	measurement, err := measurer.Measure(context.Background(), testFingerprint(12))
	if !errors.Is(err, want) || measurement.Attempts != 1 || measurement.FailedAt != 0 {
		t.Fatalf("measurement=%+v error=%v", measurement, err)
	}
	decision, _ := cache.Keepalive(testFingerprint(12), base)
	if decision.Evidence != 0 {
		t.Fatalf("error recorded evidence: %+v", decision)
	}
}

func TestMeasurerCancellationIsBoundedAndRecordsNothing(t *testing.T) {
	started := make(chan struct{})
	prober := &scriptedProbe{probe: func(ctx context.Context, _ time.Duration) (ProbeResult, error) {
		close(started)
		<-ctx.Done()
		return ProbeResult{}, ctx.Err()
	}}
	cache := newMeasurementCache(t)
	measurer, _ := NewLifetimeMeasurer(measurementPolicy(), cache, prober)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := measurer.Measure(ctx, testFingerprint(13))
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !IsMeasurementCanceled(err) {
		t.Fatalf("error = %v", err)
	}
	decision, _ := cache.Keepalive(testFingerprint(13), time.Now())
	if decision.Evidence != 0 {
		t.Fatalf("cancellation recorded evidence: %+v", decision)
	}
}

func TestMeasurerRejectsMalformedOrNonMonotonicResults(t *testing.T) {
	base := time.Unix(40_000, 0)
	for name, results := range map[string][]ProbeResult{
		"missing time": {{Reachable: true}},
		"replayed time": {
			{Reachable: true, At: base},
			{Reachable: true, At: base},
		},
	} {
		t.Run(name, func(t *testing.T) {
			cache := newMeasurementCache(t)
			measurer, _ := NewLifetimeMeasurer(measurementPolicy(), cache, &scriptedProbe{results: results})
			if _, err := measurer.Measure(context.Background(), testFingerprint(14)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMeasurementPolicyProvesTotalBudget(t *testing.T) {
	policy := measurementPolicy()
	policy.TotalTimeout--
	if _, err := NewLifetimeMeasurer(policy, newMeasurementCache(t), &scriptedProbe{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("under-budget policy error = %v", err)
	}
	policy = measurementPolicy()
	policy.IdleSteps = []time.Duration{time.Second, time.Second}
	if _, err := NewLifetimeMeasurer(policy, newMeasurementCache(t), &scriptedProbe{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unordered policy error = %v", err)
	}
}
