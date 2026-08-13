package networkadaptation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type fakePMTUProber struct {
	mu           sync.Mutex
	maximum      uint16
	now          time.Time
	calls        []uint16
	errorAt      int
	err          error
	replayedTime bool
}

func (p *fakePMTUProber) ProbePayload(_ context.Context, size uint16) (PMTUProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, size)
	if p.errorAt > 0 && len(p.calls) == p.errorAt {
		return PMTUProbeResult{}, p.err
	}
	if !p.replayedTime || len(p.calls) == 1 {
		p.now = p.now.Add(time.Millisecond)
	}
	return PMTUProbeResult{Supported: size <= p.maximum, At: p.now}, nil
}

type pmtuProbeFunc func(context.Context, uint16) (PMTUProbeResult, error)

func (f pmtuProbeFunc) ProbePayload(ctx context.Context, size uint16) (PMTUProbeResult, error) {
	return f(ctx, size)
}

func (p *fakePMTUProber) prober() PMTUProber {
	return p
}

func TestPMTUMeasurerFindsMaximumWithRepeatedAuthenticatedSuccess(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	prober := &fakePMTUProber{maximum: 1378, now: time.Unix(70_000, 0)}
	measurer, err := NewPMTUMeasurer(policy, prober.prober())
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := measurer.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !measurement.Complete || !measurement.Eligible || measurement.PacketSize != 1378 || measurement.Attempts < policy.SuccessesPerSize || measurement.ObservedAt.IsZero() {
		t.Fatalf("measurement = %+v", measurement)
	}
	prober.mu.Lock()
	calls := append([]uint16(nil), prober.calls...)
	prober.mu.Unlock()
	minimumCalls := 0
	for _, size := range calls {
		if size == policy.MinimumPayload {
			minimumCalls++
		}
	}
	if minimumCalls != policy.SuccessesPerSize {
		t.Fatalf("minimum probe calls = %d, calls=%v", minimumCalls, calls)
	}
}

func TestPMTUMeasurerMarksPathIneligibleBelowQUICFloor(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	prober := &fakePMTUProber{maximum: 1199, now: time.Unix(71_000, 0)}
	measurer, _ := NewPMTUMeasurer(policy, prober.prober())
	measurement, err := measurer.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !measurement.Complete || measurement.Eligible || measurement.PacketSize != 0 || measurement.Attempts != 1 {
		t.Fatalf("measurement = %+v", measurement)
	}
}

func TestPMTUMeasurerDoesNotPublishPartialResultOnError(t *testing.T) {
	want := errors.New("probe authentication failed")
	policy := DevelopmentPMTUPolicy()
	prober := &fakePMTUProber{maximum: policy.MaximumPayload, now: time.Unix(72_000, 0), errorAt: 5, err: want}
	measurer, _ := NewPMTUMeasurer(policy, prober.prober())
	measurement, err := measurer.Measure(context.Background())
	if !errors.Is(err, want) || measurement.Complete || measurement.Attempts != 5 {
		t.Fatalf("measurement=%+v error=%v", measurement, err)
	}
	cache, _ := NewPMTUCache(policy)
	if err := cache.Record(pmtuKey(1, 1), measurement); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial record error = %v", err)
	}
}

func TestPMTUMeasurerRejectsReplayedObservationTime(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	prober := &fakePMTUProber{maximum: policy.MaximumPayload, now: time.Unix(73_000, 0), replayedTime: true}
	measurer, _ := NewPMTUMeasurer(policy, prober.prober())
	if _, err := measurer.Measure(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestPMTUPolicyRejectsUnprovableBudget(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	policy.TotalTimeout = time.Second
	if _, err := NewPMTUMeasurer(policy, pmtuProbeFunc(func(context.Context, uint16) (PMTUProbeResult, error) { return PMTUProbeResult{}, nil })); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestPMTUCacheScopesExpiresAndFencesObservations(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	cache, _ := NewPMTUCache(policy)
	now := time.Unix(74_000, 0)
	key := pmtuKey(2, 4)
	measurement := PMTUMeasurement{Complete: true, Eligible: true, PacketSize: 1340, Attempts: 12, ObservedAt: now}
	if err := cache.Record(key, measurement); err != nil {
		t.Fatal(err)
	}
	if observation, ok := cache.Lookup(key, now.Add(time.Second)); !ok || observation.PacketSize != 1340 {
		t.Fatalf("observation=%+v ok=%v", observation, ok)
	}
	if _, ok := cache.Lookup(pmtuKey(2, 5), now.Add(time.Second)); ok {
		t.Fatal("observation crossed network generation")
	}
	if err := cache.Record(key, measurement); err == nil {
		t.Fatal("replayed observation accepted")
	}
	if _, ok := cache.Lookup(key, now.Add(policy.CacheTTL)); ok {
		t.Fatal("expired observation returned")
	}
	if cache.Invalidate() != 0 {
		t.Fatal("expired observation remained after lookup")
	}
}

func TestPMTUCacheEvictsAndInvalidatesBoundedPaths(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	policy.MaximumPaths = 2
	cache, _ := NewPMTUCache(policy)
	now := time.Unix(75_000, 0)
	for marker := byte(1); marker <= 3; marker++ {
		measurement := PMTUMeasurement{Complete: true, Eligible: true, PacketSize: 1200, Attempts: 3, ObservedAt: now.Add(time.Duration(marker) * time.Second)}
		if err := cache.Record(pmtuKey(marker, 1), measurement); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := cache.Lookup(pmtuKey(1, 1), now.Add(4*time.Second)); ok {
		t.Fatal("least-recently-used path retained")
	}
	if removed := cache.Invalidate(); removed != 2 || cache.Invalidate() != 0 {
		t.Fatalf("removed = %d", removed)
	}
}

func TestPMTUObservationConfiguresOnlyNewSession(t *testing.T) {
	now := time.Unix(76_000, 0)
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	observation := PMTUObservation{Eligible: true, PacketSize: 1400, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	configured, err := ApplyPMTU(base, observation, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if configured.InitialPacketSize != 1400 || base.InitialPacketSize != 1200 {
		t.Fatalf("configured=%+v base=%+v", configured, base)
	}
	if _, err := ApplyPMTU(base, observation, observation.ExpiresAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired observation error = %v", err)
	}
	observation.Eligible = false
	if _, err := ApplyPMTU(base, observation, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ineligible observation error = %v", err)
	}
}

func pmtuKey(marker byte, generation uint64) PMTUKey {
	return PMTUKey{Fingerprint: testFingerprint(marker), PathID: "direct", NetworkGeneration: generation}
}
