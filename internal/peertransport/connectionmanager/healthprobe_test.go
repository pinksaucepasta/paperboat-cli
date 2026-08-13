package connectionmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type probeTransport struct {
	mu        sync.Mutex
	state     State
	exchanges [][16]byte
	failAt    int
	closed    int
}

func (p *probeTransport) State() State { return p.state }
func (p *probeTransport) Close() error {
	p.mu.Lock()
	p.closed++
	p.mu.Unlock()
	return nil
}
func (p *probeTransport) HealthExchange(_ context.Context, nonce [16]byte) (uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchanges = append(p.exchanges, nonce)
	if p.failAt == len(p.exchanges) {
		return 0, errors.New("rejected")
	}
	return uint32(len(p.exchanges) - 1), nil
}

type probeDialer struct {
	transport ProbeTransport
	err       error
	attempt   ProbeAttempt
	calls     int
}

type sampleRecorder struct {
	samples []HealthSample
	err     error
}

type promotionDecider struct {
	promote bool
	err     error
	attempt ProbeAttempt
}

func (d *promotionDecider) PromoteProbe(attempt ProbeAttempt) (bool, error) {
	d.attempt = attempt
	return d.promote, d.err
}

type qualityKeys struct {
	key     QualityKey
	attempt ProbeAttempt
}

func (k *qualityKeys) QualityKey(attempt ProbeAttempt) (QualityKey, error) {
	k.attempt = attempt
	return k.key, nil
}

func (r *sampleRecorder) RecordHealthSample(sample HealthSample) error {
	r.samples = append(r.samples, sample)
	return r.err
}

func (d *probeDialer) DialProbe(_ context.Context, attempt ProbeAttempt) (ProbeTransport, error) {
	d.attempt = attempt
	d.calls++
	return d.transport, d.err
}

func TestAuthenticatedHealthProbePromotesExactVerifiedCarrierWithoutRedial(t *testing.T) {
	transport := &probeTransport{state: StateTrusted}
	dialer := &probeDialer{transport: transport}
	recorder := &sampleRecorder{}
	decider := &promotionDecider{promote: true}
	probe, err := NewAuthenticatedHealthProbe(dialer, DevelopmentHealthProbePolicy(), recorder, decider)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	probe.now = func() time.Time { return now }
	attempt := ProbeAttempt{Generation: 7, NetworkGeneration: 9}
	result, err := probe.Probe(context.Background(), attempt)
	if err != nil {
		t.Fatal(err)
	}
	if result.Connection != transport || !result.Promote || dialer.attempt != attempt || dialer.calls != 1 {
		t.Fatalf("result=%#v attempt=%#v dials=%d", result, dialer.attempt, dialer.calls)
	}
	if decider.attempt != attempt {
		t.Fatalf("decision attempt=%+v", decider.attempt)
	}
	if len(transport.exchanges) != 1 {
		t.Fatalf("nonces=%x", transport.exchanges)
	}
	if len(recorder.samples) != 1 || recorder.samples[0].Exchange != 1 || recorder.samples[0].PTOs != 0 {
		t.Fatalf("samples=%+v", recorder.samples)
	}
	if transport.closed != 0 {
		t.Fatalf("successful transport closed %d times", transport.closed)
	}
}

func TestAuthenticatedHealthProbeClosesOnExchangeFailure(t *testing.T) {
	transport := &probeTransport{state: StateTrusted, failAt: 1}
	probe, _ := NewAuthenticatedHealthProbe(&probeDialer{transport: transport}, HealthProbePolicy{Exchanges: 1}, &sampleRecorder{}, &promotionDecider{promote: true})
	probe.now = func() time.Time { return time.Unix(0, 0).Add(time.Hour) }
	if _, err := probe.Probe(context.Background(), ProbeAttempt{Generation: 1, NetworkGeneration: 1}); err == nil {
		t.Fatal("exchange failure accepted")
	}
	if transport.closed != 1 {
		t.Fatalf("closed=%d", transport.closed)
	}
}

func TestAuthenticatedHealthProbeCancellationDoesNotDialTransport(t *testing.T) {
	transport := &probeTransport{state: StateTrusted}
	probe, _ := NewAuthenticatedHealthProbe(&probeDialer{transport: transport}, DevelopmentHealthProbePolicy(), &sampleRecorder{}, &promotionDecider{promote: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probe.Probe(ctx, ProbeAttempt{Generation: 1, NetworkGeneration: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if transport.closed != 0 {
		t.Fatalf("closed=%d", transport.closed)
	}
}

func TestAuthenticatedHealthProbeRejectsUntrustedTransport(t *testing.T) {
	transport := &probeTransport{state: StateReady}
	probe, _ := NewAuthenticatedHealthProbe(&probeDialer{transport: transport}, DevelopmentHealthProbePolicy(), &sampleRecorder{}, &promotionDecider{promote: true})
	if _, err := probe.Probe(context.Background(), ProbeAttempt{Generation: 1, NetworkGeneration: 1}); err == nil {
		t.Fatal("untrusted probe accepted")
	}
	if transport.closed != 1 || len(transport.exchanges) != 0 {
		t.Fatalf("closed=%d exchanges=%d", transport.closed, len(transport.exchanges))
	}
}

func TestAuthenticatedHealthProbeClosesOnRecorderFailure(t *testing.T) {
	transport := &probeTransport{state: StateTrusted}
	probe, _ := NewAuthenticatedHealthProbe(&probeDialer{transport: transport}, DevelopmentHealthProbePolicy(), &sampleRecorder{err: errors.New("stale quality key")}, &promotionDecider{promote: true})
	if _, err := probe.Probe(context.Background(), ProbeAttempt{Generation: 1, NetworkGeneration: 1}); err == nil {
		t.Fatal("recorder failure accepted")
	}
	if transport.closed != 1 {
		t.Fatalf("closed=%d", transport.closed)
	}
}

func TestHealthProbePolicyValidation(t *testing.T) {
	for _, policy := range []HealthProbePolicy{{}, {Exchanges: 2}, {Exchanges: 3}} {
		if _, err := NewAuthenticatedHealthProbe(&probeDialer{}, policy, &sampleRecorder{}, &promotionDecider{}); err == nil {
			t.Fatalf("accepted %#v", policy)
		}
	}
}

func TestQualityHealthRecorderWritesAttemptScopedDirectObservation(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	keys := &qualityKeys{key: qualityKey(31)}
	recorder, err := NewQualityHealthRecorder(cache, keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(7000, 0)
	recorder.now = func() time.Time { return now }
	attempt := ProbeAttempt{Generation: 4, NetworkGeneration: 8}
	if err := recorder.RecordHealthSample(HealthSample{Attempt: attempt, Exchange: 1, Completed: 12 * time.Millisecond, PTOs: 1}); err != nil {
		t.Fatal(err)
	}
	if keys.attempt != attempt {
		t.Fatalf("attempt=%+v", keys.attempt)
	}
	_, direct, _, err := cache.Select(keys.key, now)
	if err != nil || direct.Samples != 1 || direct.PTOs != 1 {
		t.Fatalf("direct=%+v err=%v", direct, err)
	}
}

func TestQualityHealthRecorderRejectsInvalidSample(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	recorder, _ := NewQualityHealthRecorder(cache, &qualityKeys{key: qualityKey(32)})
	if err := recorder.RecordHealthSample(HealthSample{}); err == nil {
		t.Fatal("invalid sample accepted")
	}
}

func TestQualityProbePromotionDeciderAppliesSelectionCause(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	key := qualityKey(41)
	keys := &qualityKeys{key: key}
	base := time.Unix(8000, 0)
	reachability, err := NewQualityProbePromotionDecider(cache, keys, RelaySelectedForReachability)
	if err != nil {
		t.Fatal(err)
	}
	reachability.now = func() time.Time { return base }
	eligible, err := reachability.PromoteProbe(ProbeAttempt{Generation: 1, NetworkGeneration: 2})
	if err != nil || !eligible {
		t.Fatalf("reachability eligible=%v err=%v", eligible, err)
	}

	quality, _ := NewQualityProbePromotionDecider(cache, keys, RelaySelectedForQuality)
	quality.now = func() time.Time { return base.Add(30 * time.Second) }
	eligible, err = quality.PromoteProbe(ProbeAttempt{Generation: 2, NetworkGeneration: 2})
	if err != nil || eligible {
		t.Fatalf("unqualified quality eligible=%v err=%v", eligible, err)
	}
	recordSeries(t, cache, key, PathRelayQUIC, base.Add(20*time.Second), 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathDirectQUIC, base.Add(20*time.Second), 30*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	eligible, err = quality.PromoteProbe(ProbeAttempt{Generation: 3, NetworkGeneration: 2})
	if err != nil || !eligible {
		t.Fatalf("qualified quality eligible=%v err=%v", eligible, err)
	}
}

func TestDevelopmentRecoveryUsesImmediateAuthenticatedExchange(t *testing.T) {
	probe := DevelopmentProbePolicy()
	health := DevelopmentHealthProbePolicy()
	if probe.InitialBackoff <= 0 || health.Exchanges != 1 {
		t.Fatalf("probe=%+v health=%+v", probe, health)
	}
}
