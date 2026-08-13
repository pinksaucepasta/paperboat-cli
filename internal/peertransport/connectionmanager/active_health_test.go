package connectionmanager

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type activeHealthTransport struct {
	errors []error
	nonces [][16]byte
}

type activeHealthPTOTransport struct {
	activeHealthTransport
	total    atomic.Uint32
	changed  chan struct{}
	read     chan struct{}
	exchange activeHealthTransportFunc
	suspect  atomic.Uint32
	trusted  atomic.Uint32
}

func (t *activeHealthPTOTransport) PTOCount() uint32 {
	if t.read != nil {
		select {
		case t.read <- struct{}{}:
		default:
		}
	}
	return t.total.Load()
}
func (t *activeHealthPTOTransport) PTOChanged() <-chan struct{} { return t.changed }
func (t *activeHealthPTOTransport) PathSuspect()                { t.suspect.Add(1) }
func (t *activeHealthPTOTransport) PathTrusted()                { t.trusted.Add(1) }
func (t *activeHealthPTOTransport) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	if t.exchange != nil {
		return t.exchange(ctx, nonce)
	}
	return t.activeHealthTransport.HealthExchange(ctx, nonce)
}

func (t *activeHealthTransport) HealthExchange(_ context.Context, nonce [16]byte) (uint32, error) {
	t.nonces = append(t.nonces, nonce)
	index := len(t.nonces) - 1
	if index < len(t.errors) {
		return uint32(index), t.errors[index]
	}
	return uint32(index), nil
}

type activeHealthRecorder struct {
	samples []ActiveHealthSample
	err     error
}

type activeHealthKeys struct {
	key     QualityKey
	binding ActiveHealthBinding
	err     error
}

func (k *activeHealthKeys) ActiveHealthQualityKey(binding ActiveHealthBinding) (QualityKey, error) {
	k.binding = binding
	return k.key, k.err
}

func (r *activeHealthRecorder) RecordActiveHealth(sample ActiveHealthSample) error {
	r.samples = append(r.samples, sample)
	return r.err
}

func TestActiveHealthMonitorRecordsSuccessAndStopsOnCancellation(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.random = bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	now := time.Unix(100, 0)
	monitor.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	monitor.wait = func(context.Context, time.Duration) error {
		waits++
		if waits == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	transport := &activeHealthTransport{}
	binding := ActiveHealthBinding{Path: PathRelayQUIC, Generation: 3, NetworkGeneration: 4}
	if err := monitor.Run(ctx, binding, transport); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error=%v", err)
	}
	if len(recorder.samples) != 1 || !recorder.samples[0].Succeeded || recorder.samples[0].Binding != binding || recorder.samples[0].Sequence != 1 || recorder.samples[0].PTOs != 0 {
		t.Fatalf("samples=%+v", recorder.samples)
	}
	if len(transport.nonces) != 1 || transport.nonces[0] == [16]byte{} {
		t.Fatalf("nonces=%x", transport.nonces)
	}
}

func TestActiveHealthMonitorFailsWithinOneBoundedMiss(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.random = bytes.NewReader(bytes.Repeat([]byte{1}, 128))
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	now := time.Unix(200, 0)
	monitor.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	rejected := &Failure{Class: FailureTransient, Path: PathDirectQUIC, Cause: errors.New("missed")}
	transport := &activeHealthTransport{errors: []error{rejected}}
	err := monitor.Run(context.Background(), ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 2}, transport)
	if !errors.Is(err, ErrPathSuspect) || len(recorder.samples) != 1 || recorder.samples[0].Succeeded {
		t.Fatalf("error=%v samples=%+v", err, recorder.samples)
	}
}

func TestDevelopmentActiveHealthPolicyAcceptsObservedDirectWANLatency(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, err := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	monitor.wait = func(context.Context, time.Duration) error {
		waits++
		if waits == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	transport := activeHealthTransportFunc(func(ctx context.Context, _ [16]byte) (uint32, error) {
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return 0, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	if err := monitor.Run(ctx, ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 1}, transport); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(recorder.samples) != 1 || !recorder.samples[0].Succeeded {
		t.Fatalf("samples=%+v", recorder.samples)
	}
}

func TestDevelopmentActiveHealthPolicyMatchesMagicsockTrustWindow(t *testing.T) {
	policy := DevelopmentActiveHealthPolicy()
	if policy.HeartbeatInterval != 3*time.Second || policy.PathTrustDuration != 6500*time.Millisecond {
		t.Fatalf("policy=%+v", policy)
	}
}

func TestActiveHealthMonitorFailsBeforeHeartbeatAfterTwoQUICPTOs(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	transport := &activeHealthPTOTransport{changed: make(chan struct{}, 1), read: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- monitor.Run(context.Background(), ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 1}, transport)
	}()
	<-transport.read
	transport.total.Store(2)
	transport.changed <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPathSuspect) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("two PTOs waited for the heartbeat deadline")
	}
	if len(recorder.samples) != 1 || recorder.samples[0].Succeeded || recorder.samples[0].PTOs != 2 {
		t.Fatalf("samples=%+v", recorder.samples)
	}
	if transport.suspect.Load() == 0 {
		t.Fatal("first PTO did not mark the path suspect")
	}
}

func TestActiveHealthMonitorFailsDuringExchangeAfterTwoQUICPTOs(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	started := make(chan struct{})
	transport := &activeHealthPTOTransport{changed: make(chan struct{}, 1), exchange: func(ctx context.Context, _ [16]byte) (uint32, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		done <- monitor.Run(context.Background(), ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 1}, transport)
	}()
	<-started
	transport.total.Store(2)
	transport.changed <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPathSuspect) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("two PTOs waited for the exchange deadline")
	}
	if len(recorder.samples) != 1 || recorder.samples[0].Succeeded || recorder.samples[0].PTOs != 2 {
		t.Fatalf("samples=%+v", recorder.samples)
	}
	if transport.suspect.Load() == 0 {
		t.Fatal("in-flight PTO did not mark the path suspect")
	}
}

func TestActiveHealthMonitorReturnsTerminalFailureWithoutSuspectDowngrade(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.random = bytes.NewReader(make([]byte, 16))
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	terminal := &Failure{Class: FailureAuthentication, Path: PathRelayQUIC, Cause: errors.New("health authentication failed")}
	err := monitor.Run(context.Background(), ActiveHealthBinding{Path: PathRelayQUIC, Generation: 1, NetworkGeneration: 1}, &activeHealthTransport{errors: []error{terminal}})
	if !errors.Is(err, terminal) || errors.Is(err, ErrPathSuspect) || len(recorder.samples) != 0 {
		t.Fatalf("error=%v samples=%d", err, len(recorder.samples))
	}
}

func TestActiveHealthMonitorDoesNotRecordCallerCancellationAsLoss(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.random = bytes.NewReader(make([]byte, 16))
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	transport := activeHealthTransportFunc(func(context.Context, [16]byte) (uint32, error) {
		cancel()
		return 0, context.Canceled
	})
	if err := monitor.Run(ctx, ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 1}, transport); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(recorder.samples) != 0 {
		t.Fatalf("cancellation samples=%+v", recorder.samples)
	}
}

func TestActiveHealthMonitorFailsClosedOnRecorderError(t *testing.T) {
	recorderErr := errors.New("stale quality generation")
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), &activeHealthRecorder{err: recorderErr})
	monitor.random = bytes.NewReader(make([]byte, 16))
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	if err := monitor.Run(context.Background(), ActiveHealthBinding{Path: PathWSS, Generation: 1, NetworkGeneration: 1}, &activeHealthTransport{}); !errors.Is(err, recorderErr) {
		t.Fatalf("Run() error=%v", err)
	}
}

func TestActiveHealthMonitorSequenceExhaustionNeverWraps(t *testing.T) {
	recorder := &activeHealthRecorder{}
	monitor, _ := NewActiveHealthMonitor(DevelopmentActiveHealthPolicy(), recorder)
	monitor.random = bytes.NewReader(make([]byte, 16))
	monitor.wait = func(context.Context, time.Duration) error { return nil }
	now := time.Unix(300, 0)
	monitor.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	transport := &activeHealthTransport{}
	binding := ActiveHealthBinding{Path: PathRelayQUIC, Generation: 1, NetworkGeneration: 1}
	if err := monitor.run(context.Background(), binding, transport, ^uint64(0)); !errors.Is(err, ErrActiveHealthExhausted) {
		t.Fatalf("error=%v", err)
	}
	if len(recorder.samples) != 1 || recorder.samples[0].Sequence != ^uint64(0) || len(transport.nonces) != 1 {
		t.Fatalf("samples=%+v exchanges=%d", recorder.samples, len(transport.nonces))
	}
	if err := monitor.run(context.Background(), binding, transport, 0); !errors.Is(err, ErrActiveHealthExhausted) || len(transport.nonces) != 1 {
		t.Fatalf("repeated error=%v exchanges=%d", err, len(transport.nonces))
	}
}

func TestActiveHealthPolicyValidation(t *testing.T) {
	valid := DevelopmentActiveHealthPolicy()
	for _, mutate := range []func(*ActiveHealthPolicy){
		func(p *ActiveHealthPolicy) { p.HeartbeatInterval = 0 },
		func(p *ActiveHealthPolicy) { p.PathTrustDuration = p.HeartbeatInterval },
		func(p *ActiveHealthPolicy) { p.PathTrustDuration = time.Minute + 1 },
	} {
		policy := valid
		mutate(&policy)
		if _, err := NewActiveHealthMonitor(policy, &activeHealthRecorder{}); err == nil {
			t.Fatalf("accepted policy=%+v", policy)
		}
	}
}

func TestQualityActiveHealthRecorderWritesGenerationScopedPath(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	keys := &activeHealthKeys{key: qualityKey(71)}
	recorder, err := NewQualityActiveHealthRecorder(cache, keys)
	if err != nil {
		t.Fatal(err)
	}
	binding := ActiveHealthBinding{Path: PathRelayQUIC, Generation: 5, NetworkGeneration: 9}
	now := time.Unix(9000, 0)
	if err := recorder.RecordActiveHealth(ActiveHealthSample{Binding: binding, Sequence: 1, At: now, Completed: 30 * time.Millisecond, PTOs: 1, Succeeded: true}); err != nil {
		t.Fatal(err)
	}
	if keys.binding != binding {
		t.Fatalf("binding=%+v", keys.binding)
	}
	_, _, relay, err := cache.Select(keys.key, now)
	if err != nil || relay.Samples != 1 || relay.PTOs != 1 {
		t.Fatalf("relay=%+v error=%v", relay, err)
	}
}

func TestQualityActiveHealthRecorderIgnoresWSSAndRejectsStaleKey(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	keyErr := errors.New("stale health binding")
	recorder, _ := NewQualityActiveHealthRecorder(cache, &activeHealthKeys{key: qualityKey(72), err: keyErr})
	base := ActiveHealthSample{Binding: ActiveHealthBinding{Path: PathDirectQUIC, Generation: 1, NetworkGeneration: 1}, Sequence: 1, At: time.Now(), Completed: time.Millisecond, Succeeded: true}
	if err := recorder.RecordActiveHealth(base); !errors.Is(err, keyErr) {
		t.Fatalf("stale key error=%v", err)
	}
	base.Binding.Path = PathWSS
	keys := &activeHealthKeys{key: qualityKey(73), err: keyErr}
	recorder, _ = NewQualityActiveHealthRecorder(cache, keys)
	if err := recorder.RecordActiveHealth(base); err != nil {
		t.Fatalf("WSS no-op error=%v", err)
	}
	if keys.binding != (ActiveHealthBinding{}) {
		t.Fatalf("WSS requested quality key for binding=%+v", keys.binding)
	}
}

type activeHealthTransportFunc func(context.Context, [16]byte) (uint32, error)

func (f activeHealthTransportFunc) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	return f(ctx, nonce)
}
