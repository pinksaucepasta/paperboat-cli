package connectionmanager

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

type probeRunnerFunc func(context.Context, ProbeAttempt) (ProbeResult, error)

func (f probeRunnerFunc) Probe(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
	return f(ctx, attempt)
}

type probePromoterFunc func(ProbeAttempt, Connection) error

func (f probePromoterFunc) Promote(attempt ProbeAttempt, connection Connection) error {
	return f(attempt, connection)
}

var discardProbe = probePromoterFunc(func(ProbeAttempt, Connection) error { return nil })

func TestDevelopmentProbePolicyRecoversPromptlyAndRemainsBounded(t *testing.T) {
	policy := DevelopmentProbePolicy()
	if policy.InitialBackoff != 5*time.Second || policy.MaximumBackoff != 5*time.Second || policy.Jitter != 0.2 || policy.AttemptTimeout != 15*time.Second {
		t.Fatalf("policy=%+v", policy)
	}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
}

func successfulProbe(promote bool) ProbeResult {
	return ProbeResult{Connection: &fakeConnection{}, Promote: promote}
}

func TestProbeDelayBacksOffAndCaps(t *testing.T) {
	s, err := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Second, MaximumBackoff: 4 * time.Second}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) { return successfulProbe(false), nil }), discardProbe)
	if err != nil {
		t.Fatal(err)
	}
	s.random = func() float64 { return .5 }
	if got := s.delay(); got != time.Second {
		t.Fatal(got)
	}
	s.failures = 3
	if got := s.delay(); got != 4*time.Second {
		t.Fatal(got)
	}
}

func TestProbeSchedulerStartsFirstRecoveryImmediately(t *testing.T) {
	started := make(chan time.Time, 1)
	s, err := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
		started <- time.Now()
		return successfulProbe(true), nil
	}), discardProbe)
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := (<-started).Sub(begin); elapsed > 100*time.Millisecond {
		t.Fatalf("first recovery waited %s", elapsed)
	}
}

func TestProbeSchedulerNetworkChangeInterruptsBackoff(t *testing.T) {
	started := make(chan ProbeAttempt, 2)
	s, err := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour}, probeRunnerFunc(func(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
		started <- attempt
		return successfulProbe(false), nil
	}), discardProbe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	first := <-started
	if first.Generation != 1 || first.NetworkGeneration != 1 {
		t.Fatalf("first=%+v", first)
	}
	s.NetworkChanged()
	select {
	case attempt := <-started:
		if attempt.Generation != 2 || attempt.NetworkGeneration != 2 {
			t.Fatalf("%+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("network change did not wake probe")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeSchedulerNetworkChangeCancelsActiveStaleProbe(t *testing.T) {
	started := make(chan ProbeAttempt, 2)
	canceled := make(chan struct{}, 1)
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour}, probeRunnerFunc(func(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
		started <- attempt
		if attempt.Generation == 1 {
			<-ctx.Done()
			canceled <- struct{}{}
			return ProbeResult{}, ctx.Err()
		}
		return successfulProbe(false), nil
	}), discardProbe)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	first := <-started
	if first.Generation != 1 || first.NetworkGeneration != 1 {
		t.Fatalf("first=%+v", first)
	}
	s.NetworkChanged()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("old-network probe was not canceled")
	}
	second := <-started
	if second.Generation != 2 || second.NetworkGeneration != 2 {
		t.Fatalf("second=%+v", second)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeSchedulerFailureBackoffAndCancellation(t *testing.T) {
	attempts := make(chan ProbeAttempt, 1)
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Millisecond, MaximumBackoff: 2 * time.Millisecond, Jitter: 0}, probeRunnerFunc(func(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
		attempts <- attempt
		return ProbeResult{}, errors.New("unreachable")
	}), discardProbe)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	first := <-attempts
	if first.Generation != 1 {
		t.Fatal(first)
	}
	second := <-attempts
	if second.Generation != 2 {
		t.Fatalf("second=%+v", second)
	}
}

func TestProbeSchedulerPathChangeResetsOnlyStalePathBackoff(t *testing.T) {
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Second, MaximumBackoff: 30 * time.Second, Jitter: 0}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
		return ProbeResult{}, errors.New("unreachable")
	}), discardProbe)
	if err := s.SetPath(PathDirectQUIC); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.failures = 5
	s.mu.Unlock()
	if err := s.SetPath(PathDirectQUIC); err != nil {
		t.Fatal(err)
	}
	if delay := s.delay(); delay != 30*time.Second {
		t.Fatalf("same-path delay=%v", delay)
	}
	if err := s.SetPath(PathRelayQUIC); err != nil {
		t.Fatal(err)
	}
	if delay := s.delay(); delay != time.Second {
		t.Fatalf("new-path delay=%v", delay)
	}
}

func TestProbeSchedulerPromotesDirectWithinAttemptDeadline(t *testing.T) {
	connection := &fakeConnection{}
	promoted := make(chan struct{}, 1)
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour, AttemptTimeout: time.Second}, probeRunnerFunc(func(ctx context.Context, _ ProbeAttempt) (ProbeResult, error) {
		timer := time.NewTimer(25 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return ProbeResult{Connection: connection, Promote: true}, nil
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}), probePromoterFunc(func(ProbeAttempt, Connection) error {
		promoted <- struct{}{}
		return nil
	}))
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()
	select {
	case <-promoted:
	case <-time.After(time.Second):
		t.Fatal("background recovery was canceled before promotion")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProbeSchedulerTimesOutDirectGenerationAndRetriesFresh(t *testing.T) {
	started := make(chan ProbeAttempt, 3)
	timedOut := make(chan ProbeAttempt, 2)
	recovered := &fakeConnection{}
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond, AttemptTimeout: 10 * time.Millisecond}, probeRunnerFunc(func(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
		started <- attempt
		if attempt.Generation < 3 {
			<-ctx.Done()
			timedOut <- attempt
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{Connection: recovered, Promote: true}, nil
	}), discardProbe)
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, second, third := <-started, <-started, <-started
	if first.Generation != 1 || second.Generation != 2 || third.Generation != 3 || first.NetworkGeneration != second.NetworkGeneration || second.NetworkGeneration != third.NetworkGeneration {
		t.Fatalf("first=%+v second=%+v third=%+v", first, second, third)
	}
	for generation := uint64(1); generation <= 2; generation++ {
		select {
		case attempt := <-timedOut:
			if attempt.Generation != generation {
				t.Fatalf("timed out=%+v want generation=%d", attempt, generation)
			}
		default:
			t.Fatalf("direct generation %d did not time out", generation)
		}
	}
}

func TestProbeSchedulerDoesNotApplyDirectTimeoutToRelayProbe(t *testing.T) {
	started := make(chan struct{}, 1)
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour, AttemptTimeout: time.Millisecond}, probeRunnerFunc(func(ctx context.Context, _ ProbeAttempt) (ProbeResult, error) {
		started <- struct{}{}
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return successfulProbe(true), nil
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}), discardProbe)
	if err := s.SetPath(PathRelayQUIC); err != nil {
		t.Fatal(err)
	}
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-started
}

func TestProbeSchedulerTransfersEligibleTrustedConnection(t *testing.T) {
	connection := &fakeConnection{}
	promoted := make(chan ProbeAttempt, 1)
	s, _ := NewProbeScheduler(
		ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour},
		probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
			return ProbeResult{Connection: connection, Promote: true}, nil
		}),
		probePromoterFunc(func(attempt ProbeAttempt, got Connection) error {
			if got != connection {
				t.Fatalf("connection=%T", got)
			}
			promoted <- attempt
			return nil
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	s.NetworkChanged()
	attempt := <-promoted
	if attempt.Generation != 1 || attempt.NetworkGeneration != 2 || connection.closeCount() != 0 {
		t.Fatalf("attempt=%+v closes=%d", attempt, connection.closeCount())
	}
	if err := <-done; err != nil {
		t.Fatalf("err=%v", err)
	}
	cancel()
}

func TestProbeSchedulerClosesRejectedAndStaleConnections(t *testing.T) {
	first := &fakeConnection{}
	secondStarted := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	var promotions int
	s, _ := NewProbeScheduler(
		ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour},
		probeRunnerFunc(func(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
			if attempt.Generation == 1 {
				<-releaseFirst
				return ProbeResult{Connection: first, Promote: true}, nil
			}
			secondStarted <- struct{}{}
			<-ctx.Done()
			return ProbeResult{}, ctx.Err()
		}),
		probePromoterFunc(func(ProbeAttempt, Connection) error { promotions++; return nil }),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	s.NetworkChanged()
	// Let the first attempt start, then invalidate its network while its runner
	// deliberately ignores cancellation.
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		active := s.activeGeneration
		s.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
	s.NetworkChanged()
	close(releaseFirst)
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("fresh probe did not start")
	}
	if first.closeCount() != 1 || promotions != 0 {
		t.Fatalf("stale closes=%d promotions=%d", first.closeCount(), promotions)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeSchedulerRetriesRejectedLogicalStreamPromotion(t *testing.T) {
	first := &fakeConnection{}
	second := &fakeConnection{}
	var probes, promotions int
	s, _ := NewProbeScheduler(
		ProbePolicy{InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond},
		probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
			probes++
			if probes == 1 {
				return ProbeResult{Connection: first, Promote: true}, nil
			}
			return ProbeResult{Connection: second, Promote: true}, nil
		}),
		probePromoterFunc(func(ProbeAttempt, Connection) error {
			promotions++
			if promotions == 1 {
				return errors.New("logical stream attachment failed")
			}
			return nil
		}),
	)
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if probes != 2 || promotions != 2 || first.closeCount() != 1 || second.closeCount() != 0 {
		t.Fatalf("probes=%d promotions=%d first closes=%d second closes=%d", probes, promotions, first.closeCount(), second.closeCount())
	}
}

func TestProbeSchedulerAttemptExhaustionIsPermanent(t *testing.T) {
	calls := 0
	s, err := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Second, MaximumBackoff: time.Second}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
		calls++
		return successfulProbe(false), nil
	}), discardProbe)
	if err != nil {
		t.Fatal(err)
	}
	s.generation = math.MaxUint64
	for range 2 {
		if runErr := s.Run(context.Background()); !errors.Is(runErr, ErrProbeExhausted) {
			t.Fatalf("error=%v", runErr)
		}
		if s.generation != math.MaxUint64 || calls != 0 {
			t.Fatalf("generation=%d calls=%d", s.generation, calls)
		}
	}
}

func TestProbeSchedulerNetworkGenerationExhaustionInterruptsRun(t *testing.T) {
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Hour, MaximumBackoff: time.Hour}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
		t.Fatal("runner called after network generation exhaustion")
		return ProbeResult{}, nil
	}), discardProbe)
	s.networkGeneration = math.MaxUint64
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()
	s.NetworkChanged()
	select {
	case err := <-done:
		if !errors.Is(err, ErrProbeExhausted) || s.networkGeneration != math.MaxUint64 {
			t.Fatalf("generation=%d error=%v", s.networkGeneration, err)
		}
	case <-time.After(time.Second):
		t.Fatal("network generation exhaustion did not wake scheduler")
	}
}

func TestProbeSchedulerFailureCounterSaturates(t *testing.T) {
	var cancel context.CancelFunc
	s, _ := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond}, probeRunnerFunc(func(context.Context, ProbeAttempt) (ProbeResult, error) {
		cancel()
		return ProbeResult{}, errors.New("unreachable")
	}), discardProbe)
	s.failures = math.MaxUint32
	ctx, stop := context.WithCancel(context.Background())
	cancel = stop
	if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if s.failures != math.MaxUint32 {
		t.Fatalf("failures=%d", s.failures)
	}
}

func TestProbeSchedulerCarriesConfiguredRecoveryPath(t *testing.T) {
	seen := make(chan Path, 1)
	s, err := NewProbeScheduler(ProbePolicy{InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond}, probeRunnerFunc(func(_ context.Context, attempt ProbeAttempt) (ProbeResult, error) {
		seen <- attempt.Path
		return ProbeResult{}, errors.New("stop")
	}), discardProbe)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPath(PathRelayQUIC); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case path := <-seen:
		if path != PathRelayQUIC {
			t.Fatalf("path=%v", path)
		}
		cancel()
	case <-time.After(time.Second):
		t.Fatal("probe did not run")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
