package directpath

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sethvargo/go-retry"
)

func TestSupervisorReplacesMappingAttemptWithFreshGeneration(t *testing.T) {
	factory := &recordingAssemblyFactory{}
	supervisor := newTestSupervisor(t, factory.create)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 7); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	first := awaitAssembly(t, ctx, supervisor)
	if first.Generation() != (Generation{Attempt: 1, Network: 7}) {
		t.Fatalf("first generation=%+v", first.Generation())
	}
	first.signalReplacement(ErrMappingInvalidated)
	second := awaitAssembly(t, ctx, supervisor)
	if second == first || second.Generation() != (Generation{Attempt: 2, Network: 7}) {
		t.Fatalf("second=%p generation=%+v", second, second.Generation())
	}
	select {
	case <-first.done:
	case <-ctx.Done():
		t.Fatal("replaced assembly remained open")
	}
}

func TestSupervisorRetryableFactoryFailureUsesNewAttemptGeneration(t *testing.T) {
	var mu sync.Mutex
	var generations []Generation
	supervisor := newTestSupervisor(t, func(_ context.Context, generation Generation) (*Assembly, error) {
		mu.Lock()
		generations = append(generations, generation)
		call := len(generations)
		mu.Unlock()
		if call == 1 {
			return nil, RetryableFactoryError(errors.New("signaling temporarily unavailable"))
		}
		return testAssembly(generation), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	assembly := awaitAssembly(t, ctx, supervisor)
	if assembly.Generation() != (Generation{Attempt: 2, Network: 3}) {
		t.Fatalf("generation=%+v", assembly.Generation())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(generations) != 2 || generations[0].Attempt != 1 || generations[1].Attempt != 2 {
		t.Fatalf("factory generations=%+v", generations)
	}
}

func TestSupervisorTerminalFailureWaitsForExplicitRetry(t *testing.T) {
	terminal := errors.New("authorization revoked")
	var mu sync.Mutex
	calls := 0
	supervisor := newTestSupervisor(t, func(_ context.Context, generation Generation) (*Assembly, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil, terminal
		}
		return testAssembly(generation), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 4); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	update := awaitUpdate(t, ctx, supervisor)
	if !errors.Is(update.Err, terminal) || update.Assembly != nil {
		t.Fatalf("terminal update=%+v", update)
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	if calls != 1 {
		t.Fatalf("terminal failure retried %d times", calls)
	}
	mu.Unlock()
	if !supervisor.Retry() {
		t.Fatal("explicit retry rejected")
	}
	assembly := awaitAssembly(t, ctx, supervisor)
	if assembly.Generation().Attempt != 2 {
		t.Fatalf("retry generation=%+v", assembly.Generation())
	}
}

func TestSupervisorNetworkChangeClosesLateFactoryResult(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	late := make(chan *Assembly, 1)
	supervisor := newTestSupervisor(t, func(_ context.Context, generation Generation) (*Assembly, error) {
		if generation.Network == 1 {
			close(started)
			<-release
			assembly := testAssembly(generation)
			late <- assembly
			return assembly, nil
		}
		return testAssembly(generation), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	<-started
	if !supervisor.NetworkChanged(2) || supervisor.NetworkChanged(2) {
		t.Fatal("network change not fenced")
	}
	close(release)
	lateAssembly := <-late
	current := awaitAssembly(t, ctx, supervisor)
	if current.Generation().Network != 2 || current == lateAssembly {
		t.Fatalf("published generation=%+v", current.Generation())
	}
	select {
	case <-lateAssembly.done:
	case <-ctx.Done():
		t.Fatal("late stale assembly remained open")
	}
}

func TestSupervisorShutdownCancelsFactoryAndPublishesNothing(t *testing.T) {
	started := make(chan struct{})
	supervisor := newTestSupervisor(t, func(ctx context.Context, _ Generation) (*Assembly, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	runCtx, runCancel := context.WithCancel(context.Background())
	if err := supervisor.Start(runCtx, 1); err != nil {
		t.Fatal(err)
	}
	<-started
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	runCancel()
	if _, _, ok := supervisor.Current(); ok {
		t.Fatal("assembly published during shutdown")
	}
}

func TestSupervisorReplacesUnexpectedlyClosedCurrentAssembly(t *testing.T) {
	supervisor := newTestSupervisor(t, AssemblyFactoryFunc(func(_ context.Context, generation Generation) (*Assembly, error) {
		return testAssembly(generation), nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 6); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	first := awaitAssembly(t, ctx, supervisor)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	var reason error
	for reason == nil {
		update := awaitUpdate(t, ctx, supervisor)
		reason = update.Reason
	}
	if !errors.Is(reason, ErrAssemblyClosed) {
		t.Fatalf("replacement reason=%v", reason)
	}
	second := awaitAssembly(t, ctx, supervisor)
	if second.Generation().Attempt != first.Generation().Attempt+1 {
		t.Fatalf("replacement generation=%+v", second.Generation())
	}
}

func TestSupervisorExhaustedBackoffWaitsForExplicitRetry(t *testing.T) {
	want := errors.New("control plane unavailable")
	calls := 0
	policy := ReplacementPolicy{AttemptTimeout: time.Second, RecoveryBudget: 4 * time.Second, InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond}
	supervisor, err := NewSupervisor(SupervisorConfig{
		Factory: AssemblyFactoryFunc(func(_ context.Context, generation Generation) (*Assembly, error) {
			calls++
			if calls == 1 {
				return nil, RetryableFactoryError(want)
			}
			return testAssembly(generation), nil
		}),
		Policy:  policy,
		Backoff: func() retry.Backoff { return retry.BackoffFunc(func() (time.Duration, bool) { return 0, true }) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	update := awaitUpdate(t, ctx, supervisor)
	if !errors.Is(update.Err, want) || calls != 1 {
		t.Fatalf("update=%+v calls=%d", update, calls)
	}
	if !supervisor.Retry() {
		t.Fatal("retry rejected after exhausted backoff")
	}
	if assembly := awaitAssembly(t, ctx, supervisor); assembly.Generation().Attempt != 2 {
		t.Fatalf("generation=%+v", assembly.Generation())
	}
}

func TestSupervisorRejectsTypedNilFactoryAndBackoff(t *testing.T) {
	policy := DevelopmentReplacementPolicy()
	var factory AssemblyFactoryFunc
	if _, err := NewSupervisor(SupervisorConfig{Factory: factory, Policy: policy}); !errors.Is(err, ErrSupervisorInvalid) {
		t.Fatalf("typed nil factory error=%v", err)
	}
	var backoff retry.BackoffFunc
	supervisor, err := NewSupervisor(SupervisorConfig{
		Factory: AssemblyFactoryFunc(func(context.Context, Generation) (*Assembly, error) { return nil, nil }),
		Policy:  policy, Backoff: func() retry.Backoff { return backoff },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	update := awaitUpdate(t, ctx, supervisor)
	if !errors.Is(update.Err, ErrSupervisorInvalid) {
		t.Fatalf("typed nil backoff update=%+v", update)
	}
	_ = supervisor.Shutdown(context.Background())
}

func TestSupervisorPermanentlyRejectsAttemptGenerationOverflow(t *testing.T) {
	calls := 0
	supervisor := newTestSupervisor(t, func(_ context.Context, generation Generation) (*Assembly, error) {
		calls++
		return testAssembly(generation), nil
	})
	supervisor.attempt = ^uint64(0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Shutdown(context.Background())
	update := awaitUpdate(t, ctx, supervisor)
	if !errors.Is(update.Err, ErrSupervisorInvalid) || update.Generation != (Generation{}) || calls != 0 {
		t.Fatalf("overflow update=%+v calls=%d", update, calls)
	}
	if supervisor.Retry() {
		t.Fatal("accepted retry after permanent attempt exhaustion")
	}
}

type recordingAssemblyFactory struct {
	mu          sync.Mutex
	generations []Generation
}

func (f *recordingAssemblyFactory) create(_ context.Context, generation Generation) (*Assembly, error) {
	f.mu.Lock()
	f.generations = append(f.generations, generation)
	f.mu.Unlock()
	return testAssembly(generation), nil
}

func newTestSupervisor(t *testing.T, factory AssemblyFactoryFunc) *Supervisor {
	t.Helper()
	policy := ReplacementPolicy{
		AttemptTimeout: time.Second, RecoveryBudget: 4 * time.Second,
		InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond,
	}
	supervisor, err := NewSupervisor(SupervisorConfig{
		Factory: factory, Policy: policy,
		Backoff: func() retry.Backoff { return retry.BackoffFunc(func() (time.Duration, bool) { return 0, false }) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

func testAssembly(generation Generation) *Assembly {
	return &Assembly{
		attempt: generation.Attempt, network: generation.Network,
		replacementGeneration: generation.Network, replacement: make(chan error, 1), done: make(chan struct{}),
	}
}

func awaitAssembly(t *testing.T, ctx context.Context, supervisor *Supervisor) *Assembly {
	t.Helper()
	for {
		update := awaitUpdate(t, ctx, supervisor)
		if update.Assembly != nil {
			return update.Assembly
		}
	}
}

func awaitUpdate(t *testing.T, ctx context.Context, supervisor *Supervisor) ReplacementUpdate {
	t.Helper()
	select {
	case update := <-supervisor.Updates():
		return update
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return ReplacementUpdate{}
	}
}
