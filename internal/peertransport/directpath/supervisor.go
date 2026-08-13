package directpath

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/sethvargo/go-retry"
)

var ErrSupervisorInvalid = errors.New("invalid direct path generation supervisor")

type Generation struct {
	Attempt uint64
	Network uint64
}

func (g Generation) valid() bool { return g.Attempt > 0 && g.Network > 0 }

func (a *Assembly) Generation() Generation {
	if a == nil {
		return Generation{}
	}
	return Generation{Attempt: a.attempt, Network: a.network}
}

type AssemblyFactory interface {
	Create(context.Context, Generation) (*Assembly, error)
}

type AssemblyFactoryFunc func(context.Context, Generation) (*Assembly, error)

func (f AssemblyFactoryFunc) Create(ctx context.Context, generation Generation) (*Assembly, error) {
	return f(ctx, generation)
}

type ReplacementPolicy struct {
	AttemptTimeout time.Duration
	RecoveryBudget time.Duration
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
	JitterPercent  uint64
}

func DevelopmentReplacementPolicy() ReplacementPolicy {
	return ReplacementPolicy{
		AttemptTimeout: 15 * time.Second, RecoveryBudget: time.Minute,
		InitialBackoff: 250 * time.Millisecond, MaximumBackoff: 5 * time.Second, JitterPercent: 20,
	}
}

func (p ReplacementPolicy) valid() bool {
	return p.AttemptTimeout > 0 && p.RecoveryBudget > p.AttemptTimeout && p.InitialBackoff > 0 && p.MaximumBackoff >= p.InitialBackoff && p.JitterPercent <= 100
}

type retryableFactoryError struct{ cause error }

func (e *retryableFactoryError) Error() string {
	return "retryable direct path factory failure: " + e.cause.Error()
}
func (e *retryableFactoryError) Unwrap() error { return e.cause }

func RetryableFactoryError(cause error) error {
	if cause == nil {
		return nil
	}
	return &retryableFactoryError{cause: cause}
}

type ReplacementUpdate struct {
	Generation Generation
	Assembly   *Assembly
	Reason     error
	Err        error
}

type SupervisorConfig struct {
	Factory AssemblyFactory
	Policy  ReplacementPolicy
	Backoff func() retry.Backoff
}

type Supervisor struct {
	config   SupervisorConfig
	wake     chan struct{}
	updates  chan ReplacementUpdate
	notifyMu sync.Mutex

	mu               sync.Mutex
	cancel           context.CancelFunc
	done             chan struct{}
	current          *Assembly
	network          uint64
	attempt          uint64
	attemptExhausted bool
	owner            *supervisorOwner
	buildCancel      context.CancelFunc
	running          bool
	started          bool
}

type supervisorOwner struct {
	//lint:ignore U1000 The byte keeps independently allocated supervisor owners pointer-distinct.
	marker byte
}

func NewSupervisor(config SupervisorConfig) (*Supervisor, error) {
	if nilAssemblyFactory(config.Factory) || !config.Policy.valid() {
		return nil, ErrSupervisorInvalid
	}
	if config.Backoff == nil {
		policy := config.Policy
		config.Backoff = func() retry.Backoff {
			backoff := retry.WithCappedDuration(policy.MaximumBackoff, retry.NewExponential(policy.InitialBackoff))
			backoff = retry.WithJitterPercent(policy.JitterPercent, backoff)
			return retry.WithMaxDuration(policy.RecoveryBudget, backoff)
		}
	}
	return &Supervisor{config: config, wake: make(chan struct{}, 1), updates: make(chan ReplacementUpdate, 16)}, nil
}

func (s *Supervisor) Start(ctx context.Context, networkGeneration uint64) error {
	if s == nil || ctx == nil || networkGeneration == 0 {
		return ErrSupervisorInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrSupervisorInvalid
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel, s.done, s.network, s.owner, s.running, s.started = cancel, make(chan struct{}), networkGeneration, &supervisorOwner{}, true, true
	go s.loop(runCtx)
	return nil
}

func (s *Supervisor) Updates() <-chan ReplacementUpdate {
	if s == nil {
		return nil
	}
	return s.updates
}

func (s *Supervisor) Current() (*Assembly, Generation, bool) {
	if s == nil {
		return nil, Generation{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil, Generation{}, false
	}
	return s.current, s.current.Generation(), true
}

func (s *Supervisor) NetworkChanged(generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.mu.Lock()
	if !s.running || generation <= s.network {
		s.mu.Unlock()
		return false
	}
	s.network = generation
	s.owner = &supervisorOwner{}
	current, cancel := s.current, s.buildCancel
	s.current = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if current != nil {
		current.NetworkChanged(generation)
	}
	s.notify(ReplacementUpdate{Generation: Generation{Network: generation}, Reason: ErrNetworkChanged})
	s.wakeup()
	return true
}

// Retry starts a fresh attempt generation after a terminal or exhausted
// recovery cycle. It never reuses credentials from the failed factory call.
func (s *Supervisor) Retry() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	if !s.running || s.current != nil || s.attemptExhausted {
		s.mu.Unlock()
		return false
	}
	s.owner = &supervisorOwner{}
	cancel := s.buildCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wakeup()
	return true
}

func (s *Supervisor) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrSupervisorInvalid
	}
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) loop(ctx context.Context) {
	defer s.finish()
	for {
		s.mu.Lock()
		owner, network, hasCurrent := s.owner, s.network, s.current != nil
		s.mu.Unlock()
		if !hasCurrent {
			assembly, generation, err := s.build(ctx, owner, network)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.mu.Lock()
				stale := owner != s.owner || network != s.network
				s.mu.Unlock()
				if stale {
					continue
				}
				s.notify(ReplacementUpdate{Generation: generation, Err: err})
			} else {
				s.mu.Lock()
				if owner != s.owner || network != s.network || s.current != nil {
					s.mu.Unlock()
					_ = assembly.Close()
					continue
				}
				s.current = assembly
				s.mu.Unlock()
				s.notify(ReplacementUpdate{Generation: generation, Assembly: assembly})
				go s.watch(ctx, assembly, generation)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
	}
}

func (s *Supervisor) build(ctx context.Context, owner *supervisorOwner, network uint64) (*Assembly, Generation, error) {
	recoveryCtx, recoveryCancel := context.WithTimeout(ctx, s.config.Policy.RecoveryBudget)
	defer recoveryCancel()
	buildCtx, buildCancel := context.WithCancel(recoveryCtx)
	s.mu.Lock()
	if owner == nil || owner != s.owner || network != s.network {
		s.mu.Unlock()
		buildCancel()
		return nil, Generation{}, context.Canceled
	}
	s.buildCancel = buildCancel
	s.mu.Unlock()
	defer func() {
		buildCancel()
		s.mu.Lock()
		s.buildCancel = nil
		s.mu.Unlock()
	}()
	type result struct {
		assembly   *Assembly
		generation Generation
	}
	backoff := s.config.Backoff()
	if nilBackoff(backoff) {
		return nil, Generation{}, ErrSupervisorInvalid
	}
	created, err := retry.DoValue(buildCtx, backoff, func(callCtx context.Context) (result, error) {
		s.mu.Lock()
		if owner != s.owner || network != s.network {
			s.mu.Unlock()
			return result{}, context.Canceled
		}
		if s.attempt == ^uint64(0) {
			s.attemptExhausted = true
			s.mu.Unlock()
			return result{}, ErrSupervisorInvalid
		}
		s.attempt++
		generation := Generation{Attempt: s.attempt, Network: network}
		s.mu.Unlock()
		attemptCtx, cancel := context.WithTimeout(callCtx, s.config.Policy.AttemptTimeout)
		assembly, createErr := s.config.Factory.Create(attemptCtx, generation)
		cancel()
		if callErr := callCtx.Err(); callErr != nil {
			if assembly != nil {
				_ = assembly.Close()
			}
			return result{}, callErr
		}
		if assembly != nil && (createErr != nil || assembly.Generation() != generation) {
			_ = assembly.Close()
			assembly = nil
			if createErr == nil {
				createErr = errors.New("direct path factory returned a stale generation")
			}
		}
		if createErr == nil && assembly == nil {
			createErr = errors.New("direct path factory returned no assembly")
		}
		if createErr != nil {
			var retryable *retryableFactoryError
			if errors.As(createErr, &retryable) {
				return result{}, retry.RetryableError(createErr)
			}
			return result{}, createErr
		}
		return result{assembly: assembly, generation: generation}, nil
	})
	return created.assembly, created.generation, err
}

func (s *Supervisor) watch(ctx context.Context, assembly *Assembly, generation Generation) {
	var reason error
	select {
	case <-ctx.Done():
		return
	case reason = <-assembly.ReplacementRequired():
	case <-assembly.Done():
		select {
		case reason = <-assembly.ReplacementRequired():
		default:
			reason = ErrAssemblyClosed
		}
	}
	s.mu.Lock()
	if s.current != assembly {
		s.mu.Unlock()
		return
	}
	s.current = nil
	s.owner = &supervisorOwner{}
	s.mu.Unlock()
	_ = assembly.Close()
	s.notify(ReplacementUpdate{Generation: generation, Reason: reason})
	s.wakeup()
}

func (s *Supervisor) finish() {
	s.mu.Lock()
	current := s.current
	s.current = nil
	s.running = false
	s.buildCancel = nil
	done := s.done
	s.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
	close(done)
}

func (s *Supervisor) wakeup() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Supervisor) notify(update ReplacementUpdate) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	select {
	case s.updates <- update:
		return
	default:
	}
	// Updates are a bounded latest-state stream. If a consumer falls behind,
	// discard the oldest observation and retain the newest lifecycle state.
	select {
	case <-s.updates:
	default:
	}
	select {
	case s.updates <- update:
	default:
	}
}

func nilAssemblyFactory(factory AssemblyFactory) bool {
	return nilInterface(factory)
}

func nilBackoff(backoff retry.Backoff) bool {
	return nilInterface(backoff)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
