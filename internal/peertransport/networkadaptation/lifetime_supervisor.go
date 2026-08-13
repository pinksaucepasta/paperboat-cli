package networkadaptation

import (
	"context"
	"reflect"
	"sync"
)

type LifetimeMeasurementRunner interface {
	Measure(context.Context, Fingerprint) (Measurement, error)
}

type LifetimeMeasurementResult func(Fingerprint, Measurement, error)

type lifetimeMeasurementRun struct {
	fingerprint Fingerprint
	generation  uint64
	cancel      context.CancelFunc
	done        chan struct{}
}

// LifetimeSupervisor serializes long-running authenticated lifetime
// measurements and keeps at most the newest pending network fingerprint.
type LifetimeSupervisor struct {
	ctx      context.Context
	runner   LifetimeMeasurementRunner
	onResult LifetimeMeasurementResult

	mu         sync.Mutex
	active     *lifetimeMeasurementRun
	pending    Fingerprint
	generation uint64
	closed     bool
}

func NewLifetimeSupervisor(ctx context.Context, runner LifetimeMeasurementRunner, onResult LifetimeMeasurementResult) (*LifetimeSupervisor, error) {
	if ctx == nil || nilLifetimeRunner(runner) {
		return nil, ErrInvalid
	}
	return &LifetimeSupervisor{ctx: ctx, runner: runner, onResult: onResult}, nil
}

// Trigger starts a measurement or replaces the pending fingerprint. It never
// runs two measurements concurrently, including when cancellation is ignored.
func (s *LifetimeSupervisor) Trigger(fingerprint Fingerprint) bool {
	if s == nil || !fingerprint.Valid() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return false
	}
	if s.active == nil {
		s.startLocked(fingerprint)
		return true
	}
	if s.pending == fingerprint || !s.pending.Valid() && s.active.fingerprint == fingerprint {
		return false
	}
	s.pending = fingerprint
	s.active.cancel()
	return true
}

// Invalidate cancels active work and discards any queued old-network work.
func (s *LifetimeSupervisor) Invalidate() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	s.generation++
	count := 0
	if s.active != nil {
		count++
		s.active.cancel()
	}
	if s.pending.Valid() {
		count++
		s.pending = Fingerprint{}
	}
	s.mu.Unlock()
	return count
}

func (s *LifetimeSupervisor) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	s.closed = true
	s.generation++
	s.pending = Fingerprint{}
	active := s.active
	if active != nil {
		active.cancel()
	}
	s.mu.Unlock()
	if active == nil {
		return nil
	}
	select {
	case <-active.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *LifetimeSupervisor) startLocked(fingerprint Fingerprint) {
	ctx, cancel := context.WithCancel(s.ctx)
	run := &lifetimeMeasurementRun{
		fingerprint: fingerprint,
		generation:  s.generation,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	s.active = run
	go func() {
		measurement, err := s.runner.Measure(ctx, fingerprint)
		s.finish(run, measurement, err)
	}()
}

func (s *LifetimeSupervisor) finish(run *lifetimeMeasurementRun, measurement Measurement, err error) {
	run.cancel()
	s.mu.Lock()
	if s.active != run {
		s.mu.Unlock()
		close(run.done)
		return
	}
	pending := s.pending
	s.pending = Fingerprint{}
	s.active = nil
	closed := s.closed || s.ctx.Err() != nil
	callback := s.onResult
	current := !closed && !pending.Valid() && run.generation == s.generation
	if !closed && pending.Valid() {
		s.startLocked(pending)
	}
	s.mu.Unlock()
	if current && callback != nil {
		callback(run.fingerprint, measurement, err)
	}
	close(run.done)
}

func nilLifetimeRunner(runner LifetimeMeasurementRunner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
