package connectionmanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrPathSuspect           = errors.New("selected peer path health is suspect")
	ErrActiveHealthExhausted = errors.New("active path health sequence exhausted")
	errTwoPTOs               = errors.New("peer QUIC reached two PTOs since the last authenticated health exchange")
	errActiveHealthRebind    = errors.New("active health monitor rebind requested")
)

type activeHealthRebindKey struct{}

type activeHealthRebindSignal struct{ done <-chan struct{} }

func withActiveHealthRebind(ctx context.Context, done <-chan struct{}) context.Context {
	return context.WithValue(ctx, activeHealthRebindKey{}, activeHealthRebindSignal{done: done})
}

func activeHealthRebindRequested(ctx context.Context) bool {
	if done := activeHealthRebindDone(ctx); done != nil {
		select {
		case <-done:
			return true
		default:
		}
	}
	return false
}

func activeHealthRebindDone(ctx context.Context) <-chan struct{} {
	if signal, ok := ctx.Value(activeHealthRebindKey{}).(activeHealthRebindSignal); ok {
		return signal.done
	}
	return nil
}

type ActiveHealthTransport interface {
	HealthExchange(context.Context, [16]byte) (uint32, error)
}

type activeHealthPTOObserver interface {
	PTOCount() uint32
	PTOChanged() <-chan struct{}
}

type activeHealthConfidenceObserver interface {
	PathSuspect()
	PathTrusted()
}

type ActiveHealthBinding struct {
	Path              Path
	Generation        uint64
	NetworkGeneration uint64
}

type ActiveHealthSample struct {
	Binding   ActiveHealthBinding
	Sequence  uint64
	At        time.Time
	Completed time.Duration
	PTOs      uint32
	Succeeded bool
}

type ActiveHealthRecorder interface {
	RecordActiveHealth(ActiveHealthSample) error
}

type ActiveHealthQualityKeySource interface {
	ActiveHealthQualityKey(ActiveHealthBinding) (QualityKey, error)
}

type QualityActiveHealthRecorder struct {
	cache *QualityCache
	keys  ActiveHealthQualityKeySource
}

func NewQualityActiveHealthRecorder(cache *QualityCache, keys ActiveHealthQualityKeySource) (*QualityActiveHealthRecorder, error) {
	if cache == nil || keys == nil {
		return nil, errors.New("quality cache and active health key source are required")
	}
	return &QualityActiveHealthRecorder{cache: cache, keys: keys}, nil
}

func (r *QualityActiveHealthRecorder) RecordActiveHealth(sample ActiveHealthSample) error {
	if r == nil || r.cache == nil || r.keys == nil || !validActiveHealthBinding(sample.Binding) || sample.Sequence == 0 || sample.At.IsZero() || sample.Completed <= 0 {
		return errors.New("invalid quality active health sample")
	}
	if sample.Binding.Path == PathWSS {
		return nil
	}
	key, err := r.keys.ActiveHealthQualityKey(sample.Binding)
	if err != nil {
		return err
	}
	return r.cache.Record(key, QualityObservation{Path: sample.Binding.Path, At: sample.At, Completion: sample.Completed, Succeeded: sample.Succeeded, PTOs: sample.PTOs})
}

type ActiveHealthPolicy struct {
	HeartbeatInterval time.Duration
	PathTrustDuration time.Duration
}

func DevelopmentActiveHealthPolicy() ActiveHealthPolicy {
	return ActiveHealthPolicy{
		// Keep fault detection below the terminal continuity budget while
		// allowing one authenticated exchange to establish trust.
		HeartbeatInterval: 500 * time.Millisecond,
		PathTrustDuration: 1500 * time.Millisecond,
	}
}

func (p ActiveHealthPolicy) valid() bool {
	return p.HeartbeatInterval > 0 && p.HeartbeatInterval <= time.Minute &&
		p.PathTrustDuration > p.HeartbeatInterval && p.PathTrustDuration <= time.Minute
}

type ActiveHealthMonitor struct {
	policy   ActiveHealthPolicy
	recorder ActiveHealthRecorder
	random   io.Reader
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
}

func NewActiveHealthMonitor(policy ActiveHealthPolicy, recorder ActiveHealthRecorder) (*ActiveHealthMonitor, error) {
	if !policy.valid() || recorder == nil {
		return nil, errors.New("invalid active path health monitor")
	}
	return &ActiveHealthMonitor{policy: policy, recorder: recorder, random: rand.Reader, now: time.Now, wait: waitProbe}, nil
}

// Run owns health exchanges for one selected path generation. The caller
// cancels it when the selection, network generation, or lease ownership ends.
func (m *ActiveHealthMonitor) Run(ctx context.Context, binding ActiveHealthBinding, transport ActiveHealthTransport) error {
	return m.run(ctx, binding, transport, 1)
}

func (m *ActiveHealthMonitor) run(ctx context.Context, binding ActiveHealthBinding, transport ActiveHealthTransport, sequence uint64) error {
	if m == nil || ctx == nil || transport == nil || !validActiveHealthBinding(binding) {
		return errors.New("invalid active path health run")
	}
	if sequence == 0 {
		return ErrActiveHealthExhausted
	}
	for {
		if activeHealthRebindRequested(ctx) {
			return errActiveHealthRebind
		}
		waitStarted := m.now()
		ptos, err := m.waitForHeartbeat(ctx, transport, m.policy.HeartbeatInterval)
		if err != nil {
			if activeHealthRebindRequested(ctx) {
				return errActiveHealthRebind
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, errTwoPTOs) {
				completed := m.now().Sub(waitStarted)
				if completed <= 0 {
					completed = time.Nanosecond
				}
				sample := ActiveHealthSample{Binding: binding, Sequence: sequence, At: m.now().UTC(), Completed: completed, PTOs: ptos, Succeeded: false}
				if recordErr := m.recorder.RecordActiveHealth(sample); recordErr != nil {
					return fmt.Errorf("record active health: %w", recordErr)
				}
				return fmt.Errorf("%w: %v", ErrPathSuspect, err)
			}
			return err
		}
		if activeHealthRebindRequested(ctx) {
			return errActiveHealthRebind
		}
		var nonce [16]byte
		if _, err := io.ReadFull(m.random, nonce[:]); err != nil {
			return fmt.Errorf("generate active health nonce: %w", err)
		}
		// A graceful role rebind is a separate signal, so it cannot abort an
		// already allocated ordered relay handle. Hard cancellation still flows
		// through the runner context and interrupts the bounded exchange.
		exchangeCtx, cancel := context.WithTimeout(ctx, m.policy.PathTrustDuration-m.policy.HeartbeatInterval)
		started := m.now()
		ptos, exchangeErr := monitorHealthExchange(exchangeCtx, transport, nonce)
		completed := m.now().Sub(started)
		cancel()
		if completed <= 0 {
			completed = time.Nanosecond
		}
		sample := ActiveHealthSample{Binding: binding, Sequence: sequence, At: m.now().UTC(), Completed: completed, PTOs: ptos, Succeeded: exchangeErr == nil}
		if exchangeErr == nil {
			markPathTrusted(transport)
			if err := m.recorder.RecordActiveHealth(sample); err != nil {
				return fmt.Errorf("record active health: %w", err)
			}
			if sequence == ^uint64(0) {
				return ErrActiveHealthExhausted
			}
			if activeHealthRebindRequested(ctx) {
				return errActiveHealthRebind
			}
			sequence++
			continue
		}
		if activeHealthRebindRequested(ctx) {
			return errActiveHealthRebind
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !errors.Is(exchangeErr, errTwoPTOs) && !activeHealthAllowsFallback(exchangeErr) {
			return exchangeErr
		}
		if err := m.recorder.RecordActiveHealth(sample); err != nil {
			return fmt.Errorf("record active health: %w", err)
		}
		return fmt.Errorf("%w: %v", ErrPathSuspect, exchangeErr)
	}
}

type activeHealthExchangeResult struct {
	ptos uint32
	err  error
}

func monitorHealthExchange(ctx context.Context, transport ActiveHealthTransport, nonce [16]byte) (uint32, error) {
	observer, ok := transport.(activeHealthPTOObserver)
	if !ok || observer.PTOChanged() == nil {
		return transport.HealthExchange(ctx, nonce)
	}
	baseline := observer.PTOCount()
	done := make(chan activeHealthExchangeResult, 1)
	go func() {
		ptos, err := transport.HealthExchange(ctx, nonce)
		done <- activeHealthExchangeResult{ptos: ptos, err: err}
	}()
	for {
		select {
		case result := <-done:
			return result.ptos, result.err
		case <-ctx.Done():
			result := <-done
			return result.ptos, result.err
		case <-observer.PTOChanged():
			current := observer.PTOCount()
			if current < baseline {
				return 0, ErrActiveHealthExhausted
			}
			if current-baseline >= 1 {
				markPathSuspect(transport)
			}
			if current-baseline >= 2 {
				return current - baseline, errTwoPTOs
			}
		}
	}
}

func (m *ActiveHealthMonitor) waitForHeartbeat(ctx context.Context, transport ActiveHealthTransport, duration time.Duration) (uint32, error) {
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if rebind := activeHealthRebindDone(ctx); rebind != nil {
		go func() {
			select {
			case <-rebind:
				cancel()
			case <-waitCtx.Done():
			}
		}()
	}
	observer, ok := transport.(activeHealthPTOObserver)
	if !ok || observer.PTOChanged() == nil {
		return 0, m.wait(waitCtx, duration)
	}
	baseline := observer.PTOCount()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return 0, waitCtx.Err()
		case <-timer.C:
			current := observer.PTOCount()
			if current < baseline {
				return 0, ErrActiveHealthExhausted
			}
			return current - baseline, nil
		case <-observer.PTOChanged():
			current := observer.PTOCount()
			if current < baseline {
				return 0, ErrActiveHealthExhausted
			}
			if current-baseline >= 1 {
				markPathSuspect(transport)
			}
			if current-baseline >= 2 {
				return current - baseline, errTwoPTOs
			}
		}
	}
}

func markPathSuspect(transport ActiveHealthTransport) {
	if observer, ok := transport.(activeHealthConfidenceObserver); ok {
		observer.PathSuspect()
	}
}

func markPathTrusted(transport ActiveHealthTransport) {
	if observer, ok := transport.(activeHealthConfidenceObserver); ok {
		observer.PathTrusted()
	}
}

func activeHealthAllowsFallback(err error) bool {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func validActiveHealthBinding(binding ActiveHealthBinding) bool {
	return (binding.Path == PathDirectQUIC || binding.Path == PathRelayQUIC || binding.Path == PathWSS) && binding.Generation > 0 && binding.NetworkGeneration > 0
}
