package connectionmanager

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"
)

var ErrProbeExhausted = errors.New("direct recovery probe generation exhausted")

// ProbePolicy bounds recovery probes independently from consumer connection races.
type ProbePolicy struct {
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
	Jitter         float64
	AttemptTimeout time.Duration
}

func DevelopmentProbePolicy() ProbePolicy {
	// Recovery runs only while an application is using a lower-priority path.
	// The first attempt and every network-change wake are immediate. Repeated
	// errors use the same five-second throttle as Tailscale's error-triggered
	// magicsock rebind: peer descriptors have longer remote setup lifetimes, so
	// a sub-second loop can exhaust the host's bounded attempt admission even
	// though this client already canceled each failed dial.
	return ProbePolicy{InitialBackoff: 5 * time.Second, MaximumBackoff: 5 * time.Second, Jitter: 0.2, AttemptTimeout: 15 * time.Second}
}

func (p ProbePolicy) validate() error {
	if p.InitialBackoff <= 0 || p.MaximumBackoff < p.InitialBackoff || p.Jitter < 0 || p.Jitter >= 1 || p.AttemptTimeout < 0 {
		return errors.New("invalid recovery probe policy")
	}
	return nil
}

type ProbeAttempt struct {
	Generation        uint64
	NetworkGeneration uint64
	Path              Path
}

type ProbeRunner interface {
	Probe(context.Context, ProbeAttempt) (ProbeResult, error)
}

type ProbeResult struct {
	Connection Connection
	Promote    bool
}

type ProbePromoter interface {
	Promote(ProbeAttempt, Connection) error
}

// ProbeScheduler runs at most one probe and wakes immediately when the network changes.
type ProbeScheduler struct {
	policy   ProbePolicy
	runner   ProbeRunner
	promoter ProbePromoter
	random   func() float64
	network  chan struct{}

	mu                sync.Mutex
	generation        uint64
	networkGeneration uint64
	failures          uint32
	activeGeneration  uint64
	activeCancel      context.CancelFunc
	exhausted         bool
	immediate         bool
	path              Path
}

// SetPath selects the authenticated path that recovery probes must verify.
// It is intentionally limited to direct QUIC and relay QUIC.
func (s *ProbeScheduler) SetPath(path Path) error {
	if s == nil || path != PathDirectQUIC && path != PathRelayQUIC {
		return errors.New("invalid recovery probe path")
	}
	s.mu.Lock()
	if s.path != 0 && s.path != path {
		// Backoff measures failures of one concrete path. Carrying direct-path
		// failures into relay recovery can postpone the first usable fallback
		// probe by the full maximum backoff.
		s.failures = 0
		s.immediate = true
	}
	s.path = path
	s.mu.Unlock()
	return nil
}

func NewProbeScheduler(policy ProbePolicy, runner ProbeRunner, promoter ProbePromoter) (*ProbeScheduler, error) {
	if err := policy.validate(); err != nil || runner == nil || promoter == nil {
		return nil, errors.New("invalid recovery probe scheduler")
	}
	return &ProbeScheduler{policy: policy, runner: runner, promoter: promoter, random: rand.Float64, network: make(chan struct{}, 1), networkGeneration: 1, immediate: true}, nil
}

func (s *ProbeScheduler) NetworkChanged() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.networkGeneration == math.MaxUint64 {
		s.exhausted = true
	} else {
		s.networkGeneration++
	}
	s.failures = 0
	s.immediate = true
	cancel := s.activeCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	select {
	case s.network <- struct{}{}:
	default:
	}
}

func (s *ProbeScheduler) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("nil recovery probe scheduler")
	}
	for {
		s.mu.Lock()
		if s.exhausted || s.generation == math.MaxUint64 {
			s.exhausted = true
			s.mu.Unlock()
			return ErrProbeExhausted
		}
		s.mu.Unlock()
		s.mu.Lock()
		immediate := s.immediate
		s.immediate = false
		s.mu.Unlock()
		if !immediate {
			delay := s.delay()
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-s.network:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
			}
		}
		s.mu.Lock()
		if s.exhausted || s.generation == math.MaxUint64 {
			s.exhausted = true
			s.mu.Unlock()
			return ErrProbeExhausted
		}
		s.generation++
		path := s.path
		if path == 0 {
			path = PathDirectQUIC
		}
		attempt := ProbeAttempt{Generation: s.generation, NetworkGeneration: s.networkGeneration, Path: path}
		s.mu.Unlock()
		// Direct recovery mints generation-scoped ICE credentials and candidates.
		// Bound that complete generation independently from the descriptor's
		// longer admission lifetime while the selected relay keeps carrying data.
		probeCtx, cancel := context.WithCancel(ctx)
		if path == PathDirectQUIC && s.policy.AttemptTimeout > 0 {
			probeCtx, cancel = context.WithTimeout(ctx, s.policy.AttemptTimeout)
		}
		s.mu.Lock()
		s.activeGeneration = attempt.Generation
		s.activeCancel = cancel
		s.mu.Unlock()
		started := time.Now()
		result, err := s.runner.Probe(probeCtx, attempt)
		cancel()
		s.mu.Lock()
		if s.activeGeneration == attempt.Generation {
			s.activeGeneration = 0
			s.activeCancel = nil
		}
		currentNetwork := !s.exhausted && attempt.NetworkGeneration == s.networkGeneration
		if err == nil && nilConnection(result.Connection) {
			err = &Failure{Class: FailureInternal, Path: PathDirectQUIC, Cause: errors.New("probe returned no connection")}
		}
		if err == nil && result.Connection.State() != StateTrusted {
			err = &Failure{Class: FailureProtocol, Path: PathDirectQUIC, Cause: errors.New("probe returned an untrusted direct path")}
		}
		promoted := false
		if err == nil && currentNetwork && result.Promote {
			err = s.promoter.Promote(attempt, result.Connection)
			if err == nil {
				result.Connection = nil
				promoted = true
			}
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("peer recovery probe failed", "path", uint8(path), "generation", attempt.Generation, "network_generation", attempt.NetworkGeneration, "elapsed_ms", time.Since(started).Milliseconds(), "error", err)
		} else if promoted {
			slog.Info("peer recovery probe promoted", "path", uint8(path), "generation", attempt.Generation, "network_generation", attempt.NetworkGeneration, "elapsed_ms", time.Since(started).Milliseconds())
		}
		if currentNetwork {
			if err == nil {
				s.failures = 0
			} else if !errors.Is(err, context.Canceled) && s.failures < math.MaxUint32 {
				s.failures++
			}
		}
		s.mu.Unlock()
		if !nilConnection(result.Connection) {
			_ = result.Connection.Close()
		}
		if promoted {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *ProbeScheduler) delay() time.Duration {
	s.mu.Lock()
	failures := s.failures
	s.mu.Unlock()
	delay := s.policy.InitialBackoff
	for i := uint32(0); i < failures && delay < s.policy.MaximumBackoff; i++ {
		if delay > s.policy.MaximumBackoff/2 {
			delay = s.policy.MaximumBackoff
			break
		}
		delay *= 2
	}
	if delay > s.policy.MaximumBackoff {
		delay = s.policy.MaximumBackoff
	}
	if s.policy.Jitter == 0 {
		return delay
	}
	factor := 1 + (s.random()*2-1)*s.policy.Jitter
	return time.Duration(float64(delay) * factor)
}
