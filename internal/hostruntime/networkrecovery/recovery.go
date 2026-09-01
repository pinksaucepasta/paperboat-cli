// Package networkrecovery owns the stable-host network recovery policy.
//
// The package deliberately separates observing a network change from replacing
// a carrier.  An observer may report route, address, resolver, proxy, path, or
// wake changes from any platform.  A replacer is responsible for staging a new
// authenticated carrier and only returning after it is ready.  The controller
// never mutates the active carrier itself, so a failed replacement leaves the
// last-known-good carrier available to its owner.
package networkrecovery

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

var (
	ErrInvalidConfiguration = errors.New("invalid network recovery configuration")
	ErrInvalidObservation   = errors.New("invalid network recovery observation")
	ErrStopped              = errors.New("network recovery stopped")
	ErrNoPendingChange      = errors.New("no pending network change")
	ErrReplacementNotReady  = errors.New("network carrier replacement was not ready")
	ErrIdentityChanged      = errors.New("network carrier identity changed")

	// These sentinel errors let platform and transport code classify failures
	// without coupling the controller to a particular carrier implementation.
	ErrAuthentication = errors.New("network carrier authentication failed")
	ErrConfiguration  = errors.New("network carrier configuration failed")
	ErrDNS            = errors.New("network carrier DNS failed")
	ErrOrigin         = errors.New("network carrier origin failed")
	ErrEdge           = errors.New("network carrier edge failed")
	ErrLocalSystem    = errors.New("network carrier local system failed")
	ErrTimeout        = errors.New("network carrier operation timed out")
)

// Reason identifies a network input that can invalidate an outbound carrier.
// Reasons are intentionally coarse and contain no interface names, addresses,
// hostnames, proxy URLs, or other sensitive network details.
type Reason uint16

const (
	ReasonDefaultRoute Reason = 1 << iota
	ReasonInterfaceAddress
	ReasonDNS
	ReasonProxy
	ReasonPathViability
	ReasonSleepWake
)

const allReasons = ReasonDefaultRoute | ReasonInterfaceAddress | ReasonDNS | ReasonProxy | ReasonPathViability | ReasonSleepWake

// Observation is a privacy-preserving network change notification. Generation
// is monotonic for the host installation and fences stale callbacks.
type Observation struct {
	Generation uint64
	Reasons    Reason
	Viable     bool
	At         time.Time
}

func (o Observation) Validate() error {
	if o.Generation == 0 || o.Reasons == 0 || o.Reasons&^allReasons != 0 {
		return ErrInvalidObservation
	}
	return nil
}

// Identity is the durable logical identity that must survive carrier
// replacement. Session/process and network generations do not belong here.
type Identity struct {
	EnvironmentID string
	MachineID     string
	TunnelID      string
	ConnectorID   string
}

func (i Identity) Validate() error {
	if i.EnvironmentID == "" || i.MachineID == "" || i.TunnelID == "" || i.ConnectorID == "" {
		return ErrInvalidConfiguration
	}
	return nil
}

// ReplacementRequest is immutable input for one staged carrier attempt.
type ReplacementRequest struct {
	Identity                  Identity
	NetworkGeneration         uint64
	PreviousNetworkGeneration uint64
	Reasons                   Reason
	Attempt                   uint32
}

func (r ReplacementRequest) Validate() error {
	if err := r.Identity.Validate(); err != nil || r.NetworkGeneration == 0 || r.Reasons == 0 || r.Reasons&^allReasons != 0 || r.Attempt == 0 {
		return ErrInvalidConfiguration
	}
	return nil
}

// ReplacementResult is returned only after the new carrier has passed
// authenticated readiness. CarrierGeneration is the carrier/config generation
// and is kept separate from NetworkGeneration.
type ReplacementResult struct {
	Identity          Identity
	NetworkGeneration uint64
	CarrierGeneration uint64
	Ready             bool
}

func (r ReplacementResult) Validate() error {
	if err := r.Identity.Validate(); err != nil || r.NetworkGeneration == 0 || r.CarrierGeneration == 0 {
		return ErrInvalidConfiguration
	}
	if !r.Ready {
		return ErrReplacementNotReady
	}
	return nil
}

// CarrierReplacer stages and activates a new carrier. Implementations must
// preserve the old carrier until the returned result is ready and must fence a
// request whose NetworkGeneration is stale.
type CarrierReplacer interface {
	Replace(context.Context, ReplacementRequest) (ReplacementResult, error)
}

// EventSource adapts a platform network monitor to the recovery controller.
// Start returns a bounded stream of privacy-preserving observations. Close is
// idempotent and must not retain callbacks after it returns.
type EventSource interface {
	Start(context.Context) (<-chan Observation, error)
	Close() error
}

// Timer is the small timer surface needed by the controller. It makes debounce,
// retry, and stable-ready tests deterministic with a fake clock.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Clock is injectable so retry scheduling and stability windows can be tested
// without sleeping.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now().UTC() }
func (realClock) NewTimer(d time.Duration) Timer { return realTimer{timer: time.NewTimer(d)} }

type realTimer struct{ timer *time.Timer }

func (t realTimer) C() <-chan time.Time        { return t.timer.C }
func (t realTimer) Stop() bool                 { return t.timer.Stop() }
func (t realTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }

// FailureClass is the stable, secret-free retry/health dimension.
type FailureClass string

const (
	FailureAuthentication FailureClass = "authentication"
	FailureConfiguration  FailureClass = "configuration"
	FailureDNS            FailureClass = "dns"
	FailureOrigin         FailureClass = "origin"
	FailureEdge           FailureClass = "edge"
	FailureLocalSystem    FailureClass = "local_system"
	FailureTimeout        FailureClass = "timeout"
	FailureCanceled       FailureClass = "canceled"
	FailureUnknown        FailureClass = "unknown"
)

// Failure is a typed error with a stable retry decision. Cause is retained for
// errors.Is/errors.As by the caller but is never copied into HealthSnapshot.
type Failure struct {
	Class     FailureClass
	Permanent bool
	Cause     error
}

func (f Failure) Error() string {
	if f.Cause == nil {
		return string(f.Class)
	}
	return fmt.Sprintf("%s failure: %v", f.Class, f.Cause)
}

func (f Failure) Unwrap() error { return f.Cause }

func (f Failure) FailureClass() FailureClass { return f.Class }
func (f Failure) PermanentFailure() bool     { return f.Permanent }

func NewFailure(class FailureClass, permanent bool, cause error) error {
	if class == "" {
		class = FailureUnknown
	}
	return Failure{Class: class, Permanent: permanent, Cause: cause}
}

type failureMarker interface {
	FailureClass() FailureClass
	PermanentFailure() bool
}

// Classify maps transport/platform errors into the bounded retry policy.
func Classify(err error) Failure {
	if err == nil {
		return Failure{}
	}
	var marker failureMarker
	if errors.As(err, &marker) {
		return Failure{Class: marker.FailureClass(), Permanent: marker.PermanentFailure(), Cause: err}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return Failure{Class: FailureCanceled, Permanent: true, Cause: err}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrTimeout):
		return Failure{Class: FailureTimeout, Cause: err}
	case errors.Is(err, ErrAuthentication):
		return Failure{Class: FailureAuthentication, Permanent: true, Cause: err}
	case errors.Is(err, ErrConfiguration):
		return Failure{Class: FailureConfiguration, Permanent: true, Cause: err}
	case errors.Is(err, ErrIdentityChanged):
		return Failure{Class: FailureConfiguration, Permanent: true, Cause: err}
	case errors.Is(err, ErrReplacementNotReady):
		return Failure{Class: FailureLocalSystem, Cause: err}
	case errors.Is(err, ErrDNS):
		return Failure{Class: FailureDNS, Cause: err}
	case errors.Is(err, ErrOrigin):
		return Failure{Class: FailureOrigin, Cause: err}
	case errors.Is(err, ErrEdge):
		return Failure{Class: FailureEdge, Cause: err}
	case errors.Is(err, ErrLocalSystem):
		return Failure{Class: FailureLocalSystem, Cause: err}
	default:
		return Failure{Class: FailureUnknown, Cause: err}
	}
}

// HealthState is the typed network recovery projection.
type HealthState string

const (
	StateUnknown  HealthState = "unknown"
	StateReady    HealthState = "ready"
	StateDegraded HealthState = "degraded"
	StateDown     HealthState = "down"
	StateStopped  HealthState = "stopped"
)

// HealthSnapshot contains only stable codes and scheduling metadata. It never
// exposes the underlying error, endpoint, address, credential, or network
// fingerprint.
type HealthSnapshot struct {
	State                   HealthState  `json:"state"`
	Code                    string       `json:"code"`
	Failure                 FailureClass `json:"failure,omitempty"`
	Reason                  Reason       `json:"reason,omitempty"`
	NetworkGeneration       uint64       `json:"network_generation,omitempty"`
	ActiveNetworkGeneration uint64       `json:"active_network_generation,omitempty"`
	Attempt                 uint32       `json:"attempt,omitempty"`
	NextRetryAt             time.Time    `json:"next_retry_at,omitempty"`
	StableSince             time.Time    `json:"stable_since,omitempty"`
	CheckedAt               time.Time    `json:"checked_at"`
}

// NextRetry reports the exact scheduled retry, if one exists.
func (h HealthSnapshot) NextRetry() (time.Time, bool) {
	if h.NextRetryAt.IsZero() {
		return time.Time{}, false
	}
	return h.NextRetryAt, true
}

type Config struct {
	Identity          Identity
	Replacer          CarrierReplacer
	Source            EventSource
	Clock             Clock
	Debounce          time.Duration
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	StableReadyWindow time.Duration
	Jitter            func(time.Duration) time.Duration
}

const (
	defaultDebounce          = 250 * time.Millisecond
	defaultInitialBackoff    = time.Second
	defaultMaxBackoff        = time.Minute
	defaultStableReadyWindow = 5 * time.Second
)

type Controller struct {
	config Config

	mu                sync.RWMutex
	pending           *Observation
	pendingAt         time.Time
	latestGeneration  uint64
	activeGeneration  uint64
	retryObservation  *Observation
	retryAt           time.Time
	attempt           uint32
	stableSince       time.Time
	health            HealthSnapshot
	wake              chan struct{}
	runCancel         context.CancelFunc
	runDone           chan struct{}
	started           bool
	stopped           bool
	debounceTimer     Timer
	retryTimer        Timer
	stableTimer       Timer
	workMu            sync.Mutex
	attemptCancel     context.CancelFunc
	attemptGeneration uint64
	attemptToken      uint64
}

func New(config Config) (*Controller, error) {
	if err := config.Identity.Validate(); err != nil || config.Replacer == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.Debounce == 0 {
		config.Debounce = defaultDebounce
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = defaultInitialBackoff
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = defaultMaxBackoff
	}
	if config.StableReadyWindow == 0 {
		config.StableReadyWindow = defaultStableReadyWindow
	}
	if config.Debounce < 0 || config.InitialBackoff <= 0 || config.MaxBackoff < config.InitialBackoff || config.StableReadyWindow <= 0 {
		return nil, ErrInvalidConfiguration
	}
	if config.Jitter == nil {
		config.Jitter = func(capacity time.Duration) time.Duration {
			if capacity <= 0 {
				return 0
			}
			return time.Duration(rand.Float64() * float64(capacity))
		}
	}
	c := &Controller{config: config, wake: make(chan struct{}, 1)}
	c.health = HealthSnapshot{State: StateUnknown, Code: "network_waiting", CheckedAt: config.Clock.Now()}
	return c, nil
}

// Observe accepts a network observation. Events from an older generation are
// ignored; events in the same debounce window are merged by generation.
func (c *Controller) Observe(observation Observation) error {
	if c == nil {
		return ErrInvalidConfiguration
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	if observation.At.IsZero() {
		observation.At = c.config.Clock.Now()
	}
	var cancelAttempt context.CancelFunc
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return ErrStopped
	}
	if observation.Generation < c.latestGeneration {
		c.mu.Unlock()
		return nil
	}
	isNewGeneration := observation.Generation > c.latestGeneration
	c.latestGeneration = observation.Generation
	if c.pending == nil || isNewGeneration || c.pending.Generation != observation.Generation {
		copyObservation := observation
		c.pending = &copyObservation
	} else {
		c.pending.Reasons |= observation.Reasons
		c.pending.Viable = observation.Viable
		c.pending.At = observation.At
	}
	c.pendingAt = observation.At
	if isNewGeneration {
		// A new network generation is a new state decision. It is allowed to
		// retry a previously permanent auth/config failure after fresh state.
		c.retryObservation = nil
		c.retryAt = time.Time{}
		c.attempt = 0
		c.stableSince = time.Time{}
		cancelAttempt = c.attemptCancel
	}
	c.health.State = StateDegraded
	c.health.Code = "network_change_pending"
	c.health.Failure = ""
	c.health.Reason = c.pending.Reasons
	c.health.NetworkGeneration = c.latestGeneration
	c.health.NextRetryAt = time.Time{}
	c.health.StableSince = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	c.mu.Unlock()
	if cancelAttempt != nil {
		cancelAttempt()
	}
	c.signal()
	return nil
}

// Flush forces the current debounced observation to be processed. It is useful
// for deterministic callers and is also a safe synchronous recovery primitive
// for a service that has its own event loop.
func (c *Controller) Flush(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	observation, ok := c.takePending(true)
	if !ok {
		observation, ok = c.takeRetry()
		if !ok {
			return ErrNoPendingChange
		}
	}
	return c.replace(ctx, observation)
}

// Tick processes work whose injected clock says it is due. It is primarily
// useful to deterministic service loops and tests; Start performs the same
// work automatically with timers.
func (c *Controller) Tick(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	if observation, ok := c.takePending(false); ok {
		return c.replace(ctx, observation)
	}
	if observation, ok := c.takeRetry(); ok {
		return c.replace(ctx, observation)
	}
	c.resetAfterStable()
	return nil
}

// Start starts the optional source and the controller's debounce/retry loop.
func (c *Controller) Start(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	c.mu.Lock()
	if c.started || c.stopped {
		c.mu.Unlock()
		return ErrInvalidConfiguration
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.started = true
	c.runCancel = cancel
	c.runDone = make(chan struct{})
	c.debounceTimer = c.config.Clock.NewTimer(time.Hour)
	c.retryTimer = c.config.Clock.NewTimer(time.Hour)
	c.stableTimer = c.config.Clock.NewTimer(time.Hour)
	c.debounceTimer.Stop()
	c.retryTimer.Stop()
	c.stableTimer.Stop()
	done := c.runDone
	source := c.config.Source
	c.mu.Unlock()
	if source != nil {
		events, err := source.Start(runCtx)
		if err != nil {
			cancel()
			c.mu.Lock()
			c.started = false
			c.runCancel = nil
			c.runDone = nil
			c.mu.Unlock()
			return err
		}
		go c.consume(runCtx, events)
	}
	go c.loop(runCtx, done)
	return nil
}

func (c *Controller) consume(ctx context.Context, events <-chan Observation) {
	if events == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case observation, ok := <-events:
			if !ok {
				return
			}
			_ = c.Observe(observation)
		}
	}
}

// Stop cancels any in-flight replacement and closes the source. It is safe to
// call multiple times and preserves bounded shutdown under cancellation.
func (c *Controller) Stop(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil
	}
	c.stopped = true
	c.health.State = StateStopped
	c.health.Code = "stopped"
	c.health.NextRetryAt = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	cancel, done, source := c.runCancel, c.runDone, c.config.Source
	c.runCancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var sourceErr error
	if source != nil {
		sourceErr = source.Close()
	}
	if done == nil {
		return sourceErr
	}
	select {
	case <-done:
		return sourceErr
	case <-ctx.Done():
		return errors.Join(sourceErr, ctx.Err())
	}
}

func (c *Controller) Shutdown(ctx context.Context) error { return c.Stop(ctx) }

// Health returns a copy suitable for health endpoints and metrics adapters.
func (c *Controller) Health() HealthSnapshot {
	if c == nil {
		return HealthSnapshot{State: StateDown, Code: "invalid"}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := c.health
	snapshot.CheckedAt = c.config.Clock.Now()
	return snapshot
}

func (c *Controller) Snapshot() HealthSnapshot { return c.Health() }

func (c *Controller) NextRetryAt() (time.Time, bool) { return c.Health().NextRetry() }

func (c *Controller) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Controller) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		c.configureTimers()
		var debounceC, retryC, stableC <-chan time.Time
		c.mu.RLock()
		if c.debounceTimer != nil && c.pending != nil {
			debounceC = c.debounceTimer.C()
		}
		if c.retryTimer != nil && !c.retryAt.IsZero() {
			retryC = c.retryTimer.C()
		}
		if c.stableTimer != nil && !c.stableSince.IsZero() {
			stableC = c.stableTimer.C()
		}
		c.mu.RUnlock()
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
			continue
		case <-debounceC:
			if observation, ok := c.takePending(false); ok {
				_ = c.replace(ctx, observation)
			}
		case <-retryC:
			if observation, ok := c.takeRetry(); ok {
				_ = c.replace(ctx, observation)
			}
		case <-stableC:
			c.resetAfterStable()
		}
	}
}

func (c *Controller) configureTimers() {
	now := c.config.Clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.debounceTimer != nil {
		if c.pending == nil {
			c.debounceTimer.Stop()
		} else {
			c.resetTimer(c.debounceTimer, remaining(c.pendingAt.Add(c.config.Debounce), now))
		}
	}
	if c.retryTimer != nil {
		if c.retryAt.IsZero() {
			c.retryTimer.Stop()
		} else {
			c.resetTimer(c.retryTimer, remaining(c.retryAt, now))
		}
	}
	if c.stableTimer != nil {
		if c.stableSince.IsZero() {
			c.stableTimer.Stop()
		} else {
			c.resetTimer(c.stableTimer, remaining(c.stableSince.Add(c.config.StableReadyWindow), now))
		}
	}
}

func (c *Controller) resetTimer(timer Timer, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	if !timer.Stop() {
		select {
		case <-timer.C():
		default:
		}
	}
	timer.Reset(delay)
}

func remaining(deadline, now time.Time) time.Duration {
	if !deadline.After(now) {
		return 0
	}
	return deadline.Sub(now)
}

func (c *Controller) takePending(force bool) (Observation, bool) {
	now := c.config.Clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil || (!force && now.Before(c.pendingAt.Add(c.config.Debounce))) {
		return Observation{}, false
	}
	observation := *c.pending
	c.pending = nil
	c.pendingAt = time.Time{}
	return observation, true
}

func (c *Controller) takeRetry() (Observation, bool) {
	now := c.config.Clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retryObservation == nil || c.retryAt.IsZero() || now.Before(c.retryAt) || c.retryObservation.Generation != c.latestGeneration {
		return Observation{}, false
	}
	observation := *c.retryObservation
	c.retryObservation = nil
	c.retryAt = time.Time{}
	return observation, true
}

func (c *Controller) replace(ctx context.Context, observation Observation) error {
	c.workMu.Lock()
	defer c.workMu.Unlock()
	if err := observation.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return ErrStopped
	}
	if observation.Generation < c.latestGeneration {
		c.mu.Unlock()
		return nil
	}
	attempt := c.attempt + 1
	previous := c.activeGeneration
	identity := c.config.Identity
	c.health.State = StateDegraded
	c.health.Code = "carrier_replacing"
	c.health.Failure = ""
	c.health.Attempt = attempt
	c.health.Reason = observation.Reasons
	c.health.NetworkGeneration = observation.Generation
	c.health.NextRetryAt = time.Time{}
	c.health.StableSince = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	c.mu.Unlock()

	request := ReplacementRequest{Identity: identity, NetworkGeneration: observation.Generation, PreviousNetworkGeneration: previous, Reasons: observation.Reasons, Attempt: attempt}
	if err := request.Validate(); err != nil {
		return c.fail(observation, err)
	}
	if observation.Reasons&ReasonPathViability != 0 && !observation.Viable {
		c.markUnavailable(observation)
		return nil
	}
	attemptCtx, cancelAttempt := context.WithCancel(ctx)
	c.mu.Lock()
	if observation.Generation < c.latestGeneration || c.stopped {
		c.mu.Unlock()
		cancelAttempt()
		return nil
	}
	c.attemptCancel = cancelAttempt
	c.attemptGeneration = observation.Generation
	c.attemptToken++
	attemptToken := c.attemptToken
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.attemptGeneration == observation.Generation && c.attemptToken == attemptToken {
			c.attemptCancel = nil
			c.attemptGeneration = 0
		}
		c.mu.Unlock()
		cancelAttempt()
	}()
	result, err := c.config.Replacer.Replace(attemptCtx, request)
	if err == nil {
		if resultErr := result.Validate(); resultErr != nil {
			err = resultErr
		} else if result.Identity != identity {
			err = ErrIdentityChanged
		} else if result.NetworkGeneration != observation.Generation {
			err = fmt.Errorf("%w: network generation %d", ErrInvalidObservation, result.NetworkGeneration)
		}
	}
	if err != nil {
		return c.fail(observation, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return ErrStopped
	}
	// A newer event may have arrived while the carrier was being staged. Never
	// let an older completion replace the newer network state.
	if observation.Generation < c.latestGeneration {
		return nil
	}
	c.activeGeneration = result.NetworkGeneration
	c.retryObservation = nil
	c.retryAt = time.Time{}
	c.stableSince = c.config.Clock.Now()
	c.health.State = StateReady
	c.health.Code = "carrier_ready"
	c.health.Failure = ""
	c.health.NetworkGeneration = c.latestGeneration
	c.health.ActiveNetworkGeneration = c.activeGeneration
	c.health.StableSince = c.stableSince
	c.health.NextRetryAt = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	c.signal()
	return nil
}

func (c *Controller) markUnavailable(observation Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || observation.Generation < c.latestGeneration {
		return
	}
	c.retryObservation = nil
	c.retryAt = time.Time{}
	c.stableSince = time.Time{}
	c.health.State = StateDown
	c.health.Code = "network_unavailable"
	c.health.Failure = ""
	c.health.Reason = observation.Reasons
	c.health.NetworkGeneration = observation.Generation
	c.health.ActiveNetworkGeneration = c.activeGeneration
	c.health.NextRetryAt = time.Time{}
	c.health.StableSince = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
}

func (c *Controller) fail(observation Observation, err error) error {
	failure := Classify(err)
	if failure.Class == FailureCanceled && errors.Is(err, context.Canceled) {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return ErrStopped
	}
	if observation.Generation < c.latestGeneration {
		return err
	}
	c.attempt++
	c.health.Failure = failure.Class
	c.health.Reason = observation.Reasons
	c.health.NetworkGeneration = c.latestGeneration
	c.health.ActiveNetworkGeneration = c.activeGeneration
	c.health.Attempt = c.attempt
	c.health.StableSince = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	if failure.Permanent {
		c.retryObservation = nil
		c.retryAt = time.Time{}
		c.health.State = StateDown
		c.health.Code = failureCode(failure.Class)
		c.health.NextRetryAt = time.Time{}
		return err
	}
	delay := c.backoff(c.attempt)
	if delay < 0 {
		delay = 0
	}
	c.retryAt = c.config.Clock.Now().Add(delay)
	copyObservation := observation
	c.retryObservation = &copyObservation
	c.health.State = StateDegraded
	c.health.Code = "carrier_retry_scheduled"
	c.health.NextRetryAt = c.retryAt
	c.signal()
	return err
}

func (c *Controller) backoff(attempt uint32) time.Duration {
	capDelay := c.config.InitialBackoff
	for i := uint32(1); i < attempt && capDelay < c.config.MaxBackoff; i++ {
		if capDelay > c.config.MaxBackoff/2 {
			capDelay = c.config.MaxBackoff
			break
		}
		capDelay *= 2
	}
	if capDelay > c.config.MaxBackoff {
		capDelay = c.config.MaxBackoff
	}
	delay := c.config.Jitter(capDelay)
	if delay < 0 {
		return 0
	}
	if delay > capDelay {
		return capDelay
	}
	return delay
}

func (c *Controller) resetAfterStable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stableSince.IsZero() || c.config.Clock.Now().Before(c.stableSince.Add(c.config.StableReadyWindow)) || c.activeGeneration == 0 || c.activeGeneration != c.latestGeneration {
		return
	}
	c.attempt = 0
	c.retryObservation = nil
	c.retryAt = time.Time{}
	c.health.State = StateReady
	c.health.Code = "carrier_stable"
	c.health.Failure = ""
	c.health.Attempt = 0
	c.health.NextRetryAt = time.Time{}
	c.health.CheckedAt = c.config.Clock.Now()
	c.stableSince = time.Time{}
	c.health.StableSince = time.Time{}
}

func failureCode(class FailureClass) string {
	switch class {
	case FailureAuthentication:
		return "carrier_authentication_failed"
	case FailureConfiguration:
		return "carrier_configuration_failed"
	case FailureDNS:
		return "carrier_dns_failed"
	case FailureOrigin:
		return "carrier_origin_failed"
	case FailureEdge:
		return "carrier_edge_failed"
	case FailureTimeout:
		return "carrier_timeout"
	case FailureLocalSystem:
		return "carrier_local_system_failed"
	case FailureCanceled:
		return "carrier_canceled"
	default:
		return "carrier_failed"
	}
}
