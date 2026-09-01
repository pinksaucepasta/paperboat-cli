package networkrecovery

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*fakeTimer]struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC), timers: make(map[*fakeTimer]struct{})}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(delay time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &fakeTimer{clock: c, ch: make(chan time.Time, 1)}
	c.timers[timer] = struct{}{}
	timer.active = true
	timer.deadline = c.now.Add(delay)
	return timer
}

func (c *fakeClock) Advance(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	for timer := range c.timers {
		if !timer.active || timer.deadline.After(c.now) {
			continue
		}
		timer.active = false
		select {
		case timer.ch <- c.now:
		default:
		}
	}
	c.mu.Unlock()
}

type fakeTimer struct {
	clock    *fakeClock
	ch       chan time.Time
	active   bool
	deadline time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := t.active
	t.active = false
	select {
	case <-t.ch:
	default:
	}
	return wasActive
}

func (t *fakeTimer) Reset(delay time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := t.active
	select {
	case <-t.ch:
	default:
	}
	t.active = true
	t.deadline = t.clock.now.Add(delay)
	return wasActive
}

type scriptedReplacer struct {
	mu       sync.Mutex
	requests []ReplacementRequest
	results  []error
	ready    map[uint64]ReplacementResult
	calls    chan ReplacementRequest
	block    chan struct{}
	canceled chan struct{}
}

func (r *scriptedReplacer) Replace(ctx context.Context, request ReplacementRequest) (ReplacementResult, error) {
	r.mu.Lock()
	r.requests = append(r.requests, request)
	if r.calls != nil {
		select {
		case r.calls <- request:
		default:
		}
	}
	var err error
	if len(r.results) > 0 {
		err, r.results = r.results[0], r.results[1:]
	}
	block := r.block
	result := r.ready[request.NetworkGeneration]
	r.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			if r.canceled != nil {
				close(r.canceled)
			}
			return ReplacementResult{}, ctx.Err()
		}
	}
	if err != nil {
		return ReplacementResult{}, err
	}
	return result, nil
}

func identity() Identity {
	return Identity{EnvironmentID: "env_01", MachineID: "machine_01", TunnelID: "tunnel_01", ConnectorID: "connector_01"}
}

func readyResult(i Identity, network, carrier uint64) ReplacementResult {
	return ReplacementResult{Identity: i, NetworkGeneration: network, CarrierGeneration: carrier, Ready: true}
}

func newControllerForTest(t *testing.T, clock *fakeClock, replacer CarrierReplacer) *Controller {
	t.Helper()
	controller, err := New(Config{
		Identity: identity(), Replacer: replacer, Clock: clock, Debounce: 100 * time.Millisecond,
		InitialBackoff: 200 * time.Millisecond, MaxBackoff: 800 * time.Millisecond,
		StableReadyWindow: 500 * time.Millisecond, Jitter: func(capacity time.Duration) time.Duration { return capacity / 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func observe(t *testing.T, controller *Controller, generation uint64, reasons Reason, viable bool) {
	t.Helper()
	if err := controller.Observe(Observation{Generation: generation, Reasons: reasons, Viable: viable}); err != nil {
		t.Fatal(err)
	}
}

func TestControllerDebouncesMergesAndPreservesIdentity(t *testing.T) {
	clock := newFakeClock()
	replacer := &scriptedReplacer{ready: map[uint64]ReplacementResult{1: readyResult(identity(), 1, 11), 2: readyResult(identity(), 2, 12)}}
	controller := newControllerForTest(t, clock, replacer)
	observe(t, controller, 1, ReasonDefaultRoute, true)
	observe(t, controller, 1, ReasonProxy, true)
	if err := controller.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacer.mu.Lock()
	if len(replacer.requests) != 1 {
		t.Fatalf("requests=%d", len(replacer.requests))
	}
	first := replacer.requests[0]
	replacer.mu.Unlock()
	if first.NetworkGeneration != 1 || first.PreviousNetworkGeneration != 0 || first.Reasons != ReasonDefaultRoute|ReasonProxy || first.Identity != identity() {
		t.Fatalf("request=%+v", first)
	}
	if got := controller.Health(); got.State != StateReady || got.ActiveNetworkGeneration != 1 || got.StableSince.IsZero() {
		t.Fatalf("health=%+v", got)
	}

	clock.Advance(500 * time.Millisecond)
	if err := controller.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := controller.Health(); got.Code != "carrier_stable" || got.Attempt != 0 {
		t.Fatalf("stable health=%+v", got)
	}

	observe(t, controller, 2, ReasonSleepWake, true)
	clock.Advance(100 * time.Millisecond)
	if err := controller.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacer.mu.Lock()
	second := replacer.requests[1]
	replacer.mu.Unlock()
	if second.NetworkGeneration != 2 || second.PreviousNetworkGeneration != 1 || second.Identity != identity() {
		t.Fatalf("replacement request=%+v", second)
	}
	if got := controller.Health(); got.ActiveNetworkGeneration != 2 || got.State != StateReady {
		t.Fatalf("replacement health=%+v", got)
	}

	// A stale callback cannot regress the active LKG generation.
	if err := controller.Observe(Observation{Generation: 1, Reasons: ReasonDNS}); err != nil {
		t.Fatal(err)
	}
	if got := controller.Health(); got.ActiveNetworkGeneration != 2 {
		t.Fatalf("stale callback changed health=%+v", got)
	}
}

func TestControllerClassifiesRetriesAndPublishesExactNextRetry(t *testing.T) {
	clock := newFakeClock()
	replacer := &scriptedReplacer{results: []error{ErrDNS}, ready: map[uint64]ReplacementResult{1: readyResult(identity(), 1, 21)}}
	controller := newControllerForTest(t, clock, replacer)
	observe(t, controller, 1, ReasonDefaultRoute, true)
	if err := controller.Flush(context.Background()); !errors.Is(err, ErrDNS) {
		t.Fatalf("flush err=%v", err)
	}
	if got := controller.Health(); got.State != StateDegraded || got.Failure != FailureDNS || got.Code != "carrier_retry_scheduled" {
		t.Fatalf("retry health=%+v", got)
	} else if want := clock.Now().Add(100 * time.Millisecond); !got.NextRetryAt.Equal(want) {
		t.Fatalf("next retry=%s want=%s", got.NextRetryAt, want)
	}
	if got := controller.Health(); got.ActiveNetworkGeneration != 0 {
		t.Fatalf("failed replacement lost LKG=%+v", got)
	}
	clock.Advance(100 * time.Millisecond)
	if err := controller.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := controller.Health(); got.State != StateReady || got.ActiveNetworkGeneration != 1 {
		t.Fatalf("retry result health=%+v", got)
	}

	replacer.mu.Lock()
	replacer.results = []error{ErrAuthentication}
	replacer.mu.Unlock()
	observe(t, controller, 3, ReasonProxy, true)
	if err := controller.Flush(context.Background()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("auth flush err=%v", err)
	}
	if got := controller.Health(); got.State != StateDown || got.Failure != FailureAuthentication || !got.NextRetryAt.IsZero() {
		t.Fatalf("permanent failure health=%+v", got)
	}
	// A new generation explicitly reopens a permanent failure decision.
	replacer.mu.Lock()
	replacer.ready[4] = readyResult(identity(), 4, 24)
	replacer.mu.Unlock()
	observe(t, controller, 4, ReasonInterfaceAddress, true)
	if err := controller.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := controller.Health(); got.State != StateReady || got.ActiveNetworkGeneration != 4 {
		t.Fatalf("new generation health=%+v", got)
	}
}

func TestControllerRejectsUnreadyOrChangedCarrierAndNeverLeaksCause(t *testing.T) {
	clock := newFakeClock()
	replacer := &scriptedReplacer{results: []error{nil}, ready: map[uint64]ReplacementResult{1: {Identity: identity(), NetworkGeneration: 1, CarrierGeneration: 1, Ready: false}}}
	controller := newControllerForTest(t, clock, replacer)
	observe(t, controller, 1, ReasonPathViability, true)
	if err := controller.Flush(context.Background()); !errors.Is(err, ErrReplacementNotReady) {
		t.Fatalf("flush err=%v", err)
	}
	if got := controller.Health(); got.Failure != FailureLocalSystem || got.State != StateDegraded || got.NextRetryAt.IsZero() {
		t.Fatalf("unready health=%+v", got)
	}

	replacer.mu.Lock()
	replacer.results = []error{nil}
	replacer.ready[2] = readyResult(Identity{EnvironmentID: "env_01", MachineID: "machine_01", TunnelID: "other", ConnectorID: "connector_01"}, 2, 2)
	replacer.mu.Unlock()
	clock.Advance(100 * time.Millisecond)
	observe(t, controller, 2, ReasonDNS, true)
	if err := controller.Flush(context.Background()); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("identity err=%v", err)
	}
	if got := controller.Health(); got.Failure != FailureConfiguration || got.State != StateDown {
		t.Fatalf("identity health=%+v", got)
	}

	// A non-viable path is surfaced as unavailable after debounce and does not
	// start a retry loop that would only amplify a known outage.
	clock.Advance(100 * time.Millisecond)
	observe(t, controller, 3, ReasonPathViability, false)
	if err := controller.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := controller.Health(); got.State != StateDown || got.Code != "network_unavailable" || !got.NextRetryAt.IsZero() {
		t.Fatalf("unavailable health=%+v", got)
	}

	encoded, err := json.Marshal(controller.Health())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "other") {
		t.Fatalf("health leaked replacement details: %s", encoded)
	}
}

type fakeSource struct {
	mu       sync.Mutex
	events   chan Observation
	closed   chan struct{}
	closeErr error
}

func (s *fakeSource) Start(context.Context) (<-chan Observation, error) { return s.events, nil }
func (s *fakeSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return s.closeErr
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition did not become true")
	}
}

func waitForDebounceTimer(t *testing.T, controller *Controller) {
	t.Helper()
	waitFor(t, func() bool {
		controller.mu.RLock()
		pending := controller.pending != nil
		timer := controller.debounceTimer
		debounce := controller.config.Debounce
		controller.mu.RUnlock()
		if !pending || timer == nil {
			return false
		}
		fake, ok := timer.(*fakeTimer)
		if !ok {
			return true
		}
		fake.clock.mu.Lock()
		defer fake.clock.mu.Unlock()
		return fake.active && fake.deadline.Equal(fake.clock.now.Add(debounce))
	})
}

func TestControllerSourceDebounceAndCancellation(t *testing.T) {
	clock := newFakeClock()
	source := &fakeSource{events: make(chan Observation, 8), closed: make(chan struct{})}
	block := make(chan struct{})
	canceled := make(chan struct{})
	replacer := &scriptedReplacer{ready: map[uint64]ReplacementResult{1: readyResult(identity(), 1, 1)}, calls: make(chan ReplacementRequest, 2), block: block, canceled: canceled}
	controller, err := New(Config{Identity: identity(), Replacer: replacer, Source: source, Clock: clock, Debounce: 100 * time.Millisecond, InitialBackoff: time.Second, MaxBackoff: 2 * time.Second, StableReadyWindow: time.Second, Jitter: func(d time.Duration) time.Duration { return d }})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(context.Background()) })
	source.events <- Observation{Generation: 1, Reasons: ReasonDefaultRoute, Viable: true}
	source.events <- Observation{Generation: 1, Reasons: ReasonDNS, Viable: true}
	waitFor(t, func() bool {
		health := controller.Health()
		return health.Code == "network_change_pending" && health.Reason == ReasonDefaultRoute|ReasonDNS
	})
	// The source consumer and controller loop are separate goroutines. Wait
	// until the loop has armed the fake timer before advancing the fake clock;
	// otherwise the advance can be consumed before timer setup and leave this
	// test waiting on a deadline that has already passed.
	waitForDebounceTimer(t, controller)
	clock.Advance(100 * time.Millisecond)
	select {
	case request := <-replacer.calls:
		if request.Reasons != ReasonDefaultRoute|ReasonDNS {
			t.Fatalf("merged request=%+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("debounced replacement did not start")
	}
	if err := controller.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("in-flight replacement was not canceled")
	}
	select {
	case <-source.closed:
	default:
		t.Fatal("source was not closed")
	}
}

type generationFenceReplacer struct {
	started  chan ReplacementRequest
	mu       sync.Mutex
	active   []uint64
	finished chan struct{}
}

func (r *generationFenceReplacer) Replace(ctx context.Context, request ReplacementRequest) (ReplacementResult, error) {
	select {
	case r.started <- request:
	case <-ctx.Done():
		return ReplacementResult{}, ctx.Err()
	}
	if request.NetworkGeneration == 1 {
		select {
		case <-ctx.Done():
			close(r.finished)
			return ReplacementResult{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	select {
	case <-ctx.Done():
		return ReplacementResult{}, ctx.Err()
	default:
	}
	r.mu.Lock()
	r.active = append(r.active, request.NetworkGeneration)
	r.mu.Unlock()
	return readyResult(identity(), request.NetworkGeneration, request.NetworkGeneration), nil
}

func TestControllerCancelsStaleReplacementBeforeActivation(t *testing.T) {
	clock := newFakeClock()
	replacer := &generationFenceReplacer{started: make(chan ReplacementRequest, 2), finished: make(chan struct{})}
	controller := newControllerForTest(t, clock, replacer)
	observe(t, controller, 1, ReasonDefaultRoute, true)
	firstDone := make(chan error, 1)
	go func() { firstDone <- controller.Flush(context.Background()) }()
	first := <-replacer.started
	if first.NetworkGeneration != 1 {
		t.Fatalf("first request=%+v", first)
	}
	if err := controller.Observe(Observation{Generation: 2, Reasons: ReasonSleepWake, Viable: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replacer.finished:
	case <-time.After(time.Second):
		t.Fatal("stale replacement was not canceled")
	}
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("stale replacement err=%v", err)
	}
	replacer.mu.Lock()
	activated := append([]uint64(nil), replacer.active...)
	replacer.mu.Unlock()
	for _, generation := range activated {
		if generation == 1 {
			t.Fatalf("stale generation activated: %v", activated)
		}
	}
	if err := controller.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacer.mu.Lock()
	activated = append([]uint64(nil), replacer.active...)
	replacer.mu.Unlock()
	if len(activated) != 1 || activated[0] != 2 {
		t.Fatalf("activated=%v", activated)
	}
}

func TestControllerReturnsEventSourceCloseError(t *testing.T) {
	closeErr := errors.New("source close failed")
	source := &fakeSource{events: make(chan Observation), closed: make(chan struct{}), closeErr: closeErr}
	controller, err := New(Config{Identity: identity(), Replacer: &scriptedReplacer{}, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Stop(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("stop err=%v", err)
	}
}

func TestFailureClassificationIsTypedAndBounded(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		class     FailureClass
		permanent bool
	}{
		{"auth", ErrAuthentication, FailureAuthentication, true},
		{"config", ErrConfiguration, FailureConfiguration, true},
		{"dns", ErrDNS, FailureDNS, false},
		{"timeout", context.DeadlineExceeded, FailureTimeout, false},
		{"cancel", context.Canceled, FailureCanceled, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Classify(test.err)
			if got.Class != test.class || got.Permanent != test.permanent || !errors.Is(got, test.err) {
				t.Fatalf("failure=%+v", got)
			}
		})
	}
	clock := newFakeClock()
	replacer := &scriptedReplacer{results: []error{ErrDNS, ErrDNS, ErrDNS}, ready: map[uint64]ReplacementResult{}}
	controller := newControllerForTest(t, clock, replacer)
	observe(t, controller, 1, ReasonDefaultRoute, true)
	if err := controller.Flush(context.Background()); err == nil {
		t.Fatal("expected first failure")
	}
	if got := controller.Health().NextRetryAt; !got.Equal(clock.Now().Add(100 * time.Millisecond)) {
		t.Fatalf("retry=%s", got)
	}
	clock.Advance(100 * time.Millisecond)
	if err := controller.Tick(context.Background()); err == nil {
		t.Fatal("expected second failure")
	}
	if got := controller.Health().NextRetryAt; !got.Equal(clock.Now().Add(200 * time.Millisecond)) {
		t.Fatalf("capped exponential retry=%s", got)
	}
	clock.Advance(200 * time.Millisecond)
	if err := controller.Tick(context.Background()); err == nil {
		t.Fatal("expected third failure")
	}
	if got := controller.Health().NextRetryAt; !got.Equal(clock.Now().Add(400 * time.Millisecond)) {
		t.Fatalf("third retry=%s", got)
	}
}
