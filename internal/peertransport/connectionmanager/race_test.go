package connectionmanager

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

type connectResult struct {
	connection Connection
	err        error
}

type fakeConnector struct {
	started chan Attempt
	results map[Path]chan connectResult
}

type oneShotConnector struct {
	started  chan Attempt
	release  chan struct{}
	canceled chan Path
	direct   Connection
}

func (c *oneShotConnector) Connect(ctx context.Context, attempt Attempt) (Connection, error) {
	c.started <- attempt
	select {
	case <-c.release:
	case <-ctx.Done():
		c.canceled <- attempt.Path
		return nil, ctx.Err()
	}
	if attempt.Path == PathDirectQUIC {
		return c.direct, nil
	}
	<-ctx.Done()
	c.canceled <- attempt.Path
	return nil, ctx.Err()
}

func newFakeConnector() *fakeConnector {
	return &fakeConnector{started: make(chan Attempt, 10), results: map[Path]chan connectResult{PathDirectQUIC: make(chan connectResult, 1), PathRelayQUIC: make(chan connectResult, 1), PathWSS: make(chan connectResult, 1)}}
}

func (f *fakeConnector) Connect(ctx context.Context, attempt Attempt) (Connection, error) {
	f.started <- attempt
	select {
	case result := <-f.results[attempt.Path]:
		return result.connection, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type fakeConnection struct {
	mu     sync.Mutex
	closed int
	state  State
}

type relayMetadataConnection struct {
	*fakeConnection
	region string
}

func (c *relayMetadataConnection) RelayRegion() string { return c.region }

type initialHealthConnection struct {
	mu       sync.Mutex
	state    State
	closed   int
	nonce    [16]byte
	admitErr error
}

func (c *initialHealthConnection) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *initialHealthConnection) Close() error {
	c.mu.Lock()
	c.closed++
	c.state = StateFailed
	c.mu.Unlock()
	return nil
}

func (c *initialHealthConnection) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *initialHealthConnection) ActiveHealthCapability() (ActiveHealthCapability, error) {
	return ActiveHealthCapability{Path: PathDirectQUIC, Transport: selectedHealthTransport{}}, nil
}

func (c *initialHealthConnection) AdmitInitialHealth(_ context.Context, nonce [16]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonce = nonce
	if c.admitErr != nil {
		return c.admitErr
	}
	c.state = StateTrusted
	return nil
}

func (c *fakeConnection) State() State {
	if c.state == 0 {
		return StateTrusted
	}
	return c.state
}

func (c *fakeConnection) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *fakeConnection) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func testRacer(t *testing.T, connector Connector) *Racer {
	t.Helper()
	racer, err := NewRacer(Config{RelayDelay: time.Second, WSSDelay: 2 * time.Second, ConnectTimeout: 5 * time.Second}, connector)
	if err != nil {
		t.Fatal(err)
	}
	racer.after = func(context.Context, time.Duration) <-chan struct{} {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	racer.after = func(ctx context.Context, delay time.Duration) <-chan struct{} {
		result := make(chan struct{})
		if delay == 0 {
			close(result)
		}
		return result
	}
	return racer
}

func TestRaceStartsDirectAndCancelsDelayedFallbacks(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 7, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection, err}
	}()
	attempt := receiveAttempt(t, connector.started)
	if attempt.Generation != 7 {
		t.Fatalf("attempt=%+v", attempt)
	}
	connection := &fakeConnection{}
	connector.results[PathDirectQUIC] <- connectResult{connection: connection}
	result := <-done
	if result.err != nil || result.selection.Path != PathDirectQUIC || result.selection.Connection != connection || connection.closeCount() != 0 {
		t.Fatalf("selection=%+v err=%v closes=%d", result.selection, result.err, connection.closeCount())
	}
}

func TestDiagnosticModesContainExactlyOneRequestedPath(t *testing.T) {
	racer := testRacer(t, newFakeConnector())
	for _, test := range []struct {
		mode Mode
		path Path
	}{{ModeDirectQUIC, PathDirectQUIC}, {ModeRelayQUIC, PathRelayQUIC}, {ModeWSS, PathWSS}} {
		candidates, err := racer.candidates(test.mode, NetworkUnknown)
		if err != nil || len(candidates) != 1 || candidates[0].path != test.path || candidates[0].delay != 0 {
			t.Fatalf("mode=%d candidates=%#v err=%v", test.mode, candidates, err)
		}
	}
}

func TestRelayRaceStartsQUICAndWSSWithoutDirect(t *testing.T) {
	racer := testRacer(t, newFakeConnector())
	candidates, err := racer.candidates(ModeRelayRace, NetworkUnknown)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	if candidates[0].path != PathRelayQUIC || candidates[1].path != PathWSS || candidates[0].delay != 0 || candidates[1].delay != 0 {
		t.Fatalf("relay candidates=%#v", candidates)
	}
}

func TestRecoveryRaceExcludesFailedPathAndStartsNextImmediately(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.connectExcluding(context.Background(), 8, ModeAuto, NetworkUnknown, PathDirectQUIC)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	seen := make(map[Path]bool, 2)
	for range 2 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("attempts=%v", seen)
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	result := <-done
	if result.err != nil || result.selection.Path != PathRelayQUIC || result.selection.Connection != relay {
		t.Fatalf("selection=%+v error=%v", result.selection, result.err)
	}
}

func TestRecoveryRaceFailsWhenNoPathRemains(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	if _, err := racer.connectExcluding(context.Background(), 1, ModeWSS, NetworkUDPBlocked, PathWSS); err == nil {
		t.Fatal("recovery accepted an empty candidate set")
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("unexpected attempt=%+v", attempt)
	default:
	}
}

func TestRaceAdmitsReadyConnectionBeforeSelection(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 9, ModeQUIC, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &initialHealthConnection{state: StateReady}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	result := <-done
	connection.mu.Lock()
	nonce, closes, state := connection.nonce, connection.closed, connection.state
	connection.mu.Unlock()
	if result.err != nil || result.selection.Connection != connection || nonce == [16]byte{} || closes != 0 || state != StateTrusted {
		t.Fatalf("selection=%+v error=%v nonce=%x closes=%d state=%d", result.selection, result.err, nonce, closes, state)
	}
}

func TestRaceInitialHealthProtocolFailureStopsFallback(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan error, 1)
	go func() {
		_, err := racer.Connect(context.Background(), 2, ModeAuto, NetworkUnknown)
		done <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &initialHealthConnection{state: StateReady, admitErr: &Failure{Class: FailureProtocol, Cause: errors.New("health nonce authentication failed")}}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureProtocol || failure.Path != attempt.Path {
		t.Fatalf("error=%v", err)
	}
	if connection.closed != 1 {
		t.Fatalf("closes=%d", connection.closed)
	}
}

func TestRaceInitialHealthTransportClosePromotesReadyRelay(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 2, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	directAttempt := receiveAttemptPath(t, connector.started, PathDirectQUIC)
	direct := &initialHealthConnection{state: StateReady, admitErr: errors.New("remote application close")}
	connector.results[directAttempt.Path] <- connectResult{connection: direct}
	for direct.closeCount() == 0 {
		runtime.Gosched()
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	result := <-done
	if result.err != nil || result.selection.Path != PathRelayQUIC || result.selection.Connection != relay || direct.closed != 1 {
		t.Fatalf("selection=%+v err=%v direct_closes=%d", result.selection, result.err, direct.closed)
	}
}

func TestRaceInitialHealthTypedReachabilityFailureAllowsFallback(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 2, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	directAttempt := receiveAttemptPath(t, connector.started, PathDirectQUIC)
	direct := &initialHealthConnection{state: StateReady, admitErr: &Failure{Class: FailureReachability, Path: PathDirectQUIC, Cause: errors.New("selected path unreachable")}}
	connector.results[directAttempt.Path] <- connectResult{connection: direct}
	for direct.closeCount() == 0 {
		runtime.Gosched()
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	result := <-done
	if result.err != nil || result.selection.Path != PathRelayQUIC || result.selection.Connection != relay || direct.closed != 1 {
		t.Fatalf("selection=%+v error=%v direct closes=%d", result.selection, result.err, direct.closed)
	}
}

func TestOneShotRacePreventsConcurrentHealthAdmissions(t *testing.T) {
	direct := &fakeConnection{}
	connector := &oneShotConnector{started: make(chan Attempt, 3), release: make(chan struct{}), canceled: make(chan Path, 2), direct: direct}
	racer := testRacer(t, connector)
	racer.config.OneShot = true
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 2, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	started := map[Path]bool{}
	for range 3 {
		started[receiveAttempt(t, connector.started).Path] = true
	}
	if !started[PathDirectQUIC] || !started[PathRelayQUIC] || !started[PathWSS] {
		t.Fatalf("started=%v", started)
	}
	close(connector.release)
	result := <-done
	if result.err != nil || result.selection.Path != PathDirectQUIC || result.selection.Connection != direct {
		t.Fatalf("selection=%+v err=%v", result.selection, result.err)
	}
	canceled := map[Path]bool{}
	for range 2 {
		select {
		case path := <-connector.canceled:
			canceled[path] = true
		case <-time.After(time.Second):
			t.Fatal("one-shot race left a loser health admission running")
		}
	}
	if !canceled[PathRelayQUIC] || !canceled[PathWSS] {
		t.Fatalf("canceled=%v", canceled)
	}
}

func TestSequentialFallbackDefersDescriptorAdmissionUntilPriorFailure(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	racer.config.SequentialFallback = true
	racer.config.OneShot = true
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 9, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathDirectQUIC {
		t.Fatalf("first attempt=%+v", attempt)
	}
	connector.results[PathDirectQUIC] <- connectResult{err: &Failure{Class: FailureReachability, Path: PathDirectQUIC, Cause: errors.New("direct attempt fenced")}}
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathRelayQUIC {
		t.Fatalf("second attempt=%+v", attempt)
	}
	connector.results[PathRelayQUIC] <- connectResult{err: &Failure{Class: FailureTransient, Path: PathRelayQUIC, Cause: errors.New("relay attempt fenced")}}
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathWSS {
		t.Fatalf("third attempt=%+v", attempt)
	}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	result := <-done
	if result.err != nil || result.selection.Path != PathWSS || result.selection.Connection != wss {
		t.Fatalf("selection=%+v err=%v", result.selection, result.err)
	}
}

func TestSequentialFallbackTimesOutDirectAndPromotesRelayWithinOverallDeadline(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	racer.config.SequentialFallback = true
	racer.config.OneShot = true
	racer.config.RelayDelay = 50 * time.Millisecond
	// Production uses equal relay and WSS delays. Relay must retain its full
	// per-candidate budget rather than receiving a zero-duration difference.
	racer.config.WSSDelay = racer.config.RelayDelay
	racer.config.ConnectTimeout = time.Second
	started := time.Now()
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 10, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathDirectQUIC {
		t.Fatalf("first attempt=%+v", attempt)
	}
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathRelayQUIC {
		t.Fatalf("relay did not start after direct preference budget: %+v", attempt)
	}
	// Let a viable relay use part of its budget. A zero-duration relay context
	// would advance to WSS before this result can be delivered.
	time.Sleep(10 * time.Millisecond)
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	result := <-done
	if result.err != nil || result.selection.Path != PathRelayQUIC || result.selection.Connection != relay {
		t.Fatalf("selection=%+v err=%v", result.selection, result.err)
	}
	if elapsed := time.Since(started); elapsed >= racer.config.ConnectTimeout {
		t.Fatalf("sequential fallback exhausted overall deadline: elapsed=%s", elapsed)
	}
}

func TestRelayFirstSequentialFallbackAvoidsDirectBeforeReachableRelay(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	racer.config.SequentialFallback = true
	racer.config.RelayFirst = true
	racer.config.OneShot = true
	done := make(chan struct {
		selection Selection
		err       error
	}, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 11, ModeAuto, NetworkUnknown)
		done <- struct {
			selection Selection
			err       error
		}{selection: selection, err: err}
	}()
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathRelayQUIC {
		t.Fatalf("first attempt=%+v", attempt)
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	result := <-done
	if result.err != nil || result.selection.Path != PathRelayQUIC || result.selection.Connection != relay {
		t.Fatalf("selection=%+v err=%v", result.selection, result.err)
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("reachable relay incorrectly started another path: %+v", attempt)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSynchronousReachabilityFailureStartsNextPathImmediately(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	errs := make(chan error, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 1, ModeAuto, NetworkUnknown)
		done <- selection
		errs <- err
	}()
	receiveAttemptPath(t, connector.started, PathDirectQUIC)
	connector.results[PathDirectQUIC] <- connectResult{err: &Failure{Class: FailureReachability, Cause: errors.New("unreachable")}}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	selection := <-done
	if err := <-errs; err != nil || selection.Path != PathRelayQUIC {
		t.Fatalf("selection=%+v err=%v", selection, err)
	}
}

func TestSynchronousNATFailureStartsRelayImmediately(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	errs := make(chan error, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 11, ModeAuto, NetworkUnknown)
		done <- selection
		errs <- err
	}()
	receiveAttemptPath(t, connector.started, PathDirectQUIC)
	connector.results[PathDirectQUIC] <- connectResult{err: &Failure{Class: FailureNAT, Path: PathDirectQUIC, Cause: errors.New("ICE checklist exhausted")}}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	selection := <-done
	if err := <-errs; err != nil || selection.Path != PathRelayQUIC || selection.Connection != relay {
		t.Fatalf("selection=%+v err=%v", selection, err)
	}
}

func TestSecurityFailureStopsWithoutFallback(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan error, 1)
	go func() {
		_, err := racer.Connect(context.Background(), 1, ModeAuto, NetworkUnknown)
		done <- err
	}()
	receiveAttemptPath(t, connector.started, PathDirectQUIC)
	connector.results[PathDirectQUIC] <- connectResult{err: &Failure{Class: FailureCertificate, Cause: errors.New("wrong peer")}}
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureCertificate {
		t.Fatalf("err=%v", err)
	}
}

func TestKnownUDPBlockingStartsOnlyWSS(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 2, ModeAuto, NetworkUDPBlocked)
		done <- selection
	}()
	if attempt := receiveAttempt(t, connector.started); attempt.Path != PathWSS {
		t.Fatalf("attempt=%+v", attempt)
	}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	if selection := <-done; selection.Path != PathWSS {
		t.Fatalf("selection=%+v", selection)
	}
}

func TestAutoStartsRelayAndWSSConcurrentlyWhenDirectIsInfeasible(t *testing.T) {
	connector := newFakeConnector()
	racer, err := NewRacer(Config{RelayDelay: time.Second, WSSDelay: 2 * time.Second, ConnectTimeout: 5 * time.Second}, connector)
	if err != nil {
		t.Fatal(err)
	}
	racer.after = func(context.Context, time.Duration) <-chan struct{} {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 3, ModeAuto, NetworkDirectInfeasible)
		done <- selection
	}()
	seen := make(map[Path]bool, 2)
	for range 2 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("attempts=%v", seen)
	}
	connector.results[PathRelayQUIC] <- connectResult{err: &Failure{Class: FailureTimeout, Path: PathRelayQUIC, Cause: context.DeadlineExceeded}}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	if selection := <-done; selection.Path != PathWSS || selection.Connection != wss {
		t.Fatalf("selection=%+v", selection)
	}
}

func TestAutoReturnsRelayImmediatelyAndWarmsWSSInBackground(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 4, ModeAuto, NetworkDirectInfeasible)
		done <- selection
	}()
	seen := make(map[Path]bool, 2)
	for range 2 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("attempts=%v", seen)
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	var selection Selection
	select {
	case selection = <-done:
	case <-time.After(time.Second):
		t.Fatal("relay selection waited for WSS standby")
	}
	if selection.Path != PathRelayQUIC || selection.Connection != relay || selection.StandbyReady == nil {
		t.Fatalf("selection=%+v", selection)
	}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	standby := <-selection.StandbyReady
	if standby.Err != nil || standby.Selection.Path != PathWSS || standby.Selection.Connection != wss {
		t.Fatalf("standby=%+v", standby)
	}
}

func TestAutoReturnsWSSImmediatelyAndReportsLateRelayUpgrade(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 5, ModeAuto, NetworkDirectInfeasible)
		done <- selection
	}()
	for range 2 {
		receiveAttempt(t, connector.started)
	}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	selection := <-done
	if selection.Path != PathWSS || selection.Connection != wss || selection.StandbyReady == nil {
		t.Fatalf("selection=%+v", selection)
	}
	relay := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	upgrade := <-selection.StandbyReady
	if upgrade.Err != nil || upgrade.Selection.Path != PathRelayQUIC || upgrade.Selection.Connection != relay {
		t.Fatalf("upgrade=%+v", upgrade)
	}
}

func TestReadyRelayReturnsFirstAndReportsLateDirectUpgrade(t *testing.T) {
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 3, ModeAuto, NetworkRelayPreferred)
		done <- selection
	}()
	seen := make(map[Path]bool, 3)
	for range 3 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathDirectQUIC] || !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("attempts=%v", seen)
	}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	selection := <-done
	if selection.Path != PathRelayQUIC || selection.Connection != relay || selection.StandbyReady == nil {
		t.Fatalf("selection=%+v", selection)
	}
	connector.results[PathWSS] <- connectResult{err: &Failure{Class: FailureReachability, Path: PathWSS, Cause: errors.New("WSS unavailable")}}
	connector.results[PathDirectQUIC] <- connectResult{connection: direct}
	upgrade := <-selection.StandbyReady
	if upgrade.Err != nil || upgrade.Selection.Path != PathDirectQUIC || upgrade.Selection.Connection != direct || direct.closeCount() != 0 || relay.closeCount() != 0 {
		t.Fatalf("upgrade=%+v direct closes=%d relay closes=%d", upgrade, direct.closeCount(), relay.closeCount())
	}
}

func TestWSSIsRetainedWhenDirectWinsAndRelayFails(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 9, ModeAuto, NetworkRelayPreferred)
		done <- selection
	}()
	seen := make(map[Path]bool, 3)
	for range 3 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathDirectQUIC] || !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("initial attempts=%v", seen)
	}
	direct := &fakeConnection{}
	connector.results[PathDirectQUIC] <- connectResult{connection: direct}
	var selection Selection
	select {
	case selection = <-done:
	case <-time.After(time.Second):
		t.Fatal("direct selection waited for standby")
	}
	if selection.Path != PathDirectQUIC || selection.StandbyReady == nil {
		t.Fatalf("selection=%+v", selection)
	}
	connector.results[PathRelayQUIC] <- connectResult{err: &Failure{Class: FailureReachability, Path: PathRelayQUIC, Cause: errors.New("relay unavailable")}}
	wss := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: wss}
	standby := <-selection.StandbyReady
	if standby.Err != nil || standby.Selection.Path != PathWSS || standby.Selection.Connection != wss || direct.closeCount() != 0 || wss.closeCount() != 0 {
		t.Fatalf("standby=%+v direct closes=%d wss closes=%d", standby, direct.closeCount(), wss.closeCount())
	}
}

func TestPreferenceDeadlineSelectsReadyRelay(t *testing.T) {
	connector := newFakeConnector()
	// Keep a generous margin under the test process deadline; the race detector
	// can delay a one-second timer enough to make this assertion flaky.
	racer, err := NewRacer(Config{RelayDelay: 250 * time.Millisecond, WSSDelay: 250 * time.Millisecond, ConnectTimeout: 5 * time.Second}, connector)
	if err != nil {
		t.Fatal(err)
	}
	racer.after = func(context.Context, time.Duration) <-chan struct{} {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	done := make(chan Selection, 1)
	go func() {
		selection, _ := racer.Connect(context.Background(), 12, ModeAuto, NetworkUnknown)
		done <- selection
	}()
	seenDirect, seenRelay := false, false
	for range 3 {
		attempt := receiveAttempt(t, connector.started)
		seenDirect = seenDirect || attempt.Path == PathDirectQUIC
		seenRelay = seenRelay || attempt.Path == PathRelayQUIC
		if seenDirect && seenRelay {
			break
		}
	}
	if !seenDirect || !seenRelay {
		t.Fatalf("attempts did not include direct and relay: direct=%v relay=%v", seenDirect, seenRelay)
	}
	relay := &fakeConnection{}
	select {
	case selection := <-done:
		t.Fatalf("relay selected before direct preference deadline: %+v", selection)
	case <-time.After(100 * time.Millisecond):
	}
	// Relay is ready by the preference deadline.
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	selection := <-done
	if selection.Path != PathRelayQUIC || selection.Connection != relay {
		t.Fatalf("selection=%+v", selection)
	}
}

func TestUnknownConnectorErrorFailsClosed(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan error, 1)
	go func() {
		_, err := racer.Connect(context.Background(), 1, ModeAuto, NetworkUnknown)
		done <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	connector.results[attempt.Path] <- connectResult{err: errors.New("untyped connector failure")}
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureInternal {
		t.Fatalf("err=%v", err)
	}
}

func TestRaceConfigurationRequiresOrderedBoundedDelays(t *testing.T) {
	connector := newFakeConnector()
	for _, config := range []Config{
		{},
		{RelayDelay: 2 * time.Second, WSSDelay: time.Second, ConnectTimeout: 3 * time.Second},
		{RelayDelay: time.Second, WSSDelay: 2 * time.Second, ConnectTimeout: 2 * time.Second},
	} {
		if _, err := NewRacer(config, connector); err == nil {
			t.Fatalf("accepted config=%+v", config)
		}
	}
}

func TestUntrustedConnectionFailsClosedAndIsClosed(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan error, 1)
	go func() {
		_, err := racer.Connect(context.Background(), 1, ModeAuto, NetworkUnknown)
		done <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{state: StateReady}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureProtocol || connection.closeCount() != 1 {
		t.Fatalf("err=%v closes=%d", err, connection.closeCount())
	}
}

func receiveAttempt(t *testing.T, attempts <-chan Attempt) Attempt {
	t.Helper()
	select {
	case attempt := <-attempts:
		return attempt
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for connection attempt")
		return Attempt{}
	}
}

func receiveAttemptPath(t *testing.T, attempts <-chan Attempt, path Path) Attempt {
	t.Helper()
	for range 10 {
		attempt := receiveAttempt(t, attempts)
		if attempt.Path == path {
			return attempt
		}
	}
	t.Fatalf("timed out waiting for path %d", path)
	return Attempt{}
}

func TestRaceCarriesValidatedRelayRegionMetadata(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	result := make(chan Selection, 1)
	errResult := make(chan error, 1)
	go func() {
		selection, err := racer.Connect(context.Background(), 1, ModeQUIC, NetworkDirectInfeasible)
		result <- selection
		errResult <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	connector.results[attempt.Path] <- connectResult{connection: &relayMetadataConnection{fakeConnection: &fakeConnection{state: StateTrusted}, region: "bom"}}
	selection := <-result
	if err := <-errResult; err != nil || selection.Path != PathRelayQUIC || selection.RelayRegion != "bom" {
		t.Fatalf("selection=%#v err=%v", selection, err)
	}
}

func TestRaceRejectsRelayMetadataOnDirectPath(t *testing.T) {
	connector := newFakeConnector()
	racer := testRacer(t, connector)
	done := make(chan error, 1)
	go func() {
		_, err := racer.Connect(context.Background(), 1, ModeQUIC, NetworkUnknown)
		done <- err
	}()
	attempt := receiveAttemptPath(t, connector.started, PathDirectQUIC)
	connection := &relayMetadataConnection{fakeConnection: &fakeConnection{state: StateTrusted}, region: "bom"}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureProtocol || failure.Path != PathDirectQUIC || connection.closeCount() != 1 {
		t.Fatalf("err=%v closes=%d", err, connection.closeCount())
	}
}
