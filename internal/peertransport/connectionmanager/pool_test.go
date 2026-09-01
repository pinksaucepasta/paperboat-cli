package connectionmanager

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type latePoolConnector struct {
	started chan Attempt
	result  chan Connection
}

type ownedPoolAttempt struct {
	attempt Attempt
	result  chan Connection
}

type ownedPoolConnector struct {
	started chan ownedPoolAttempt
}

type abortableFakeConnection struct {
	*fakeConnection
	aborted chan error
}

func (c *abortableFakeConnection) AbortApplications(err error) { c.aborted <- err }

func TestPoolInvalidationAbortsLogicalApplicationsBeforeCarrierClose(t *testing.T) {
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	connection := &abortableFakeConnection{fakeConnection: &fakeConnection{}, aborted: make(chan error, 1)}
	pool.classes[peerquic.ClassInteractive] = &classState{selected: &managedConnection{selection: Selection{Path: PathDirectQUIC, Connection: connection}, applicationLeases: 1}}
	pool.Invalidate()
	select {
	case abortErr := <-connection.aborted:
		if !errors.Is(abortErr, ErrPoolInvalidated) {
			t.Fatalf("abort error=%v", abortErr)
		}
	default:
		t.Fatal("logical applications were not aborted")
	}
	if connection.closeCount() != 1 {
		t.Fatalf("carrier closes=%d", connection.closeCount())
	}
}

func TestAvailabilitySubscriberReceivesCorrectionIndependentOfPreviousCandidate(t *testing.T) {
	pool, err := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct, relay, wss := &fakeConnection{}, &fakeConnection{}, &fakeConnection{}
	state := &classState{generation: 7,
		selected:  &managedConnection{selection: Selection{Generation: 7, Path: PathDirectQUIC, Connection: direct}},
		standby:   &managedConnection{selection: Selection{Generation: 7, Path: PathRelayQUIC, Connection: relay}},
		secondary: &managedConnection{selection: Selection{Generation: 7, Path: PathWSS, Connection: wss}},
	}
	syncEntryRoles(state)
	pool.classes[peerquic.ClassInteractive] = state
	inbox, unsubscribe := pool.SubscribeAvailability(peerquic.ClassInteractive)
	defer unsubscribe()
	initial := <-inbox
	if initial.Preferred.Connection != direct || len(initial.Available) != 3 {
		t.Fatalf("initial=%+v", initial)
	}
	pool.mu.Lock()
	oldSelected, oldStandby, oldSecondary := state.selected, state.standby, state.secondary
	state.selected, state.standby, state.secondary = oldStandby, oldSecondary, nil
	syncEntryRoles(state, oldSelected, oldStandby, oldSecondary)
	pool.publishAvailabilityLocked(peerquic.ClassInteractive, state, state.selected)
	pool.mu.Unlock()
	corrected := <-inbox
	if corrected.Revision <= initial.Revision || corrected.Preferred.Connection != relay || len(corrected.Available) != 2 || corrected.Available[1].Connection != wss {
		t.Fatalf("corrected=%+v initial_revision=%d", corrected, initial.Revision)
	}
}

func (c *ownedPoolConnector) Connect(_ context.Context, attempt Attempt) (Connection, error) {
	call := ownedPoolAttempt{attempt: attempt, result: make(chan Connection, 1)}
	c.started <- call
	return <-call.result, nil
}

func (c *latePoolConnector) Connect(_ context.Context, attempt Attempt) (Connection, error) {
	c.started <- attempt
	return <-c.result, nil
}

func TestPoolSingleFlightsConcurrentAcquireAndReleasesExactlyOnce(t *testing.T) {
	connector := newFakeConnector()
	pool, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	leases := make(chan *Lease, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
			leases <- lease
			errs <- err
		}()
	}
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	wait.Wait()
	first, second := <-leases, <-leases
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if first == nil || second == nil || first.Connection != connection || second.Connection != connection || first.Generation != 1 || second.Generation != 1 {
		t.Fatalf("leases=%+v %+v", first, second)
	}
	select {
	case extra := <-connector.started:
		t.Fatalf("duplicate connection attempt %+v", extra)
	default:
	}
	first.Release()
	first.Release()
	if connection.closeCount() != 0 {
		t.Fatal("connection closed with a live lease")
	}
	second.Release()
	if connection.closeCount() != 0 {
		t.Fatalf("close count=%d", connection.closeCount())
	}
	if err := pool.Close(); err != nil || connection.closeCount() != 1 {
		t.Fatalf("pool close=%v count=%d", err, connection.closeCount())
	}
}

func TestPoolAdoptsLateWarmRelayAndPromotesWithoutReconnect(t *testing.T) {
	connector := newFakeConnector()
	pool, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	leaseResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkUnknown)
		leaseResult <- lease
	}()
	attempts := []Attempt{receiveAttempt(t, connector.started), receiveAttempt(t, connector.started), receiveAttempt(t, connector.started)}
	seen := map[Path]bool{}
	for _, attempt := range attempts {
		seen[attempt.Path] = true
	}
	if !seen[PathDirectQUIC] || !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("attempts=%+v", attempts)
	}
	connector.results[PathWSS] <- connectResult{err: &Failure{Class: FailureReachability, Path: PathWSS, Cause: errors.New("test WSS unavailable")}}
	direct := &fakeConnection{}
	connector.results[PathDirectQUIC] <- connectResult{connection: direct}
	lease := <-leaseResult
	if lease == nil || lease.Connection != direct || lease.Path != PathDirectQUIC {
		t.Fatalf("lease=%+v", lease)
	}
	relay := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	connector.results[PathRelayQUIC] <- connectResult{connection: relay}
	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		standby := pool.classLocked(peerquic.ClassInteractive).standby
		pool.mu.Unlock()
		if standby != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late relay was not adopted")
		}
		time.Sleep(time.Millisecond)
	}
	pool.mu.Lock()
	state := pool.classLocked(peerquic.ClassInteractive)
	promoted := pool.failHealthLocked(peerquic.ClassInteractive, state.selected)
	selected := state.selected
	pool.mu.Unlock()
	if !promoted || selected == nil || selected.selection.Connection != relay || selected.selection.Path != PathRelayQUIC || direct.closeCount() != 0 || relay.closeCount() != 0 {
		t.Fatalf("promoted=%t selected=%+v direct_closes=%d relay_closes=%d", promoted, selected, direct.closeCount(), relay.closeCount())
	}
	lease.Release()
	if direct.closeCount() != 1 {
		t.Fatalf("retired direct closes=%d", direct.closeCount())
	}
	_ = pool.Close()
}

func TestPoolCloseCancelsInFlightAcquire(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	done := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkUnknown)
		done <- err
	}()
	_ = receiveAttempt(t, connector.started)
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("acquire error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool close did not cancel acquisition")
	}
}

func TestPoolClassGenerationExhaustionIsPermanent(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = math.MaxUint64

	for range 2 {
		if _, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkUnknown); !errors.Is(err, ErrPoolGenerationExhausted) {
			t.Fatalf("error=%v", err)
		}
		if state.generation != math.MaxUint64 || !state.exhausted {
			t.Fatalf("state=%+v", state)
		}
		select {
		case attempt := <-connector.started:
			t.Fatalf("connector invoked after exhaustion: %+v", attempt)
		default:
		}
	}
}

func TestPoolLeaseExhaustionNeverMakesLiveConnectionIdle(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	connection := &fakeConnection{}
	entry := &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: connection}, applicationLeases: math.MaxUint64}
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 1, selected: entry}

	for range 2 {
		if _, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkUnknown); !errors.Is(err, ErrPoolLeaseExhausted) {
			t.Fatalf("error=%v", err)
		}
		if entry.applicationLeases != math.MaxUint64 || entry.closed || connection.closeCount() != 0 {
			t.Fatalf("leases=%d closed=%t close count=%d", entry.applicationLeases, entry.closed, connection.closeCount())
		}
	}
}

func TestPoolNetworkGenerationExhaustionFencesNewConnections(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	pool.networkGeneration = math.MaxUint64
	pool.NetworkChanged()
	if !pool.networkExhausted || pool.networkGeneration != math.MaxUint64 {
		t.Fatalf("network generation=%d exhausted=%t", pool.networkGeneration, pool.networkExhausted)
	}
	if _, err := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeAuto, NetworkUnknown); !errors.Is(err, ErrPoolGenerationExhausted) {
		t.Fatalf("error=%v", err)
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("connector invoked after network exhaustion: %+v", attempt)
	default:
	}
}

func TestPoolNetworkChangeCancelsStaleAcquireAndAllowsNewGeneration(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	stale := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeAuto, NetworkUnknown)
		stale <- err
	}()
	first := receiveAttempt(t, connector.started)
	pool.NetworkChanged()
	select {
	case err := <-stale:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stale acquire error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network change did not cancel stale acquisition")
	}
drainStale:
	for {
		select {
		case staleAttempt := <-connector.started:
			if staleAttempt.Generation != first.Generation {
				t.Fatalf("unexpected queued attempt=%+v", staleAttempt)
			}
		default:
			break drainStale
		}
	}
	fresh := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeWSS, NetworkUDPBlocked)
		fresh <- lease
	}()
	second := receiveAttempt(t, connector.started)
	if second.Generation <= first.Generation || second.Path != PathWSS {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	connector.results[second.Path] <- connectResult{connection: &fakeConnection{}}
	lease := <-fresh
	if lease == nil {
		t.Fatal("fresh acquisition failed")
	}
	lease.Release()
	_ = pool.Close()
}

func TestPoolTransferClassNeverStartsBackgroundCarrierFallback(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	pool.mu.Lock()
	pool.classes[peerquic.ClassTransfer] = &classState{generation: 1, mode: ModeAuto, network: NetworkDirectInfeasible, policySet: true}
	pool.startRecoveryLocked(peerquic.ClassTransfer, PathDirectQUIC)
	pool.mu.Unlock()
	select {
	case attempt := <-connector.started:
		t.Fatalf("transfer fallback attempt=%+v", attempt)
	default:
	}
	_ = pool.Close()
}

func TestPoolTransferRaceStopsAfterDirectFailure(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	done := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassTransfer, ModeAuto, NetworkUnknown)
		done <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	if attempt.Path != PathDirectQUIC {
		t.Fatalf("transfer attempt=%+v", attempt)
	}
	connector.results[PathDirectQUIC] <- connectResult{err: &Failure{Class: FailureReachability, Cause: errors.New("direct unavailable")}}
	if err := <-done; err == nil {
		t.Fatal("transfer direct failure reported success")
	}
	select {
	case fallback := <-connector.started:
		t.Fatalf("transfer carrier fallback=%+v", fallback)
	default:
	}
	_ = pool.Close()
}

func TestPoolRejectsInjectedWSSLeaseForTransferClass(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	connection := &fakeConnection{}
	entry := &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: connection}}
	pool.mu.Lock()
	_, err := pool.leaseLocked(peerquic.ClassTransfer, entry)
	pool.mu.Unlock()
	if err == nil || entry.applicationLeases != 0 {
		t.Fatalf("lease error=%v leases=%d", err, entry.applicationLeases)
	}
	_ = connection.Close()
	_ = pool.Close()
}

func TestPoolReplacementDrainsOldConnection(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	oldLeaseResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
		oldLeaseResult <- lease
	}()
	oldAttempt := receiveAttempt(t, connector.started)
	oldConnection := &fakeConnection{}
	connector.results[oldAttempt.Path] <- connectResult{connection: oldConnection}
	oldLease := <-oldLeaseResult

	replaced := make(chan error, 1)
	go func() {
		replaced <- pool.Replace(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
	}()
	newAttempt := receiveAttempt(t, connector.started)
	if newAttempt.Generation != oldAttempt.Generation+1 {
		t.Fatalf("old=%+v new=%+v", oldAttempt, newAttempt)
	}
	newConnection := &fakeConnection{}
	connector.results[newAttempt.Path] <- connectResult{connection: newConnection}
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	newLease, err := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
	if err != nil || newLease.Connection != newConnection {
		t.Fatalf("new lease=%+v err=%v", newLease, err)
	}
	if oldConnection.closeCount() != 0 {
		t.Fatal("draining connection closed before its lease")
	}
	oldLease.Release()
	if oldConnection.closeCount() != 1 {
		t.Fatal("draining connection did not close after last lease")
	}
	newLease.Release()
	if newConnection.closeCount() != 0 {
		t.Fatal("selected connection did not enter grace")
	}
	if err := pool.Close(); err != nil || newConnection.closeCount() != 1 {
		t.Fatalf("pool close=%v count=%d", err, newConnection.closeCount())
	}
}

func TestPoolPromotesDirectProbeBeforeNewLeaseAndDrainsRelay(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	relay := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	direct := &fakeConnection{}
	previous := &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, RelayRegion: "bom", Connection: relay}, applicationLeases: 1}
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 4, selected: previous}
	if err := pool.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	state := pool.classes[peerquic.ClassInteractive]
	if state.selected == nil || state.selected.selection.Connection != direct || state.selected.selection.Path != PathDirectQUIC || state.selected.selection.Generation != 5 || state.standby != previous || state.draining != previous || relay.closeCount() != 0 || state.selected.applicationLeases != 0 || previous.applicationLeases != 1 {
		t.Fatalf("state=%+v relay closes=%d", state, relay.closeCount())
	}
	if snapshot, err := pool.Snapshot(peerquic.ClassInteractive); err != nil || snapshot.Path != PathDirectQUIC || snapshot.RelayRegion != "" || snapshot.ActivePath != PathRelayQUIC || snapshot.ActiveRelayRegion != "bom" || snapshot.Leases != 1 {
		t.Fatalf("draining snapshot=%+v err=%v", snapshot, err)
	}
	lease, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkUnknown)
	if err != nil || lease.Connection != direct || lease.Path != PathDirectQUIC {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	pool.release(peerquic.ClassInteractive, previous)
	if relay.closeCount() != 0 || direct.closeCount() != 0 || state.draining != nil || state.standby != previous {
		t.Fatalf("relay=%d direct=%d", relay.closeCount(), direct.closeCount())
	}
	if snapshot, err := pool.Snapshot(peerquic.ClassInteractive); err != nil || snapshot.StandbyPath != PathRelayQUIC {
		t.Fatalf("retained standby snapshot=%+v err=%v", snapshot, err)
	}
	if !pool.Retire(peerquic.ClassInteractive, direct) || state.selected != previous {
		t.Fatalf("relay fallback was not selected: %+v", state)
	}
	if relay.closeCount() != 0 || direct.closeCount() != 0 {
		t.Fatalf("after fallback relay=%d direct=%d", relay.closeCount(), direct.closeCount())
	}
	lease.Release()
	if direct.closeCount() != 1 {
		t.Fatalf("direct did not close after final lease: %d", direct.closeCount())
	}
	if pool.Retire(peerquic.ClassInteractive, relay) || relay.closeCount() != 1 {
		t.Fatalf("final relay retirement selected=%+v closes=%d", state.selected, relay.closeCount())
	}
	_ = pool.Close()
}

type promotionAwareConnection struct {
	*fakeConnection
	promoted chan struct{}
}

func (c *promotionAwareConnection) PromoteStreams() { close(c.promoted) }

type standbyAwareConnection struct {
	*fakeConnection
	mu       sync.Mutex
	standbys []Connection
}

func (c *standbyAwareConnection) SetStandby(value Connection) {
	c.mu.Lock()
	c.standbys = append(c.standbys, value)
	c.mu.Unlock()
}

func (c *standbyAwareConnection) lastStandby() Connection {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.standbys) == 0 {
		return nil
	}
	return c.standbys[len(c.standbys)-1]
}

func TestPoolRejectsIneligibleProbeWithoutTakingOwnership(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	connection := &fakeConnection{}
	pool.classes[peerquic.ClassPreview] = &classState{selected: &managedConnection{selection: Selection{Path: PathWSS, Connection: &fakeConnection{}}}}
	if err := pool.PromoteDirect(peerquic.ClassPreview, connection); err == nil || connection.closeCount() != 0 {
		t.Fatalf("err=%v closes=%d", err, connection.closeCount())
	}
	_ = pool.Close()
}

func TestPoolRejectsAndClosesStaleAttemptResult(t *testing.T) {
	connector := &latePoolConnector{started: make(chan Attempt, 3), result: make(chan Connection, 1)}
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	done := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
		done <- err
	}()
	_ = receiveAttempt(t, connector.started)
	pool.Invalidate()
	connection := &fakeConnection{}
	connector.result <- connection
	err := <-done
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != FailureGeneration || connection.closeCount() != 1 {
		t.Fatalf("err=%v closes=%d", err, connection.closeCount())
	}
}

func TestPoolInvalidationReleasesAttemptOwnershipBeforeLateResult(t *testing.T) {
	connector := &ownedPoolConnector{started: make(chan ownedPoolAttempt, 2)}
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	oldDone := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
		oldDone <- err
	}()
	oldCall := <-connector.started
	pool.Invalidate()

	newDone := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
		newDone <- lease
	}()
	var newCall ownedPoolAttempt
	select {
	case newCall = <-connector.started:
	case <-time.After(time.Second):
		t.Fatal("replacement remained blocked by stale connector")
	}
	if newCall.attempt.Generation <= oldCall.attempt.Generation {
		t.Fatalf("old=%+v new=%+v", oldCall.attempt, newCall.attempt)
	}
	newConnection := &fakeConnection{}
	newCall.result <- newConnection
	newLease := <-newDone
	if newLease == nil || newLease.Connection != newConnection {
		t.Fatalf("new lease=%+v", newLease)
	}

	oldConnection := &fakeConnection{}
	oldCall.result <- oldConnection
	var failure *Failure
	if err := <-oldDone; !errors.As(err, &failure) || failure.Class != FailureGeneration || oldConnection.closeCount() != 1 {
		t.Fatalf("old error=%v failure=%+v closes=%d", err, failure, oldConnection.closeCount())
	}
	newLease.Release()
	_ = pool.Close()
}

func TestPoolClassesHaveIndependentAttemptGenerations(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 10 * time.Minute})
	results := make(chan *Lease, 2)
	for _, class := range []peerquic.Class{peerquic.ClassInteractive, peerquic.ClassPreview} {
		go func(class peerquic.Class) {
			lease, _ := pool.Acquire(context.Background(), class, ModeRelayQUIC, NetworkDirectInfeasible)
			results <- lease
		}(class)
	}
	first := receiveAttempt(t, connector.started)
	second := receiveAttempt(t, connector.started)
	if first.Generation != 1 || second.Generation != 1 {
		t.Fatalf("attempts=%+v %+v", first, second)
	}
	connector.results[first.Path] <- connectResult{connection: &fakeConnection{}}
	connector.results[second.Path] <- connectResult{connection: &fakeConnection{}}
	(<-results).Release()
	(<-results).Release()
	_ = pool.Close()
}

func TestPoolIdleGraceIsCanceledByReuseAndClosesOnExpiry(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 30 * time.Second})
	timers := &fakeIdleTimers{}
	pool.after = timers.after
	result := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
		result <- lease
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	first := <-result
	first.Release()
	firstTimer := timers.timer(t, 0)
	if firstTimer.delay != 30*time.Second || connection.closeCount() != 0 {
		t.Fatalf("delay=%v closes=%d", firstTimer.delay, connection.closeCount())
	}

	second, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkDirectInfeasible)
	if err != nil || second.Connection != connection {
		t.Fatalf("lease=%+v err=%v", second, err)
	}
	firstTimer.fire()
	if connection.closeCount() != 0 {
		t.Fatal("canceled idle timer closed reused connection")
	}
	second.Release()
	secondTimer := timers.timer(t, 1)
	firstTimer.forceFire()
	if connection.closeCount() != 0 {
		t.Fatal("stale idle callback closed connection during new grace period")
	}
	secondTimer.fire()
	if connection.closeCount() != 1 {
		t.Fatalf("closes=%d", connection.closeCount())
	}
}

func TestPoolStandbyArrivalDoesNotCancelDirectWinner(t *testing.T) {
	direct := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	relay := &fakeConnection{}
	p, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	state := p.classLocked(peerquic.ClassInteractive)
	state.generation = 1
	state.selected = &managedConnection{selection: Selection{Generation: 1, Path: PathDirectQUIC, Connection: direct}}
	future := make(chan StandbyResult, 1)
	p.adoptStandbyFutureLocked(peerquic.ClassInteractive, state, future)
	future <- StandbyResult{Selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}}
	deadline := time.After(time.Second)
	for {
		p.mu.Lock()
		adopted := state.standby != nil
		p.mu.Unlock()
		if adopted {
			break
		}
		select {
		case <-deadline:
			t.Fatal("standby was not adopted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if direct.closeCount() != 0 {
		t.Fatalf("direct winner closed when standby arrived: %d", direct.closeCount())
	}
	if direct.lastStandby() != relay {
		t.Fatal("direct winner was not given the authenticated standby")
	}
}

func TestPoolReplacesFailedApplicationStandbyWithSecondary(t *testing.T) {
	direct := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	relay := &fakeConnection{}
	wss := &fakeConnection{}
	state := &classState{
		generation: 1,
		selected:   &managedConnection{selection: Selection{Generation: 1, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 1},
		standby:    &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}},
		secondary:  &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: wss}},
	}
	pool := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1)}
	pool.mu.Lock()
	pool.failHealthLocked(peerquic.ClassInteractive, state.standby)
	pool.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for direct.lastStandby() != wss && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if relay.closeCount() != 1 || state.standby == nil || state.standby.selection.Connection != wss || direct.lastStandby() != wss {
		t.Fatalf("relay_closes=%d standby=%+v prepared=%T", relay.closeCount(), state.standby, direct.lastStandby())
	}
}

func TestSelectedDrainingRelayFailureRetainsApplicationLeaseBehindWSS(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	relay := &managedConnection{selection: Selection{Generation: 5, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	wss := &managedConnection{selection: Selection{Generation: 5, Path: PathWSS, Connection: &fakeConnection{}}}
	state := &classState{generation: 5, mode: ModeAuto, policySet: true, selected: relay, standby: wss, draining: relay}
	syncEntryRoles(state, relay, wss)
	pool.classes[peerquic.ClassInteractive] = state
	pool.mu.Lock()
	if !pool.failHealthLocked(peerquic.ClassInteractive, relay) {
		pool.mu.Unlock()
		t.Fatal("selected relay failure not reported")
	}
	snapshot, ok := pool.availabilitySnapshotLocked(peerquic.ClassInteractive)
	leases := pool.applicationLeasesLocked(state)
	selected, draining := state.selected, state.draining
	pool.mu.Unlock()
	if !ok || snapshot.Preferred.Connection != wss.selection.Connection || selected != wss || draining != relay || leases != 1 || relay.closed {
		t.Fatalf("snapshot=%+v ok=%t selected=%p draining=%p leases=%d relay_closed=%t", snapshot, ok, selected, draining, leases, relay.closed)
	}
	_ = pool.Close()
}

func TestPoolRestartsSelectedHealthWhenLeaseIsDraining(t *testing.T) {
	health := newPoolHealthRunner()
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{CloseWhenIdle: true, Health: health, HealthTransport: poolHealthFactory})
	if err != nil {
		t.Fatal(err)
	}
	relay := &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	selected := &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}}}
	state := &classState{generation: 1, selected: selected, draining: relay}
	syncEntryRoles(state, selected, relay)
	pool.classes[peerquic.ClassInteractive] = state
	pool.mu.Lock()
	pool.ensureHealthLocked(peerquic.ClassInteractive, state, selected)
	pool.mu.Unlock()
	run := health.next(t)
	if run.binding.Path != PathRelayQUIC {
		t.Fatalf("health path=%v", run.binding.Path)
	}
	_ = pool.Close()
	run.assertCanceled(t)
}

func TestPoolInvalidationCancelsIdleGrace(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 30 * time.Second})
	timers := &fakeIdleTimers{}
	pool.after = timers.after
	result := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
		result <- lease
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	(<-result).Release()
	timer := timers.timer(t, 0)
	pool.Invalidate()
	timer.fire()
	if connection.closeCount() != 1 {
		t.Fatalf("closes=%d", connection.closeCount())
	}
}

func TestPoolNetworkChangeRetiresUDPAndPreservesWSS(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	direct := &fakeConnection{}
	wss := &fakeConnection{}
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 4, selected: &managedConnection{selection: Selection{Generation: 4, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 1}}
	pool.classes[peerquic.ClassPreview] = &classState{generation: 7, selected: &managedConnection{selection: Selection{Generation: 7, Path: PathWSS, Connection: wss}, applicationLeases: 1}}
	pool.NetworkChanged()
	if direct.closeCount() != 0 || pool.classes[peerquic.ClassInteractive].selected != nil || pool.classes[peerquic.ClassInteractive].generation != 5 {
		t.Fatalf("direct closes=%d state=%+v", direct.closeCount(), pool.classes[peerquic.ClassInteractive])
	}
	if wss.closeCount() != 0 || pool.classes[peerquic.ClassPreview].selected == nil || pool.classes[peerquic.ClassPreview].generation != 8 {
		t.Fatalf("wss closes=%d state=%+v", wss.closeCount(), pool.classes[peerquic.ClassPreview])
	}
	_ = pool.Close()
}

func TestPoolNetworkChangePromotesRelayStandbyForActiveDirect(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	state := &classState{generation: 4,
		selected: &managedConnection{selection: Selection{Generation: 4, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 2},
		standby:  &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: relay}},
	}
	pool.classes[peerquic.ClassInteractive] = state
	pool.NetworkChanged()
	if direct.closeCount() != 0 || relay.closeCount() != 0 || state.selected == nil || state.selected.selection.Connection != relay || state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != direct || state.draining.applicationLeases != 2 || state.generation != 5 {
		t.Fatalf("direct=%d relay=%d state=%+v", direct.closeCount(), relay.closeCount(), state)
	}
	_ = pool.Close()
}

func TestPoolSnapshotReportsOnlyReadyActiveStandby(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	state := &classState{generation: 4,
		selected: &managedConnection{selection: Selection{Generation: 4, Path: PathDirectQUIC, Connection: &fakeConnection{}}, applicationLeases: 1},
		standby:  &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: &fakeConnection{}}},
	}
	pool.classes[peerquic.ClassInteractive] = state
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.ActivePath != PathDirectQUIC || snapshot.StandbyPath != PathRelayQUIC || snapshot.Leases != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	state.standby.closed = true
	snapshot, err = pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.StandbyPath != 0 {
		t.Fatalf("closed standby snapshot=%+v err=%v", snapshot, err)
	}
	state.standby.closed = false
	state.selected.applicationLeases = 0
	snapshot, err = pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.StandbyPath != 0 || snapshot.Leases != 0 {
		t.Fatalf("idle snapshot=%+v err=%v", snapshot, err)
	}
	_ = pool.Close()
}

func TestPoolSnapshotRetainsLeasedPathAfterSelectedHealthFailure(t *testing.T) {
	pool, err := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct := &fakeConnection{}
	state := &classState{generation: 4, selected: &managedConnection{
		selection:         Selection{Generation: 4, Path: PathDirectQUIC, Connection: direct},
		applicationLeases: 2,
	}}
	pool.classes[peerquic.ClassInteractive] = state

	pool.mu.Lock()
	if !pool.failHealthLocked(peerquic.ClassInteractive, state.selected) {
		pool.mu.Unlock()
		t.Fatal("selected health failure was not reported")
	}
	pool.mu.Unlock()

	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Selected || snapshot.Path != 0 || snapshot.ActivePath != PathDirectQUIC || snapshot.Leases != 2 {
		t.Fatalf("snapshot lost leased path: %+v", snapshot)
	}
	if len(snapshot.PathConsumers) != 1 || snapshot.PathConsumers[0].Path != PathDirectQUIC || snapshot.PathConsumers[0].ActiveConsumers != 2 {
		t.Fatalf("path consumers=%+v", snapshot.PathConsumers)
	}
	if state.draining == nil || state.draining.selection.Connection != direct {
		t.Fatalf("failed leased carrier was not retained: %+v", state)
	}
	_ = pool.Close()
}

func TestPoolSnapshotReportsDeterministicPerPathLeaseCounts(t *testing.T) {
	pool, err := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct := &fakeConnection{}
	relay := &relayMetadataConnection{fakeConnection: &fakeConnection{}, region: "bom"}
	wss := &relayMetadataConnection{fakeConnection: &fakeConnection{}, region: "sin"}
	state := &classState{generation: 5,
		selected:  &managedConnection{selection: Selection{Generation: 5, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 2},
		standby:   &managedConnection{selection: Selection{Generation: 5, Path: PathRelayQUIC, RelayRegion: "bom", Connection: relay}, applicationLeases: 3},
		secondary: &managedConnection{selection: Selection{Generation: 5, Path: PathWSS, RelayRegion: "sin", Connection: wss}, applicationLeases: 1},
	}
	// Keep one path in two pool roles to prove entries are deduplicated before
	// aggregation, as happens while a selected carrier is being promoted.
	state.draining = state.standby
	pool.classes[peerquic.ClassInteractive] = state

	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.PathConsumers) != 3 {
		t.Fatalf("path consumers=%+v", snapshot.PathConsumers)
	}
	want := []PathConsumer{
		{Path: PathDirectQUIC, ActiveConsumers: 2},
		{Path: PathRelayQUIC, ActiveConsumers: 3, RelayRegion: "bom"},
		{Path: PathWSS, ActiveConsumers: 1, RelayRegion: "sin"},
	}
	for index := range want {
		if snapshot.PathConsumers[index] != want[index] {
			t.Fatalf("path consumers[%d]=%+v want=%+v", index, snapshot.PathConsumers[index], want[index])
		}
	}
	_ = pool.Close()
}

func TestPoolSnapshotFallsBackToLeasedPathWhenCommittedObserverIsEmpty(t *testing.T) {
	pool, err := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct := &committedFakeConnection{fakeConnection: &fakeConnection{}}
	state := &classState{generation: 6, selected: &managedConnection{
		selection:         Selection{Generation: 6, Path: PathDirectQUIC, Connection: direct},
		applicationLeases: 1,
	}}
	pool.classes[peerquic.ClassInteractive] = state

	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActivePath != PathDirectQUIC || snapshot.Leases != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	_ = pool.Close()
}

type committedFakeConnection struct {
	*fakeConnection
	committed uint64
}

func (c *committedFakeConnection) CommittedApplications() uint64 { return c.committed }

func TestPoolSnapshotReportsCommittedPathWithoutRedirectingLease(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	relay := &committedFakeConnection{fakeConnection: &fakeConnection{}}
	wss := &committedFakeConnection{fakeConnection: &fakeConnection{}, committed: 1}
	relayEntry := &managedConnection{selection: Selection{Generation: 5, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}
	wssEntry := &managedConnection{selection: Selection{Generation: 5, Path: PathWSS, Connection: wss}}
	state := &classState{generation: 5, selected: wssEntry, standby: relayEntry, draining: relayEntry}
	pool.classes[peerquic.ClassInteractive] = state
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.ActivePath != PathWSS || snapshot.Leases != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if relayEntry.applicationLeases != 1 || wssEntry.applicationLeases != 0 {
		t.Fatalf("lease ownership changed relay=%d wss=%d", relayEntry.applicationLeases, wssEntry.applicationLeases)
	}
	_ = pool.Close()
}

func TestPoolSnapshotReportsFallbackDistinctFromCommittedPath(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	direct := &committedFakeConnection{fakeConnection: &fakeConnection{}}
	relay := &committedFakeConnection{fakeConnection: &fakeConnection{}, committed: 1}
	wss := &committedFakeConnection{fakeConnection: &fakeConnection{}}
	relayEntry := &managedConnection{selection: Selection{Generation: 6, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}
	pool.classes[peerquic.ClassInteractive] = &classState{
		generation: 6,
		selected:   &managedConnection{selection: Selection{Generation: 6, Path: PathDirectQUIC, Connection: direct}},
		standby:    relayEntry,
		secondary:  &managedConnection{selection: Selection{Generation: 6, Path: PathWSS, Connection: wss}},
		draining:   relayEntry,
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.ActivePath != PathRelayQUIC || snapshot.StandbyPath != PathWSS {
		t.Fatalf("relay migration snapshot=%+v err=%v", snapshot, err)
	}

	relay.committed = 0
	wss.committed = 1
	snapshot, err = pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.ActivePath != PathWSS || snapshot.StandbyPath != PathRelayQUIC {
		t.Fatalf("WSS migration snapshot=%+v err=%v", snapshot, err)
	}
	_ = pool.Close()
}

func TestPoolNetworkChangeFencesInFlightResultWithoutClosingWSSSelection(t *testing.T) {
	connector := &latePoolConnector{started: make(chan Attempt, 3), result: make(chan Connection, 1)}
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	done := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeAuto, NetworkDirectInfeasible)
		done <- err
	}()
	_ = receiveAttempt(t, connector.started)
	pool.NetworkChanged()
	connection := &fakeConnection{}
	connector.result <- connection
	var failure *Failure
	if err := <-done; !errors.As(err, &failure) || failure.Class != FailureGeneration || connection.closeCount() != 1 {
		t.Fatalf("err=%v failure=%+v closes=%d", err, failure, connection.closeCount())
	}
}

func TestPoolReplacementWithoutNewLeaseClosesAfterDrainAndGrace(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 30 * time.Second})
	timers := &fakeIdleTimers{}
	pool.after = timers.after
	oldResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
		oldResult <- lease
	}()
	oldAttempt := receiveAttempt(t, connector.started)
	oldConnection := &fakeConnection{}
	connector.results[oldAttempt.Path] <- connectResult{connection: oldConnection}
	oldLease := <-oldResult

	replaced := make(chan error, 1)
	go func() {
		replaced <- pool.Replace(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
	}()
	newAttempt := receiveAttempt(t, connector.started)
	newConnection := &fakeConnection{}
	connector.results[newAttempt.Path] <- connectResult{connection: newConnection}
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	if len(timers.values) != 0 {
		t.Fatal("replacement entered grace while old lease remained")
	}
	oldLease.Release()
	if oldConnection.closeCount() != 1 || newConnection.closeCount() != 0 {
		t.Fatalf("old=%d new=%d", oldConnection.closeCount(), newConnection.closeCount())
	}
	timers.timer(t, 0).fire()
	if newConnection.closeCount() != 1 {
		t.Fatalf("new closes=%d", newConnection.closeCount())
	}
}

func TestPoolRejectsInvalidIdleGrace(t *testing.T) {
	connector := newFakeConnector()
	for _, grace := range []time.Duration{0, -time.Second, 10*time.Minute + time.Nanosecond} {
		if _, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: grace}); err == nil {
			t.Fatalf("grace %v accepted", grace)
		}
	}
}

func TestPoolRejectsHealthTransportWithoutRunner(t *testing.T) {
	if _, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, HealthTransport: poolHealthFactory}); err == nil {
		t.Fatal("accepted health transport without runner")
	}
}

func TestPoolChangesCoalesceAndSnapshotRemainsAuthoritative(t *testing.T) {
	connector := newFakeConnector()
	pool, _ := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	connection := &fakeConnection{}
	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 3, selected: &managedConnection{selection: Selection{Generation: 3, Path: PathWSS, Connection: connection}, applicationLeases: 1}}
	pool.signalLocked()
	pool.signalLocked()
	pool.signalLocked()
	pool.mu.Unlock()
	select {
	case <-pool.Changes():
	case <-time.After(time.Second):
		t.Fatal("pool change signal missing")
	}
	select {
	case <-pool.Changes():
		t.Fatal("pool changes did not coalesce")
	default:
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || !snapshot.Selected || snapshot.Path != PathWSS || snapshot.ActivePath != PathWSS || snapshot.Generation != 3 || snapshot.Leases != 1 || snapshot.Closed {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	_ = pool.Close()
}

func TestPoolChangeSubscriptionCannotBeConsumedByObserver(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	subscriber, unsubscribe := pool.SubscribeChanges()
	defer unsubscribe()
	pool.mu.Lock()
	pool.signalLocked()
	pool.mu.Unlock()
	select {
	case <-pool.Changes():
	case <-time.After(time.Second):
		t.Fatal("observer change signal missing")
	}
	select {
	case <-subscriber:
	case <-time.After(time.Second):
		t.Fatal("independent subscriber change signal missing")
	}
	_ = pool.Close()
}

func TestPoolHealthFollowsFirstAndLastLease(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	pool, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory})
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkDirectInfeasible)
		firstResult <- lease
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	first := <-firstResult
	started := health.next(t)
	if started.binding.Generation != first.Generation || started.binding.NetworkGeneration != 1 || started.binding.Path != first.Path {
		t.Fatalf("binding=%+v lease=%+v", started.binding, first)
	}
	second, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkDirectInfeasible)
	if err != nil {
		t.Fatal(err)
	}
	health.assertNoStart(t)
	first.Release()
	started.assertRunning(t)
	second.Release()
	started.assertCanceled(t)
	_ = pool.Close()
}

func TestPoolDisabledRelayHealthCoversQUICAndWSS(t *testing.T) {
	for _, test := range []struct {
		path      Path
		wantStart bool
	}{
		{path: PathDirectQUIC, wantStart: true},
		{path: PathRelayQUIC},
		{path: PathWSS},
	} {
		t.Run(string(test.path), func(t *testing.T) {
			health := newPoolHealthRunner()
			pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{
				IdleGrace:                time.Minute,
				Health:                   health,
				HealthTransport:          poolHealthFactory,
				DisableRelayActiveHealth: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			entry := &managedConnection{selection: Selection{Generation: 1, Path: test.path, Connection: &fakeConnection{}}, applicationLeases: 1}
			pool.classes[peerquic.ClassInteractive] = &classState{generation: 1, selected: entry}
			pool.mu.Lock()
			err = pool.startHealthLocked(peerquic.ClassInteractive, entry)
			pool.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if test.wantStart {
				run := health.next(t)
				_ = pool.Close()
				run.assertCanceled(t)
				return
			}
			health.assertNoStart(t)
			if entry.healthCancel != nil || entry.healthToken != nil {
				t.Fatal("disabled relay health retained monitor ownership")
			}
			_ = pool.Close()
		})
	}
}

func TestPoolHealthOwnsActiveStandbysAndFallsThroughToWSS(t *testing.T) {
	health := newPoolHealthRunner()
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{CloseWhenIdle: true, Health: health, HealthTransport: poolHealthFactory})
	if err != nil {
		t.Fatal(err)
	}
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	wss := &fakeConnection{}
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 1
	state.selected = &managedConnection{selection: Selection{Generation: 1, Path: PathDirectQUIC, Connection: direct}}
	state.standby = &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}}
	state.secondary = &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: wss}}
	pool.mu.Lock()
	lease, err := pool.leaseLocked(peerquic.ClassInteractive, state.selected)
	pool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	runs := make(map[Path]*poolHealthRun, 3)
	for range 3 {
		run := health.next(t)
		runs[run.binding.Path] = run
	}
	directHealth, relayHealth, wssHealth := runs[PathDirectQUIC], runs[PathRelayQUIC], runs[PathWSS]
	if directHealth == nil || relayHealth == nil || wssHealth == nil {
		t.Fatalf("health runs=%v", runs)
	}
	relayHealth.fail(ErrPathSuspect)
	deadline := time.Now().Add(time.Second)
	for relay.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	pool.mu.Lock()
	standby, secondary := state.standby, state.secondary
	pool.mu.Unlock()
	if relay.closeCount() != 1 || standby == nil || standby.selection.Connection != wss || secondary != nil || direct.closeCount() != 0 || wss.closeCount() != 0 {
		t.Fatalf("direct=%d relay=%d wss=%d standby=%+v secondary=%+v", direct.closeCount(), relay.closeCount(), wss.closeCount(), standby, secondary)
	}
	directHealth.assertRunning(t)
	wssHealth.assertRunning(t)
	lease.Release()
	directHealth.assertCanceled(t)
	wssHealth.assertCanceled(t)
	if direct.closeCount() != 1 || wss.closeCount() != 1 {
		t.Fatalf("final closes direct=%d wss=%d", direct.closeCount(), wss.closeCount())
	}
}

func TestPoolHealthTracksDrainingReplacement(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory})
	oldResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
		oldResult <- lease
	}()
	oldAttempt := receiveAttempt(t, connector.started)
	connector.results[oldAttempt.Path] <- connectResult{connection: &fakeConnection{}}
	oldLease := <-oldResult
	oldHealth := health.next(t)
	replaced := make(chan error, 1)
	go func() {
		replaced <- pool.Replace(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
	}()
	newAttempt := receiveAttempt(t, connector.started)
	connector.results[newAttempt.Path] <- connectResult{connection: &fakeConnection{}}
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	oldHealth.assertRunning(t)
	health.assertNoStart(t)
	newLease, err := pool.Acquire(context.Background(), peerquic.ClassPreview, ModeRelayQUIC, NetworkDirectInfeasible)
	if err != nil {
		t.Fatal(err)
	}
	newHealth := health.next(t)
	oldLease.Release()
	oldHealth.assertCanceled(t)
	newHealth.assertRunning(t)
	newLease.Release()
	newHealth.assertCanceled(t)
	_ = pool.Close()
}

func TestPoolRestartsWSSHealthOnNetworkChange(t *testing.T) {
	health := newPoolHealthRunner()
	pool, _ := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory})
	wss := &fakeConnection{}
	entry := &managedConnection{selection: Selection{Generation: 7, Path: PathWSS, Connection: wss}, applicationLeases: 1}
	pool.classes[peerquic.ClassPreview] = &classState{generation: 7, selected: entry}
	pool.mu.Lock()
	if err := pool.startHealthLocked(peerquic.ClassPreview, entry); err != nil {
		t.Fatal(err)
	}
	pool.mu.Unlock()
	first := health.next(t)
	pool.NetworkChanged()
	first.assertCanceled(t)
	second := health.next(t)
	if second.binding.NetworkGeneration != 2 || second.binding.Generation != 7 || wss.closeCount() != 0 {
		t.Fatalf("binding=%+v closes=%d", second.binding, wss.closeCount())
	}
	_ = pool.Close()
	second.assertCanceled(t)
}

func TestPoolDisablesProtocolHealthOnlyForPreviewClass(t *testing.T) {
	health := newPoolHealthRunner()
	pool, _ := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory, DisablePreviewActiveHealth: true})
	preview := &managedConnection{selection: Selection{Generation: 1, Path: PathDirectQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	interactive := &managedConnection{selection: Selection{Generation: 2, Path: PathDirectQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	pool.classes[peerquic.ClassPreview] = &classState{generation: 1, selected: preview}
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 2, selected: interactive}
	pool.mu.Lock()
	if err := pool.startHealthLocked(peerquic.ClassPreview, preview); err != nil {
		t.Fatal(err)
	}
	if err := pool.startHealthLocked(peerquic.ClassInteractive, interactive); err != nil {
		t.Fatal(err)
	}
	pool.mu.Unlock()
	if preview.healthCancel != nil {
		t.Fatal("preview protocol health started after HTTP/3 handoff")
	}
	run := health.next(t)
	if run.binding.Generation != 2 {
		t.Fatalf("interactive health binding=%+v", run.binding)
	}
	_ = pool.Close()
	run.assertCanceled(t)
}

func TestPoolHealthFailureFencesAndClosesSelection(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory})
	result := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayQUIC, NetworkDirectInfeasible)
		result <- lease
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	lease := <-result
	started := health.next(t)
	started.fail(errors.New("two missed health exchanges"))
	deadline := time.Now().Add(time.Second)
	for connection.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.Selected || snapshot.Generation != 2 || connection.closeCount() != 0 {
		t.Fatalf("snapshot=%+v error=%v closes=%d", snapshot, err, connection.closeCount())
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("terminal health failure started fallback %+v", attempt)
	default:
	}
	lease.Release()
	if connection.closeCount() != 1 {
		t.Fatalf("failed selection closes after release=%d", connection.closeCount())
	}
	_ = pool.Close()
}

func TestPoolSuspectRelayHealthPromotesWarmWSSWithoutReconnect(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: poolHealthFactory})
	result := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeRelayRace, NetworkDirectInfeasible)
		result <- lease
	}()
	seen := make(map[Path]bool, 2)
	for range 2 {
		attempt := receiveAttempt(t, connector.started)
		seen[attempt.Path] = true
	}
	if !seen[PathRelayQUIC] || !seen[PathWSS] {
		t.Fatalf("initial attempts=%v", seen)
	}
	failed := &fakeConnection{}
	connector.results[PathRelayQUIC] <- connectResult{connection: failed}
	lease := <-result
	replacement := &fakeConnection{}
	connector.results[PathWSS] <- connectResult{connection: replacement}
	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		ready := pool.classLocked(peerquic.ClassInteractive).standby != nil
		pool.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WSS standby was not adopted")
		}
		time.Sleep(time.Millisecond)
	}
	runs := make(map[Path]*poolHealthRun, 2)
	for range 2 {
		run := health.next(t)
		runs[run.binding.Path] = run
	}
	if runs[PathRelayQUIC] == nil || runs[PathWSS] == nil {
		t.Fatalf("health runs=%v", runs)
	}
	runs[PathRelayQUIC].fail(fmt.Errorf("%w: relay health missed", ErrPathSuspect))
	deadline = time.Now().Add(time.Second)
	for {
		snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Selected && snapshot.Path == PathWSS && !snapshot.Connecting {
			if snapshot.Generation != 1 || failed.closeCount() != 0 || replacement.closeCount() != 0 {
				t.Fatalf("snapshot=%+v failed closes=%d replacement closes=%d", snapshot, failed.closeCount(), replacement.closeCount())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery did not publish: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	runs[PathWSS].assertRunning(t)
	select {
	case attempt := <-connector.started:
		t.Fatalf("warm standby promotion reconnected: %+v", attempt)
	default:
	}
	lease.Release()
	_ = pool.Close()
}

func TestPoolRejectsHealthTransportConstructionFailure(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	constructionErr := errors.New("missing authenticated health adapter")
	pool, _ := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health, HealthTransport: func(Selection) (ActiveHealthTransport, error) { return nil, constructionErr }})
	done := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkDirectInfeasible)
		done <- err
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	if err := <-done; !errors.Is(err, constructionErr) || connection.closeCount() != 1 {
		t.Fatalf("error=%v closes=%d", err, connection.closeCount())
	}
}

type poolHealthTransport struct{}

func (poolHealthTransport) HealthExchange(context.Context, [16]byte) (uint32, error) { return 0, nil }

func poolHealthFactory(Selection) (ActiveHealthTransport, error) { return poolHealthTransport{}, nil }

type poolHealthRunner struct{ started chan *poolHealthRun }

type poolHealthRun struct {
	binding ActiveHealthBinding
	done    chan struct{}
	failure chan error
}

func newPoolHealthRunner() *poolHealthRunner {
	return &poolHealthRunner{started: make(chan *poolHealthRun, 16)}
}

func (r *poolHealthRunner) Run(ctx context.Context, binding ActiveHealthBinding, _ ActiveHealthTransport) error {
	run := &poolHealthRun{binding: binding, done: make(chan struct{}), failure: make(chan error, 1)}
	r.started <- run
	defer close(run.done)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-activeHealthRebindDone(ctx):
		return errActiveHealthRebind
	case err := <-run.failure:
		return err
	}
}

func (r *poolHealthRunner) next(t *testing.T) *poolHealthRun {
	t.Helper()
	select {
	case run := <-r.started:
		return run
	case <-time.After(time.Second):
		t.Fatal("health monitor did not start")
		return nil
	}
}

func (r *poolHealthRunner) assertNoStart(t *testing.T) {
	t.Helper()
	select {
	case run := <-r.started:
		t.Fatalf("unexpected health start %+v", run.binding)
	case <-time.After(20 * time.Millisecond):
	}
}

func (r *poolHealthRun) assertCanceled(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("health monitor was not canceled")
	}
}

func (r *poolHealthRun) assertRunning(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
		t.Fatal("health monitor stopped early")
	default:
	}
}

func (r *poolHealthRun) fail(err error) { r.failure <- err }

type fakeIdleTimers struct {
	mu     sync.Mutex
	values []*fakeIdleTimer
}

func (f *fakeIdleTimers) after(delay time.Duration, callback func()) idleTimer {
	timer := &fakeIdleTimer{delay: delay, callback: callback}
	f.mu.Lock()
	f.values = append(f.values, timer)
	f.mu.Unlock()
	return timer
}

func (f *fakeIdleTimers) timer(t *testing.T, index int) *fakeIdleTimer {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if index >= len(f.values) {
		t.Fatalf("timer %d missing", index)
	}
	return f.values[index]
}

type fakeIdleTimer struct {
	mu       sync.Mutex
	delay    time.Duration
	callback func()
	stopped  bool
	fired    bool
}

func (t *fakeIdleTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	return true
}

func (t *fakeIdleTimer) fire() {
	t.mu.Lock()
	if t.stopped || t.fired {
		t.mu.Unlock()
		return
	}
	t.fired = true
	callback := t.callback
	t.mu.Unlock()
	callback()
}

func (t *fakeIdleTimer) forceFire() {
	t.mu.Lock()
	callback := t.callback
	t.mu.Unlock()
	callback()
}

func TestDirectHealthFailurePromotesWarmRelayWithoutReconnect(t *testing.T) {
	connector := newFakeConnector()
	pool, err := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 5
	selected := &managedConnection{selection: Selection{Generation: 5, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 1}
	state.selected = selected
	state.standby = &managedConnection{selection: Selection{Generation: 5, Path: PathRelayQUIC, Connection: relay}}
	pool.mu.Lock()
	promoted := pool.failHealthLocked(peerquic.ClassInteractive, selected)
	pool.mu.Unlock()
	if !promoted || state.selected == nil || state.selected.selection.Path != PathRelayQUIC || state.selected.selection.Connection != relay || state.standby != nil || state.generation != 5 || direct.closeCount() != 0 || relay.closeCount() != 0 {
		t.Fatalf("promoted=%v selected=%+v standby=%+v generation=%d direct_closes=%d relay_closes=%d", promoted, state.selected, state.standby, state.generation, direct.closeCount(), relay.closeCount())
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("warm promotion reconnected: %+v", attempt)
	default:
	}
}

func TestPoolRetireSelectedPromotesWarmRelayWithoutReconnect(t *testing.T) {
	connector := newFakeConnector()
	pool, err := NewPool(testRacer(t, connector), DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	other := &fakeConnection{}
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 7
	state.selected = &managedConnection{selection: Selection{Generation: 7, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 1}
	state.standby = &managedConnection{selection: Selection{Generation: 7, Path: PathRelayQUIC, Connection: relay}}

	if pool.Retire(peerquic.ClassInteractive, other) {
		t.Fatal("unselected connection retirement changed the pool")
	}
	if !pool.Retire(peerquic.ClassInteractive, direct) {
		t.Fatal("selected direct retirement did not promote the warm relay")
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || !snapshot.Selected || snapshot.Path != PathRelayQUIC || snapshot.Generation != 7 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if direct.closeCount() != 0 || relay.closeCount() != 0 || other.closeCount() != 0 {
		t.Fatalf("closes direct=%d relay=%d other=%d", direct.closeCount(), relay.closeCount(), other.closeCount())
	}
	select {
	case attempt := <-connector.started:
		t.Fatalf("retirement reconnected instead of promoting standby: %+v", attempt)
	default:
	}
	_ = pool.Close()
}

func TestPoolRetainsCanonicalWSSAcrossRelayAndDirectPromotion(t *testing.T) {
	wss := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	relay := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	direct := &standbyAwareConnection{fakeConnection: &fakeConnection{}}
	state := &classState{
		generation: 9,
		mode:       ModeAuto,
		policySet:  true,
		selected:   &managedConnection{selection: Selection{Generation: 9, Path: PathWSS, Connection: wss}, applicationLeases: 1},
	}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 8), networkGeneration: 1}
	if err := p.PromoteRelayQUIC(peerquic.ClassInteractive, relay); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for relay.lastStandby() != wss && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state.selected == nil || state.selected.selection.Connection != relay || state.standby == nil || state.standby.selection.Connection != wss || state.secondary != nil {
		t.Fatalf("WSS -> relay roles=%+v", state)
	}
	if relay.lastStandby() != wss || wss.closeCount() != 0 {
		t.Fatalf("relay publication=%p WSS=%p closes=%d", relay.lastStandby(), wss, wss.closeCount())
	}
	if err := p.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for direct.lastStandby() != relay && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state.selected == nil || state.selected.selection.Connection != direct || state.standby == nil || state.standby.selection.Connection != relay || state.secondary == nil || state.secondary.selection.Connection != wss {
		t.Fatalf("relay -> direct roles=%+v", state)
	}
	if direct.lastStandby() != relay || wss.closeCount() != 0 || relay.closeCount() != 0 {
		t.Fatalf("direct fallback=%p relay=%p closes relay=%d WSS=%d", direct.lastStandby(), relay, relay.closeCount(), wss.closeCount())
	}
}

func TestPoolDirectFailurePrefersReadyRelayQUIC(t *testing.T) {
	direct := &fakeConnection{}
	relay := &fakeConnection{}
	wss := &fakeConnection{}
	state := &classState{
		generation: 1,
		selected:   &managedConnection{selection: Selection{Generation: 1, Path: PathDirectQUIC, Connection: direct}, applicationLeases: 1},
		standby:    &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}},
		secondary:  &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: wss}},
	}
	pool := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1)}
	if !pool.Retire(peerquic.ClassInteractive, direct) || state.selected == nil || state.selected.selection.Connection != relay || state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != direct || state.draining.applicationLeases != 1 || state.standby == nil || state.standby.selection.Connection != wss {
		t.Fatalf("relay QUIC was not promoted: %+v", state)
	}
}

func TestPoolDirectRecoveryRetainsRelayFailbackHierarchy(t *testing.T) {
	relay := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	wss := &fakeConnection{}
	direct := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	state := &classState{generation: 4,
		selected: &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1},
		standby:  &managedConnection{selection: Selection{Generation: 4, Path: PathWSS, Connection: wss}},
	}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 1}
	if err := p.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	if state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != relay || state.draining.applicationLeases != 1 || state.standby == nil || state.standby.selection.Path != PathRelayQUIC || state.secondary == nil || state.secondary.selection.Path != PathWSS {
		t.Fatalf("promoted state=%+v", state)
	}
	if !p.Retire(peerquic.ClassInteractive, direct) || state.selected == nil || state.selected.selection.Path != PathRelayQUIC || state.selected.applicationLeases != 1 || state.standby == nil || state.standby.selection.Path != PathWSS {
		t.Fatalf("relay failback state=%+v", state)
	}
	lease := &Lease{release: func() { p.release(peerquic.ClassInteractive, state.selected) }}
	_ = lease
	_ = p.Close()
}

func TestPoolDirectRecoveryRebindsRetainedRelayHealth(t *testing.T) {
	health := newPoolHealthRunner()
	p, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{CloseWhenIdle: true, Health: health, HealthTransport: poolHealthFactory})
	if err != nil {
		t.Fatal(err)
	}
	relay := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	wss := &fakeConnection{}
	direct := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	state := p.classLocked(peerquic.ClassInteractive)
	state.generation = 4
	state.selected = &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: relay}}
	state.standby = &managedConnection{selection: Selection{Generation: 4, Path: PathWSS, Connection: wss}}
	p.mu.Lock()
	lease, err := p.leaseLocked(peerquic.ClassInteractive, state.selected)
	p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	oldRuns := make(map[Path]*poolHealthRun, 2)
	for range 2 {
		run := health.next(t)
		oldRuns[run.binding.Path] = run
	}
	if err := p.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	newRuns := make(map[Path]*poolHealthRun, 3)
	for range 3 {
		run := health.next(t)
		newRuns[run.binding.Path] = run
	}
	for path, run := range oldRuns {
		run.assertCanceled(t)
		if run.binding.Generation != 4 {
			t.Fatalf("old %v health generation=%d", path, run.binding.Generation)
		}
	}
	for _, path := range []Path{PathDirectQUIC, PathRelayQUIC, PathWSS} {
		run := newRuns[path]
		if run == nil || run.binding.Generation != 5 {
			t.Fatalf("new %v health=%+v", path, run)
		}
	}
	if relay.closeCount() != 0 || wss.closeCount() != 0 {
		t.Fatalf("retained fallback closed relay=%d wss=%d", relay.closeCount(), wss.closeCount())
	}
	lease.Release()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPoolDirectPromotionAdoptsOwningLateWSSFuture(t *testing.T) {
	relay := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	direct := &fakeConnection{}
	wss := &fakeConnection{}
	state := &classState{
		generation:     4,
		selected:       &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1},
		upgradePending: true,
	}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 1}
	future := make(chan StandbyResult, 1)
	p.adoptStandbyFutureLocked(peerquic.ClassInteractive, state, future)
	if err := p.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	future <- StandbyResult{Selection: Selection{Generation: 4, Path: PathWSS, Connection: wss}}
	close(future)
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		adopted := state.secondary != nil && state.secondary.selection.Connection == wss
		generation := uint64(0)
		if state.secondary != nil {
			generation = state.secondary.selection.Generation
		}
		p.mu.Unlock()
		if adopted {
			if generation != 5 {
				t.Fatalf("WSS generation=%d", generation)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("late WSS was not retained: %+v closes=%d", state, wss.closeCount())
		}
		time.Sleep(time.Millisecond)
	}
	_ = p.Close()
}

func TestPoolInvalidationRejectsLateStandbyFuture(t *testing.T) {
	relay := &fakeConnection{}
	wss := &fakeConnection{}
	state := &classState{generation: 4, selected: &managedConnection{selection: Selection{Generation: 4, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 1}
	future := make(chan StandbyResult, 1)
	p.adoptStandbyFutureLocked(peerquic.ClassInteractive, state, future)
	p.Invalidate()
	future <- StandbyResult{Selection: Selection{Generation: 4, Path: PathWSS, Connection: wss}}
	close(future)
	deadline := time.Now().Add(time.Second)
	for wss.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if wss.closeCount() != 1 || state.selected != nil || state.standby != nil || state.secondary != nil {
		t.Fatalf("late WSS closes=%d state=%+v", wss.closeCount(), state)
	}
}

func TestPoolNetworkChangePromotesWSSFromRelayPrimary(t *testing.T) {
	relay := &fakeConnection{}
	wss := &fakeConnection{}
	state := &classState{
		generation: 1,
		selected:   &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1},
		secondary:  &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: wss}},
	}
	pool := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 1}
	pool.NetworkChanged()
	if state.selected == nil || state.selected.selection.Connection != wss || state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != relay || state.draining.applicationLeases != 1 || relay.closeCount() != 0 {
		t.Fatalf("network change did not promote WSS: %+v relay closes=%d", state, relay.closeCount())
	}
}

func TestPoolPromotesVerifiedRelayQUICBackFromWSSWithoutLeaseLoss(t *testing.T) {
	wss := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	relay := &promotionAwareConnection{fakeConnection: &fakeConnection{}, promoted: make(chan struct{})}
	state := &classState{
		generation: 3,
		selected:   &managedConnection{selection: Selection{Generation: 3, Path: PathWSS, Connection: wss}, applicationLeases: 2},
	}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 2}
	if err := p.PromoteRelayQUIC(peerquic.ClassInteractive, relay); err != nil {
		t.Fatal(err)
	}
	if state.selected == nil || state.selected.selection.Path != PathRelayQUIC || state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != wss || state.draining.applicationLeases != 2 || state.standby == nil || state.standby.selection.Path != PathWSS {
		t.Fatalf("relay promotion state=%+v", state)
	}
	if wss.closeCount() != 0 {
		t.Fatalf("WSS closed during promotion: %d", wss.closeCount())
	}
	_ = p.Close()
}

func TestPoolPromotesRelayQUICAfterEmptyDrainingCarrier(t *testing.T) {
	wss := &fakeConnection{}
	relay := &fakeConnection{}
	old := &fakeConnection{}
	state := &classState{
		generation: 2,
		selected:   &managedConnection{selection: Selection{Generation: 2, Path: PathWSS, Connection: wss}, applicationLeases: 1},
		draining:   &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: old}, applicationLeases: 0},
	}
	p := &Pool{classes: map[peerquic.Class]*classState{peerquic.ClassInteractive: state}, changes: make(chan struct{}, 1), networkGeneration: 1}
	if err := p.PromoteRelayQUIC(peerquic.ClassInteractive, relay); err != nil {
		t.Fatal(err)
	}
	if state.selected == nil || state.selected.selection.Path != PathRelayQUIC || state.selected.applicationLeases != 0 || state.draining == nil || state.draining.selection.Connection != wss || state.draining.applicationLeases != 1 || old.closeCount() != 1 {
		t.Fatalf("promotion state=%+v old closes=%d", state, old.closeCount())
	}
}

func TestPoolWarmHoldIsNotAnApplicationLease(t *testing.T) {
	connector := newFakeConnector()
	pool, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	warmDone := make(chan struct{})
	var warm *Lease
	go func() {
		defer close(warmDone)
		warm, err = pool.Warm(context.Background(), peerquic.ClassInteractive, ModeDirectQUIC, NetworkUnknown)
	}()
	attempt := <-connector.started
	connection := &fakeConnection{}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	<-warmDone
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.Leases != 0 || !snapshot.Selected || snapshot.Path != PathDirectQUIC {
		t.Fatalf("warm snapshot=%+v err=%v", snapshot, err)
	}
	time.Sleep(40 * time.Millisecond)
	if connection.closeCount() != 0 {
		t.Fatal("warm carrier closed while warm hold was active")
	}
	relay := &fakeConnection{}
	pool.mu.Lock()
	state := pool.classLocked(peerquic.ClassInteractive)
	direct := state.selected
	state.standby = &managedConnection{selection: Selection{Generation: state.generation, Path: PathRelayQUIC, Connection: relay}}
	if !pool.failHealthLocked(peerquic.ClassInteractive, direct) {
		pool.mu.Unlock()
		t.Fatal("warm direct failure was not promoted")
	}
	pool.mu.Unlock()
	snapshot, err = pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.Leases != 0 || snapshot.Path != PathRelayQUIC || !snapshot.Selected {
		t.Fatalf("warm failover snapshot=%+v err=%v", snapshot, err)
	}
	time.Sleep(40 * time.Millisecond)
	if relay.closeCount() != 0 {
		t.Fatal("warm relay closed after direct promotion")
	}
	warm.Release()
	deadline := time.Now().Add(time.Second)
	for relay.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if connection.closeCount() != 1 || relay.closeCount() != 1 {
		t.Fatalf("warm carrier closes direct=%d relay=%d", connection.closeCount(), relay.closeCount())
	}
	_ = pool.Close()
}

type recordingCandidateSource struct {
	mu       sync.Mutex
	attempts []Attempt
	contexts []context.Context
	started  chan struct{}
	result   chan connectResult
}

func (s *recordingCandidateSource) OpenCandidate(ctx context.Context, attempt Attempt) (Connection, error) {
	s.mu.Lock()
	s.attempts = append(s.attempts, attempt)
	s.contexts = append(s.contexts, ctx)
	s.mu.Unlock()
	s.started <- struct{}{}
	select {
	case result := <-s.result:
		return result.connection, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestPoolReplenishesConsumedInitialWSSWithFreshSingleFlightAttempt(t *testing.T) {
	source := &recordingCandidateSource{started: make(chan struct{}, 2), result: make(chan connectResult, 2)}
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, CandidateSource: source})
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeConnection{}
	initialWSS := &fakeConnection{}
	future := make(chan StandbyResult, 1)
	pool.mu.Lock()
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 7
	state.mode = ModeRelayRace
	state.policySet = true
	state.selected = &managedConnection{selection: Selection{Generation: 7, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}
	syncEntryRoles(state)
	pool.adoptStandbyFutureLocked(peerquic.ClassInteractive, state, future)
	pool.mu.Unlock()
	future <- StandbyResult{Selection: Selection{Generation: 7, Path: PathWSS, Connection: initialWSS}}
	close(future)

	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		ready := state.standby != nil && state.standby.selection.Connection == initialWSS && state.standbyFuture == nil
		pool.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial standby future did not complete")
		}
		time.Sleep(time.Millisecond)
	}

	pool.mu.Lock()
	pool.failHealthLocked(peerquic.ClassInteractive, state.standby)
	// A second observation while the request is in flight must remain single-flight.
	pool.ensureStandbyReplenishmentLocked(peerquic.ClassInteractive, state)
	pool.mu.Unlock()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("fresh WSS replenishment did not start")
	}
	select {
	case <-source.started:
		t.Fatal("missing fallback started more than one replenishment")
	case <-time.After(20 * time.Millisecond):
	}
	freshWSS := &fakeConnection{}
	source.result <- connectResult{connection: freshWSS}
	deadline = time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		adopted := state.standby != nil && state.standby.selection.Connection == freshWSS
		pool.mu.Unlock()
		if adopted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh WSS candidate was not adopted")
		}
		time.Sleep(time.Millisecond)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.attempts) != 1 || source.attempts[0] != (Attempt{Generation: 7, Path: PathWSS}) {
		t.Fatalf("fresh attempts=%+v", source.attempts)
	}
	if len(source.contexts) != 1 || source.contexts[0].Err() != context.Canceled {
		t.Fatalf("replenishment context was not fresh and bounded: contexts=%d err=%v", len(source.contexts), source.contexts[0].Err())
	}
	if initialWSS.closeCount() != 1 || freshWSS.closeCount() != 0 {
		t.Fatalf("candidate closes initial=%d fresh=%d", initialWSS.closeCount(), freshWSS.closeCount())
	}
}

func TestPoolRetriesFailedWSSReplenishmentWithFreshAttempt(t *testing.T) {
	source := &recordingCandidateSource{started: make(chan struct{}, 3), result: make(chan connectResult, 3)}
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, CandidateSource: source})
	if err != nil {
		t.Fatal(err)
	}
	timers := &fakeIdleTimers{}
	pool.after = timers.after
	relay := &fakeConnection{}
	pool.mu.Lock()
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 9
	state.mode = ModeRelayRace
	state.policySet = true
	state.selected = &managedConnection{selection: Selection{Generation: 9, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}
	syncEntryRoles(state)
	pool.ensureStandbyReplenishmentLocked(peerquic.ClassInteractive, state)
	pool.mu.Unlock()

	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("first replenishment did not start")
	}
	invalid := &fakeConnection{}
	invalid.state = StateFailed
	source.result <- connectResult{connection: invalid}
	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		waiting := state.replenishment != nil && state.replenishment.retry != nil
		pool.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed replenishment did not schedule retry")
		}
		time.Sleep(time.Millisecond)
	}
	retry := timers.timer(t, 0)
	if retry.delay != standbyReplenishmentBackoff {
		t.Fatalf("retry delay=%v", retry.delay)
	}
	retry.fire()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("fresh replenishment did not start after failure")
	}
	fresh := &fakeConnection{}
	source.result <- connectResult{connection: fresh}
	deadline = time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		adopted := state.standby != nil && state.standby.selection.Connection == fresh && state.replenishment == nil
		pool.mu.Unlock()
		if adopted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh retry candidate was not adopted")
		}
		time.Sleep(time.Millisecond)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.attempts) != 2 || source.attempts[0] != (Attempt{Generation: 9, Path: PathWSS}) || source.attempts[1] != (Attempt{Generation: 9, Path: PathWSS}) {
		t.Fatalf("attempts=%+v", source.attempts)
	}
	if len(source.contexts) != 2 || source.contexts[0] == source.contexts[1] {
		t.Fatalf("replenishment did not use fresh contexts: %d", len(source.contexts))
	}
	if invalid.closeCount() != 1 {
		t.Fatalf("invalid replenishment closes=%d", invalid.closeCount())
	}
}

func TestPoolDoesNotReplenishTrustedRetainedWSS(t *testing.T) {
	source := &recordingCandidateSource{started: make(chan struct{}, 1), result: make(chan connectResult, 1)}
	pool, err := NewPool(testRacer(t, newFakeConnector()), PoolConfig{IdleGrace: time.Minute, CandidateSource: source})
	if err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	state := pool.classLocked(peerquic.ClassInteractive)
	state.generation = 11
	state.mode = ModeAuto
	state.policySet = true
	state.selected = &managedConnection{selection: Selection{Generation: 11, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	retained := &fakeConnection{}
	state.standby = &managedConnection{selection: Selection{Generation: 11, Path: PathWSS, Connection: retained}}
	syncEntryRoles(state)
	pool.ensureStandbyReplenishmentLocked(peerquic.ClassInteractive, state)
	pool.mu.Unlock()
	select {
	case <-source.started:
		t.Fatal("trusted retained WSS triggered replenishment")
	case <-time.After(20 * time.Millisecond):
	}
	if retained.closeCount() != 0 {
		t.Fatal("trusted retained WSS was closed")
	}
}
