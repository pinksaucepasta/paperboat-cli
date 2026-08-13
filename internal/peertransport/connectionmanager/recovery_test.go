package connectionmanager

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type fakeRecoveryScheduler struct {
	starts  chan int32
	stopped chan int32
	count   atomic.Int32
}

type blockingRecoveryScheduler struct {
	started chan struct{}
	release chan struct{}
	once    atomic.Bool
}

func (s *blockingRecoveryScheduler) Run(ctx context.Context) error {
	if s.once.CompareAndSwap(false, true) {
		close(s.started)
		<-s.release
		return nil
	}
	<-ctx.Done()
	return context.Cause(ctx)
}

func newFakeRecoveryScheduler() *fakeRecoveryScheduler {
	return &fakeRecoveryScheduler{starts: make(chan int32, 8), stopped: make(chan int32, 8)}
}

func (s *fakeRecoveryScheduler) Run(ctx context.Context) error {
	generation := s.count.Add(1)
	s.starts <- generation
	<-ctx.Done()
	s.stopped <- generation
	return ctx.Err()
}

func TestRecoverySupervisorFollowsRelayLeaseLifecycleAndPromotion(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	relay := &fakeConnection{}
	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 1, selected: &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: relay}, applicationLeases: 1}}
	pool.classes[peerquic.ClassTransfer] = &classState{generation: 1, selected: &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}}
	pool.signalLocked()
	pool.mu.Unlock()

	interactive := newFakeRecoveryScheduler()
	preview := newFakeRecoveryScheduler()
	supervisor, err := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: interactive, Preview: preview})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.starts, 1, "relay scheduler start")
	assertNoValue(t, preview.starts, "inactive preview scheduler")

	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive].selected.applicationLeases = 0
	pool.signalLocked()
	pool.mu.Unlock()
	wantValue(t, interactive.stopped, 1, "zero-lease scheduler stop")

	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive].selected.applicationLeases = 1
	pool.classes[peerquic.ClassInteractive].selected.selection.Path = PathWSS
	pool.signalLocked()
	pool.mu.Unlock()
	wantValue(t, interactive.starts, 2, "renewed WSS lease scheduler start")

	direct := &fakeConnection{}
	if err := pool.PromoteDirect(peerquic.ClassInteractive, direct); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.stopped, 2, "promotion scheduler stop")
	assertNoValue(t, interactive.starts, "scheduler restart after direct promotion")
	assertNoValue(t, preview.starts, "transfer activity did not start preview recovery")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func TestRecoverySupervisorDoesNotCompeteWithPendingInitialUpgrade(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive] = &classState{
		generation: 1,
		selected: &managedConnection{
			selection:         Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}},
			applicationLeases: 1,
		},
		// The initial race still owns its late direct/WSS result channel.
		// Starting recovery here creates a second
		// independent direct promotion owner for the same logical streams.
		upgradePending: true,
	}
	pool.signalLocked()
	pool.mu.Unlock()

	interactive := newFakeRecoveryScheduler()
	supervisor, err := NewRecoverySupervisor(RecoverySupervisorConfig{
		Pool:        pool,
		Interactive: interactive,
		Preview:     newFakeRecoveryScheduler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertNoValue(t, interactive.starts, "recovery competed with initial upgrade")

	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive].upgradePending = false
	pool.signalLocked()
	pool.mu.Unlock()
	wantValue(t, interactive.starts, 1, "recovery after initial upgrade completed")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func TestRecoverySupervisorRestartsWhenSelectedFallbackPathChanges(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive] = &classState{generation: 1, selected: &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}}
	pool.mu.Unlock()
	interactive := newFakeRecoveryScheduler()
	supervisor, _ := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: interactive, Preview: newFakeRecoveryScheduler()})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.starts, 1, "relay recovery start")

	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive].selected.selection.Path = PathWSS
	pool.signalLocked()
	pool.mu.Unlock()
	wantValue(t, interactive.stopped, 1, "relay recovery stop after WSS promotion")
	wantValue(t, interactive.starts, 2, "WSS recovery restart")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.stopped, 2, "WSS recovery shutdown")
	_ = pool.Close()
}

func TestRecoverySupervisorRestartsOnWSSWithLeaseOnDrainingSource(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	relayEntry := &managedConnection{selection: Selection{Generation: 1, Path: PathRelayQUIC, Connection: &fakeConnection{}}, applicationLeases: 1}
	wssEntry := &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: &fakeConnection{}}}
	state := &classState{generation: 1, mode: ModeAuto, policySet: true, selected: relayEntry, standby: wssEntry}
	syncEntryRoles(state, relayEntry, wssEntry)
	pool.classes[peerquic.ClassInteractive] = state
	interactive := newFakeRecoveryScheduler()
	supervisor, _ := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: interactive, Preview: newFakeRecoveryScheduler()})
	if err := supervisor.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.starts, 1, "relay direct-recovery start")
	pool.mu.Lock()
	state.selected, state.standby, state.draining = wssEntry, nil, relayEntry
	syncEntryRoles(state, relayEntry, wssEntry)
	pool.signalLocked()
	pool.mu.Unlock()
	wantValue(t, interactive.stopped, 1, "direct recovery canceled after WSS promotion")
	wantValue(t, interactive.starts, 2, "relay recovery started with draining lease")
	if err := supervisor.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func TestRecoverySupervisorShutdownCancelsAllClassSchedulers(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	pool.mu.Lock()
	for _, class := range []peerquic.Class{peerquic.ClassInteractive, peerquic.ClassPreview} {
		pool.classes[class] = &classState{generation: 1, selected: &managedConnection{selection: Selection{Generation: 1, Path: PathWSS, Connection: &fakeConnection{}}, applicationLeases: 1}}
	}
	pool.mu.Unlock()
	interactive, preview := newFakeRecoveryScheduler(), newFakeRecoveryScheduler()
	supervisor, _ := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: interactive, Preview: preview})
	_ = supervisor.Start(context.Background())
	wantValue(t, interactive.starts, 1, "interactive start")
	wantValue(t, preview.starts, 1, "preview start")
	if err := supervisor.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantValue(t, interactive.stopped, 1, "interactive stop")
	wantValue(t, preview.stopped, 1, "preview stop")
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func TestRecoverySupervisorRejectsMissingOwnersAndDuplicateStart(t *testing.T) {
	if _, err := NewRecoverySupervisor(RecoverySupervisorConfig{}); err == nil {
		t.Fatal("missing recovery owners accepted")
	}
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	supervisor, _ := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: newFakeRecoveryScheduler(), Preview: newFakeRecoveryScheduler()})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background()); err == nil {
		t.Fatal("duplicate start accepted")
	}
	if err := supervisor.Shutdown(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func TestRecoverySupervisorTimeoutRetainsOwnershipUntilRunnerExits(t *testing.T) {
	pool, _ := NewPool(testRacer(t, newFakeConnector()), DevelopmentPoolConfig())
	pool.mu.Lock()
	pool.classes[peerquic.ClassInteractive] = &classState{selected: &managedConnection{selection: Selection{Path: PathWSS, Connection: &fakeConnection{}}, applicationLeases: 1}}
	pool.mu.Unlock()
	blocking := &blockingRecoveryScheduler{started: make(chan struct{}), release: make(chan struct{})}
	supervisor, _ := NewRecoverySupervisor(RecoverySupervisorConfig{Pool: pool, Interactive: blocking, Preview: newFakeRecoveryScheduler()})
	_ = supervisor.Start(context.Background())
	<-blocking.started
	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := supervisor.Shutdown(shutdownCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown err=%v", err)
	}
	if err := supervisor.Start(context.Background()); err == nil {
		t.Fatal("restart accepted while prior runner remained active")
	}
	close(blocking.release)
	if err := supervisor.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
}

func wantValue(t *testing.T, values <-chan int32, want int32, name string) {
	t.Helper()
	select {
	case got := <-values:
		if got != want {
			t.Fatalf("%s=%d want=%d", name, got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func assertNoValue(t *testing.T, values <-chan int32, name string) {
	t.Helper()
	select {
	case got := <-values:
		t.Fatalf("unexpected %s: %d", name, got)
	case <-time.After(20 * time.Millisecond):
	}
}
