package transportmanager

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type testConnection struct{ closes atomic.Uint64 }

func (*testConnection) State() connectionmanager.State { return connectionmanager.StateTrusted }
func (c *testConnection) Close() error                 { c.closes.Add(1); return nil }

type testConnector struct{ connection *testConnection }

func (c testConnector) Connect(context.Context, connectionmanager.Attempt) (connectionmanager.Connection, error) {
	return c.connection, nil
}

func testFactory(t *testing.T, calls *atomic.Uint64, connection *testConnection) Factory {
	t.Helper()
	return func(context.Context) (*connectionmanager.Pool, error) {
		calls.Add(1)
		racer, err := connectionmanager.NewRacer(connectionmanager.Config{RelayDelay: time.Millisecond, WSSDelay: 2 * time.Millisecond, ConnectTimeout: time.Second}, testConnector{connection: connection})
		if err != nil {
			return nil, err
		}
		return connectionmanager.NewPool(racer, connectionmanager.PoolConfig{IdleGrace: time.Minute})
	}
}

func TestManagerReusesOnePoolAcrossConcurrentConsumers(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	connection := &testConnection{}
	factory := testFactory(t, &calls, connection)
	leases := make(chan *Lease, 8)
	errs := make(chan error, 8)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, acquireErr := manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, factory)
			leases <- lease
			errs <- acquireErr
		}()
	}
	wait.Wait()
	acquired := make([]*Lease, 0, 8)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		lease := <-leases
		if lease.Connection() != connection || lease.Path() != connectionmanager.PathDirectQUIC {
			t.Fatal("unexpected shared lease")
		}
		acquired = append(acquired, lease)
	}
	if calls.Load() != 1 {
		t.Fatalf("factory calls=%d", calls.Load())
	}
	if connection.closes.Load() != 0 {
		t.Fatal("pool closed with active consumers")
	}
	for _, lease := range acquired {
		lease.Release()
	}
	if connection.closes.Load() != 1 {
		t.Fatal("last consumer did not close pool")
	}
}

func TestManagerAcquireCachedNeverConstructsState(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.AcquireCached(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty cache error=%v", err)
	}
	var calls atomic.Uint64
	connection := &testConnection{}
	created, err := manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, connection))
	if err != nil {
		t.Fatal(err)
	}
	cached, err := manager.AcquireCached(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Connection() != connection || calls.Load() != 1 {
		t.Fatalf("cached connection=%p calls=%d", cached.Connection(), calls.Load())
	}
	cached.Release()
	created.Release()
}

func TestManagerCanceledCreatorIsNotRetained(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, acquireErr := manager.Acquire(ctx, "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, func(factoryCtx context.Context) (*connectionmanager.Pool, error) {
			close(started)
			<-factoryCtx.Done()
			return nil, factoryCtx.Err()
		})
		result <- acquireErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("manager creator did not start")
	}
	cancel()
	select {
	case acquireErr := <-result:
		if !errors.Is(acquireErr, context.Canceled) {
			t.Fatalf("acquire error=%v", acquireErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled creator did not return")
	}
	if snapshots := manager.Snapshots(); len(snapshots) != 0 {
		t.Fatalf("canceled creator retained snapshots=%+v", snapshots)
	}
}

func TestManagerLastConsumerClosesMachinePoolImmediately(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	connection := &testConnection{}
	factory := func(context.Context) (*connectionmanager.Pool, error) {
		calls.Add(1)
		racer, racerErr := connectionmanager.NewRacer(connectionmanager.Config{RelayDelay: time.Millisecond, WSSDelay: 2 * time.Millisecond, ConnectTimeout: time.Second}, testConnector{connection: connection})
		if racerErr != nil {
			return nil, racerErr
		}
		return connectionmanager.NewPool(racer, connectionmanager.PoolConfig{IdleGrace: 20 * time.Millisecond})
	}
	lease, err := manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, factory)
	if err != nil {
		t.Fatal(err)
	}
	pool := lease.Pool()
	lease.Release()
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || !snapshot.Closed || snapshot.Selected || snapshot.Warm {
		t.Fatalf("released snapshot=%+v err=%v", snapshot, err)
	}
	if _, err := manager.AcquireCached(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("released machine remained cached: %v", err)
	}
	if calls.Load() != 1 || connection.closes.Load() != 1 {
		t.Fatalf("calls=%d closes=%d", calls.Load(), connection.closes.Load())
	}
}

func TestManagerInvalidationClosesAndRebuildsCarrier(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	first := &testConnection{}
	lease, err := manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, first))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if first.closes.Load() != 1 {
		t.Fatalf("old closes=%d", first.closes.Load())
	}
	second := &testConnection{}
	lease, err = manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, second))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || second.closes.Load() != 0 {
		t.Fatalf("calls=%d new closes=%d", calls.Load(), second.closes.Load())
	}
	lease.Release()
}

func TestManagerExpiresAfterLastLeaseGrace(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	connection := &testConnection{}
	lease, err := manager.Acquire(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, connection))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	deadline := time.Now().Add(time.Second)
	for connection.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if connection.closes.Load() != 1 {
		t.Fatal("carrier did not expire")
	}
}

func TestManagerSnapshotsAndInvalidatesAll(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	connections := []*testConnection{{}, {}}
	leases := make([]*Lease, 0, 2)
	for index, key := range []string{"machine:1", "machine:2"} {
		lease, acquireErr := manager.Acquire(context.Background(), key, peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, connections[index]))
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		leases = append(leases, lease)
	}
	if snapshots := manager.Snapshots(); len(snapshots) != 2 {
		t.Fatalf("snapshots=%+v", snapshots)
	}
	if err := manager.InvalidateAll(); err != nil {
		t.Fatal(err)
	}
	if snapshots := manager.Snapshots(); len(snapshots) != 0 {
		t.Fatalf("snapshots after invalidation=%+v", snapshots)
	}
	for _, lease := range leases {
		lease.Release()
	}
	for index, connection := range connections {
		if connection.closes.Load() != 1 {
			t.Fatalf("connection %d closes=%d", index, connection.closes.Load())
		}
	}
}

func TestManagerInvalidatePrefixLeavesOtherScopesIntact(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	first, second := &testConnection{}, &testConnection{}
	firstLease, err := manager.Acquire(context.Background(), "machine:1:1:interactive", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, first))
	if err != nil {
		t.Fatal(err)
	}
	secondLease, err := manager.Acquire(context.Background(), "machine:2:1:interactive", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, second))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.InvalidatePrefix("machine:1:"); err != nil {
		t.Fatal(err)
	}
	if first.closes.Load() != 1 || second.closes.Load() != 0 {
		t.Fatalf("closes first=%d second=%d", first.closes.Load(), second.closes.Load())
	}
	if snapshots := manager.Snapshots(); len(snapshots) != 1 || snapshots[0].Key != "machine:2:1:interactive" {
		t.Fatalf("snapshots=%+v", snapshots)
	}
	firstLease.Release()
	secondLease.Release()
}

func TestManagerRetirePrefixLetsActiveLeaseDrain(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var calls atomic.Uint64
	connection := &testConnection{}
	lease, err := manager.Acquire(context.Background(), "machine:1:1:interactive", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, testFactory(t, &calls, connection))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RetirePrefix("machine:1:"); err != nil {
		t.Fatal(err)
	}
	if connection.closes.Load() != 0 {
		t.Fatal("retirement closed an active application")
	}
	if _, err := manager.AcquireCached(context.Background(), "machine:1:1:interactive", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("retired pool remained reusable: %v", err)
	}
	lease.Release()
	if connection.closes.Load() != 1 {
		t.Fatalf("final release closes=%d", connection.closes.Load())
	}
}

func TestManagerOwnedCleanupRunsOnceAfterPoolClose(t *testing.T) {
	manager, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var factoryCalls, cleanupCalls atomic.Uint64
	connection := &testConnection{}
	lease, err := manager.AcquireOwned(context.Background(), "machine:1", peerquic.ClassInteractive, connectionmanager.ModeDirectQUIC, connectionmanager.NetworkUnknown, func(ctx context.Context) (*connectionmanager.Pool, func() error, error) {
		pool, createErr := testFactory(t, &factoryCalls, connection)(ctx)
		return pool, func() error {
			cleanupCalls.Add(1)
			if connection.closes.Load() == 0 {
				t.Error("cleanup ran before pool close")
			}
			return nil
		}, createErr
	})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	deadline := time.Now().Add(time.Second)
	for cleanupCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if cleanupCalls.Load() != 1 || connection.closes.Load() != 1 {
		t.Fatalf("cleanup=%d closes=%d", cleanupCalls.Load(), connection.closes.Load())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("cleanup after repeated close=%d", cleanupCalls.Load())
	}
}
