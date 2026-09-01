package tunnelmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

type blockingNetworkStateStore struct {
	StateStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingNetworkStateStore) Snapshot() (hoststate.State, uint64, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.StateStore.Snapshot()
}

func TestNetworkRecoveryCoordinatorFansOutAndPreservesActiveOnFailure(t *testing.T) {
	now := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	firstSnapshot := tunnelSnapshotFor(t, "tunnel_01", 1, "active")
	secondSnapshot := tunnelSnapshotFor(t, "tunnel_02", 1, "active")
	firstLKG, secondLKG := firstSnapshot, secondSnapshot
	store := &memoryStateStore{state: hoststate.State{
		Tunnels: []hoststate.Tunnel{
			{ID: "tunnel_01", StableEndpointID: testManagedTunnelEndpointID, DesiredState: "active", DesiredGeneration: 1, AppliedGeneration: 1, DesiredSnapshot: firstSnapshot, LastKnownGood: &firstLKG, UpdatedAt: now},
			{ID: "tunnel_02", StableEndpointID: testManagedTunnelEndpointID2, DesiredState: "active", DesiredGeneration: 1, AppliedGeneration: 1, DesiredSnapshot: secondSnapshot, LastKnownGood: &secondLKG, UpdatedAt: now},
		},
		RouteGenerations: []hoststate.RouteGeneration{{TunnelID: "tunnel_01", RouteID: "route_01", Generation: 1}, {TunnelID: "tunnel_02", RouteID: "route_02", Generation: 1}},
		Connectors: []hoststate.Connector{
			{ID: "connector_01", TunnelID: "tunnel_01", HostID: "host_01", Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_01", Generation: 1}, RotationGeneration: 1, LastAppliedGeneration: 1},
			{ID: "connector_02", TunnelID: "tunnel_02", HostID: "host_01", Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_02", Generation: 1}, RotationGeneration: 1, LastAppliedGeneration: 1},
		},
	}, revision: 1}
	oldFirst, oldSecond := &fakeActive{}, &fakeActive{}
	newFirst, newSecond := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {
		{probe: ProbeResult{Ready: true}, active: oldFirst},
		{probe: ProbeResult{Ready: true}, active: oldSecond},
		{probe: ProbeResult{Ready: true}, active: newFirst},
		{probe: ProbeResult{Ready: true}, active: newSecond},
	}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewNetworkRecoveryCoordinator(NetworkRecoveryCoordinatorConfig{
		Manager: manager,
		Factory: func(_ context.Context, tunnel hoststate.Tunnel, connector hoststate.Connector) (networkrecovery.Identity, networkrecovery.CarrierReplacer, error) {
			identity := networkrecovery.Identity{EnvironmentID: "env_01", MachineID: connector.HostID, TunnelID: tunnel.ID, ConnectorID: connector.ID}
			replacer, replacerErr := NewNetworkCarrierReplacer(manager, identity)
			return identity, replacer, replacerErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	event := networkmonitor.Event{Generation: 21, Reasons: networkmonitor.ReasonDefaultRoute | networkmonitor.ReasonProxy, Rebind: true, Viable: true}
	coordinator.HandleNetworkEvent(event)
	if err := coordinator.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstActive, firstOK := manager.ActiveForTunnel("tunnel_01")
	if !firstOK || firstActive == oldFirst || firstActive == nil {
		t.Fatalf("first active=%v ok=%t requests=%d health=%+v", firstActive, firstOK, len(factory.requests), coordinator.HealthSnapshots())
	}
	secondActive, secondOK := manager.ActiveForTunnel("tunnel_02")
	if !secondOK || secondActive == oldSecond || secondActive == nil || secondActive == firstActive {
		t.Fatalf("second active=%v ok=%t first=%v", secondActive, secondOK, firstActive)
	}
	prepared := len(factory.requests)
	coordinator.HandleNetworkEvent(event)
	if err := coordinator.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != prepared {
		t.Fatalf("same network event staged another carrier: prepared=%d want=%d", len(factory.requests), prepared)
	}
	failedEvent := networkmonitor.Event{Generation: 22, Reasons: networkmonitor.ReasonViability, Rebind: true, Viable: true}
	coordinator.HandleNetworkEvent(failedEvent)
	if err := coordinator.Flush(context.Background()); err == nil {
		t.Fatal("missing candidate unexpectedly succeeded")
	}
	if active, ok := manager.ActiveForTunnel("tunnel_01"); !ok || active != firstActive {
		t.Fatalf("failed replacement changed first active=%v ok=%t", active, ok)
	}
	health, ok := coordinator.Health("tunnel_01")
	if !ok || health.State != networkrecovery.StateDegraded || health.NetworkGeneration != 22 || health.NextRetryAt.IsZero() {
		t.Fatalf("failed replacement health=%+v ok=%t", health, ok)
	}
	if err := coordinator.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinator.HandleNetworkEvent(networkmonitor.Event{Generation: 23, Reasons: networkmonitor.ReasonWake, Rebind: true, Viable: true})
	if err := coordinator.Flush(context.Background()); !errors.Is(err, ErrNetworkRecoveryNotStarted) {
		t.Fatalf("post-shutdown flush=%v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkRecoveryCoordinatorCallbackCoalescesWhileWorkerIsBlocked(t *testing.T) {
	now := time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)
	base := &memoryStateStore{state: hoststate.State{}, revision: 1}
	manager := newTestManager(t, base, &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	blocked := &blockingNetworkStateStore{StateStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	manager.config.Store = blocked
	coordinator, err := NewNetworkRecoveryCoordinator(NetworkRecoveryCoordinatorConfig{
		Manager: manager,
		Factory: func(context.Context, hoststate.Tunnel, hoststate.Connector) (networkrecovery.Identity, networkrecovery.CarrierReplacer, error) {
			return networkrecovery.Identity{}, nil, errors.New("factory must not be reached without an active tunnel")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinator.HandleNetworkEvent(networkmonitor.Event{Generation: 7, Reasons: networkmonitor.ReasonDefaultRoute, Rebind: true, Viable: true})
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("network recovery worker did not reach blocked snapshot")
	}
	returned := make(chan struct{})
	go func() {
		coordinator.HandleNetworkEvent(networkmonitor.Event{Generation: 8, Reasons: networkmonitor.ReasonProxy, Rebind: true, Viable: true})
		coordinator.HandleNetworkEvent(networkmonitor.Event{Generation: 9, Reasons: networkmonitor.ReasonWake, Rebind: true, Viable: true})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("network monitor callback blocked behind store snapshot")
	}
	coordinator.mu.Lock()
	pending := coordinator.pending
	coordinator.mu.Unlock()
	if pending == nil || pending.Generation != 9 || pending.Reasons != networkmonitor.ReasonWake {
		t.Fatalf("coalesced pending event=%+v", pending)
	}
	close(blocked.release)
	if err := coordinator.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkRecoveryCoordinatorCancelsBlockedFactoryOnShutdown(t *testing.T) {
	now := time.Date(2026, 8, 31, 17, 0, 0, 0, time.UTC)
	store, _ := networkState(t)
	active := &fakeActive{}
	managerFactory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, managerFactory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	factoryStarted := make(chan struct{})
	factoryCanceled := make(chan struct{})
	coordinator, err := NewNetworkRecoveryCoordinator(NetworkRecoveryCoordinatorConfig{
		Manager: manager,
		Factory: func(ctx context.Context, _ hoststate.Tunnel, _ hoststate.Connector) (networkrecovery.Identity, networkrecovery.CarrierReplacer, error) {
			close(factoryStarted)
			<-ctx.Done()
			close(factoryCanceled)
			return networkrecovery.Identity{}, nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinator.HandleNetworkEvent(networkmonitor.Event{Generation: 31, Reasons: networkmonitor.ReasonDNS, Rebind: true, Viable: true})
	select {
	case <-factoryStarted:
	case <-time.After(time.Second):
		t.Fatal("network recovery factory was not started")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := coordinator.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown with cancellable factory: %v", err)
	}
	select {
	case <-factoryCanceled:
	case <-time.After(time.Second):
		t.Fatal("factory did not observe coordinator cancellation")
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
