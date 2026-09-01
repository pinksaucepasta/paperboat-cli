package tunnelmanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

func TestCoordinatedConfigApplierStagesDesiredThenWaitsForExactRuntimeReadiness(t *testing.T) {
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 7}
	releaseProbe := make(chan struct{})
	oldActive, nextActive := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true, HealthyRoutes: []string{"route_01"}}, active: oldActive}},
		2: {{probeFn: func(ctx context.Context) (ProbeResult, error) {
			select {
			case <-releaseProbe:
				return ProbeResult{Ready: true, HealthyRoutes: []string{"route_01"}}, nil
			case <-ctx.Done():
				return ProbeResult{}, ctx.Err()
			}
		}, active: nextActive}},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	applier := &CoordinatedConfigApplier{
		State:   &connectorprotocol.HostStateApplier{Store: store, Clock: connectorprotocol.ClockFunc(func() time.Time { return now }), StableEndpointID: testManagedTunnelEndpointID},
		Manager: manager,
	}
	snapshot, err := connectorprotocol.NewSnapshot("tunnel_01", 2, tunnelSnapshot(t, 2).Payload)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = "account_01", "connector_01", "session_02", 2
	prepared, err := applier.PrepareSnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	staged, _, err := store.Snapshot()
	if err != nil || staged.Tunnels[0].DesiredGeneration != 2 || staged.Tunnels[0].AppliedGeneration != 1 || staged.Tunnels[0].LastKnownGood.Generation != 1 || staged.Connectors[0].LastAppliedGeneration != 1 {
		t.Fatalf("desired stage changed LKG: state=%+v err=%v", staged, err)
	}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, waitErr := applier.WaitReady(short, snapshot)
	cancel()
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("readiness before origin probe = %v", waitErr)
	}
	close(releaseProbe)
	manager.Notify()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	readiness, err := applier.WaitReady(wait, snapshot)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if !readiness.EdgeReady || !readiness.RouteReady || !readiness.OriginReady || readiness.SessionID != snapshot.SessionID || readiness.ProcessGeneration != snapshot.ProcessGeneration || readiness.Generation != 2 || readiness.ContentHash != snapshot.ContentHash {
		t.Fatalf("readiness = %+v", readiness)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatalf("protocol activation did not observe exact manager promotion: %v", err)
	}
	// Join the serialized reconcile path before inspecting the old fake's
	// drain counters; readiness publishes the replacement before drain ends.
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	committed, _, err := store.Snapshot()
	if err != nil || committed.Tunnels[0].AppliedGeneration != 2 || committed.Tunnels[0].LastKnownGood.Generation != 2 || committed.Connectors[0].LastAppliedGeneration != 2 {
		t.Fatalf("manager promotion = %+v err=%v", committed, err)
	}
	if oldActive.drains != 1 || oldActive.closes != 1 {
		t.Fatalf("old active drain/close = %d/%d", oldActive.drains, oldActive.closes)
	}
}

func TestCoordinatedConfigApplierPreservesLKGWhenCandidateFails(t *testing.T) {
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 3}
	oldActive := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: oldActive}},
		// PrepareSnapshot wakes the background reconcile loop before the
		// explicit ReconcileNow below joins it. Supply one deterministic failed
		// candidate for each serialized attempt so scheduling order cannot turn
		// the LKG assertion into a fake-factory exhaustion failure.
		2: {
			{probe: ProbeResult{Ready: false, FailedRoutes: []string{"route_01"}}, probeErr: ErrOriginUnavailable},
			{probe: ProbeResult{Ready: false, FailedRoutes: []string{"route_01"}}, probeErr: ErrOriginUnavailable},
		},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	applier := &CoordinatedConfigApplier{State: &connectorprotocol.HostStateApplier{Store: store, Clock: connectorprotocol.ClockFunc(func() time.Time { return now }), StableEndpointID: testManagedTunnelEndpointID}, Manager: manager}
	snapshot, err := connectorprotocol.NewSnapshot("tunnel_01", 2, tunnelSnapshot(t, 2).Payload)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = "account_01", "connector_01", "session_02", 2
	prepared, err := applier.PrepareSnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatalf("failed desired reconcile returned a global error = %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, err = applier.WaitReady(short, snapshot)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("failed candidate readiness = %v", err)
	}
	if err := prepared.Activate(context.Background()); !errors.Is(err, connectorprotocol.ErrNotReady) {
		t.Fatalf("failed candidate activation = %v", err)
	}
	state, _, err := store.Snapshot()
	if err != nil || state.Tunnels[0].DesiredGeneration != 2 || state.Tunnels[0].AppliedGeneration != 1 || state.Tunnels[0].LastKnownGood.Generation != 1 || state.Connectors[0].LastAppliedGeneration != 1 {
		t.Fatalf("failed candidate replaced LKG: state=%+v err=%v", state, err)
	}
	if oldActive.drains != 0 || oldActive.closes != 0 {
		t.Fatalf("failed candidate interrupted old active: %d/%d", oldActive.drains, oldActive.closes)
	}
}

func TestCoordinatedConfigApplierWaitsForPausedAndDeletedRuntimeState(t *testing.T) {
	for _, desiredState := range []string{"paused", "deleted"} {
		t.Run(desiredState, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
			store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 5}
			oldActive := &fakeActive{}
			factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
				1: {{probe: ProbeResult{Ready: true}, active: oldActive}},
			}, err: map[uint64]error{}}
			manager := newTestManager(t, store, factory, now, func(Observation) {})
			if err := manager.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer manager.Shutdown(context.Background())
			applier := &CoordinatedConfigApplier{State: &connectorprotocol.HostStateApplier{Store: store, Clock: connectorprotocol.ClockFunc(func() time.Time { return now }), StableEndpointID: testManagedTunnelEndpointID}, Manager: manager}
			snapshot, err := connectorprotocol.NewSnapshot("tunnel_01", 2, tunnelSnapshotDesired(t, 2, desiredState).Payload)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = "account_01", "connector_01", "session_02", 2
			prepared, err := applier.PrepareSnapshot(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(context.Background(), time.Second)
			readiness, err := applier.WaitReady(wait, snapshot)
			cancel()
			if err != nil || !readiness.EdgeReady || !readiness.RouteReady || !readiness.OriginReady {
				t.Fatalf("%s readiness=%+v err=%v", desiredState, readiness, err)
			}
			if err := prepared.Activate(context.Background()); err != nil {
				t.Fatalf("%s protocol activation: %v", desiredState, err)
			}
			if err := manager.ReconcileNow(context.Background()); err != nil {
				t.Fatal(err)
			}
			state, _, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if desiredState == "paused" {
				if len(state.Tunnels) != 1 || state.Tunnels[0].AppliedGeneration != 2 || state.Tunnels[0].DesiredState != "paused" || state.Connectors[0].LastAppliedGeneration != 2 {
					t.Fatalf("paused durable state=%+v", state)
				}
			} else if len(state.Tunnels) != 0 || len(state.Connectors) != 0 {
				t.Fatalf("deleted durable state=%+v", state)
			}
			if oldActive.drains != 1 || oldActive.closes != 1 {
				t.Fatalf("%s old active drain/close=%d/%d", desiredState, oldActive.drains, oldActive.closes)
			}
		})
	}
}

func TestDeletedReadinessWaitsForActiveDrainAfterDesiredStateRemoval(t *testing.T) {
	store := &memoryStateStore{revision: 6}
	active := &fakeActive{tunnelID: "tunnel_01", connectorID: "connector_01", generation: 1, hash: "old-hash"}
	manager := &Manager{config: Config{Store: store}, active: map[string]Active{"tunnel_01": active}}
	applier := &CoordinatedConfigApplier{Manager: manager}
	snapshot := connectorprotocol.Snapshot{TunnelID: "tunnel_01"}
	ready, terminal, err := applier.readiness(snapshot, "deleted")
	if ready || terminal || err != nil {
		t.Fatalf("readiness during drain = (%v, %v, %v)", ready, terminal, err)
	}
	delete(manager.active, "tunnel_01")
	ready, terminal, err = applier.readiness(snapshot, "deleted")
	if !ready || terminal || err != nil {
		t.Fatalf("readiness after drain = (%v, %v, %v)", ready, terminal, err)
	}
}
