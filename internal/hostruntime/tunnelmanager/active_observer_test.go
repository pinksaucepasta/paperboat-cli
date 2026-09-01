package tunnelmanager

import (
	"context"
	"testing"
	"time"
)

func TestManagerActiveObserverSeesGenerationReplacementAndRemoval(t *testing.T) {
	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 1), revision: 1}
	lkg, desired := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: lkg}},
		2: {{probe: ProbeResult{Ready: true}, active: desired}},
	}, err: map[uint64]error{}}
	var changes []ActiveChange
	manager, err := New(Config{
		Store: store, Factory: factory, HostID: "host_01", Clock: func() time.Time { return now },
		ReconcileInterval: time.Hour, ApplyTimeout: time.Second, DrainTimeout: time.Second,
		Report: func(Observation) {}, ActiveObserver: func(change ActiveChange) { changes = append(changes, change) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].Previous != nil || changes[0].Current != lkg || changes[1].Previous != lkg || changes[1].Current != desired {
		t.Fatalf("active changes after replacement = %+v", changes)
	}
	if active, ok := manager.ActiveForTunnel("tunnel_01"); !ok || active != desired {
		t.Fatalf("active lookup = %v, ok=%v", active, ok)
	}
	if snapshot := manager.ActiveSnapshot(); len(snapshot) != 1 || snapshot["tunnel_01"] != desired {
		t.Fatalf("active snapshot = %+v", snapshot)
	}
	store.mu.Lock()
	store.state.Tunnels = nil
	store.state.Connectors = nil
	store.state.RouteGenerations = nil
	store.revision++
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active, ok := manager.ActiveForTunnel("tunnel_01"); ok || active != nil {
		t.Fatalf("removed active lookup = %v, ok=%v", active, ok)
	}
	if len(changes) != 3 || changes[2].Previous != desired || changes[2].Current != nil {
		t.Fatalf("active changes after removal = %+v", changes)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
