package tunnelmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
)

func networkIdentity() networkrecovery.Identity {
	return networkrecovery.Identity{EnvironmentID: "env_01", MachineID: "machine_01", TunnelID: "tunnel_01", ConnectorID: "connector_01"}
}

func networkState(t *testing.T) (*memoryStateStore, hoststate.ConfigSnapshot) {
	t.Helper()
	snapshot := tunnelSnapshot(t, 1)
	return &memoryStateStore{state: tunnelState(t, 1, 1), revision: 9}, snapshot
}

func TestNetworkCarrierReplacementSwapsReadyCarrierAndPreservesLKG(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store, snapshot := networkState(t)
	old, replacement := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {
		{probe: ProbeResult{Ready: true}, active: old},
		{probe: ProbeResult{Ready: true}, active: replacement},
	}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentity := manager.WorkloadIdentities()
	if !manager.ObserveNetworkGeneration(7) {
		t.Fatal("network generation was not recorded")
	}
	replacer, err := NewNetworkCarrierReplacer(manager, networkIdentity())
	if err != nil {
		t.Fatal(err)
	}
	result, err := replacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: networkIdentity(), NetworkGeneration: 7, Reasons: networkrecovery.ReasonDefaultRoute, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.NetworkGeneration != 7 || result.CarrierGeneration != snapshot.Generation {
		t.Fatalf("result=%+v", result)
	}
	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != replacement {
		t.Fatalf("active=%v ok=%t", active, ok)
	}
	if old.drains != 1 || old.closes != 1 {
		t.Fatalf("old lifecycle drain=%d close=%d", old.drains, old.closes)
	}
	after, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Tunnels[0].DesiredSnapshot.ContentHash != before.Tunnels[0].DesiredSnapshot.ContentHash || after.Tunnels[0].LastKnownGood.ContentHash != before.Tunnels[0].LastKnownGood.ContentHash || after.Tunnels[0].AppliedGeneration != before.Tunnels[0].AppliedGeneration {
		t.Fatalf("network replacement mutated durable LKG: before=%+v after=%+v", before.Tunnels[0], after.Tunnels[0])
	}
	if got := manager.WorkloadIdentities(); len(got) != 1 || len(beforeIdentity) != 1 || got[0] != beforeIdentity[0] {
		t.Fatalf("logical identity changed before=%q after=%q", beforeIdentity, got)
	}
	if manager.NetworkGeneration() != 7 {
		t.Fatalf("network generation=%d", manager.NetworkGeneration())
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCarrierReplacementIsPerTunnelAndReplaySafe(t *testing.T) {
	now := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	firstSnapshot := tunnelSnapshotFor(t, "tunnel_01", 1, "active")
	secondSnapshot := tunnelSnapshotFor(t, "tunnel_02", 1, "active")
	firstLKG, secondLKG := firstSnapshot, secondSnapshot
	store := &memoryStateStore{state: hoststate.State{
		Tunnels: []hoststate.Tunnel{
			{ID: "tunnel_01", StableEndpointID: testManagedTunnelEndpointID, DesiredState: "active", DesiredGeneration: 1, AppliedGeneration: 1, DesiredSnapshot: firstSnapshot, LastKnownGood: &firstLKG, UpdatedAt: now},
			{ID: "tunnel_02", StableEndpointID: testManagedTunnelEndpointID2, DesiredState: "active", DesiredGeneration: 1, AppliedGeneration: 1, DesiredSnapshot: secondSnapshot, LastKnownGood: &secondLKG, UpdatedAt: now},
		},
		RouteGenerations: []hoststate.RouteGeneration{
			{TunnelID: "tunnel_01", RouteID: "route_01", Generation: 1},
			{TunnelID: "tunnel_02", RouteID: "route_02", Generation: 1},
		},
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
	var observations []Observation
	manager := newTestManager(t, store, factory, now, func(observation Observation) { observations = append(observations, observation) })
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstIdentity := networkIdentity()
	secondIdentity := firstIdentity
	secondIdentity.TunnelID = "tunnel_02"
	secondIdentity.ConnectorID = "connector_02"
	firstReplacer, err := NewNetworkCarrierReplacer(manager, firstIdentity)
	if err != nil {
		t.Fatal(err)
	}
	secondReplacer, err := NewNetworkCarrierReplacer(manager, secondIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.ObserveTunnelNetworkGeneration(firstIdentity.TunnelID, 13) {
		t.Fatal("first tunnel network generation was not recorded")
	}
	if !manager.ObserveTunnelNetworkGeneration(secondIdentity.TunnelID, 13) {
		t.Fatal("second tunnel network generation was not recorded independently")
	}
	if _, err := firstReplacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: firstIdentity, NetworkGeneration: 13, Reasons: networkrecovery.ReasonDefaultRoute, Attempt: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := secondReplacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: secondIdentity, NetworkGeneration: 13, Reasons: networkrecovery.ReasonDefaultRoute, Attempt: 1}); err != nil {
		t.Fatal(err)
	}
	prepared := len(factory.requests)
	if prepared != 4 {
		t.Fatalf("prepared=%d, want startup plus one replacement per tunnel", prepared)
	}
	result, err := firstReplacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: firstIdentity, NetworkGeneration: 13, Reasons: networkrecovery.ReasonDefaultRoute, Attempt: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.CarrierGeneration != newFirst.generation || len(factory.requests) != prepared {
		t.Fatalf("same-generation replay staged another carrier: result=%+v requests=%d", result, len(factory.requests))
	}
	if got, ok := manager.ActiveForTunnel("tunnel_01"); !ok || got != newFirst {
		t.Fatalf("first active=%v ok=%t", got, ok)
	}
	if got, ok := manager.ActiveForTunnel("tunnel_02"); !ok || got != newSecond {
		t.Fatalf("second active=%v ok=%t", got, ok)
	}
	if oldFirst.drains != 1 || oldFirst.closes != 1 || oldSecond.drains != 1 || oldSecond.closes != 1 {
		t.Fatalf("old lifecycle first=(%d,%d) second=(%d,%d)", oldFirst.drains, oldFirst.closes, oldSecond.drains, oldSecond.closes)
	}
	for _, observation := range observations {
		if observation.Code == CodeNetworkReattached && observation.DesiredGeneration != observation.AppliedGeneration {
			t.Fatalf("network reattach changed config generations: %+v", observation)
		}
	}
	firstObserved, firstApplied, firstInFlight, ok := manager.NetworkRecoveryState("tunnel_01")
	if !ok || firstObserved != 13 || firstApplied != 13 || firstInFlight != 0 {
		t.Fatalf("first network state=(%d,%d,%d,%t)", firstObserved, firstApplied, firstInFlight, ok)
	}
	secondObserved, secondApplied, secondInFlight, ok := manager.NetworkRecoveryState("tunnel_02")
	if !ok || secondObserved != 13 || secondApplied != 13 || secondInFlight != 0 {
		t.Fatalf("second network state=(%d,%d,%d,%t)", secondObserved, secondApplied, secondInFlight, ok)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCarrierReplacementFailureLeavesLKGActive(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	store, _ := networkState(t)
	old := &fakeActive{}
	failed := &fakeCandidate{probe: ProbeResult{Ready: false, FailedRoutes: []string{"route_01"}}, probeErr: ErrOriginUnavailable, active: &fakeActive{}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: old}, failed}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.ObserveNetworkGeneration(8)
	replacer, err := NewNetworkCarrierReplacer(manager, networkIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: networkIdentity(), NetworkGeneration: 8, Reasons: networkrecovery.ReasonDNS, Attempt: 1}); !errors.Is(err, ErrOriginUnavailable) {
		t.Fatalf("replacement error=%v", err)
	}
	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != old {
		t.Fatalf("failed replacement changed active=%v ok=%t", active, ok)
	}
	if old.drains != 0 || old.closes != 0 || failed.aborted != 1 {
		t.Fatalf("LKG lifecycle old=(drain %d close %d) failed abort=%d", old.drains, old.closes, failed.aborted)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type delayedNetworkCandidate struct {
	fakeCandidate
	entered chan struct{}
	release chan struct{}
	active  *fakeActive
	once    sync.Once
}

func (c *delayedNetworkCandidate) ProbeOrigins(ctx context.Context) (ProbeResult, error) {
	c.once.Do(func() { close(c.entered) })
	select {
	case <-c.release:
		return ProbeResult{Ready: true}, nil
	case <-ctx.Done():
		return ProbeResult{}, ctx.Err()
	}
}

func (c *delayedNetworkCandidate) Activate(context.Context) (Active, error) {
	return c.active, nil
}

func TestNetworkCarrierReplacementRejectsStaleCompletion(t *testing.T) {
	now := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	store, _ := networkState(t)
	old := &fakeActive{}
	delayed := &delayedNetworkCandidate{entered: make(chan struct{}), release: make(chan struct{}), active: &fakeActive{}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: old}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Append a same-config replacement candidate after initial startup.
	factory.mu.Lock()
	factory.candidates[1] = append(factory.candidates[1], &fakeCandidate{probeFn: delayed.ProbeOrigins, active: delayed.active})
	factory.mu.Unlock()
	manager.ObserveNetworkGeneration(9)
	replacer, err := NewNetworkCarrierReplacer(manager, networkIdentity())
	if err != nil {
		t.Fatal(err)
	}
	resultDone := make(chan error, 1)
	go func() {
		_, replaceErr := replacer.Replace(context.Background(), networkrecovery.ReplacementRequest{Identity: networkIdentity(), NetworkGeneration: 9, Reasons: networkrecovery.ReasonSleepWake, Attempt: 1})
		resultDone <- replaceErr
	}()
	// Wait until the candidate is staged, then advance the network fence before
	// allowing activation. This simulates a second event during replacement.
	select {
	case <-delayed.entered:
	case <-time.After(time.Second):
		t.Fatal("replacement candidate did not stage")
	}
	if !manager.ObserveNetworkGeneration(10) {
		t.Fatal("new network generation was not recorded")
	}
	close(delayed.release)
	if err := <-resultDone; !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale completion error=%v", err)
	}
	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != old || old.drains != 0 || old.closes != 0 {
		t.Fatalf("stale completion changed LKG active=%v ok=%t old=(%d,%d)", active, ok, old.drains, old.closes)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCarrierReplacementCancellationLeavesManagerUsable(t *testing.T) {
	now := time.Date(2026, 8, 31, 13, 30, 0, 0, time.UTC)
	store, _ := networkState(t)
	old := &fakeActive{}
	block := make(chan struct{})
	blocked := &fakeCandidate{probeFn: func(ctx context.Context) (ProbeResult, error) {
		select {
		case <-block:
			return ProbeResult{Ready: true}, nil
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}, active: &fakeActive{}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: old}, blocked}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.ObserveNetworkGeneration(11)
	replacer, err := NewNetworkCarrierReplacer(manager, networkIdentity())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	resultDone := make(chan error, 1)
	go func() {
		_, replaceErr := replacer.Replace(ctx, networkrecovery.ReplacementRequest{Identity: networkIdentity(), NetworkGeneration: 11, Reasons: networkrecovery.ReasonPathViability, Attempt: 1})
		resultDone <- replaceErr
	}()
	cancel()
	if err := <-resultDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != old {
		t.Fatalf("canceled replacement changed active=%v ok=%t", active, ok)
	}
	close(block)
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
