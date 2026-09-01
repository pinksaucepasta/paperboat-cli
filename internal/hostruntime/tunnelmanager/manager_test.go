package tunnelmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

const (
	testManagedTunnelEndpointID  = "123e4567-e89b-12d3-a456-426614174000"
	testManagedTunnelEndpointID2 = "123e4567-e89b-12d3-a456-426614174001"
)

type memoryStateStore struct {
	mu              sync.Mutex
	state           hoststate.State
	revision        uint64
	conflicts       int
	conflictHook    func(*memoryStateStore)
	snapshotFailure error
}

func (s *memoryStateStore) Snapshot() (hoststate.State, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshotFailure != nil {
		return hoststate.State{}, 0, s.snapshotFailure
	}
	return cloneTestState(s.state), s.revision, nil
}

func (s *memoryStateStore) Commit(expected uint64, next hoststate.State) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conflicts > 0 {
		s.conflicts--
		if s.conflictHook != nil {
			hook := s.conflictHook
			s.conflictHook = nil
			hook(s)
		}
		return 0, hoststate.ErrConflict
	}
	if expected != s.revision {
		return 0, hoststate.ErrConflict
	}
	if err := next.Validate(); err != nil {
		return 0, err
	}
	s.state = cloneTestState(next)
	s.revision++
	return s.revision, nil
}

type fakeFactory struct {
	mu         sync.Mutex
	requests   []ApplyRequest
	candidates map[uint64][]*fakeCandidate
	err        map[uint64]error
}

func (f *fakeFactory) Prepare(_ context.Context, request ApplyRequest) (Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if err := f.err[request.Snapshot.Generation]; err != nil {
		return nil, err
	}
	items := f.candidates[request.Snapshot.Generation]
	if len(items) == 0 {
		return nil, errors.New("missing fake candidate")
	}
	candidate := items[0]
	f.candidates[request.Snapshot.Generation] = items[1:]
	candidate.request = request
	return candidate, nil
}

type fakeCandidate struct {
	request    ApplyRequest
	probe      ProbeResult
	probeErr   error
	probeFn    func(context.Context) (ProbeResult, error)
	activateFn func(context.Context) (Active, error)
	active     *fakeActive
	aborted    int
}

func (c *fakeCandidate) ProbeOrigins(ctx context.Context) (ProbeResult, error) {
	if c.probeFn != nil {
		return c.probeFn(ctx)
	}
	return c.probe, c.probeErr
}

func (c *fakeCandidate) Activate(ctx context.Context) (Active, error) {
	if c.activateFn != nil {
		return c.activateFn(ctx)
	}
	if c.active == nil {
		c.active = &fakeActive{}
	}
	c.active.tunnelID = c.request.Tunnel.ID
	c.active.connectorID = c.request.Connector.ID
	c.active.generation = c.request.Snapshot.Generation
	c.active.hash = c.request.Snapshot.ContentHash
	return c.active, nil
}

func (c *fakeCandidate) Abort(context.Context) error { c.aborted++; return nil }

type fakeActive struct {
	tunnelID, connectorID, hash string
	generation                  uint64
	drains, closes              int
	closeFn                     func(context.Context) error
}

func (a *fakeActive) TunnelID() string            { return a.tunnelID }
func (a *fakeActive) ConnectorID() string         { return a.connectorID }
func (a *fakeActive) Generation() uint64          { return a.generation }
func (a *fakeActive) ContentHash() string         { return a.hash }
func (a *fakeActive) Drain(context.Context) error { a.drains++; return nil }
func (a *fakeActive) Close(ctx context.Context) error {
	a.closes++
	if a.closeFn != nil {
		return a.closeFn(ctx)
	}
	return nil
}

func TestManagerReattachesLKGThenAtomicallyPromotesDesired(t *testing.T) {
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	state := tunnelState(t, 2, 1)
	store := &memoryStateStore{state: state, revision: 7}
	lkgActive, desiredActive := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: false, FailedRoutes: []string{"route_01"}}, active: lkgActive}},
		2: {{probe: ProbeResult{Ready: true, HealthyRoutes: []string{"route_01"}}, active: desiredActive}},
	}, err: map[uint64]error{}}
	var observations []Observation
	manager := newTestManager(t, store, factory, now, func(observation Observation) { observations = append(observations, observation) })
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := manager.ResourceCounts()["tunnels"]; got != 1 {
		t.Fatalf("active tunnels=%d", got)
	}
	identities := manager.WorkloadIdentities()
	if len(identities) != 1 || identities[0] != "tunnel_01\x00connector_01\x002\x00"+desiredActive.hash {
		t.Fatalf("workload identities=%q", identities)
	}
	if len(factory.requests) != 2 || !factory.requests[0].Recovery || factory.requests[1].Recovery {
		t.Fatalf("apply order=%+v", factory.requests)
	}
	if factory.requests[0].Tunnel.ID != "tunnel_01" || factory.requests[0].Connector.ID != "connector_01" || factory.requests[1].Tunnel.StableEndpointID != testManagedTunnelEndpointID {
		t.Fatalf("stable identity changed: %+v", factory.requests)
	}
	if lkgActive.drains != 1 || lkgActive.closes != 1 {
		got, _, _ := store.Snapshot()
		t.Fatalf("old generation drain=%d close=%d requests=%+v observations=%+v state=%+v", lkgActive.drains, lkgActive.closes, factory.requests, observations, got)
	}
	got, _, _ := store.Snapshot()
	if got.Tunnels[0].AppliedGeneration != 2 || got.Tunnels[0].LastKnownGood == nil || got.Tunnels[0].LastKnownGood.Generation != 2 || got.Connectors[0].LastAppliedGeneration != 2 {
		t.Fatalf("promoted state=%+v", got)
	}
	if len(observations) != 3 || observations[0].Code != CodeOriginUnavailable || observations[1].Code != CodeReattached || observations[2].Code != CodeReady {
		t.Fatalf("observations=%+v", observations)
	}
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != 2 {
		t.Fatalf("duplicate generation prepared %d times", len(factory.requests))
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if desiredActive.drains != 1 || desiredActive.closes != 1 {
		t.Fatalf("shutdown drain=%d close=%d", desiredActive.drains, desiredActive.closes)
	}
}

func TestManagerKeepsLKGWhenDesiredOriginFails(t *testing.T) {
	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 1), revision: 1}
	lkg, rejectedActive := &fakeActive{}, &fakeActive{}
	rejected := &fakeCandidate{probe: ProbeResult{Ready: false, FailureCode: CodeOriginUnavailable}, active: rejectedActive}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: lkg}},
		2: {rejected},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active := manager.activeFor("tunnel_01"); active == nil || active.Generation() != 1 {
		t.Fatalf("active generation=%v", active)
	}
	got, _, _ := store.Snapshot()
	if got.Tunnels[0].AppliedGeneration != 1 || got.Tunnels[0].LastKnownGood.Generation != 1 {
		t.Fatalf("failed desired replaced LKG: %+v", got.Tunnels[0])
	}
	if rejected.aborted != 1 || rejectedActive.closes != 0 || rejectedActive.generation != 0 {
		t.Fatalf("rejected candidate was not aborted safely: candidate=%+v active=%+v", rejected, rejectedActive)
	}
	if len(factory.requests) != 2 || factory.requests[0].Snapshot.Generation != 1 || factory.requests[1].Snapshot.Generation != 2 {
		t.Fatalf("requests=%+v", factory.requests)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerPersistenceConflictNeverReplacesActiveLKG(t *testing.T) {
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 1), revision: 1, conflicts: 4}
	lkg, desired := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: lkg}},
		2: {{probe: ProbeResult{Ready: true}, active: desired}},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active := manager.activeFor("tunnel_01"); active == nil || active.Generation() != 1 {
		t.Fatalf("conflicting desired replaced LKG: %v", active)
	}
	if desired.closes != 1 || lkg.drains != 0 {
		t.Fatalf("candidate close=%d old drain=%d", desired.closes, lkg.drains)
	}
	got, _, _ := store.Snapshot()
	if got.Tunnels[0].AppliedGeneration != 1 {
		t.Fatalf("conflicting persistence advanced state: %+v", got.Tunnels[0])
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerNeverPromotesAfterConnectorIdentityDisappears(t *testing.T) {
	now := time.Date(2026, 8, 30, 22, 30, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 1), revision: 1, conflicts: 1}
	store.conflictHook = func(value *memoryStateStore) {
		value.state.Connectors = nil
		value.revision++
	}
	lkg, desired := &fakeActive{}, &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: lkg}},
		2: {{probe: ProbeResult{Ready: true}, active: desired}},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current := manager.activeFor("tunnel_01"); current != lkg || current.Generation() != 1 {
		t.Fatalf("connector removal replaced LKG: %v", current)
	}
	if desired.closes != 1 || lkg.drains != 0 {
		t.Fatalf("candidate close=%d old drain=%d", desired.closes, lkg.drains)
	}
	got, _, _ := store.Snapshot()
	if got.Tunnels[0].AppliedGeneration != 1 || len(got.Connectors) != 0 {
		t.Fatalf("identity removal was overwritten: %+v", got)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerRejectsDesiredGenerationRollback(t *testing.T) {
	now := time.Date(2026, 8, 30, 22, 45, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 2), revision: 2}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{2: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state = tunnelState(t, 1, 1)
	store.revision++
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current := manager.activeFor("tunnel_01"); current != active || current.Generation() != 2 || active.drains != 0 || active.closes != 0 {
		t.Fatalf("rollback replaced current runtime: %+v", current)
	}
	if len(factory.requests) != 1 {
		t.Fatalf("rollback prepared another candidate: %+v", factory.requests)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerRejectsStalePauseWithoutDowngradingLKG(t *testing.T) {
	now := time.Date(2026, 8, 30, 22, 50, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 2, 2), revision: 2}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{2: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stale := tunnelState(t, 1, 1)
	paused := tunnelSnapshotDesired(t, 1, "paused")
	stale.Tunnels[0].DesiredState = "paused"
	stale.Tunnels[0].DesiredSnapshot = paused
	stale.Tunnels[0].LastKnownGood = &paused
	store.mu.Lock()
	store.state = stale
	store.revision++
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current := manager.activeFor("tunnel_01"); current != active || current.Generation() != 2 || active.drains != 0 || active.closes != 0 {
		t.Fatalf("stale pause downgraded active generation: %+v", current)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerCrashRecoveryUsesSameTunnelAndConnectorIdentity(t *testing.T) {
	now := time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC)
	state := tunnelState(t, 1, 1)
	store := &memoryStateStore{state: state, revision: 1}
	firstActive := &fakeActive{}
	firstFactory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: firstActive}}}, err: map[uint64]error{}}
	first := newTestManager(t, store, firstFactory, now, func(Observation) {})
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	recoveredActive := &fakeActive{}
	recoveredFactory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: recoveredActive}}}, err: map[uint64]error{}}
	recovered := newTestManager(t, store, recoveredFactory, now.Add(time.Minute), func(Observation) {})
	if err := recovered.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(recoveredFactory.requests) != 1 || recoveredFactory.requests[0].Tunnel.ID != "tunnel_01" || recoveredFactory.requests[0].Connector.ID != "connector_01" || !recoveredFactory.requests[0].Recovery {
		t.Fatalf("recovery identity=%+v", recoveredFactory.requests)
	}
	_ = recovered.Shutdown(context.Background())
}

func TestManagerRejectsDuplicateLocalConnectorIdentity(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	state := tunnelState(t, 1, 1)
	duplicate := state.Connectors[0]
	duplicate.ID = "connector_02"
	state.Connectors = append(state.Connectors, duplicate)
	store := &memoryStateStore{state: state, revision: 1}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	var observed Observation
	manager := newTestManager(t, store, factory, now, func(value Observation) { observed = value })
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != 0 || observed.Code != CodeConnectorUnavailable || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("duplicate connector accepted requests=%d observation=%+v", len(factory.requests), observed)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerPreservesTrafficWhenDesiredStoreIsUnavailable(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.snapshotFailure = errors.New("control-plane cache temporarily unavailable")
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err == nil {
		t.Fatal("unavailable desired store was reported as success")
	}
	if current := manager.activeFor("tunnel_01"); current != active || active.drains != 0 || active.closes != 0 {
		t.Fatalf("store outage disturbed LKG current=%v drains=%d closes=%d", current, active.drains, active.closes)
	}
	store.mu.Lock()
	store.snapshotFailure = nil
	store.mu.Unlock()
	_ = manager.Shutdown(context.Background())
}

func TestManagerUsesCachedLKGDuringControlPlaneOutage(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	var observations []Observation
	manager, err := New(Config{
		Store: store, Factory: factory, HostID: "host_01", Clock: func() time.Time { return now },
		Refresh:           func(context.Context) error { return errors.New("control plane offline") },
		ReconcileInterval: time.Hour, ApplyTimeout: time.Second, DrainTimeout: time.Second,
		Report: func(observation Observation) { observations = append(observations, observation) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current := manager.activeFor("tunnel_01"); current != active || current.Generation() != 1 {
		t.Fatalf("control outage did not restore cached LKG: %v", current)
	}
	if len(factory.requests) != 1 || !factory.requests[0].Recovery {
		t.Fatalf("control outage requests=%+v", factory.requests)
	}
	if len(observations) != 2 || observations[0].Code != CodeControlUnavailable || observations[1].Code != CodeReattached || !observations[0].Retryable {
		t.Fatalf("control outage observations=%+v", observations)
	}
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != 1 || active.drains != 0 || active.closes != 0 {
		t.Fatalf("offline reconcile disturbed traffic requests=%d drains=%d closes=%d", len(factory.requests), active.drains, active.closes)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerPauseStopsTrafficAndPersistsPausedGeneration(t *testing.T) {
	now := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	var observations []Observation
	manager := newTestManager(t, store, factory, now, func(value Observation) { observations = append(observations, value) })
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	paused := tunnelSnapshotDesired(t, 2, "paused")
	store.state.Tunnels[0].DesiredState = "paused"
	store.state.Tunnels[0].DesiredGeneration = 2
	store.state.Tunnels[0].DesiredSnapshot = paused
	store.state.Tunnels[0].UpdatedAt = now.Add(time.Minute)
	store.revision++
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current := manager.activeFor("tunnel_01"); current != nil {
		t.Fatalf("paused tunnel remained active: %v", current)
	}
	if active.drains != 1 || active.closes != 1 || len(factory.requests) != 1 {
		t.Fatalf("pause lifecycle drains=%d closes=%d prepares=%d", active.drains, active.closes, len(factory.requests))
	}
	got, _, _ := store.Snapshot()
	if got.Tunnels[0].AppliedGeneration != 2 || got.Tunnels[0].LastKnownGood == nil || got.Tunnels[0].LastKnownGood.ContentHash != paused.ContentHash || got.Connectors[0].LastAppliedGeneration != 2 {
		t.Fatalf("paused generation not persisted: %+v", got)
	}
	if observations[len(observations)-1].Code != CodePaused {
		t.Fatalf("pause observation=%+v", observations)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerNeverReattachesPausedLKGAfterRestart(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	state := tunnelState(t, 2, 2)
	paused := tunnelSnapshotDesired(t, 2, "paused")
	state.Tunnels[0].DesiredState = "paused"
	state.Tunnels[0].DesiredSnapshot = paused
	state.Tunnels[0].LastKnownGood = &paused
	store := &memoryStateStore{state: state, revision: 4}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != 0 || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("paused LKG was restored requests=%+v active=%d", factory.requests, manager.ResourceCounts()["tunnels"])
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerResumeSkipsPausedLKGAndActivatesDesired(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC)
	state := tunnelState(t, 3, 2)
	paused := tunnelSnapshotDesired(t, 2, "paused")
	state.Tunnels[0].LastKnownGood = &paused
	state.Connectors[0].LastAppliedGeneration = 2
	store := &memoryStateStore{state: state, revision: 5}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{3: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(factory.requests) != 1 || factory.requests[0].Recovery || factory.requests[0].Snapshot.Generation != 3 || active.generation != 3 {
		t.Fatalf("resume requests=%+v active=%+v", factory.requests, active)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerRejectsReconcileOutsideLifecycle(t *testing.T) {
	manager := newTestManager(t, &memoryStateStore{state: tunnelState(t, 1, 1)}, &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}, time.Now(), func(Observation) {})
	if err := manager.ReconcileNow(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("reconcile before start error=%v", err)
	}
}

func TestManagerStartFailureClosesAlreadyReattachedRuntime(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 30, 0, 0, time.UTC)
	state := tunnelState(t, 1, 1)
	secondSnapshot := tunnelSnapshotFor(t, "tunnel_02", 2, "active")
	state.Tunnels = append(state.Tunnels, hoststate.Tunnel{ID: "tunnel_02", StableEndpointID: testManagedTunnelEndpointID2, DesiredState: "active", DesiredGeneration: 2, AppliedGeneration: 2, DesiredSnapshot: secondSnapshot, LastKnownGood: &secondSnapshot, UpdatedAt: now})
	state.RouteGenerations = append(state.RouteGenerations, hoststate.RouteGeneration{TunnelID: "tunnel_02", RouteID: "route_02", Generation: 2})
	state.Connectors = append(state.Connectors, hoststate.Connector{ID: "connector_02", TunnelID: "tunnel_02", HostID: "host_01", Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_02", Generation: 1}, RotationGeneration: 1, LastAppliedGeneration: 2})
	store := &memoryStateStore{state: state, revision: 1}
	firstActive := &fakeActive{}
	ctx, cancel := context.WithCancel(context.Background())
	second := &fakeCandidate{probeFn: func(context.Context) (ProbeResult, error) {
		cancel()
		return ProbeResult{}, context.Canceled
	}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: firstActive}},
		2: {second},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("start error=%v", err)
	}
	if firstActive.drains != 1 || firstActive.closes != 1 || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("partial start leaked runtime drains=%d closes=%d active=%d", firstActive.drains, firstActive.closes, manager.ResourceCounts()["tunnels"])
	}
	if second.aborted != 1 {
		t.Fatalf("canceled candidate aborts=%d", second.aborted)
	}
}

func TestManagerShutdownFencesLateCandidateActivation(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 45, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	old := &fakeActive{}
	entered := make(chan struct{})
	late := &fakeActive{tunnelID: "tunnel_01", connectorID: "connector_01", generation: 2}
	desired := tunnelSnapshot(t, 2)
	late.hash = desired.ContentHash
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{
		1: {{probe: ProbeResult{Ready: true}, active: old}},
		2: {{probe: ProbeResult{Ready: true}, activateFn: func(ctx context.Context) (Active, error) {
			close(entered)
			<-ctx.Done()
			return late, nil
		}}},
	}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.Tunnels[0].DesiredGeneration = 2
	store.state.Tunnels[0].DesiredSnapshot = desired
	store.state.Tunnels[0].UpdatedAt = now.Add(time.Minute)
	store.revision++
	store.mu.Unlock()
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- manager.ReconcileNow(context.Background()) }()
	<-entered
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-reconcileDone; !errors.Is(err, context.Canceled) && !errors.Is(err, ErrNotStarted) {
		t.Fatalf("late reconcile error=%v", err)
	}
	if late.closes != 1 || old.drains != 1 || old.closes != 1 || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("shutdown fence late closes=%d old drains=%d old closes=%d active=%d", late.closes, old.drains, old.closes, manager.ResourceCounts()["tunnels"])
	}
}

func TestManagerShutdownContinuesAfterCallerDeadline(t *testing.T) {
	now := time.Date(2026, 8, 31, 5, 50, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	active := &fakeActive{closeFn: func(context.Context) error {
		close(closeStarted)
		<-releaseClose
		return nil
	}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- manager.Shutdown(shutdownCtx) }()
	<-closeStarted
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first shutdown error=%v", err)
	}
	close(releaseClose)
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active.closes != 1 || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("continued shutdown closes=%d active=%d", active.closes, manager.ResourceCounts()["tunnels"])
	}
}

func TestManagerDrainsTunnelRemovedFromAuthoritativeCache(t *testing.T) {
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 1}
	active := &fakeActive{}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	var observations []Observation
	manager := newTestManager(t, store, factory, now, func(value Observation) { observations = append(observations, value) })
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state = hoststate.State{}
	store.revision++
	store.mu.Unlock()
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active.drains != 1 || active.closes != 1 || manager.ResourceCounts()["tunnels"] != 0 {
		t.Fatalf("removed tunnel lifecycle drains=%d closes=%d active=%d", active.drains, active.closes, manager.ResourceCounts()["tunnels"])
	}
	last := observations[len(observations)-1]
	if last.Code != CodeStopped || last.TunnelID != "tunnel_01" || last.ConnectorID != "connector_01" || last.AppliedGeneration != 1 {
		t.Fatalf("removed tunnel observation=%+v", last)
	}
	_ = manager.Shutdown(context.Background())
}

func TestManagerReturnsUntypedFactoryFailureInsteadOfReportingFalseAvailability(t *testing.T) {
	now := time.Date(2026, 8, 31, 6, 5, 0, 0, time.UTC)
	store := &memoryStateStore{state: tunnelState(t, 1, 0), revision: 1}
	unexpected := errors.New("credential store corrupt")
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{1: unexpected}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); !errors.Is(err, unexpected) {
		t.Fatalf("start error = %v", err)
	}
}

func newTestManager(t *testing.T, store StateStore, factory Factory, now time.Time, report func(Observation)) *Manager {
	t.Helper()
	manager, err := New(Config{Store: store, Factory: factory, HostID: "host_01", Clock: func() time.Time { return now }, ReconcileInterval: time.Hour, ApplyTimeout: time.Second, DrainTimeout: time.Second, Report: report})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func tunnelState(t *testing.T, desiredGeneration, appliedGeneration uint64) hoststate.State {
	t.Helper()
	desired := tunnelSnapshot(t, desiredGeneration)
	var lkg *hoststate.ConfigSnapshot
	if appliedGeneration > 0 {
		value := tunnelSnapshot(t, appliedGeneration)
		lkg = &value
	}
	return hoststate.State{
		Tunnels:          []hoststate.Tunnel{{ID: "tunnel_01", StableEndpointID: testManagedTunnelEndpointID, DesiredState: "active", DesiredGeneration: desiredGeneration, AppliedGeneration: appliedGeneration, DesiredSnapshot: desired, LastKnownGood: lkg, UpdatedAt: time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC)}},
		RouteGenerations: []hoststate.RouteGeneration{{TunnelID: "tunnel_01", RouteID: "route_01", Generation: desiredGeneration}},
		Connectors:       []hoststate.Connector{{ID: "connector_01", TunnelID: "tunnel_01", HostID: "host_01", Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_01", Generation: 1}, RotationGeneration: 1, LastAppliedGeneration: appliedGeneration}},
	}
}

func tunnelSnapshot(t *testing.T, generation uint64) hoststate.ConfigSnapshot {
	return tunnelSnapshotDesired(t, generation, "active")
}

func tunnelSnapshotDesired(t *testing.T, generation uint64, desiredState string) hoststate.ConfigSnapshot {
	return tunnelSnapshotFor(t, "tunnel_01", generation, desiredState)
}

func tunnelSnapshotFor(t *testing.T, tunnelID string, generation uint64, desiredState string) hoststate.ConfigSnapshot {
	t.Helper()
	routeID := "route_01"
	endpoint := "https://" + testManagedTunnelEndpointID + ".tunnel.example.test"
	if tunnelID == "tunnel_02" {
		routeID = "route_02"
		endpoint = "https://" + testManagedTunnelEndpointID2 + ".tunnel.example.test"
	}
	payload := fmt.Sprintf(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":%q,"generation":%d,"name":"demo","desired_state":%q,"access_mode":"public","stable_endpoint":%q,"expires_at":null,"routes":[{"id":%q,"name":"default","protocol":"http","match_type":"catch_all","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`, tunnelID, generation, desiredState, endpoint, routeID)
	snapshot, err := hoststate.NewConfigSnapshot(tunnelID, generation, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func cloneTestState(state hoststate.State) hoststate.State {
	raw, _ := json.Marshal(state)
	var result hoststate.State
	_ = json.Unmarshal(raw, &result)
	return result
}
