package tunnelmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
)

type trk35ProbeGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *trk35ProbeGate) probe(ctx context.Context) (ProbeResult, error) {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
		return ProbeResult{Ready: true}, nil
	case <-ctx.Done():
		return ProbeResult{}, ctx.Err()
	}
}

type trk35DrainTrackingActive struct {
	*fakeActive
	drainDone     chan struct{}
	drainOnce     sync.Once
	drainDeadline time.Time
	hasDeadline   bool
}

func (a *trk35DrainTrackingActive) Drain(ctx context.Context) error {
	a.drains++
	a.drainDeadline, a.hasDeadline = ctx.Deadline()
	a.drainOnce.Do(func() { close(a.drainDone) })
	return nil
}

func trk35NetworkActive(t *testing.T, generation uint64, hash string) *trk35DrainTrackingActive {
	t.Helper()
	return &trk35DrainTrackingActive{
		fakeActive: &fakeActive{
			tunnelID: "tunnel_01", connectorID: "connector_01", generation: generation, hash: hash,
		},
		drainDone: make(chan struct{}),
	}
}

func TestTRK35NetworkReplacementFencesOutOfOrderCompletionAndBoundsDrain(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store, snapshot := networkState(t)
	old := trk35NetworkActive(t, snapshot.Generation, snapshot.ContentHash)
	stale := trk35NetworkActive(t, snapshot.Generation, snapshot.ContentHash)
	newer := trk35NetworkActive(t, snapshot.Generation, snapshot.ContentHash)
	probeGate := &trk35ProbeGate{entered: make(chan struct{}), release: make(chan struct{})}
	initial := &fakeCandidate{
		probe: ProbeResult{Ready: true},
		activateFn: func(context.Context) (Active, error) {
			return old, nil
		},
	}
	staleCandidate := &fakeCandidate{
		probeFn: probeGate.probe,
		activateFn: func(context.Context) (Active, error) {
			return stale, nil
		},
	}
	newerCandidate := &fakeCandidate{
		probe: ProbeResult{Ready: true},
		activateFn: func(context.Context) (Active, error) {
			return newer, nil
		},
	}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{snapshot.Generation: {initial, staleCandidate, newerCandidate}}, err: map[uint64]error{}}
	manager := newTestManager(t, store, factory, now, func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacer, err := NewNetworkCarrierReplacer(manager, networkIdentity())
	if err != nil {
		t.Fatal(err)
	}

	if !manager.ObserveNetworkGeneration(20) {
		t.Fatal("first network generation was not recorded")
	}
	staleDone := make(chan error, 1)
	go func() {
		_, replaceErr := replacer.Replace(context.Background(), networkrecoveryRequest(20, 1))
		staleDone <- replaceErr
	}()
	<-probeGate.entered
	if !manager.ObserveNetworkGeneration(21) {
		t.Fatal("newer network generation was not recorded")
	}
	newerDone := make(chan error, 1)
	go func() {
		_, replaceErr := replacer.Replace(context.Background(), networkrecoveryRequest(21, 1))
		newerDone <- replaceErr
	}()
	close(probeGate.release)
	if err := <-staleDone; !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale replacement error=%v", err)
	}
	if err := <-newerDone; err != nil {
		t.Fatalf("newer replacement error=%v", err)
	}

	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != newer {
		t.Fatalf("newer active=%v ok=%t", active, ok)
	}
	if old.drains != 1 || old.closes != 1 {
		t.Fatalf("old active lifecycle drain=%d close=%d", old.drains, old.closes)
	}
	<-old.drainDone
	if !old.hasDeadline || old.drainDeadline.IsZero() {
		t.Fatal("old active drain did not receive a bounded context")
	}
	if stale.closes != 1 {
		t.Fatalf("stale candidate active handle was not closed: %d", stale.closes)
	}

	prepared := len(factory.requests)
	if _, err := replacer.Replace(context.Background(), networkrecoveryRequest(20, 2)); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale replay error=%v", err)
	}
	result, err := replacer.Replace(context.Background(), networkrecoveryRequest(21, 2))
	if err != nil || !result.Ready || result.NetworkGeneration != 21 {
		t.Fatalf("duplicate newer result=%+v err=%v", result, err)
	}
	if len(factory.requests) != prepared {
		t.Fatalf("duplicate network completion staged another carrier: requests=%d want=%d", len(factory.requests), prepared)
	}
	active, ok = manager.ActiveForTunnel("tunnel_01")
	if !ok || active != newer || old.drains != 1 || old.closes != 1 {
		t.Fatalf("duplicate replay changed active=%v ok=%t old=(%d,%d)", active, ok, old.drains, old.closes)
	}
	observed, applied, inFlight, ok := manager.NetworkRecoveryState("tunnel_01")
	if !ok || observed != 21 || applied != 21 || inFlight != 0 {
		t.Fatalf("network fence=(%d,%d,%d,%t)", observed, applied, inFlight, ok)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func networkrecoveryRequest(generation uint64, attempt uint32) networkrecovery.ReplacementRequest {
	return networkrecovery.ReplacementRequest{Identity: networkIdentity(), NetworkGeneration: generation, Reasons: networkrecovery.ReasonDNS | networkrecovery.ReasonDefaultRoute, Attempt: attempt}
}
