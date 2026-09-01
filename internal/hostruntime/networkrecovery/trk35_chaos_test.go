package networkrecovery

import (
	"context"
	"sync"
	"testing"
)

type trk35StubbornReplacer struct {
	mu       sync.Mutex
	requests []ReplacementRequest
	started  chan ReplacementRequest
	release  chan struct{}
	canceled bool
}

func (r *trk35StubbornReplacer) Replace(ctx context.Context, request ReplacementRequest) (ReplacementResult, error) {
	r.mu.Lock()
	r.requests = append(r.requests, request)
	r.mu.Unlock()
	r.started <- request
	if request.NetworkGeneration == 41 {
		// Deliberately ignore cancellation until the fake carrier finishes
		// staging. The controller must fence this late completion itself.
		<-r.release
		r.mu.Lock()
		r.canceled = ctx.Err() != nil
		r.mu.Unlock()
	}
	return readyResult(identity(), request.NetworkGeneration, request.NetworkGeneration), nil
}

func TestTRK35ControllerCoalescesDNSRouteStormAndFencesStaleCompletion(t *testing.T) {
	clock := newFakeClock()
	replacer := &trk35StubbornReplacer{
		started: make(chan ReplacementRequest, 4),
		release: make(chan struct{}),
	}
	controller := newControllerForTest(t, clock, replacer)

	observe(t, controller, 41, ReasonDNS, true)
	firstDone := make(chan error, 1)
	go func() { firstDone <- controller.Flush(context.Background()) }()
	first := <-replacer.started
	if first.NetworkGeneration != 41 || first.Reasons != ReasonDNS || first.Attempt != 1 {
		t.Fatalf("first replacement=%+v", first)
	}

	// A DNS/default-route reconnect storm arrives while generation 41 is still
	// staging. Same-generation reasons merge, while a late generation-41 event
	// is rejected and cannot erase generation 42.
	observe(t, controller, 42, ReasonDNS, true)
	observe(t, controller, 42, ReasonDefaultRoute, true)
	observe(t, controller, 41, ReasonDNS, true)
	if got := controller.Health(); got.NetworkGeneration != 42 || got.ActiveNetworkGeneration != 0 || got.State != StateDegraded {
		t.Fatalf("storm health before stale completion=%+v", got)
	}

	close(replacer.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("stale completion error=%v", err)
	}
	replacer.mu.Lock()
	canceled := replacer.canceled
	replacer.mu.Unlock()
	if !canceled {
		t.Fatal("new generation did not cancel stale replacement")
	}
	if got := controller.Health(); got.ActiveNetworkGeneration != 0 || got.NetworkGeneration != 42 {
		t.Fatalf("stale completion changed active state=%+v", got)
	}

	if err := controller.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacer.mu.Lock()
	requests := append([]ReplacementRequest(nil), replacer.requests...)
	replacer.mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("replacement requests=%d, want one stale and one coalesced current", len(requests))
	}
	second := requests[1]
	if second.NetworkGeneration != 42 || second.Reasons != ReasonDNS|ReasonDefaultRoute || second.PreviousNetworkGeneration != 0 || second.Attempt != 1 {
		t.Fatalf("coalesced replacement=%+v", second)
	}
	if got := controller.Health(); got.State != StateReady || got.ActiveNetworkGeneration != 42 || got.NetworkGeneration != 42 {
		t.Fatalf("current replacement health=%+v", got)
	}
}
