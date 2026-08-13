package peerrelay

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportActivityKeepsStandbyWhileConsumerIsActive(t *testing.T) {
	var canceled atomic.Int32
	activity := newTransportActivity(func() { canceled.Add(1) })
	activity.Ready()
	activity.Open()
	time.Sleep(50 * time.Millisecond)
	if canceled.Load() != 0 {
		t.Fatal("active consumer expired reusable transport")
	}
	activity.Close()
	if canceled.Load() != 0 {
		t.Fatal("stream migration canceled retained transport")
	}
	activity.Stop()
	if canceled.Load() != 1 {
		t.Fatalf("transport stop cancellations=%d", canceled.Load())
	}
}

func TestCandidateOwnersAreIndependentAndParentCancellationFansOut(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	first := newCandidateOwner(parent, nil)
	second := newCandidateOwner(parent, nil)
	first.Stop()
	select {
	case <-first.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stopped candidate remained alive")
	}
	select {
	case <-second.ctx.Done():
		t.Fatal("one candidate canceled its sibling")
	default:
	}
	select {
	case <-parent.Done():
		t.Fatal("child candidate canceled descriptor authority")
	default:
	}
	cancelParent()
	select {
	case <-second.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("descriptor revocation did not cancel retained candidate")
	}
	second.Stop()
}

func TestCandidateOwnerClosesExactlyOnce(t *testing.T) {
	var closed atomic.Int32
	owner := newCandidateOwner(context.Background(), func(stage string) {
		if stage == "carrier_closed" {
			closed.Add(1)
		}
	})
	owner.Stop()
	owner.Stop()
	if closed.Load() != 1 {
		t.Fatalf("candidate close events=%d", closed.Load())
	}
}

func TestTransportActivityReadyWithoutConsumerDoesNotExpire(t *testing.T) {
	canceled := make(chan struct{})
	activity := newTransportActivity(func() { close(canceled) })
	activity.Ready()
	select {
	case <-canceled:
		t.Fatal("ready standby expired without an ownership event")
	case <-time.After(50 * time.Millisecond):
	}
	activity.Stop()
}

func TestTransportActivityFinalConsumerDoesNotCloseCandidate(t *testing.T) {
	canceled := make(chan struct{})
	activity := newTransportActivity(func() { close(canceled) })
	activity.Ready()
	activity.Open()
	activity.Close()
	select {
	case <-canceled:
		t.Fatal("final stream release closed candidate-owned attempt")
	case <-time.After(50 * time.Millisecond):
	}
	activity.Stop()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("attempt stop did not close candidate lifetime")
	}
}

func TestTransportActivityLifecycleEventsAndStopAreIdempotent(t *testing.T) {
	var canceled atomic.Int32
	events := make(chan string, 4)
	activity := newTransportActivity(func() { canceled.Add(1) }, func(event string) { events <- event })
	activity.Ready()
	activity.Open()
	activity.Close()
	activity.Stop()
	activity.Stop()
	close(events)
	var got []string
	for event := range events {
		got = append(got, event)
	}
	want := []string{"stream_activity_zero", "carrier_retained_idle", "carrier_closed"}
	if len(got) != len(want) {
		t.Fatalf("events=%v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("events=%v", got)
		}
	}
	if canceled.Load() != 1 {
		t.Fatalf("transport cancellations=%d", canceled.Load())
	}
}
