package peerrelay

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
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

func TestCandidateOwnerAdoptReleaseIsIdempotentAndFenced(t *testing.T) {
	owner := newCandidateOwner(context.Background(), nil)
	id := candidatelease.ID("candidate")
	if err := owner.Configure(id, 7); err != nil {
		t.Fatal(err)
	}
	adopt := candidatelease.Message{Version: 1, Type: candidatelease.Adopt, Candidate: id, LeaseGeneration: 7}
	for range 2 {
		ack, err := owner.Handle(adopt)
		if err != nil || ack.Type != candidatelease.AdoptAck {
			t.Fatalf("adopt ack=%+v err=%v", ack, err)
		}
	}
	if err := owner.Retained(); err != nil {
		t.Fatal(err)
	}
	release := candidatelease.Message{Version: 1, Type: candidatelease.Release, Candidate: id, LeaseGeneration: 7}
	for range 2 {
		ack, err := owner.Handle(release)
		if err != nil || ack.Type != candidatelease.ReleaseAck {
			t.Fatalf("release ack=%+v err=%v", ack, err)
		}
	}
	if _, err := owner.Handle(adopt); !errors.Is(err, candidatelease.ErrFenced) {
		t.Fatalf("adopt after release error=%v", err)
	}
	if _, err := owner.Handle(candidatelease.Message{Version: 1, Type: candidatelease.Release, Candidate: "other", LeaseGeneration: 7}); !errors.Is(err, candidatelease.ErrFenced) {
		t.Fatalf("wrong candidate error=%v", err)
	}
}

func TestDirectCandidateSetupWaitsForAdoptionBeforeCanceling(t *testing.T) {
	setup, cancelSetup := context.WithCancel(context.Background())
	owner := newCandidateOwner(context.Background(), nil)
	id := candidatelease.ID("candidate")
	if err := owner.Configure(id, 7); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- retainDirectCandidate(setup, cancelSetup, owner) }()
	select {
	case err := <-done:
		t.Fatalf("retention returned before adoption: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if setup.Err() != nil {
		t.Fatalf("setup canceled before adoption: %v", setup.Err())
	}
	if _, err := owner.Handle(candidatelease.Message{Version: 1, Type: candidatelease.Adopt, Candidate: id, LeaseGeneration: 7}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retention did not complete after adoption")
	}
	if !errors.Is(setup.Err(), context.Canceled) {
		t.Fatalf("setup remained live after adoption: %v", setup.Err())
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
