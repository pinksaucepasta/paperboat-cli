package networkadaptation

import (
	"context"
	"sync"
	"testing"
	"time"
)

type supervisedLifetimeRunner struct {
	mu        sync.Mutex
	calls     []Fingerprint
	active    int
	maxActive int
	started   chan Fingerprint
	release   chan struct{}
}

func (r *supervisedLifetimeRunner) Measure(ctx context.Context, fingerprint Fingerprint) (Measurement, error) {
	r.mu.Lock()
	r.calls = append(r.calls, fingerprint)
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	r.mu.Unlock()
	if r.started != nil {
		r.started <- fingerprint
	}
	if r.release != nil {
		<-r.release // Deliberately permit cancellation-ignoring fixtures.
	} else {
		<-ctx.Done()
	}
	r.mu.Lock()
	r.active--
	r.mu.Unlock()
	return Measurement{}, ctx.Err()
}

func TestLifetimeSupervisorCoalescesAndSerializesReplacement(t *testing.T) {
	runner := &supervisedLifetimeRunner{started: make(chan Fingerprint, 3), release: make(chan struct{}, 2)}
	supervisor, err := NewLifetimeSupervisor(context.Background(), runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second, newest := Fingerprint{1}, Fingerprint{2}, Fingerprint{3}
	if !supervisor.Trigger(first) || supervisor.Trigger(first) {
		t.Fatal("initial trigger was not single-flight")
	}
	if got := <-runner.started; got != first {
		t.Fatalf("first=%x", got)
	}
	if !supervisor.Trigger(second) || !supervisor.Trigger(newest) || supervisor.Trigger(newest) {
		t.Fatal("replacement coalescing mismatch")
	}
	runner.release <- struct{}{}
	if got := <-runner.started; got != newest {
		t.Fatalf("replacement=%x want=%x", got, newest)
	}
	runner.release <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	maxActive, calls := runner.maxActive, append([]Fingerprint(nil), runner.calls...)
	runner.mu.Unlock()
	if maxActive != 1 || len(calls) != 2 || calls[0] != first || calls[1] != newest {
		t.Fatalf("max active=%d calls=%v", maxActive, calls)
	}
}

func TestLifetimeSupervisorNewestFingerprintCanReturnToActiveValue(t *testing.T) {
	runner := &supervisedLifetimeRunner{started: make(chan Fingerprint, 3), release: make(chan struct{}, 2)}
	supervisor, err := NewLifetimeSupervisor(context.Background(), runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second := Fingerprint{1}, Fingerprint{2}
	if !supervisor.Trigger(first) {
		t.Fatal("initial measurement not started")
	}
	if got := <-runner.started; got != first {
		t.Fatalf("first=%x", got)
	}
	if !supervisor.Trigger(second) || !supervisor.Trigger(first) {
		t.Fatal("newest fingerprint did not replace pending work")
	}
	runner.release <- struct{}{}
	if got := <-runner.started; got != first {
		t.Fatalf("replacement=%x want=%x", got, first)
	}
	runner.release <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	calls := append([]Fingerprint(nil), runner.calls...)
	runner.mu.Unlock()
	if len(calls) != 2 || calls[0] != first || calls[1] != first {
		t.Fatalf("calls=%v", calls)
	}
}

func TestLifetimeSupervisorInvalidationDropsPendingAndResult(t *testing.T) {
	runner := &supervisedLifetimeRunner{started: make(chan Fingerprint, 2), release: make(chan struct{}, 1)}
	var resultsMu sync.Mutex
	results := 0
	supervisor, _ := NewLifetimeSupervisor(context.Background(), runner, func(Fingerprint, Measurement, error) {
		resultsMu.Lock()
		results++
		resultsMu.Unlock()
	})
	if !supervisor.Trigger(Fingerprint{1}) {
		t.Fatal("measurement not started")
	}
	<-runner.started
	if !supervisor.Trigger(Fingerprint{2}) {
		t.Fatal("replacement not queued")
	}
	if removed := supervisor.Invalidate(); removed != 2 {
		t.Fatalf("removed=%d", removed)
	}
	runner.release <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Close(ctx); err != nil {
		t.Fatal(err)
	}
	resultsMu.Lock()
	resultCount := results
	resultsMu.Unlock()
	runner.mu.Lock()
	calls := append([]Fingerprint(nil), runner.calls...)
	runner.mu.Unlock()
	if resultCount != 0 || len(calls) != 1 {
		t.Fatalf("results=%d calls=%v", resultCount, calls)
	}
}

func TestLifetimeSupervisorCloseIsBoundedAndRejectsTypedNil(t *testing.T) {
	var typedNil *LifetimeMeasurer
	if _, err := NewLifetimeSupervisor(context.Background(), typedNil, nil); err == nil {
		t.Fatal("typed-nil runner accepted")
	}
	runner := &supervisedLifetimeRunner{started: make(chan Fingerprint, 1), release: make(chan struct{})}
	supervisor, _ := NewLifetimeSupervisor(context.Background(), runner, nil)
	supervisor.Trigger(Fingerprint{1})
	<-runner.started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := supervisor.Close(ctx); !IsMeasurementCanceled(err) {
		t.Fatalf("close error=%v", err)
	}
	close(runner.release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := supervisor.Close(ctx2); err != nil {
		t.Fatal(err)
	}
	if supervisor.Trigger(Fingerprint{2}) {
		t.Fatal("closed supervisor accepted trigger")
	}
}
