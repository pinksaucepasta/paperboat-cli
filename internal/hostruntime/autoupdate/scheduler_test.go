package autoupdate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerChecksImmediatelyAndUsesBoundedJitter(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	scheduler, err := New(Config{
		Check: func(context.Context) (Result, error) { return Result{Version: "2026.08.18.1", Updated: true}, nil },
		Now:   func() time.Time { return now }, Random: func(time.Duration) (time.Duration, error) { return time.Hour, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scheduler.CheckNow(context.Background())
	state := scheduler.Snapshot()
	if err != nil || !result.Updated || result.Version != "2026.08.18.1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if state.NextCheckAt != now.Add(4*time.Hour) || state.Failures != 0 || state.Failure != "" {
		t.Fatalf("state=%+v", state)
	}
}

func TestSchedulerBackoffIsBoundedAndSuccessResetsFailures(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var attempts atomic.Uint32
	scheduler, err := New(Config{
		Check: func(context.Context) (Result, error) {
			if attempts.Add(1) < 4 {
				return Result{}, errors.New("offline")
			}
			return Result{Version: "2026.08.18.1"}, nil
		},
		Now: func() time.Time { return now }, Random: func(time.Duration) (time.Duration, error) { return 0, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	wants := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute}
	for _, want := range wants {
		if _, err := scheduler.CheckNow(context.Background()); err == nil {
			t.Fatal("failure was not returned")
		}
		if got := scheduler.Snapshot().NextCheckAt.Sub(now); got != want {
			t.Fatalf("delay=%v want=%v", got, want)
		}
	}
	if _, err := scheduler.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := scheduler.Snapshot()
	if state.Failures != 0 || state.Failure != "" || state.NextCheckAt.Sub(now) != 3*time.Hour {
		t.Fatalf("state=%+v", state)
	}
}

func TestObserveCheckRecordsReadOnlySuccessWithoutCallingConfiguredCheck(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var automaticCalls atomic.Uint32
	scheduler, err := New(Config{
		Check: func(context.Context) (Result, error) {
			automaticCalls.Add(1)
			return Result{Version: "activated", Updated: true}, nil
		},
		Now:    func() time.Time { return now },
		Random: func(time.Duration) (time.Duration, error) { return 0, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.ObserveCheck(context.Background(), func(context.Context) (Result, error) {
		return Result{}, errors.New("offline")
	}); err == nil {
		t.Fatal("read-only failure was not returned")
	}
	result, err := scheduler.ObserveCheck(context.Background(), func(context.Context) (Result, error) {
		return Result{Version: "2026.09.02.6"}, nil
	})
	if err != nil || result.Version != "2026.09.02.6" || result.Updated {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if automaticCalls.Load() != 0 {
		t.Fatalf("configured activation check called %d times", automaticCalls.Load())
	}
	state := scheduler.Snapshot()
	if state.Version != result.Version || state.Updated || state.Failure != "" || state.Failures != 0 {
		t.Fatalf("state=%+v", state)
	}
}

func TestSchedulerCancellationStopsPromptly(t *testing.T) {
	started := make(chan struct{})
	scheduler, err := New(Config{Check: func(ctx context.Context) (Result, error) {
		close(started)
		<-ctx.Done()
		return Result{}, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}
}

func TestSchedulerRejectsUnsafeBounds(t *testing.T) {
	for _, config := range []Config{
		{},
		{Check: func(context.Context) (Result, error) { return Result{}, nil }, Interval: time.Second},
		{Check: func(context.Context) (Result, error) { return Result{}, nil }, RetryFloor: time.Hour, RetryLimit: time.Minute},
	} {
		if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config=%+v err=%v", config, err)
		}
	}
}
