package networkadaptation

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncPMTUReturnsMinimumAndDeduplicatesRefresh(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	cache, _ := NewPMTUCache(policy)
	now := time.Unix(1000, 0).UTC()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	async, err := NewAsyncPMTU(AsyncPMTUConfig{Policy: policy, Cache: cache, Now: func() time.Time { return now }, Jitter: func(time.Duration) time.Duration { return 4 * time.Minute }})
	if err != nil {
		t.Fatal(err)
	}
	key := PMTUKey{Fingerprint: testFingerprint(31), PathID: "relay:bom", NetworkGeneration: 1}
	measure := func(context.Context) (PMTUMeasurement, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return PMTUMeasurement{Complete: true, Eligible: true, PacketSize: 1400, Attempts: 3, ObservedAt: now}, nil
	}
	if got := async.PacketSize(t.Context(), key, measure); got != 1200 {
		t.Fatalf("initial packet size=%d", got)
	}
	<-started
	if got := async.PacketSize(t.Context(), key, measure); got != 1200 || calls.Load() != 1 {
		t.Fatalf("concurrent packet size=%d calls=%d", got, calls.Load())
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := async.PacketSize(t.Context(), key, measure); got == 1400 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("asynchronous PMTU result was not cached")
}

func TestAsyncPMTUInvalidatesOnNetworkChange(t *testing.T) {
	policy := DevelopmentPMTUPolicy()
	cache, _ := NewPMTUCache(policy)
	now := time.Unix(1000, 0).UTC()
	key := PMTUKey{Fingerprint: testFingerprint(32), PathID: "relay:default", NetworkGeneration: 2}
	if err := cache.RecordTTL(key, PMTUMeasurement{Complete: true, Eligible: true, PacketSize: 1380, Attempts: 3, ObservedAt: now}, 4*time.Minute); err != nil {
		t.Fatal(err)
	}
	async, _ := NewAsyncPMTU(AsyncPMTUConfig{Policy: policy, Cache: cache, Now: func() time.Time { return now }})
	if async.Invalidate() != 1 {
		t.Fatal("cached PMTU entry was not invalidated")
	}
}
