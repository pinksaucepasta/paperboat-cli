package networkadaptation

import (
	"errors"
	"testing"
	"time"
)

type fixedRandom struct {
	value uint64
	err   error
}

func (r fixedRandom) Uint64() (uint64, error) { return r.value, r.err }

func testFingerprint(marker byte) Fingerprint {
	var fingerprint Fingerprint
	fingerprint[0] = marker
	return fingerprint
}

func TestLifetimeRequiresIndependentEvidenceBeforeAdaptation(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	policy.JitterFraction = 0
	cache, err := NewLifetimeCache(policy, fixedRandom{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	key := testFingerprint(1)
	for index := range 3 {
		if err := cache.RecordSuccess(key, 30*time.Second, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
		decision, err := cache.Keepalive(key, now.Add(time.Duration(index)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if index < 2 && (decision.Adapted || decision.Interval != policy.DefaultInterval) {
			t.Fatalf("premature decision after %d samples: %+v", index+1, decision)
		}
	}
	decision, _ := cache.Keepalive(key, now.Add(2*time.Second))
	want := 30*time.Second/3 - policy.SafetyMargin
	if !decision.Adapted || decision.LowerBound != 30*time.Second || decision.Interval != want || decision.Evidence != 3 {
		t.Fatalf("decision = %+v, want interval %v", decision, want)
	}
}

func TestLifetimeIgnoresCorrelatedAndFutureEvidence(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	policy.JitterFraction = 0
	cache, _ := NewLifetimeCache(policy, fixedRandom{})
	now := time.Unix(2000, 0)
	key := testFingerprint(2)
	for _, offset := range []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond, time.Hour} {
		_ = cache.RecordSuccess(key, time.Minute, now.Add(offset))
	}
	decision, _ := cache.Keepalive(key, now.Add(time.Second))
	if decision.Adapted || decision.Evidence != 1 {
		t.Fatalf("correlated/future evidence accepted: %+v", decision)
	}
}

func TestLifetimeFailureRemovesContradictedBounds(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	policy.JitterFraction = 0
	cache, _ := NewLifetimeCache(policy, fixedRandom{})
	now := time.Unix(3000, 0)
	key := testFingerprint(3)
	for index, idle := range []time.Duration{30 * time.Second, 25 * time.Second, 20 * time.Second} {
		_ = cache.RecordSuccess(key, idle, now.Add(time.Duration(index)*time.Second))
	}
	before, _ := cache.Keepalive(key, now.Add(3*time.Second))
	if !before.Adapted || before.LowerBound != 20*time.Second {
		t.Fatalf("before failure = %+v", before)
	}
	_ = cache.RecordFailure(key, 18*time.Second, now.Add(4*time.Second))
	after, _ := cache.Keepalive(key, now.Add(4*time.Second))
	if after.Adapted || after.Evidence != 0 || after.Interval != policy.DefaultInterval {
		t.Fatalf("after failure = %+v", after)
	}
}

func TestLifetimeEvidenceExpiresAndInvalidates(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	policy.JitterFraction = 0
	cache, _ := NewLifetimeCache(policy, fixedRandom{})
	now := time.Unix(4000, 0)
	key := testFingerprint(4)
	for index := range 3 {
		_ = cache.RecordSuccess(key, time.Minute, now.Add(time.Duration(index)*time.Second))
	}
	expired, _ := cache.Keepalive(key, now.Add(policy.EvidenceTTL+3*time.Second))
	if expired.Adapted || expired.Evidence != 0 {
		t.Fatalf("expired evidence retained: %+v", expired)
	}
	_ = cache.RecordSuccess(key, time.Minute, now.Add(policy.EvidenceTTL+4*time.Second))
	if removed := cache.Invalidate(); removed != 1 || cache.Invalidate() != 0 {
		t.Fatalf("invalidation counts = %d then nonzero", removed)
	}
}

func TestLifetimeIntervalIsCappedAndJitterOnlyMovesDown(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	cache, _ := NewLifetimeCache(policy, fixedRandom{value: ^uint64(0)})
	now := time.Unix(5000, 0)
	key := testFingerprint(5)
	for index := range 3 {
		_ = cache.RecordSuccess(key, 5*time.Minute, now.Add(time.Duration(index)*time.Second))
	}
	decision, err := cache.Keepalive(key, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Duration(float64(policy.MaximumInterval) * (1 - policy.JitterFraction))
	if decision.Interval != want || decision.Interval > decision.LowerBound/3-policy.SafetyMargin {
		t.Fatalf("decision = %+v, want %v", decision, want)
	}
}

func TestLifetimeRandomFailureFailsClosed(t *testing.T) {
	want := errors.New("entropy unavailable")
	cache, _ := NewLifetimeCache(DevelopmentLifetimePolicy(), fixedRandom{err: want})
	if _, err := cache.Keepalive(testFingerprint(6), time.Now()); !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}

func TestLifetimeCacheEvictsLeastRecentlyUsedNetwork(t *testing.T) {
	policy := DevelopmentLifetimePolicy()
	policy.MaximumNetworks = 2
	policy.JitterFraction = 0
	cache, _ := NewLifetimeCache(policy, fixedRandom{})
	now := time.Unix(6000, 0)
	for marker := byte(1); marker <= 3; marker++ {
		_ = cache.RecordSuccess(testFingerprint(marker), time.Minute, now.Add(time.Duration(marker)*time.Second))
	}
	cache.mu.Lock()
	_, oldestPresent := cache.entries[testFingerprint(1)]
	count := len(cache.entries)
	cache.mu.Unlock()
	if oldestPresent || count != 2 {
		t.Fatalf("oldest present=%v entries=%d", oldestPresent, count)
	}
}
