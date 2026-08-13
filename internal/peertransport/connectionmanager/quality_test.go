package connectionmanager

import (
	"sync"
	"testing"
	"time"
)

func TestQualityCacheRequiresSustainedRelayAdvantage(t *testing.T) {
	cache, err := NewQualityCache(DevelopmentQualityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	key := qualityKey(1)
	base := time.Unix(1000, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	preference, direct, relay, err := cache.Select(key, base.Add(10*time.Second))
	if err != nil || preference.Path != PathRelayQUIC || preference.ExpiresAt.IsZero() || direct.P95 != 100*time.Millisecond || relay.P95 != 60*time.Millisecond || !direct.Qualified || !relay.Qualified {
		t.Fatalf("preference=%+v direct=%+v relay=%+v err=%v", preference, direct, relay, err)
	}
	classification, err := cache.NetworkClass(key, base.Add(11*time.Second))
	if err != nil || classification != NetworkRelayPreferred {
		t.Fatalf("classification=%d err=%v", classification, err)
	}
}

func TestQualityCacheDoesNotFlapWhenPathsAlternateAroundThreshold(t *testing.T) {
	policy := DevelopmentQualityPolicy()
	policy.SampleRetention = 12 * time.Second
	policy.LossWindow = 10 * time.Second
	cache, _ := NewQualityCache(policy)
	key := qualityKey(42)
	base := time.Unix(1500, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	if preference, _, _, _ := cache.Select(key, base.Add(10*time.Second)); preference.Path != PathRelayQUIC {
		t.Fatal("relay preference was not established")
	}
	recordSeries(t, cache, key, PathDirectQUIC, base.Add(20*time.Second), 92*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base.Add(20*time.Second), 85*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	preference, direct, relay, err := cache.Select(key, base.Add(30*time.Second))
	if err != nil || preference.Path != PathRelayQUIC || direct.P95 != 92*time.Millisecond || relay.P95 != 85*time.Millisecond {
		t.Fatalf("preference=%+v direct=%+v relay=%+v err=%v", preference, direct, relay, err)
	}
}

func TestQualityCacheRejectsInsufficientOrNoisySamples(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	key := qualityKey(1)
	base := time.Unix(2000, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, time.Second, 2*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 40*time.Millisecond, 0, time.Second, 2*time.Second)
	preference, direct, relay, _ := cache.Select(key, base.Add(2*time.Second))
	if preference.Path != PathDirectQUIC || direct.Qualified || relay.Qualified {
		t.Fatalf("preference=%+v direct=%+v relay=%+v", preference, direct, relay)
	}
}

func TestQualityCacheReturnsToDirectUsingAsymmetricThreshold(t *testing.T) {
	policy := DevelopmentQualityPolicy()
	policy.SampleRetention = 12 * time.Second
	policy.LossWindow = 10 * time.Second
	cache, _ := NewQualityCache(policy)
	key := qualityKey(1)
	base := time.Unix(3000, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 70*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 40*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	if preference, _, _, _ := cache.Select(key, base.Add(10*time.Second)); preference.Path != PathRelayQUIC {
		t.Fatal("relay preference was not established")
	}
	recordSeries(t, cache, key, PathDirectQUIC, base.Add(20*time.Second), 30*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base.Add(20*time.Second), 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	preference, direct, relay, _ := cache.Select(key, base.Add(30*time.Second))
	if preference.Path != PathDirectQUIC || direct.P95 != 30*time.Millisecond || relay.P95 != 60*time.Millisecond {
		t.Fatalf("preference=%+v direct=%+v relay=%+v", preference, direct, relay)
	}
}

func TestQualitySuspectRelayCannotEstablishPreference(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	key := qualityKey(1)
	base := time.Unix(4000, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 40*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	if err := cache.Record(key, QualityObservation{Path: PathRelayQUIC, At: base.Add(9 * time.Second), Completion: 40 * time.Millisecond, Succeeded: false}); err != nil {
		t.Fatal(err)
	}
	preference, _, relay, _ := cache.Select(key, base.Add(10*time.Second))
	if preference.Path != PathDirectQUIC || !relay.Suspect || relay.LossPercent <= 5 {
		t.Fatalf("preference=%+v relay=%+v", preference, relay)
	}
}

func TestQualityPreferenceExpiresAndKeysAreGenerationIsolated(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	key := qualityKey(1)
	base := time.Unix(5000, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 50*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	preference, _, _, _ := cache.Select(key, base.Add(10*time.Second))
	if preference.Path != PathRelayQUIC {
		t.Fatal("relay preference was not established")
	}
	changed := key
	changed.HostProcessGeneration++
	if isolated, _, _, _ := cache.Select(changed, base.Add(11*time.Second)); isolated.Path != PathDirectQUIC {
		t.Fatal("preference crossed host process generation")
	}
	if expired, _, _, _ := cache.Select(key, preference.ExpiresAt.Add(time.Nanosecond)); expired.Path != PathDirectQUIC {
		t.Fatalf("expired preference=%+v", expired)
	}
}

func TestDirectRecoveryEligibilityDistinguishesReachabilityAndQualityFallback(t *testing.T) {
	policy := DevelopmentQualityPolicy()
	policy.SampleRetention = 12 * time.Second
	policy.LossWindow = 10 * time.Second
	cache, _ := NewQualityCache(policy)
	key := qualityKey(7)
	base := time.Unix(5500, 0)
	recordSeries(t, cache, key, PathDirectQUIC, base, 100*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base, 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	if preference, _, _, _ := cache.Select(key, base.Add(10*time.Second)); preference.Path != PathRelayQUIC {
		t.Fatal("relay preference was not established")
	}
	if eligible, _, _, err := cache.DirectRecoveryEligible(key, RelaySelectedForReachability, base.Add(11*time.Second)); err != nil || eligible {
		t.Fatalf("reachability eligible=%v err=%v", eligible, err)
	}
	if eligible, _, _, err := cache.DirectRecoveryEligible(key, RelaySelectedForQuality, base.Add(11*time.Second)); err != nil || eligible {
		t.Fatalf("quality eligible=%v err=%v", eligible, err)
	}

	recordSeries(t, cache, key, PathDirectQUIC, base.Add(20*time.Second), 30*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	recordSeries(t, cache, key, PathRelayQUIC, base.Add(20*time.Second), 60*time.Millisecond, 0, 5*time.Second, 10*time.Second)
	eligible, direct, relay, err := cache.DirectRecoveryEligible(key, RelaySelectedForQuality, base.Add(30*time.Second))
	if err != nil || !eligible || direct.P95 != 30*time.Millisecond || relay.P95 != 60*time.Millisecond {
		t.Fatalf("eligible=%v direct=%+v relay=%+v err=%v", eligible, direct, relay, err)
	}
}

func TestDirectRecoveryReachabilityPromotesWithoutQualityHistory(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	eligible, direct, relay, err := cache.DirectRecoveryEligible(qualityKey(8), RelaySelectedForReachability, time.Unix(5600, 0))
	if err != nil || !eligible || direct.Qualified || relay.Qualified {
		t.Fatalf("eligible=%v direct=%+v relay=%+v err=%v", eligible, direct, relay, err)
	}
}

func TestQualityCacheBoundsEntriesAndConcurrentSamples(t *testing.T) {
	policy := DevelopmentQualityPolicy()
	policy.MaximumEntries = 2
	policy.MaximumSamples = 8
	cache, _ := NewQualityCache(policy)
	base := time.Unix(6000, 0)
	for index := byte(1); index <= 3; index++ {
		if err := cache.Record(qualityKey(index), QualityObservation{Path: PathDirectQUIC, At: base.Add(time.Duration(index) * time.Second), Completion: time.Millisecond, Succeeded: true}); err != nil {
			t.Fatal(err)
		}
	}
	if len(cache.items) != 2 {
		t.Fatalf("entries=%d", len(cache.items))
	}
	key := qualityKey(9)
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_ = cache.Record(key, QualityObservation{Path: PathDirectQUIC, At: base.Add(time.Duration(index) * time.Second), Completion: time.Millisecond, Succeeded: true})
		}(index)
	}
	wait.Wait()
	if len(cache.items[key].direct) != policy.MaximumSamples {
		t.Fatalf("samples=%d", len(cache.items[key].direct))
	}
}

func TestQualityCacheRejectsReplayedObservation(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	observation := QualityObservation{Path: PathDirectQUIC, At: time.Unix(7000, 0), Completion: time.Millisecond, Succeeded: true}
	if err := cache.Record(qualityKey(1), observation); err != nil {
		t.Fatal(err)
	}
	if err := cache.Record(qualityKey(1), observation); err == nil {
		t.Fatal("duplicate observation accepted")
	}
}

func TestQualityCacheInvalidationErasesAllNetworkScopedState(t *testing.T) {
	cache, _ := NewQualityCache(DevelopmentQualityPolicy())
	base := time.Unix(8000, 0)
	for marker := byte(1); marker <= 3; marker++ {
		if err := cache.Record(qualityKey(marker), QualityObservation{Path: PathDirectQUIC, At: base.Add(time.Duration(marker) * time.Second), Completion: time.Millisecond, Succeeded: true}); err != nil {
			t.Fatal(err)
		}
	}
	if removed := cache.Invalidate(); removed != 3 || len(cache.items) != 0 {
		t.Fatalf("removed=%d entries=%d", removed, len(cache.items))
	}
	if removed := cache.Invalidate(); removed != 0 {
		t.Fatalf("second invalidation removed=%d", removed)
	}
}

func recordSeries(t *testing.T, cache *QualityCache, key QualityKey, path Path, base time.Time, completion time.Duration, offsets ...time.Duration) {
	t.Helper()
	for _, offset := range offsets {
		if err := cache.Record(key, QualityObservation{Path: path, At: base.Add(offset), Completion: completion, Succeeded: true}); err != nil {
			t.Fatal(err)
		}
	}
}

func qualityKey(marker byte) QualityKey {
	var fingerprint [32]byte
	fingerprint[0] = marker
	return QualityKey{NetworkFingerprint: fingerprint, MachineID: "machine_01", HostNetworkGeneration: 1, HostProcessGeneration: 1, AuthorizationGeneration: 1}
}
