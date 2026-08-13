package networkcheck

import (
	"testing"
	"time"
)

func TestRegionalCacheUsesThreeRecentSamplesAndExpiresThem(t *testing.T) {
	cache := NewRegionalCache()
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for index, rtt := range []time.Duration{90, 40, 70, 50} {
		if err := cache.Record("fsn1", rtt*time.Millisecond, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.Record("hel1", 30*time.Millisecond, now); err != nil {
		t.Fatal(err)
	}
	vector := cache.Vector(now.Add(4 * time.Second))
	if len(vector.Samples) != 2 || vector.Samples[0].Region != "fsn1" || vector.Samples[0].RTT != 50*time.Millisecond || vector.Samples[1].Region != "hel1" {
		t.Fatalf("vector = %#v", vector)
	}
	vector = cache.Vector(now.Add(regionalSampleTTL + 3*time.Second))
	if len(vector.Samples) != 1 || vector.Samples[0].Region != "fsn1" || vector.Samples[0].RTT != 50*time.Millisecond {
		t.Fatalf("boundary vector = %#v", vector)
	}
	if vector := cache.Vector(now.Add(regionalSampleTTL + 4*time.Second)); len(vector.Samples) != 0 {
		t.Fatalf("expired vector = %#v", vector)
	}
}

func TestRegionalCacheRejectsReplayAndInvalidData(t *testing.T) {
	cache := NewRegionalCache()
	now := time.Now().UTC()
	if err := cache.Record("fsn1", time.Millisecond, now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		region string
		rtt    time.Duration
		at     time.Time
	}{{"fsn1", time.Millisecond, now}, {"FSN1", time.Millisecond, now.Add(time.Second)}, {"fsn1", 0, now.Add(time.Second)}} {
		if err := cache.Record(test.region, test.rtt, test.at); err == nil {
			t.Fatalf("accepted invalid sample %#v", test)
		}
	}
}
