package relayselection

import (
	"testing"
	"time"
)

func TestSelectorRequiresSustainedTwoEndedGain(t *testing.T) {
	selector, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1000, 0)
	states := map[string]RegionState{"bom": {Healthy: true, Capacity: true}, "fra": {Healthy: true, Capacity: true}}
	set := func(generation uint64, at time.Time, bom, fra time.Duration) Decision {
		decision, selectErr := selector.Select(at.Add(time.Second), VectorSet{Generation: generation, ObservedAt: at, Client: Vector{Samples: []RegionSample{{Region: "bom", RTT: bom / 2}, {Region: "fra", RTT: fra / 2}}}, Host: Vector{Samples: []RegionSample{{Region: "bom", RTT: bom - bom/2}, {Region: "fra", RTT: fra - fra/2}}}}, states)
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		return decision
	}
	if got := set(1, base, 80*time.Millisecond, 120*time.Millisecond); got.Region != "bom" || got.Switched {
		t.Fatalf("initial=%+v", got)
	}
	if got := set(2, base.Add(time.Second), 80*time.Millisecond, 60*time.Millisecond); got.Region != "bom" {
		t.Fatalf("short spacing switched=%+v", got)
	}
	if got := set(3, base.Add(4*time.Second), 80*time.Millisecond, 60*time.Millisecond); got.Region != "bom" {
		t.Fatalf("second sample switched=%+v", got)
	}
	if got := set(4, base.Add(11*time.Second), 80*time.Millisecond, 60*time.Millisecond); got.Region != "fra" || !got.Switched {
		t.Fatalf("sustained decision=%+v", got)
	}
}

func TestSelectorDoesNotFlapAndExcludesUnhealthyRegions(t *testing.T) {
	selector, _ := New(DevelopmentConfig())
	base := time.Unix(2000, 0)
	vectors := func(generation uint64, at time.Time, bom, fra time.Duration, states map[string]RegionState) Decision {
		decision, err := selector.Select(at.Add(time.Second), VectorSet{Generation: generation, ObservedAt: at, Client: Vector{Samples: []RegionSample{{"bom", bom / 2}, {"fra", fra / 2}}}, Host: Vector{Samples: []RegionSample{{"bom", bom / 2}, {"fra", fra / 2}}}}, states)
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}
	healthy := map[string]RegionState{"bom": {true, true}, "fra": {true, true}}
	if got := vectors(1, base, 80*time.Millisecond, 84*time.Millisecond, healthy); got.Region != "bom" {
		t.Fatalf("initial=%+v", got)
	}
	for generation := uint64(2); generation <= 8; generation++ {
		bom, fra := 80*time.Millisecond, 78*time.Millisecond
		if generation%2 == 0 {
			bom, fra = fra, bom
		}
		if got := vectors(generation, base.Add(time.Duration(generation)*4*time.Second), bom, fra, healthy); got.Region != "bom" || got.Switched {
			t.Fatalf("noise switched generation=%d decision=%+v", generation, got)
		}
	}
	unhealthy := map[string]RegionState{"bom": {Healthy: false, Capacity: true}, "fra": {Healthy: true, Capacity: true}}
	if got := vectors(9, base.Add(40*time.Second), 40*time.Millisecond, 90*time.Millisecond, unhealthy); got.Region != "fra" || !got.Switched {
		t.Fatalf("unhealthy current decision=%+v", got)
	}
}

func TestSelectorRejectsReplayAndMalformedVectors(t *testing.T) {
	selector, _ := New(DevelopmentConfig())
	now := time.Unix(3000, 0)
	states := map[string]RegionState{"bom": {true, true}}
	valid := VectorSet{Generation: 1, ObservedAt: now, Client: Vector{Samples: []RegionSample{{"bom", time.Millisecond}}}, Host: Vector{Samples: []RegionSample{{"bom", time.Millisecond}}}}
	if _, err := selector.Select(now.Add(time.Second), valid, states); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Select(now.Add(2*time.Second), valid, states); err == nil {
		t.Fatal("accepted replayed generation")
	}
	invalid := valid
	invalid.Generation = 2
	invalid.Client.Samples = append(invalid.Client.Samples, RegionSample{"bom", time.Millisecond})
	if _, err := selector.Select(now.Add(2*time.Second), invalid, states); err == nil {
		t.Fatal("accepted duplicate region")
	}
}
