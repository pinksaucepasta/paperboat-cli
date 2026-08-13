package networkcheck

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestRegionalMonitorFullAndIncrementalTargetsAreBounded(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	cache := NewRegionalCache()
	for region, rtt := range map[string]time.Duration{"ams1": 40, "fsn1": 10, "hel1": 20, "nbg1": 30, "sin1": 50} {
		if err := cache.Record(region, rtt*time.Millisecond, now); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var called []string
	probe, _ := NewRegionalProbe(RegionalProbeConfig{Timeout: time.Second,
		STUN: func(_ context.Context, endpoint string) (time.Duration, error) {
			mu.Lock()
			called = append(called, endpoint)
			mu.Unlock()
			return time.Millisecond, nil
		},
		HTTPS: func(context.Context, string) (time.Duration, error) { return 0, ErrUnreachable },
	})
	inventory := []ProbeRegion{}
	for _, region := range []string{"ams1", "fsn1", "hel1", "nbg1", "sin1"} {
		inventory = append(inventory, ProbeRegion{Region: region, STUNURL: region, HTTPSURL: region})
	}
	monitor, err := NewRegionalMonitor(RegionalMonitorConfig{Inventory: func(context.Context) ([]ProbeRegion, error) { return inventory, nil }, Probe: probe, Cache: cache, Clock: func() time.Time { return now.Add(time.Second) }, CurrentRegion: func() string { return "sin1" }, FullInterval: 5 * time.Minute, IncrementalInterval: time.Minute, Jitter: func(value time.Duration) time.Duration { return value }})
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), called...)
	mu.Unlock()
	sort.Strings(got)
	want := []string{"fsn1", "hel1", "nbg1", "sin1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("incremental targets=%v want=%v", got, want)
	}
}
