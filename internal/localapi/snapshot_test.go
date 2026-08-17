//go:build darwin || linux

package localapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSnapshotStorePublishesMonotonicImmutableSnapshots(t *testing.T) {
	initial := validSnapshot()
	store, err := NewSnapshotStore(&initial)
	if err != nil {
		t.Fatal(err)
	}
	initial.Machines[0].Alias = "mutated"
	current, err := store.Snapshot(context.Background())
	if err != nil || current.Machines[0].Alias != "studio" {
		t.Fatalf("snapshot=%#v err=%v", current, err)
	}
	current.Machines[0].Health[0].Code = "mutated"
	again, _ := store.Snapshot(context.Background())
	if again.Machines[0].Health[0].Code != "ssh_unavailable" {
		t.Fatalf("store exposed mutable health: %#v", again)
	}
	if changed, err := store.Publish(again); err != nil || changed {
		t.Fatalf("duplicate changed=%v err=%v", changed, err)
	}
	conflict := again
	conflict.DaemonState = "degraded"
	if _, err := store.Publish(conflict); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("same-generation conflict err=%v", err)
	}
	stale := again
	stale.Generation--
	if _, err := store.Publish(stale); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale err=%v", err)
	}
}

func TestSnapshotStoreWatchReturnsNextGenerationAndCoalesces(t *testing.T) {
	initial := validSnapshot()
	store, _ := NewSnapshotStore(&initial)
	result := make(chan Snapshot, 1)
	errResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		snapshot, err := store.Watch(ctx, initial.Generation)
		result <- snapshot
		errResult <- err
	}()
	for generation := initial.Generation + 1; generation <= initial.Generation+3; generation++ {
		next := validSnapshot()
		next.Generation = generation
		next.DaemonState = "degraded"
		if _, err := store.Publish(next); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case snapshot := <-result:
		if err := <-errResult; err != nil || snapshot.Generation <= initial.Generation {
			t.Fatalf("snapshot=%#v err=%v", snapshot, err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ready, err := store.Watch(context.Background(), initial.Generation)
	if err != nil || ready.Generation != initial.Generation+3 {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
}

func TestSnapshotStoreWatchCancellationAndLimit(t *testing.T) {
	store, _ := NewSnapshotStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Watch(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	store.mu.Lock()
	for index := 0; index < maxSnapshotWatchers; index++ {
		store.watchers[uint64(index+1)] = make(chan Snapshot, 1)
	}
	store.mu.Unlock()
	if _, err := store.Watch(context.Background(), 0); !errors.Is(err, ErrWatcherLimit) {
		t.Fatalf("err=%v", err)
	}
}

func TestSnapshotStoreUpdateOwnsGenerationAndCoalescesSemanticState(t *testing.T) {
	store, _ := NewSnapshotStore(nil)
	firstAt := time.Date(2026, 8, 4, 15, 0, 0, 0, time.UTC)
	changed, err := store.Update(firstAt, func(current *Snapshot) (Snapshot, error) {
		if current != nil {
			t.Fatal("unexpected current snapshot")
		}
		return Snapshot{DaemonState: "ready", Machines: []MachineStatus{}}, nil
	})
	if err != nil || !changed {
		t.Fatalf("first changed=%v err=%v", changed, err)
	}
	first, _ := store.Snapshot(context.Background())
	if first.Generation != 1 || !first.ObservedAt.Equal(firstAt) || first.Schema != SnapshotSchemaV1 {
		t.Fatalf("first=%#v", first)
	}
	changed, err = store.Update(firstAt.Add(time.Minute), func(current *Snapshot) (Snapshot, error) {
		if current == nil {
			t.Fatal("missing current snapshot")
		}
		current.Generation = 999
		current.ObservedAt = time.Now()
		return *current, nil
	})
	if err != nil || changed {
		t.Fatalf("duplicate changed=%v err=%v", changed, err)
	}
	stable, _ := store.Snapshot(context.Background())
	if stable.Generation != 1 || !stable.ObservedAt.Equal(firstAt) {
		t.Fatalf("stable=%#v", stable)
	}
	changed, err = store.Update(firstAt.Add(2*time.Minute), func(current *Snapshot) (Snapshot, error) {
		current.DaemonState = "degraded"
		return *current, nil
	})
	if err != nil || !changed {
		t.Fatalf("second changed=%v err=%v", changed, err)
	}
	second, _ := store.Snapshot(context.Background())
	if second.Generation != 2 || second.DaemonState != "degraded" || !second.ObservedAt.Equal(firstAt.Add(2*time.Minute)) {
		t.Fatalf("second=%#v", second)
	}
}

func TestRelayRegionValidationMatchesRelayBackedPaths(t *testing.T) {
	now := time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	for _, path := range []string{"relay", "wss"} {
		observation := base
		observation.SelectedPath = path
		observation.RelayRegion = "bom"
		if err := observation.Validate(); err != nil {
			t.Fatalf("%s observation rejected: %v", path, err)
		}
	}
	for _, path := range []string{"direct", "none"} {
		observation := base
		observation.SelectedPath = path
		observation.RelayRegion = "bom"
		if path == "none" {
			observation.ActiveConsumers = 0
		}
		if err := observation.Validate(); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("%s observation err=%v", path, err)
		}
	}
}

func TestTransportObservationValidatesStandbyState(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "direct", StandbyPath: "relay", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid standby: %v", err)
	}
	for name, mutate := range map[string]func(*TransportObservation){
		"same as primary":  func(value *TransportObservation) { value.StandbyPath = "direct" },
		"without consumer": func(value *TransportObservation) { value.ActiveConsumers = 0 },
		"unknown path":     func(value *TransportObservation) { value.StandbyPath = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestTransportObservationValidatesPerPathConsumers(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 2, SelectedPath: "mixed", TransportConsumers: []TransportConsumer{{Path: "direct", ActiveConsumers: 1}, {Path: "relay", ActiveConsumers: 1, RelayRegion: "bom"}}, NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid mixed consumers: %v", err)
	}
	for name, mutate := range map[string]func(*TransportObservation){
		"wrong total":       func(value *TransportObservation) { value.ActiveConsumers = 3 },
		"wrong summary":     func(value *TransportObservation) { value.SelectedPath = "direct" },
		"duplicate path":    func(value *TransportObservation) { value.TransportConsumers[1].Path = "direct" },
		"direct with relay": func(value *TransportObservation) { value.TransportConsumers[0].RelayRegion = "bom" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.TransportConsumers = append([]TransportConsumer(nil), base.TransportConsumers...)
			mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestNATMappingValidationRejectsAddressesAndMissingCategories(t *testing.T) {
	now := time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "direct", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	for _, invalid := range []string{"", "192.0.2.1:40000", "endpoint-independent"} {
		observation := base
		observation.NATMappingIPv4 = invalid
		if err := observation.Validate(); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("mapping %q err=%v", invalid, err)
		}
	}
}

func TestCaptivePortalValidationRejectsURLsAndMissingCategories(t *testing.T) {
	now := time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "direct", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	for _, invalid := range []string{"", "https://login.example.test", "portal"} {
		observation := base
		observation.CaptivePortal = invalid
		if err := observation.Validate(); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("portal %q err=%v", invalid, err)
		}
	}
}

func TestPMTUValidationRejectsRawSizesAndMissingCategories(t *testing.T) {
	now := time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC)
	base := TransportObservation{Schema: ObservationSchemaV1, SourceID: "source_1", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "direct", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	for _, invalid := range []string{"", "1372", "mtu_1372"} {
		observation := base
		observation.PMTU = invalid
		if err := observation.Validate(); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("PMTU %q err=%v", invalid, err)
		}
	}
}
