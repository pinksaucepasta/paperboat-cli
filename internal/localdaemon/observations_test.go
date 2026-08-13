package localdaemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

func observationSnapshot(now time.Time) localapi.Snapshot {
	return localapi.Snapshot{
		Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready",
		Machines: []localapi.MachineStatus{{ID: "machine_1", Alias: "Studio", Eligible: true, RuntimeState: "ready", Generation: 4, SelectedPath: "none", TransferReadiness: "ready", PreviewReadiness: "ready", SSHReadiness: "unavailable", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown"}},
	}
}

func transportObservation(source string, sequence uint64, now time.Time, consumers uint64, path string) localapi.TransportObservation {
	observation := localapi.TransportObservation{Schema: localapi.ObservationSchemaV1, SourceID: source, Sequence: sequence, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: consumers, SelectedPath: path, NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if path == "relay" {
		observation.RelayRegion = "bom"
	}
	return observation
}

func TestObservationStoreAggregatesSourcesAndSelectsFreshestPath(t *testing.T) {
	now := time.Date(2026, 8, 4, 16, 0, 0, 0, time.UTC)
	clock := now
	store, _ := localapi.NewSnapshotStore(pointerSnapshot(observationSnapshot(now)))
	observations, err := NewObservationStore(ObservationConfig{Store: store, OwnerUID: 501, Clock: func() time.Time { return clock }, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	peerA := localapi.Peer{UID: 501, GID: 20, PID: 1001}
	peerB := localapi.Peer{UID: 501, GID: 20, PID: 1002}
	if err := observations.PublishObservation(context.Background(), peerA, transportObservation("source_a", 1, now, 1, "direct")); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(time.Second)
	newest := transportObservation("source_b", 1, clock, 2, "relay")
	newest.StandbyPath = "wss"
	newest.NATMappingIPv4 = "destination_dependent"
	newest.NATMappingIPv6 = "endpoint_independent"
	newest.CaptivePortal = "suspected"
	newest.PMTU = "standard"
	if err := observations.PublishObservation(context.Background(), peerB, newest); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := store.Snapshot(context.Background())
	machine := snapshot.Machines[0]
	if snapshot.Generation != 3 || machine.ActiveConsumers != 3 || machine.SelectedPath != "relay" || machine.StandbyPath != "wss" || machine.RelayRegion != "bom" || machine.NATMappingIPv4 != "destination_dependent" || machine.NATMappingIPv6 != "endpoint_independent" || machine.CaptivePortal != "suspected" || machine.PMTU != "standard" {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	if err := observations.PublishObservation(context.Background(), peerB, newest); err != nil {
		t.Fatal(err)
	}
	duplicate, _ := store.Snapshot(context.Background())
	if duplicate.Generation != snapshot.Generation {
		t.Fatalf("duplicate generation=%d", duplicate.Generation)
	}
	if err := observations.PublishObservation(context.Background(), peerB, transportObservation("source_b", 1, clock, 1, "direct")); !errors.Is(err, localapi.ErrStaleObservation) {
		t.Fatalf("stale err=%v", err)
	}
	clock = now.Add(2 * time.Second)
	cleared := transportObservation("source_b", 2, clock, 0, "none")
	if err := observations.PublishObservation(context.Background(), peerB, cleared); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = store.Snapshot(context.Background())
	if snapshot.Machines[0].ActiveConsumers != 1 || snapshot.Machines[0].SelectedPath != "direct" || snapshot.Machines[0].StandbyPath != "none" || snapshot.Machines[0].RelayRegion != "" || snapshot.Machines[0].NATMappingIPv4 != "unknown" || snapshot.Machines[0].NATMappingIPv6 != "unknown" || snapshot.Machines[0].CaptivePortal != "unknown" || snapshot.Machines[0].PMTU != "unknown" {
		t.Fatalf("cleared snapshot=%#v", snapshot)
	}
}

func TestObservationStoreExpiresCrashedPublishersAndPreservesInventoryFields(t *testing.T) {
	now := time.Date(2026, 8, 4, 17, 0, 0, 0, time.UTC)
	clock := now
	initial := observationSnapshot(now)
	initial.Machines[0].Health = []localapi.HealthItem{{Code: "runtime_offline", Severity: "warning", Title: "Runtime is offline", Recovery: "Start the runtime", ETag: "runtime_offline"}}
	store, _ := localapi.NewSnapshotStore(&initial)
	observations, _ := NewObservationStore(ObservationConfig{Store: store, OwnerUID: 501, Clock: func() time.Time { return clock }, Interval: time.Second})
	observation := transportObservation("source_a", 1, now, 1, "wss")
	if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 501, PID: 1001}, observation); err != nil {
		t.Fatal(err)
	}
	clock = observation.ExpiresAt
	if err := observations.Expire(); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := store.Snapshot(context.Background())
	if snapshot.Machines[0].ActiveConsumers != 0 || snapshot.Machines[0].SelectedPath != "none" || len(snapshot.Machines[0].Health) != 1 || snapshot.Machines[0].Health[0].Code != "runtime_offline" {
		t.Fatalf("expired snapshot=%#v", snapshot)
	}
}

func TestObservationStoreProjectsWarmPathWithoutApplicationConsumers(t *testing.T) {
	now := time.Date(2026, 8, 8, 17, 0, 0, 0, time.UTC)
	store, err := localapi.NewSnapshotStore(pointerSnapshot(observationSnapshot(now)))
	if err != nil {
		t.Fatal(err)
	}
	observations, err := NewObservationStore(ObservationConfig{Store: store, OwnerUID: 1000, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	observation := transportObservation("source_warm", 1, now, 0, "relay")
	observation.RelayRegion = "bom"
	if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 1000, PID: 42}, observation); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	machine := snapshot.Machines[0]
	if machine.ActiveConsumers != 0 || machine.SelectedPath != "relay" || machine.RelayRegion != "bom" {
		t.Fatalf("warm observation not projected: %+v", machine)
	}
}

func TestObservationStoreEnforcesOwnerTimeAndSourceBounds(t *testing.T) {
	now := time.Date(2026, 8, 4, 18, 0, 0, 0, time.UTC)
	store, _ := localapi.NewSnapshotStore(pointerSnapshot(observationSnapshot(now)))
	observations, _ := NewObservationStore(ObservationConfig{Store: store, OwnerUID: 501, Clock: func() time.Time { return now }, Interval: time.Second})
	valid := transportObservation("source_0", 1, now, 1, "direct")
	if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 502, PID: 1}, valid); !errors.Is(err, localapi.ErrPermission) {
		t.Fatalf("foreign owner err=%v", err)
	}
	stale := valid
	stale.ObservedAt = now.Add(-time.Minute)
	stale.ExpiresAt = stale.ObservedAt.Add(15 * time.Second)
	if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 501, PID: 1}, stale); !errors.Is(err, localapi.ErrStaleObservation) {
		t.Fatalf("stale time err=%v", err)
	}
	for index := 0; index < maxObservationSources; index++ {
		observation := transportObservation(fmt.Sprintf("source_%d", index), 1, now, 1, "direct")
		if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 501, PID: index + 1}, observation); err != nil {
			t.Fatalf("source %d err=%v", index, err)
		}
	}
	extra := transportObservation("source_extra", 1, now, 1, "direct")
	if err := observations.PublishObservation(context.Background(), localapi.Peer{UID: 501, PID: 9999}, extra); !errors.Is(err, localapi.ErrObservationLimit) {
		t.Fatalf("limit err=%v", err)
	}
}

func pointerSnapshot(snapshot localapi.Snapshot) *localapi.Snapshot { return &snapshot }
