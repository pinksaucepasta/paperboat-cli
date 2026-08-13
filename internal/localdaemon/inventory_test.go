package localdaemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type machineResult struct {
	machines []api.UserMachine
	err      error
}

type scriptedMachineSource struct {
	mu      sync.Mutex
	results []machineResult
	index   int
}

type completionMachineSource struct{ *scriptedMachineSource }

func (s completionMachineSource) ListCompletionItems(context.Context, []api.UserMachine) ([]localapi.CompletionItem, error) {
	return []localapi.CompletionItem{{Kind: "machine", Value: "studio", Description: "Studio - ready", EnvironmentID: "environment_1"}}, nil
}

func (s *scriptedMachineSource) ListUserMachines(context.Context) ([]api.UserMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.index
	if index >= len(s.results) {
		index = len(s.results) - 1
	} else {
		s.index++
	}
	return s.results[index].machines, s.results[index].err
}

func newTestInventory(t *testing.T, source MachineSource, clock func() time.Time) (*Inventory, *localapi.SnapshotStore) {
	t.Helper()
	store, err := localapi.NewSnapshotStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewInventory(InventoryConfig{Source: source, Store: store, RefreshInterval: time.Second, RequestTimeout: time.Second, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return inventory, store
}

func TestInventoryPublishesSortedAuthoritativeMachines(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 0, 0, 0, time.UTC)
	observed := now.Add(-time.Minute)
	source := &scriptedMachineSource{results: []machineResult{{machines: []api.UserMachine{
		{ID: "machine_2", DisplayName: "Studio Mac", InstallationGeneration: 0, Capabilities: api.MachineCapabilities{FileReceive: api.MachineCapability{Configured: true}}},
		{ID: "machine_1", DisplayName: "Build Host", Online: true, InstallationGeneration: 7, SSHAuthority: api.SSHAuthority{TargetGeneration: 7, HostKeyGeneration: 7}, SSHLocalReady: true, RuntimeDiagnostics: api.RuntimeDiagnostics{ObservedAt: &observed}, Capabilities: api.MachineCapabilities{FileReceive: api.MachineCapability{Configured: true, Observed: true}, PreviewLaunch: api.MachineCapability{Configured: true, Observed: true}}},
		{ID: "machine_3", DisplayName: "Build Host", State: "revoked", InstallationGeneration: 2},
	}}}}
	inventory, store := newTestInventory(t, source, func() time.Time { return now })
	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 1 || snapshot.DaemonState != "ready" || !snapshot.ObservedAt.Equal(now) || len(snapshot.Machines) != 3 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	ready, revoked, stopped := snapshot.Machines[0], snapshot.Machines[1], snapshot.Machines[2]
	if ready.ID != "machine_1" || ready.RuntimeState != "ready" || !ready.Eligible || ready.Generation != 7 || ready.TransferReadiness != "ready" || ready.PreviewReadiness != "ready" || ready.SSHReadiness != "ready" || ready.LastObservedAt == nil || !ready.LastObservedAt.Equal(observed) {
		t.Fatalf("ready=%#v", ready)
	}
	if revoked.ID != "machine_3" || revoked.RuntimeState != "failed" || revoked.Eligible || len(revoked.Health) != 1 || revoked.Health[0].Code != "machine_unavailable" {
		t.Fatalf("revoked=%#v", revoked)
	}
	if stopped.ID != "machine_2" || stopped.RuntimeState != "stopped" || stopped.Eligible || stopped.Generation != 0 || stopped.TransferReadiness != "degraded" || stopped.PreviewReadiness != "unavailable" {
		t.Fatalf("stopped=%#v", stopped)
	}
}

func TestInventoryPublishesBoundedCompletionProjection(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 0, 0, 0, time.UTC)
	source := completionMachineSource{&scriptedMachineSource{results: []machineResult{{machines: []api.UserMachine{{ID: "machine_1", Alias: "studio", DisplayName: "Studio", EnvironmentID: "environment_1"}}}}}}
	inventory, _ := newTestInventory(t, source, func() time.Time { return now })
	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	projection, err := inventory.Completions(context.Background())
	if err != nil || !projection.ObservedAt.Equal(now) || len(projection.Items) != 1 || projection.Items[0].Value != "studio" {
		t.Fatalf("projection=%#v err=%v", projection, err)
	}
	projection.Items[0].Value = "changed"
	again, _ := inventory.Completions(context.Background())
	if again.Items[0].Value != "studio" {
		t.Fatal("completion projection was not cloned")
	}
}

func TestInventoryClassifiesSSHAuthorityTransitions(t *testing.T) {
	base := api.UserMachine{ID: "machine_1", DisplayName: "Studio", Online: true, InstallationGeneration: 4, SSHLocalReady: true}
	tests := []struct {
		name      string
		machine   api.UserMachine
		readiness string
		health    string
	}{
		{name: "missing target", machine: base, readiness: "unavailable", health: "ssh_target_not_ready"},
		{name: "missing host keys", machine: func() api.UserMachine { value := base; value.SSHAuthority.TargetGeneration = 4; return value }(), readiness: "degraded", health: "ssh_host_key_changed"},
		{name: "stale generation", machine: func() api.UserMachine {
			value := base
			value.SSHAuthority = api.SSHAuthority{TargetGeneration: 3, HostKeyGeneration: 3}
			return value
		}(), readiness: "degraded", health: "ssh_target_not_ready"},
		{name: "ready", machine: func() api.UserMachine {
			value := base
			value.SSHAuthority = api.SSHAuthority{TargetGeneration: 4, HostKeyGeneration: 4}
			return value
		}(), readiness: "ready"},
		{name: "local integration unavailable", machine: func() api.UserMachine {
			value := base
			value.SSHAuthority = api.SSHAuthority{TargetGeneration: 4, HostKeyGeneration: 4}
			value.SSHLocalReady = false
			value.SSHLocalCode = "ssh_target_not_ready"
			return value
		}(), readiness: "degraded", health: "ssh_target_not_ready"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := mapMachines([]api.UserMachine{test.machine})[0]
			if status.SSHReadiness != test.readiness {
				t.Fatalf("readiness=%q status=%#v", status.SSHReadiness, status)
			}
			if test.health == "" {
				if len(status.Health) != 0 {
					t.Fatalf("health=%#v", status.Health)
				}
			} else if len(status.Health) != 1 || status.Health[0].Code != test.health {
				t.Fatalf("health=%#v", status.Health)
			}
		})
	}
}

func TestInventoryProjectsOnlyTypedUpdateHealth(t *testing.T) {
	observed := time.Now().UTC()
	base := api.UserMachine{ID: "machine_1", DisplayName: "Studio", Availability: api.AvailabilityPolicy{Schema: "paperboat.availability-policy/v1", ObservedAt: &observed}}
	for name, test := range map[string]struct {
		value string
		want  string
	}{
		"healthy":           {value: "healthy", want: "healthy"},
		"recovery required": {value: "recovery_required", want: "recovery_required"},
		"unrecognized":      {value: "journal:/private/path", want: "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			machine := base
			machine.Availability.UpdateHealth = test.value
			if got := mapMachines([]api.UserMachine{machine})[0].UpdateHealth; got != test.want {
				t.Fatalf("update health=%q want=%q", got, test.want)
			}
		})
	}
}

func TestInventoryPublishesOnlySemanticTransitionsAndPreservesLastGoodMachines(t *testing.T) {
	now := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		return now.Add(time.Duration(clockCalls) * time.Minute)
	}
	machines := []api.UserMachine{{ID: "machine_1", DisplayName: "studio", Online: true, InstallationGeneration: 3}}
	unavailable := errors.New("control plane unavailable")
	source := &scriptedMachineSource{results: []machineResult{{machines: machines}, {machines: machines}, {err: unavailable}, {err: unavailable}, {machines: machines}, {machines: machines}}}
	inventory, store := newTestInventory(t, source, clock)

	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial, _ := store.Snapshot(context.Background())
	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	duplicate, _ := store.Snapshot(context.Background())
	if duplicate.Generation != initial.Generation || !duplicate.ObservedAt.Equal(initial.ObservedAt) {
		t.Fatalf("duplicate=%#v initial=%#v", duplicate, initial)
	}
	if err := inventory.Refresh(context.Background()); !errors.Is(err, unavailable) {
		t.Fatalf("failure err=%v", err)
	}
	degraded, _ := store.Snapshot(context.Background())
	if degraded.Generation != initial.Generation+1 || degraded.DaemonState != "degraded" || len(degraded.Health) != 1 || len(degraded.Machines) != 1 || degraded.Machines[0].ID != "machine_1" {
		t.Fatalf("degraded=%#v", degraded)
	}
	if err := inventory.Refresh(context.Background()); !errors.Is(err, unavailable) {
		t.Fatalf("repeat failure err=%v", err)
	}
	repeated, _ := store.Snapshot(context.Background())
	if repeated.Generation != degraded.Generation || !repeated.ObservedAt.Equal(degraded.ObservedAt) || repeated.Health[0].BrokenSince == nil || degraded.Health[0].BrokenSince == nil || !repeated.Health[0].BrokenSince.Equal(*degraded.Health[0].BrokenSince) {
		t.Fatalf("repeated=%#v degraded=%#v", repeated, degraded)
	}
	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, _ := store.Snapshot(context.Background())
	if recovered.Generation != degraded.Generation+1 || recovered.DaemonState != "ready" || len(recovered.Health) != 0 {
		t.Fatalf("recovered=%#v", recovered)
	}
	if err := inventory.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	stable, _ := store.Snapshot(context.Background())
	if stable.Generation != recovered.Generation || !stable.ObservedAt.Equal(recovered.ObservedAt) {
		t.Fatalf("stable=%#v recovered=%#v", stable, recovered)
	}
}

type blockingMachineSource struct{}

func (blockingMachineSource) ListUserMachines(ctx context.Context) ([]api.UserMachine, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestInventoryBoundsRequestsAndRunStopsOnCancellation(t *testing.T) {
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	store, _ := localapi.NewSnapshotStore(nil)
	inventory, err := NewInventory(InventoryConfig{Source: blockingMachineSource{}, Store: store, RefreshInterval: time.Second, RequestTimeout: 10 * time.Millisecond, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := inventory.Refresh(context.Background()); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(started))
	}
	snapshot, snapshotErr := store.Snapshot(context.Background())
	if snapshotErr != nil || snapshot.DaemonState != "degraded" || len(snapshot.Health) != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, snapshotErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inventory.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("inventory did not stop")
	}
}

func TestInventoryRejectsInvalidConfiguration(t *testing.T) {
	store, _ := localapi.NewSnapshotStore(nil)
	if _, err := NewInventory(InventoryConfig{Store: store}); !errors.Is(err, ErrInvalidInventoryConfig) {
		t.Fatalf("missing source err=%v", err)
	}
	if _, err := NewInventory(InventoryConfig{Source: &scriptedMachineSource{results: []machineResult{{}}}, Store: store, RefreshInterval: time.Millisecond}); !errors.Is(err, ErrInvalidInventoryConfig) {
		t.Fatalf("short interval err=%v", err)
	}
}
