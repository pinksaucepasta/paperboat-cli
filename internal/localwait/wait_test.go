package localwait

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type watchBatch struct {
	snapshots []localapi.Snapshot
	err       error
}

type fakeClient struct {
	initial localapi.Snapshot
	batches []watchBatch
	watches int
}

func (f *fakeClient) Snapshot(context.Context) (localapi.Snapshot, error) { return f.initial, nil }

func (f *fakeClient) Watch(ctx context.Context, _ uint64) (<-chan localapi.Snapshot, <-chan error) {
	updates := make(chan localapi.Snapshot, 4)
	errorsOut := make(chan error, 1)
	if f.watches < len(f.batches) {
		batch := f.batches[f.watches]
		f.watches++
		for _, snapshot := range batch.snapshots {
			updates <- snapshot
		}
		close(updates)
		errorsOut <- batch.err
		close(errorsOut)
		return updates, errorsOut
	}
	go func() {
		defer close(updates)
		defer close(errorsOut)
		<-ctx.Done()
		errorsOut <- ctx.Err()
	}()
	return updates, errorsOut
}

func waitSnapshot(generation uint64, machine localapi.MachineStatus) localapi.Snapshot {
	return localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: generation, ObservedAt: time.Date(2026, 8, 4, 12, 0, int(generation), 0, time.UTC), DaemonState: "ready", Machines: []localapi.MachineStatus{machine}}
}

func waitMachine() localapi.MachineStatus {
	return localapi.MachineStatus{ID: "machine_1", Alias: "Studio Mac", Eligible: true, RuntimeState: "offline", Generation: 4, SelectedPath: "none", TransferReadiness: "degraded", PreviewReadiness: "degraded", SSHReadiness: "unavailable", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown"}
}

func TestWaitReadinessProgressionAndBoundMachineIdentity(t *testing.T) {
	machine := waitMachine()
	initial := waitSnapshot(1, machine)
	machine.RuntimeState = "ready"
	runtimeReady := waitSnapshot(2, machine)
	machine.SelectedPath = "relay"
	machine.RelayRegion = "bom"
	transportReady := waitSnapshot(3, machine)
	machine.SSHReadiness = "ready"
	sshReady := waitSnapshot(4, machine)

	for _, test := range []struct {
		condition string
		batches   []watchBatch
		wantGen   uint64
	}{
		{"runtime", []watchBatch{{snapshots: []localapi.Snapshot{runtimeReady}, err: io.EOF}}, 2},
		{"transport", []watchBatch{{snapshots: []localapi.Snapshot{runtimeReady}, err: io.EOF}, {snapshots: []localapi.Snapshot{transportReady}, err: io.EOF}}, 3},
		{"ssh", []watchBatch{{snapshots: []localapi.Snapshot{runtimeReady, transportReady, sshReady}, err: io.EOF}}, 4},
	} {
		client := &fakeClient{initial: initial, batches: test.batches}
		result, err := Wait(context.Background(), client, machine.ID, test.condition)
		if err != nil || result.Schema != ResultSchemaV1 || result.Outcome != "ready" || result.Condition != test.condition || result.SnapshotGeneration != test.wantGen || result.Machine.ID != machine.ID {
			t.Fatalf("condition=%s result=%#v err=%v", test.condition, result, err)
		}
	}
}

func TestWaitReturnsTypedTerminalAndRemovalResults(t *testing.T) {
	machine := waitMachine()
	initial := waitSnapshot(1, machine)
	failed := machine
	failed.RuntimeState = "failed"
	failed.Health = []localapi.HealthItem{{Code: "machine_unavailable", Severity: "error", Title: "Machine is unavailable", Recovery: "Set up the machine again", ETag: "machine_unavailable"}}
	for _, test := range []struct {
		name string
		next localapi.Snapshot
		code string
	}{
		{"failed", waitSnapshot(2, failed), "machine_unavailable"},
		{"removed", localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: 2, ObservedAt: initial.ObservedAt.Add(time.Second), DaemonState: "ready", Machines: []localapi.MachineStatus{}}, "machine_removed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{initial: initial, batches: []watchBatch{{snapshots: []localapi.Snapshot{test.next}, err: io.EOF}}}
			result, err := Wait(context.Background(), client, machine.ID, "runtime")
			if err != nil || result.Outcome != "failed" || result.Code != test.code || result.Machine.ID != machine.ID {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestWaitReturnsTimeoutAndCancellationWithoutPolling(t *testing.T) {
	for _, test := range []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		outcome string
		code    string
	}{
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 10*time.Millisecond)
		}, "timeout", "wait_timeout"},
		{"canceled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, "canceled", "wait_canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()
			machine := waitMachine()
			result, err := Wait(ctx, &fakeClient{initial: waitSnapshot(1, machine)}, machine.ID, "transport")
			if err != nil || result.Outcome != test.outcome || result.Code != test.code || result.SnapshotGeneration != 1 {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestResolveMachinePrefersExactIDAndRejectsAmbiguity(t *testing.T) {
	machines := []localapi.MachineStatus{{ID: "machine_1", Alias: "Studio"}, {ID: "Studio", Alias: "Other"}, {ID: "machine_2", Alias: "studio"}}
	selected, err := ResolveMachine(machines, "Studio")
	if err != nil || selected.ID != "Studio" {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	if _, err := ResolveMachine(machines, "STUDIO"); err == nil {
		t.Fatal("ambiguous alias was accepted")
	}
	if _, err := ResolveMachine(machines, "missing"); err == nil {
		t.Fatal("missing machine was accepted")
	}
}

func TestWaitRejectsInvalidInputAndPropagatesWatchFailure(t *testing.T) {
	if _, err := Wait(context.Background(), nil, "machine_1", "runtime"); err == nil {
		t.Fatal("nil client was accepted")
	}
	machine := waitMachine()
	watchErr := errors.New("watch failed")
	client := &fakeClient{initial: waitSnapshot(1, machine), batches: []watchBatch{{err: watchErr}}}
	if _, err := Wait(context.Background(), client, machine.ID, "runtime"); !errors.Is(err, watchErr) {
		t.Fatalf("watch err=%v", err)
	}
}

func TestWaitResultContractFixtures(t *testing.T) {
	file, err := os.Open("../../testdata/contracts/fixtures/cli/wait-results.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var result Result
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&result); err != nil || result.Validate() != nil {
			t.Fatalf("invalid fixture %q: decode=%v validate=%v", scanner.Text(), err, result.Validate())
		}
		seen[result.Outcome] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"ready", "timeout", "canceled", "failed"} {
		if !seen[outcome] {
			t.Fatalf("missing %s fixture", outcome)
		}
	}
}
