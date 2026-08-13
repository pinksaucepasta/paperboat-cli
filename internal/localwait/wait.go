package localwait

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

const ResultSchemaV1 = "paperboat.wait-result/v1"

type Client interface {
	Snapshot(context.Context) (localapi.Snapshot, error)
	Watch(context.Context, uint64) (<-chan localapi.Snapshot, <-chan error)
}

type Result struct {
	Schema             string                 `json:"schema"`
	Condition          string                 `json:"condition"`
	Outcome            string                 `json:"outcome"`
	Code               string                 `json:"code,omitempty"`
	SnapshotGeneration uint64                 `json:"snapshot_generation"`
	ObservedAt         time.Time              `json:"observed_at"`
	Machine            localapi.MachineStatus `json:"machine"`
}

func (r Result) Validate() error {
	if r.Schema != ResultSchemaV1 || !validCondition(r.Condition) || r.SnapshotGeneration == 0 || r.ObservedAt.IsZero() {
		return errors.New("invalid local wait result")
	}
	snapshot := localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: r.SnapshotGeneration, ObservedAt: r.ObservedAt, DaemonState: "ready", Machines: []localapi.MachineStatus{r.Machine}}
	if snapshot.Validate() != nil {
		return errors.New("invalid local wait result")
	}
	switch r.Outcome {
	case "ready":
		if r.Code != "" {
			return errors.New("invalid local wait result")
		}
	case "timeout":
		if r.Code != "wait_timeout" {
			return errors.New("invalid local wait result")
		}
	case "canceled":
		if r.Code != "wait_canceled" {
			return errors.New("invalid local wait result")
		}
	case "failed":
		if r.Code != "machine_unavailable" && r.Code != "machine_removed" {
			return errors.New("invalid local wait result")
		}
	default:
		return errors.New("invalid local wait result")
	}
	return nil
}

func ResolveMachine(machines []localapi.MachineStatus, target string) (localapi.MachineStatus, error) {
	target = strings.TrimSpace(target)
	for _, machine := range machines {
		if machine.ID == target {
			return machine, nil
		}
	}
	var match *localapi.MachineStatus
	for index := range machines {
		if !strings.EqualFold(machines[index].Alias, target) {
			continue
		}
		if match != nil {
			return localapi.MachineStatus{}, fmt.Errorf("machine alias %q is ambiguous; use a machine ID", target)
		}
		candidate := machines[index]
		match = &candidate
	}
	if match == nil {
		return localapi.MachineStatus{}, fmt.Errorf("machine %q was not found in local status", target)
	}
	return *match, nil
}

func Wait(ctx context.Context, client Client, machineID, condition string) (Result, error) {
	if client == nil || strings.TrimSpace(machineID) == "" || !validCondition(condition) {
		return Result{}, errors.New("invalid local wait configuration")
	}
	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	return waitFromSnapshot(ctx, client, snapshot, machineID, condition)
}

func WaitTargetFromSnapshot(ctx context.Context, client Client, snapshot localapi.Snapshot, target, condition string) (Result, error) {
	if client == nil || snapshot.Validate() != nil || strings.TrimSpace(target) == "" || !validCondition(condition) {
		return Result{}, errors.New("invalid local wait configuration")
	}
	machine, err := ResolveMachine(snapshot.Machines, target)
	if err != nil {
		return Result{}, err
	}
	return waitFromSnapshot(ctx, client, snapshot, machine.ID, condition)
}

func waitFromSnapshot(ctx context.Context, client Client, snapshot localapi.Snapshot, machineID, condition string) (Result, error) {
	last, found := machineByID(snapshot.Machines, machineID)
	if !found {
		return Result{}, fmt.Errorf("machine %q disappeared from local status", machineID)
	}
	if result, done := evaluate(snapshot, last, condition); done {
		return result, nil
	}
	cursor := snapshot.Generation
	for {
		updates, watchErrors := client.Watch(ctx, cursor)
		for updates != nil || watchErrors != nil {
			select {
			case next, ok := <-updates:
				if !ok {
					updates = nil
					continue
				}
				if next.Generation <= cursor {
					return Result{}, localapi.ErrInvalidResponse
				}
				cursor = next.Generation
				snapshot = next
				machine, exists := machineByID(next.Machines, machineID)
				if !exists {
					return resultFor(next, last, condition, "failed", "machine_removed"), nil
				}
				last = machine
				if result, done := evaluate(next, machine, condition); done {
					return result, nil
				}
			case watchErr, ok := <-watchErrors:
				if !ok {
					watchErrors = nil
					continue
				}
				if ctx.Err() != nil {
					return contextResult(ctx, snapshot, last, condition), nil
				}
				if watchErr != nil && !errors.Is(watchErr, io.EOF) {
					return Result{}, watchErr
				}
				watchErrors = nil
			case <-ctx.Done():
				return contextResult(ctx, snapshot, last, condition), nil
			}
		}
		if ctx.Err() != nil {
			return contextResult(ctx, snapshot, last, condition), nil
		}
	}
}

func evaluate(snapshot localapi.Snapshot, machine localapi.MachineStatus, condition string) (Result, bool) {
	if machine.RuntimeState == "failed" || healthCode(machine.Health, "machine_unavailable") {
		return resultFor(snapshot, machine, condition, "failed", "machine_unavailable"), true
	}
	runtimeReady := machine.Eligible && machine.Generation > 0 && (machine.RuntimeState == "ready" || machine.RuntimeState == "degraded")
	ready := runtimeReady
	if condition == "transport" || condition == "ssh" {
		ready = ready && machine.SelectedPath != "none"
	}
	if condition == "ssh" {
		ready = ready && machine.SSHReadiness == "ready"
	}
	if ready {
		return resultFor(snapshot, machine, condition, "ready", ""), true
	}
	return Result{}, false
}

func contextResult(ctx context.Context, snapshot localapi.Snapshot, machine localapi.MachineStatus, condition string) Result {
	outcome, code := "canceled", "wait_canceled"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		outcome, code = "timeout", "wait_timeout"
	}
	return resultFor(snapshot, machine, condition, outcome, code)
}

func resultFor(snapshot localapi.Snapshot, machine localapi.MachineStatus, condition, outcome, code string) Result {
	return Result{Schema: ResultSchemaV1, Condition: condition, Outcome: outcome, Code: code, SnapshotGeneration: snapshot.Generation, ObservedAt: snapshot.ObservedAt, Machine: machine}
}

func machineByID(machines []localapi.MachineStatus, id string) (localapi.MachineStatus, bool) {
	for _, machine := range machines {
		if machine.ID == id {
			return machine, true
		}
	}
	return localapi.MachineStatus{}, false
}

func healthCode(items []localapi.HealthItem, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func validCondition(condition string) bool {
	return condition == "runtime" || condition == "transport" || condition == "ssh"
}
