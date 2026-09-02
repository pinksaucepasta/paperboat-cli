//go:build windows

package updated

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

type windowsGateTestProvider struct {
	target    workerupdate.DeploymentTarget
	canary    workerupdate.CanaryProbeRequest
	stability workerupdate.StabilityRequest
}

func (p *windowsGateTestProvider) CurrentTarget(context.Context, workerupdate.TargetRequest) (workerupdate.DeploymentTarget, error) {
	return p.target, nil
}

func (p *windowsGateTestProvider) ProbeCandidate(_ context.Context, request workerupdate.CanaryProbeRequest) error {
	p.canary = request
	return nil
}

func (p *windowsGateTestProvider) Drain(context.Context, workerupdate.DrainRequest) error {
	return nil
}

func (p *windowsGateTestProvider) ObserveStability(_ context.Context, request workerupdate.StabilityRequest) error {
	p.stability = request
	return nil
}

func (p *windowsGateTestProvider) VerifyRollback(context.Context, workerupdate.RollbackRequest) error {
	return nil
}

func (p *windowsGateTestProvider) Commit(context.Context, workerupdate.CommitRequest) error {
	return nil
}

func TestWindowsActivationGateRequestsUseCandidateThenActiveState(t *testing.T) {
	journal := testWindowsActivationJournal()
	provider := &windowsGateTestProvider{target: workerupdate.DeploymentTarget{
		Scope:     hostdproto.UpdateGateScopeTunnel,
		MachineID: "machine-1", AccountID: "account-1", HostID: "host-1", TunnelID: "tunnel-1", ConnectorID: "connector-1", EdgeNodeID: "edge-1", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "edge-a",
	}}
	gate, err := workerupdate.NewDeploymentActivationGate(workerupdate.DeploymentActivationGateConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidateStatus := hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: windowsCandidateWorkerID(journal.Version), APIVersion: 1, Epoch: 2}
	candidateRequest, err := windowsCandidateGateRequest(journal, candidateStatus)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Candidate(ctx, candidateRequest); err != nil {
		t.Fatal(err)
	}
	if provider.canary.Version != journal.Version || provider.canary.Target != provider.target {
		t.Fatalf("canary=%+v", provider.canary)
	}
	activeStatus := candidateStatus
	activeStatus.State = hostdproto.StateActive
	activeRequest, err := windowsActiveGateRequest(journal, activeStatus)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Active(ctx, activeRequest); err != nil {
		t.Fatal(err)
	}
	if provider.stability.Candidate != journal.Version || provider.stability.Target != provider.target {
		t.Fatalf("stability=%+v", provider.stability)
	}
	if _, err := windowsCandidateGateRequest(journal, activeStatus); err == nil {
		t.Fatal("active worker was accepted as a candidate gate input")
	}
	if strings.Contains(provider.canary.Path, "http") {
		t.Fatalf("canary path unexpectedly became an absolute URL: %q", provider.canary.Path)
	}
	if runtime.GOOS != "windows" {
		t.Fatalf("test compiled for %s", runtime.GOOS)
	}
}

func TestWindowsTransactionStateMapsEveryActivationStage(t *testing.T) {
	journal := testWindowsActivationJournal()
	tests := []struct {
		stage windowsActivationStage
		want  updateflow.Stage
	}{
		{windowsActivationStaged, updateflow.StageStaged},
		{windowsActivationCandidateValidating, updateflow.StageCandidateValidating},
		{windowsActivationCandidateReady, updateflow.StageCandidateReady},
		{windowsActivationDraining, updateflow.StageDraining},
		{windowsActivationSwitching, updateflow.StageCutover},
		{windowsActivationServicesLive, updateflow.StageMonitoring},
		{windowsActivationCommitted, updateflow.StageCommitted},
		{windowsActivationRollingBack, updateflow.StageRollback},
		{windowsActivationRollbackReady, updateflow.StageRollback},
		{windowsActivationRolledBack, updateflow.StageIdle},
	}
	for _, test := range tests {
		journal.Stage = test.stage
		state := windowsTransactionState(journal)
		if state.Stage != test.want {
			t.Fatalf("stage %q mapped to %q, want %q", test.stage, state.Stage, test.want)
		}
	}
}
