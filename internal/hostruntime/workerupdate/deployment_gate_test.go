package workerupdate

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

type recordingDeploymentProvider struct {
	target    DeploymentTarget
	canary    CanaryProbeRequest
	drain     DrainRequest
	stability StabilityRequest
	rollback  RollbackRequest
	commit    CommitRequest
}

func (p *recordingDeploymentProvider) CurrentTarget(_ context.Context, _ TargetRequest) (DeploymentTarget, error) {
	return p.target, nil
}

func (p *recordingDeploymentProvider) ProbeCandidate(_ context.Context, request CanaryProbeRequest) error {
	p.canary = request
	return nil
}
func (p *recordingDeploymentProvider) Drain(_ context.Context, request DrainRequest) error {
	p.drain = request
	return nil
}
func (p *recordingDeploymentProvider) ObserveStability(_ context.Context, request StabilityRequest) error {
	p.stability = request
	return nil
}
func (p *recordingDeploymentProvider) VerifyRollback(_ context.Context, request RollbackRequest) error {
	p.rollback = request
	return nil
}
func (p *recordingDeploymentProvider) Commit(_ context.Context, request CommitRequest) error {
	p.commit = request
	return nil
}

func deploymentTarget() DeploymentTarget {
	return DeploymentTarget{Scope: hostdproto.UpdateGateScopeTunnel, MachineID: "machine_1", AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", EdgeNodeID: "edge_1", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "hel1-a"}
}

func TestDeploymentActivationGateBindsEverySignedFence(t *testing.T) {
	provider := &recordingDeploymentProvider{target: deploymentTarget()}
	gate, err := NewDeploymentActivationGate(DeploymentActivationGateConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	previous := Release{Version: "2026.08.30.1", SHA256: strings.Repeat("b", 64), Length: 10, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2}
	candidate := previous
	candidate.Version, candidate.SHA256 = "2026.08.31.1", strings.Repeat("c", 64)
	candidate.ManifestSHA256, candidate.CanaryPath, candidate.CanaryStatus, candidate.CanarySamples = strings.Repeat("a", 64), "/.well-known/paperboat-update-canary", 204, 4
	candidate.CanaryTimeout, candidate.DrainTimeout, candidate.StabilityWindow, candidate.StabilityInterval, candidate.RollbackTimeout = time.Second, time.Second, time.Minute, time.Second, time.Second
	previous.ManifestSHA256, previous.CanaryPath, previous.CanaryStatus, previous.CanarySamples = strings.Repeat("b", 64), "/.well-known/paperboat-update-canary", 204, 4
	previous.CanaryTimeout, previous.DrainTimeout, previous.StabilityWindow, previous.StabilityInterval, previous.RollbackTimeout = time.Second, time.Second, time.Minute, time.Second, time.Second
	candidateRequest := GateRequest{TransactionID: "txn_1", Previous: previous, Candidate: candidate, Worker: hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: "worker_2", APIVersion: 1, Epoch: 2}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.Candidate(ctx, candidateRequest); err != nil {
		t.Fatal(err)
	}
	if err := gate.Drain(ctx, candidateRequest); err != nil {
		t.Fatal(err)
	}
	activeRequest := candidateRequest
	activeRequest.Worker.State, activeRequest.Window, activeRequest.Interval = hostdproto.StateActive, time.Minute, time.Second
	if err := gate.Active(ctx, activeRequest); err != nil {
		t.Fatal(err)
	}
	rollbackRequest := GateRequest{TransactionID: "txn_1", Previous: candidate, Candidate: previous, Worker: hostdproto.Status{State: hostdproto.StateActive, WorkerID: "worker_rollback", APIVersion: 1, Epoch: 3}}
	if err := gate.Rollback(ctx, rollbackRequest); err != nil {
		t.Fatal(err)
	}
	if provider.canary.Version != candidate.Version || provider.canary.ManifestSHA256 != strings.Repeat("a", 64) || provider.canary.Target != deploymentTarget() || !provider.canary.RequireEdge || !provider.canary.RequireConnector || !provider.canary.RequireRoute || !provider.canary.RequireOrigin || provider.canary.Samples != 4 {
		t.Fatalf("canary=%+v", provider.canary)
	}
	if provider.drain.Previous != previous.Version || provider.drain.Candidate != candidate.Version || provider.drain.Target != deploymentTarget() || provider.drain.Timeout <= 0 {
		t.Fatalf("drain=%+v", provider.drain)
	}
	if provider.stability.Candidate != candidate.Version || provider.stability.Window != time.Minute || provider.stability.Interval != time.Second || provider.stability.Target != deploymentTarget() {
		t.Fatalf("stability=%+v", provider.stability)
	}
	if provider.rollback.Failed != candidate.Version || provider.rollback.Restore != previous.Version || provider.rollback.Target != deploymentTarget() || len(provider.rollback.Triggers) != 1 {
		t.Fatalf("rollback=%+v", provider.rollback)
	}
	committer, ok := gate.(interface {
		Commit(context.Context, GateRequest) error
	})
	if !ok {
		t.Fatal("deployment gate does not expose terminal commit")
	}
	if err := committer.Commit(ctx, activeRequest); err != nil {
		t.Fatal(err)
	}
	if provider.commit.TransactionID != "txn_1" || provider.commit.Version != candidate.Version || provider.commit.ManifestSHA256 != candidate.ManifestSHA256 || provider.commit.Target != deploymentTarget() {
		t.Fatalf("commit=%+v", provider.commit)
	}
}

func TestDeploymentActivationGateRejectsMissingOrUnsafeSignedInputs(t *testing.T) {
	provider := &recordingDeploymentProvider{target: deploymentTarget()}
	base := DeploymentActivationGateConfig{Provider: provider}
	tests := []func(*DeploymentActivationGateConfig){
		func(c *DeploymentActivationGateConfig) { c.Provider = nil },
	}
	for index, mutate := range tests {
		candidate := base
		mutate(&candidate)
		if _, err := NewDeploymentActivationGate(candidate); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestDeploymentActivationGateRejectsInvalidCurrentTarget(t *testing.T) {
	provider := &recordingDeploymentProvider{target: deploymentTarget()}
	provider.target.ProcessEpoch = 0
	gate, err := NewDeploymentActivationGate(DeploymentActivationGateConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	release := Release{Version: "2026.08.31.1", SHA256: strings.Repeat("c", 64), Length: 10, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2}
	release.ManifestSHA256, release.CanaryPath, release.CanaryStatus, release.CanarySamples = strings.Repeat("a", 64), "/canary", 204, 3
	release.CanaryTimeout, release.DrainTimeout, release.StabilityWindow, release.StabilityInterval, release.RollbackTimeout = time.Second, time.Second, time.Minute, time.Second, time.Second
	request := GateRequest{TransactionID: "txn_1", Previous: release, Candidate: release, Worker: hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: "worker_2", APIVersion: 1, Epoch: 2}}
	if err := gate.Candidate(context.Background(), request); err == nil {
		t.Fatal("invalid current target accepted")
	}
}

func TestDeploymentGateAcceptsTruthfulStandaloneTarget(t *testing.T) {
	target := DeploymentTarget{Scope: hostdproto.UpdateGateScopeStandalone, MachineID: "machine_1", FailureDomain: "standalone"}
	if err := validateDeploymentTarget(target); err != nil {
		t.Fatalf("valid standalone target rejected: %v", err)
	}
	target.EdgeNodeID = "edge_fake"
	if err := validateDeploymentTarget(target); err == nil {
		t.Fatal("standalone target accepted fabricated edge identity")
	}
}

func TestDeploymentGateDoesNotInventTunnelRequirementsForStandalone(t *testing.T) {
	provider := &recordingDeploymentProvider{target: DeploymentTarget{Scope: hostdproto.UpdateGateScopeStandalone, MachineID: "machine_1", FailureDomain: "standalone"}}
	gate, err := NewDeploymentActivationGate(DeploymentActivationGateConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	release := Release{Version: "2026.09.02.2", SHA256: strings.Repeat("c", 64), Length: 10, Platform: runtime.GOOS, Architecture: runtime.GOARCH, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, ManifestSHA256: strings.Repeat("a", 64), CanaryPath: "/healthz", CanaryStatus: 200, CanarySamples: 2, CanaryTimeout: time.Second, DrainTimeout: time.Second, StabilityWindow: time.Minute, StabilityInterval: time.Second, RollbackTimeout: time.Second}
	request := GateRequest{TransactionID: "txn_standalone", Previous: release, Candidate: release, Worker: hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: "worker_2", APIVersion: 1, Epoch: 2}}
	if err := gate.Candidate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if provider.canary.RequireEdge || provider.canary.RequireConnector || provider.canary.RequireRoute || provider.canary.RequireOrigin {
		t.Fatalf("standalone canary invented tunnel requirements: %+v", provider.canary)
	}
}
