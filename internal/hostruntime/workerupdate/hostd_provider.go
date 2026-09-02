package workerupdate

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

var ErrHostdActivationProvider = errors.New("hostd update activation provider failed")

type HostdUpdateGateClient interface {
	UpdateGate(context.Context, hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error)
}

// HostdDeploymentProvider keeps activation authority in stable hostd. The
// updater supplies only signed static policy; hostd resolves and acts on the
// current authenticated carrier tuple for every request.
type HostdDeploymentProvider struct{ Client HostdUpdateGateClient }

func (p HostdDeploymentProvider) CurrentTarget(ctx context.Context, request TargetRequest) (DeploymentTarget, error) {
	response, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: request.TransactionID, Version: request.Version, ManifestSHA256: request.ManifestSHA256})
	if err != nil {
		return DeploymentTarget{}, err
	}
	return deploymentTargetFromHostd(response.Target)
}

func (p HostdDeploymentProvider) ProbeCandidate(ctx context.Context, request CanaryProbeRequest) error {
	target := hostdTarget(request.Target)
	_, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCandidate, TransactionID: request.TransactionID, Version: request.Version, ManifestSHA256: request.ManifestSHA256, Path: request.Path, ExpectedStatus: request.ExpectedStatus, Samples: request.Samples, TimeoutMillis: request.Timeout.Milliseconds(), ExpectedTarget: &target})
	return err
}

func (p HostdDeploymentProvider) Drain(ctx context.Context, request DrainRequest) error {
	target := hostdTarget(request.Target)
	_, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateDrain, TransactionID: request.TransactionID, Version: request.Candidate, PreviousVersion: request.Previous, ManifestSHA256: request.ManifestSHA256, TimeoutMillis: request.Timeout.Milliseconds(), ExpectedTarget: &target})
	return err
}

func (p HostdDeploymentProvider) ObserveStability(ctx context.Context, request StabilityRequest) error {
	target := hostdTarget(request.Target)
	_, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateStability, TransactionID: request.TransactionID, Version: request.Candidate, ManifestSHA256: request.ManifestSHA256, Path: request.Path, ExpectedStatus: request.ExpectedStatus, Samples: request.Samples, WindowMillis: request.Window.Milliseconds(), IntervalMillis: request.Interval.Milliseconds(), ExpectedTarget: &target})
	return err
}

func (p HostdDeploymentProvider) VerifyRollback(ctx context.Context, request RollbackRequest) error {
	target := hostdTarget(request.Target)
	_, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateRollback, TransactionID: request.TransactionID, Version: request.Failed, PreviousVersion: request.Restore, ManifestSHA256: request.ManifestSHA256, Path: request.Path, ExpectedStatus: request.ExpectedStatus, Samples: request.Samples, TimeoutMillis: request.Timeout.Milliseconds(), ExpectedTarget: &target})
	return err
}

func (p HostdDeploymentProvider) Commit(ctx context.Context, request CommitRequest) error {
	target := hostdTarget(request.Target)
	_, err := p.call(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCommit, TransactionID: request.TransactionID, Version: request.Version, ManifestSHA256: request.ManifestSHA256, ExpectedTarget: &target})
	return err
}

func (p HostdDeploymentProvider) call(ctx context.Context, request hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error) {
	if p.Client == nil || ctx == nil {
		return hostdproto.UpdateGateResponse{}, ErrHostdActivationProvider
	}
	response, err := p.Client.UpdateGate(ctx, request)
	if err != nil {
		return hostdproto.UpdateGateResponse{}, errors.Join(ErrHostdActivationProvider, err)
	}
	if _, err := deploymentTargetFromHostd(response.Target); err != nil {
		return hostdproto.UpdateGateResponse{}, err
	}
	return response, nil
}

func deploymentTargetFromHostd(value hostdproto.UpdateGateTargetBinding) (DeploymentTarget, error) {
	target := DeploymentTarget{Scope: value.Scope, MachineID: value.MachineID, AccountID: value.AccountID, HostID: value.HostID, TunnelID: value.TunnelID, ConnectorID: value.ConnectorID, EdgeNodeID: value.EdgeNodeID, ProcessEpoch: value.ProcessEpoch, SessionGeneration: value.SessionGeneration, ConfigGeneration: value.ConfigGeneration, RouteGeneration: value.RouteGeneration, FailureDomain: value.FailureDomain}
	if validateDeploymentTarget(target) != nil {
		return DeploymentTarget{}, ErrHostdActivationProvider
	}
	return target, nil
}

func hostdTarget(value DeploymentTarget) hostdproto.UpdateGateTargetBinding {
	return hostdproto.UpdateGateTargetBinding{Scope: value.Scope, MachineID: value.MachineID, AccountID: value.AccountID, HostID: value.HostID, TunnelID: value.TunnelID, ConnectorID: value.ConnectorID, EdgeNodeID: value.EdgeNodeID, ProcessEpoch: value.ProcessEpoch, SessionGeneration: value.SessionGeneration, ConfigGeneration: value.ConfigGeneration, RouteGeneration: value.RouteGeneration, FailureDomain: value.FailureDomain}
}

var _ SignedDeploymentProvider = HostdDeploymentProvider{}
