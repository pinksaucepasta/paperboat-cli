package workerupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

var ErrInvalidDeploymentGate = errors.New("invalid signed update deployment gate")

type DeploymentTarget struct {
	Scope             string
	MachineID         string
	AccountID         string
	HostID            string
	TunnelID          string
	ConnectorID       string
	EdgeNodeID        string
	ProcessEpoch      uint64
	SessionGeneration uint64
	ConfigGeneration  uint64
	RouteGeneration   uint64
	FailureDomain     string
}

type CanaryProbeRequest struct {
	TransactionID                                              string
	Version                                                    string
	ManifestSHA256                                             string
	Target                                                     DeploymentTarget
	Path                                                       string
	ExpectedStatus                                             int
	Timeout                                                    time.Duration
	Samples                                                    uint16
	RequireEdge, RequireConnector, RequireRoute, RequireOrigin bool
}

type DrainRequest struct {
	TransactionID       string
	Previous, Candidate string
	ManifestSHA256      string
	Target              DeploymentTarget
	Timeout             time.Duration
}

type StabilityRequest struct {
	TransactionID    string
	Candidate        string
	ManifestSHA256   string
	Path             string
	ExpectedStatus   int
	Samples          uint16
	Target           DeploymentTarget
	Window, Interval time.Duration
}

type RollbackRequest struct {
	TransactionID   string
	Failed, Restore string
	ManifestSHA256  string
	Path            string
	ExpectedStatus  int
	Samples         uint16
	Target          DeploymentTarget
	Timeout         time.Duration
	Triggers        []string
}

// CommitRequest closes the hostd transaction after the candidate has passed
// the complete stability window. It intentionally carries the exact target
// fence again so a delayed completion cannot commit a replacement carrier.
type CommitRequest struct {
	TransactionID  string
	Version        string
	ManifestSHA256 string
	Target         DeploymentTarget
}

// SignedDeploymentProvider accepts only exact signed release orchestration
// inputs. No credential, arbitrary URL, command, executable, or local path is
// present in this contract.
type SignedDeploymentProvider interface {
	CurrentTarget(context.Context, TargetRequest) (DeploymentTarget, error)
	ProbeCandidate(context.Context, CanaryProbeRequest) error
	Drain(context.Context, DrainRequest) error
	ObserveStability(context.Context, StabilityRequest) error
	VerifyRollback(context.Context, RollbackRequest) error
	Commit(context.Context, CommitRequest) error
}

type DeploymentActivationGateConfig struct {
	Provider SignedDeploymentProvider
}

type deploymentActivationGate struct {
	config DeploymentActivationGateConfig
}

func NewDeploymentActivationGate(config DeploymentActivationGateConfig) (ActivationGate, error) {
	if config.Provider == nil {
		return nil, ErrInvalidDeploymentGate
	}
	return &deploymentActivationGate{config: config}, nil
}

func (g *deploymentActivationGate) Candidate(ctx context.Context, request GateRequest) error {
	if g == nil || request.validateCandidate() != nil || validateActivationPolicy(request.Candidate) != nil {
		return ErrInvalidDeploymentGate
	}
	target, err := g.currentTarget(ctx, request)
	if err != nil {
		return err
	}
	standalone := target.Scope == hostdproto.UpdateGateScopeStandalone
	return g.config.Provider.ProbeCandidate(ctx, CanaryProbeRequest{
		TransactionID: request.TransactionID, Version: request.Candidate.Version,
		ManifestSHA256: request.Candidate.ManifestSHA256, Target: target,
		Path: request.Candidate.CanaryPath, ExpectedStatus: request.Candidate.CanaryStatus,
		Timeout: deadlineBudget(ctx), Samples: request.Candidate.CanarySamples,
		RequireEdge: !standalone, RequireConnector: !standalone, RequireRoute: !standalone, RequireOrigin: !standalone,
	})
}

func (g *deploymentActivationGate) Drain(ctx context.Context, request GateRequest) error {
	if g == nil || request.validateCandidate() != nil || validateActivationPolicy(request.Candidate) != nil {
		return ErrInvalidDeploymentGate
	}
	target, err := g.currentTarget(ctx, request)
	if err != nil {
		return err
	}
	return g.config.Provider.Drain(ctx, DrainRequest{TransactionID: request.TransactionID, Previous: request.Previous.Version, Candidate: request.Candidate.Version, ManifestSHA256: request.Candidate.ManifestSHA256, Target: target, Timeout: deadlineBudget(ctx)})
}

func (g *deploymentActivationGate) Active(ctx context.Context, request GateRequest) error {
	if g == nil || request.validateActive() != nil || validateActivationPolicy(request.Candidate) != nil || request.Window != request.Candidate.StabilityWindow || request.Interval != request.Candidate.StabilityInterval {
		return ErrInvalidDeploymentGate
	}
	target, err := g.currentTarget(ctx, request)
	if err != nil {
		return err
	}
	return g.config.Provider.ObserveStability(ctx, StabilityRequest{TransactionID: request.TransactionID, Candidate: request.Candidate.Version, ManifestSHA256: request.Candidate.ManifestSHA256, Path: request.Candidate.CanaryPath, ExpectedStatus: request.Candidate.CanaryStatus, Samples: request.Candidate.CanarySamples, Target: target, Window: request.Window, Interval: request.Interval})
}

func (g *deploymentActivationGate) Rollback(ctx context.Context, request GateRequest) error {
	if g == nil || request.validateActive() != nil || !lowerDigest(request.Previous.ManifestSHA256) {
		return ErrInvalidDeploymentGate
	}
	target, err := g.config.Provider.CurrentTarget(ctx, TargetRequest{TransactionID: request.TransactionID, Version: request.Previous.Version, ManifestSHA256: request.Previous.ManifestSHA256})
	if err != nil || validateDeploymentTarget(target) != nil {
		return errors.Join(ErrInvalidDeploymentGate, err)
	}
	return g.config.Provider.VerifyRollback(ctx, RollbackRequest{TransactionID: request.TransactionID, Failed: request.Previous.Version, Restore: request.Candidate.Version, ManifestSHA256: request.Previous.ManifestSHA256, Path: request.Previous.CanaryPath, ExpectedStatus: request.Previous.CanaryStatus, Samples: request.Previous.CanarySamples, Target: target, Timeout: deadlineBudget(ctx), Triggers: []string{"candidate_health_failed"}})
}

// Commit finalizes a successful cutover in the stable hostd ledger. It is a
// separate terminal action from Active so a process crash between the final
// canary and cleanup can safely retry the same commit without leaving the
// transaction in the drained recovery set.
func (g *deploymentActivationGate) Commit(ctx context.Context, request GateRequest) error {
	if g == nil || request.validateActive() != nil || validateActivationPolicy(request.Candidate) != nil {
		return ErrInvalidDeploymentGate
	}
	target, err := g.currentTarget(ctx, request)
	if err != nil {
		return err
	}
	return g.config.Provider.Commit(ctx, CommitRequest{TransactionID: request.TransactionID, Version: request.Candidate.Version, ManifestSHA256: request.Candidate.ManifestSHA256, Target: target})
}

type TargetRequest struct {
	TransactionID  string
	Version        string
	ManifestSHA256 string
}

func (g *deploymentActivationGate) currentTarget(ctx context.Context, request GateRequest) (DeploymentTarget, error) {
	target, err := g.config.Provider.CurrentTarget(ctx, TargetRequest{TransactionID: request.TransactionID, Version: request.Candidate.Version, ManifestSHA256: request.Candidate.ManifestSHA256})
	if err != nil || validateDeploymentTarget(target) != nil {
		return DeploymentTarget{}, errors.Join(ErrInvalidDeploymentGate, err)
	}
	return target, nil
}

func validateActivationPolicy(release Release) error {
	if !lowerDigest(release.ManifestSHA256) || !validCanaryPath(release.CanaryPath) || release.CanaryStatus < 200 || release.CanaryStatus > 299 || release.CanarySamples < 2 || release.CanarySamples > 32 || release.CanaryTimeout <= 0 || release.CanaryTimeout > 5*time.Minute || release.DrainTimeout <= 0 || release.DrainTimeout > 5*time.Minute || release.StabilityWindow <= 0 || release.StabilityWindow > 30*time.Minute || release.StabilityInterval <= 0 || release.StabilityInterval > release.StabilityWindow || release.RollbackTimeout <= 0 || release.RollbackTimeout > 5*time.Minute {
		return ErrInvalidDeploymentGate
	}
	return nil
}

func ValidateActivationRelease(release Release) error {
	if validateRelease(release) != nil || ValidateActivationPolicy(release) != nil {
		return ErrInvalidDeploymentGate
	}
	return nil
}

// ValidateActivationPolicy validates only the signed deployment policy. It is
// used by platform-neutral transaction journal validation where the candidate
// platform can legitimately differ from the test process platform.
func ValidateActivationPolicy(release Release) error {
	return validateActivationPolicy(release)
}

func (r GateRequest) validateCandidate() error { return r.validateState("candidate") }
func (r GateRequest) validateActive() error    { return r.validateState("active") }
func (r GateRequest) validateState(state string) error {
	workerStateValid := string(r.Worker.State) == state || state == "candidate" && r.Worker.State == hostdproto.StateActive
	if !safeEventID(r.TransactionID) || validateRelease(r.Previous) != nil || validateRelease(r.Candidate) != nil || !workerStateValid || r.Worker.WorkerID == "" || r.Worker.Epoch == 0 || r.Worker.APIVersion == 0 {
		return ErrInvalidDeploymentGate
	}
	return nil
}

var deploymentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validateDeploymentTarget(target DeploymentTarget) error {
	for _, value := range []string{target.MachineID, target.FailureDomain} {
		if !deploymentIDPattern.MatchString(value) {
			return ErrInvalidDeploymentGate
		}
	}
	switch target.Scope {
	case hostdproto.UpdateGateScopeStandalone:
		if target.AccountID != "" || target.HostID != "" || target.TunnelID != "" || target.ConnectorID != "" || target.EdgeNodeID != "" || target.ProcessEpoch != 0 || target.SessionGeneration != 0 || target.ConfigGeneration != 0 || target.RouteGeneration != 0 {
			return ErrInvalidDeploymentGate
		}
	case hostdproto.UpdateGateScopeTunnel:
		for _, value := range []string{target.AccountID, target.HostID, target.TunnelID, target.ConnectorID, target.EdgeNodeID} {
			if !deploymentIDPattern.MatchString(value) {
				return ErrInvalidDeploymentGate
			}
		}
		if target.ProcessEpoch == 0 || target.SessionGeneration == 0 || target.ConfigGeneration == 0 || target.RouteGeneration == 0 {
			return ErrInvalidDeploymentGate
		}
	default:
		return ErrInvalidDeploymentGate
	}
	return nil
}

func lowerDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validCanaryPath(value string) bool {
	if len(value) < 1 || len(value) > 512 || value[0] != '/' || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && parsed.Fragment == ""
}

func deadlineBudget(ctx context.Context) time.Duration {
	if ctx == nil {
		return 0
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining < 0 {
		return 0
	}
	return remaining
}
