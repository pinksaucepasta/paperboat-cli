package releaseplan

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

// ProviderSchema identifies the signed, machine-bound activation inputs. The
// release signer carries these inputs in authenticated TUF custom metadata;
// the host updater consumes them through its ActivationGate adapter. This
// package deliberately has no dependency on the runtime updater, which keeps
// release policy and binary activation independently deployable.
const ProviderSchema = "paperboat.release-activation/v1"

const (
	QuarantineSchema       = "paperboat.release-quarantine/v1"
	RevocationSchema       = "paperboat.release-revocation/v1"
	MaxProviderBytes int64 = 256 << 10
)

// TargetBinding is the complete identity fence for one end-to-end update
// probe. Every field is public identity or a monotonic generation. Credentials,
// local paths, URLs, and authorization headers cannot be represented here.
type TargetBinding struct {
	MachineID         string `json:"machine_id"`
	AccountID         string `json:"account_id"`
	HostID            string `json:"host_id"`
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	EdgeNodeID        string `json:"edge_node_id"`
	FailureDomain     string `json:"failure_domain"`
	ProcessEpoch      uint64 `json:"process_epoch"`
	SessionGeneration uint64 `json:"session_generation"`
	ConfigGeneration  uint64 `json:"config_generation"`
	RouteGeneration   uint64 `json:"route_generation"`
}

func (b TargetBinding) Validate() error {
	for _, value := range []string{b.MachineID, b.AccountID, b.HostID, b.TunnelID, b.ConnectorID, b.EdgeNodeID} {
		if !releasepolicy.IsIdentifier(value) {
			return ErrInvalidPlan
		}
	}
	if b.FailureDomain != "*" && !releasepolicy.IsIdentifier(b.FailureDomain) {
		return ErrInvalidPlan
	}
	if b.ProcessEpoch == 0 || b.SessionGeneration == 0 || b.ConfigGeneration == 0 || b.RouteGeneration == 0 {
		return ErrInvalidPlan
	}
	return nil
}

// ReleaseRef is a TUF-authenticated release coordinate. It intentionally
// carries the manifest digest rather than an artifact URL or local path.
type ReleaseRef struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func (r ReleaseRef) Validate() error {
	if !releasepolicy.IsVersion(r.Version) || !releasepolicy.IsDigest(r.ManifestSHA256) {
		return ErrInvalidPlan
	}
	return nil
}

type CanaryInput struct {
	Schema           string        `json:"schema"`
	TransactionID    string        `json:"transaction_id"`
	PlanSHA256       string        `json:"plan_sha256"`
	Candidate        ReleaseRef    `json:"candidate"`
	Target           TargetBinding `json:"target"`
	Path             string        `json:"path"`
	ExpectedStatus   int           `json:"expected_status"`
	TimeoutSeconds   uint32        `json:"timeout_seconds"`
	Samples          uint16        `json:"samples"`
	RequireEdge      bool          `json:"require_edge"`
	RequireConnector bool          `json:"require_connector"`
	RequireRoute     bool          `json:"require_route"`
	RequireOrigin    bool          `json:"require_origin"`
}

type DrainInput struct {
	Schema            string        `json:"schema"`
	TransactionID     string        `json:"transaction_id"`
	PlanSHA256        string        `json:"plan_sha256"`
	Previous          ReleaseRef    `json:"previous"`
	Candidate         ReleaseRef    `json:"candidate"`
	Target            TargetBinding `json:"target"`
	TimeoutSeconds    uint32        `json:"timeout_seconds"`
	ForceAfterTimeout bool          `json:"force_after_timeout"`
}

type StabilityInput struct {
	Schema               string        `json:"schema"`
	TransactionID        string        `json:"transaction_id"`
	PlanSHA256           string        `json:"plan_sha256"`
	Candidate            ReleaseRef    `json:"candidate"`
	Target               TargetBinding `json:"target"`
	WindowSeconds        uint32        `json:"window_seconds"`
	ProbeIntervalSeconds uint32        `json:"probe_interval_seconds"`
	RequireEdge          bool          `json:"require_edge"`
	RequireConnector     bool          `json:"require_connector"`
	RequireRoute         bool          `json:"require_route"`
	RequireOrigin        bool          `json:"require_origin"`
}

type RollbackInput struct {
	Schema         string        `json:"schema"`
	TransactionID  string        `json:"transaction_id"`
	PlanSHA256     string        `json:"plan_sha256"`
	Failed         ReleaseRef    `json:"failed"`
	Restore        ReleaseRef    `json:"restore"`
	Target         TargetBinding `json:"target"`
	TimeoutSeconds uint32        `json:"timeout_seconds"`
	Trigger        string        `json:"trigger"`
}

// ProviderInputs is the signed handoff from release orchestration to the
// updater's edge-aware ActivationGate. All nested requests repeat the fence
// so a request copied to another phase cannot be accepted accidentally.
type ProviderInputs struct {
	Schema        string         `json:"schema"`
	TransactionID string         `json:"transaction_id"`
	PlanSHA256    string         `json:"plan_sha256"`
	Canary        CanaryInput    `json:"canary"`
	Drain         DrainInput     `json:"drain"`
	Stability     StabilityInput `json:"stability"`
	Rollback      RollbackInput  `json:"rollback"`
}

func (p ProviderInputs) Validate() error {
	if p.Schema != ProviderSchema || !releasepolicy.IsIdentifier(p.TransactionID) || !releasepolicy.IsDigest(p.PlanSHA256) {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Canary.Schema, p.Canary.TransactionID, p.Canary.PlanSHA256, p.Canary.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Canary.Candidate.Validate() != nil || p.Canary.Path == "" || len(p.Canary.Path) > 256 || !strings.HasPrefix(p.Canary.Path, "/") || strings.ContainsAny(p.Canary.Path, "\x00\r\n") || p.Canary.ExpectedStatus < 100 || p.Canary.ExpectedStatus > 599 || p.Canary.TimeoutSeconds == 0 || p.Canary.TimeoutSeconds > 60 || p.Canary.Samples == 0 || p.Canary.Samples > 1000 || !p.Canary.RequireEdge || !p.Canary.RequireConnector || !p.Canary.RequireRoute || !p.Canary.RequireOrigin {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Drain.Schema, p.Drain.TransactionID, p.Drain.PlanSHA256, p.Drain.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Drain.Previous.Validate() != nil || p.Drain.Candidate.Validate() != nil || p.Drain.TimeoutSeconds == 0 || p.Drain.TimeoutSeconds > 120 || !p.Drain.ForceAfterTimeout {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Stability.Schema, p.Stability.TransactionID, p.Stability.PlanSHA256, p.Stability.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Stability.Candidate.Validate() != nil || p.Stability.WindowSeconds == 0 || p.Stability.WindowSeconds > 24*60*60 || p.Stability.ProbeIntervalSeconds == 0 || p.Stability.ProbeIntervalSeconds > 60 || p.Stability.ProbeIntervalSeconds > p.Stability.WindowSeconds || !p.Stability.RequireEdge || !p.Stability.RequireConnector || !p.Stability.RequireRoute || !p.Stability.RequireOrigin {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Rollback.Schema, p.Rollback.TransactionID, p.Rollback.PlanSHA256, p.Rollback.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Rollback.Failed.Validate() != nil || p.Rollback.Restore.Validate() != nil || p.Rollback.TimeoutSeconds == 0 || p.Rollback.TimeoutSeconds > 120 {
		return ErrInvalidPlan
	}
	if !releasepolicy.AllowedRollbackTrigger(p.Rollback.Trigger) {
		return ErrInvalidPlan
	}
	if p.Canary.Candidate != p.Drain.Candidate || p.Canary.Candidate != p.Stability.Candidate || p.Canary.Candidate != p.Rollback.Failed || p.Drain.Previous != p.Rollback.Restore || p.Canary.Target != p.Drain.Target || p.Canary.Target != p.Stability.Target || p.Canary.Target != p.Rollback.Target {
		return ErrInvalidPlan
	}
	return nil
}

func ProviderInputsForPlan(p Plan, transactionID string, target TargetBinding, previous ReleaseRef, rollbackTrigger string) (ProviderInputs, error) {
	if err := p.Validate(); err != nil || !releasepolicy.IsIdentifier(transactionID) || target.Validate() != nil || previous.Validate() != nil || rollbackTrigger == "" {
		return ProviderInputs{}, ErrInvalidPlan
	}
	if !releasepolicy.AllowedRollbackTrigger(rollbackTrigger) {
		return ProviderInputs{}, ErrInvalidPlan
	}
	planDigest, err := p.PlanSHA256()
	if err != nil {
		return ProviderInputs{}, ErrInvalidPlan
	}
	candidate := ReleaseRef{Version: p.Version, ManifestSHA256: p.ManifestSHA256}
	canary := CanaryInput{
		Schema: ProviderSchema, TransactionID: transactionID, PlanSHA256: planDigest, Candidate: candidate, Target: target,
		Path: p.Canary.Path, ExpectedStatus: p.Canary.ExpectedStatus, TimeoutSeconds: p.Canary.TimeoutSeconds, Samples: p.Canary.Samples,
		RequireEdge: p.Canary.RequireEdge, RequireConnector: p.Canary.RequireConnector, RequireRoute: p.Canary.RequireRoute, RequireOrigin: p.Canary.RequireOrigin,
	}
	drain := DrainInput{
		Schema: ProviderSchema, TransactionID: transactionID, PlanSHA256: planDigest, Previous: previous, Candidate: candidate, Target: target,
		TimeoutSeconds: p.Activation.DrainTimeoutSeconds, ForceAfterTimeout: true,
	}
	stability := StabilityInput{
		Schema: ProviderSchema, TransactionID: transactionID, PlanSHA256: planDigest, Candidate: candidate, Target: target,
		WindowSeconds: p.Activation.StabilityWindowSeconds, ProbeIntervalSeconds: p.Activation.StabilityProbeIntervalSeconds,
		RequireEdge: true, RequireConnector: true, RequireRoute: true, RequireOrigin: true,
	}
	rollback := RollbackInput{
		Schema: ProviderSchema, TransactionID: transactionID, PlanSHA256: planDigest, Failed: candidate, Restore: previous, Target: target,
		TimeoutSeconds: p.Activation.RollbackTimeoutSeconds, Trigger: rollbackTrigger,
	}
	result := ProviderInputs{Schema: ProviderSchema, TransactionID: transactionID, PlanSHA256: planDigest, Canary: canary, Drain: drain, Stability: stability, Rollback: rollback}
	if err := result.ValidateAgainst(p); err != nil {
		return ProviderInputs{}, err
	}
	return result, nil
}

func (p ProviderInputs) ValidateAgainst(plan Plan) error {
	if err := plan.Validate(); err != nil || p.Validate() != nil {
		return ErrInvalidPlan
	}
	expectedDigest, err := plan.PlanSHA256()
	if err != nil || expectedDigest != p.PlanSHA256 {
		return ErrInvalidPlan
	}
	candidate := ReleaseRef{Version: plan.Version, ManifestSHA256: plan.ManifestSHA256}
	if err := validateCanaryInput(p.Canary, p.TransactionID, p.PlanSHA256, candidate, plan); err != nil {
		return err
	}
	if err := validateCommonPhase(p.Drain.Schema, p.Drain.TransactionID, p.Drain.PlanSHA256, p.Drain.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Drain.Previous.Validate() != nil || p.Drain.Candidate != candidate || p.Drain.TimeoutSeconds != plan.Activation.DrainTimeoutSeconds || !p.Drain.ForceAfterTimeout {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Stability.Schema, p.Stability.TransactionID, p.Stability.PlanSHA256, p.Stability.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Stability.Candidate != candidate || p.Stability.WindowSeconds != plan.Activation.StabilityWindowSeconds || p.Stability.ProbeIntervalSeconds != plan.Activation.StabilityProbeIntervalSeconds || !p.Stability.RequireEdge || !p.Stability.RequireConnector || !p.Stability.RequireRoute || !p.Stability.RequireOrigin {
		return ErrInvalidPlan
	}
	if err := validateCommonPhase(p.Rollback.Schema, p.Rollback.TransactionID, p.Rollback.PlanSHA256, p.Rollback.Target, p.TransactionID, p.PlanSHA256); err != nil || p.Rollback.Failed != candidate || p.Rollback.Restore.Validate() != nil || p.Rollback.TimeoutSeconds != plan.Activation.RollbackTimeoutSeconds || p.Rollback.Trigger == "" {
		return ErrInvalidPlan
	}
	if !releasepolicy.AllowedRollbackTrigger(p.Rollback.Trigger) {
		return ErrInvalidPlan
	}
	return nil
}

func validateCommonPhase(schema, transactionID, planDigest string, target TargetBinding, expectedTransaction, expectedDigest string) error {
	if schema != ProviderSchema || transactionID != expectedTransaction || planDigest != expectedDigest || target.Validate() != nil {
		return ErrInvalidPlan
	}
	return nil
}

func validateCanaryInput(input CanaryInput, transactionID, planDigest string, candidate ReleaseRef, plan Plan) error {
	if err := validateCommonPhase(input.Schema, input.TransactionID, input.PlanSHA256, input.Target, transactionID, planDigest); err != nil || input.Candidate != candidate || input.Path != plan.Canary.Path || input.ExpectedStatus != plan.Canary.ExpectedStatus || input.TimeoutSeconds != plan.Canary.TimeoutSeconds || input.Samples != plan.Canary.Samples || input.RequireEdge != plan.Canary.RequireEdge || input.RequireConnector != plan.Canary.RequireConnector || input.RequireRoute != plan.Canary.RequireRoute || input.RequireOrigin != plan.Canary.RequireOrigin {
		return ErrInvalidPlan
	}
	return nil
}

func (p ProviderInputs) Bytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, ErrInvalidPlan
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func LoadTargetBinding(path string) (TargetBinding, error) {
	body, err := readBoundedJSON(path, MaxProviderBytes)
	if err != nil {
		return TargetBinding{}, err
	}
	var target TargetBinding
	if err := decodeStrict(body, &target); err != nil || target.Validate() != nil {
		return TargetBinding{}, ErrInvalidPlan
	}
	return target, nil
}

func LoadProviderInputs(path string) (ProviderInputs, error) {
	body, err := readBoundedJSON(path, MaxProviderBytes)
	if err != nil {
		return ProviderInputs{}, err
	}
	var inputs ProviderInputs
	if err := decodeStrict(body, &inputs); err != nil || inputs.Validate() != nil {
		return ProviderInputs{}, ErrInvalidPlan
	}
	return inputs, nil
}

// QuarantineOutput and RevocationOutput are safe, durable consequences of a
// failed transaction. They contain no machine path or credential material.
type QuarantineOutput struct {
	Schema         string    `json:"schema"`
	TransactionID  string    `json:"transaction_id"`
	Version        string    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	Reason         string    `json:"reason"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
	Until          time.Time `json:"until"`
}

type RevocationOutput struct {
	Schema         string    `json:"schema"`
	TransactionID  string    `json:"transaction_id"`
	Version        string    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	Reason         string    `json:"reason"`
	RevokedAt      time.Time `json:"revoked_at"`
}

func (s State) QuarantineOutput(now time.Time) (QuarantineOutput, error) {
	if err := s.Validate(); err != nil || !s.Quarantined || s.QuarantineUntil == nil || now.IsZero() || strings.TrimSpace(s.Failure) == "" {
		return QuarantineOutput{}, ErrInvalidState
	}
	return QuarantineOutput{Schema: QuarantineSchema, TransactionID: s.TransactionID, Version: s.Version, ManifestSHA256: s.ManifestSHA256, Reason: s.Failure, QuarantinedAt: s.UpdatedAt.UTC(), Until: s.QuarantineUntil.UTC()}, nil
}

func (s State) RevocationOutput(now time.Time) (RevocationOutput, error) {
	if err := s.Validate(); err != nil || !s.Revoked || now.IsZero() || strings.TrimSpace(s.Failure) == "" {
		return RevocationOutput{}, ErrInvalidState
	}
	return RevocationOutput{Schema: RevocationSchema, TransactionID: s.TransactionID, Version: s.Version, ManifestSHA256: s.ManifestSHA256, Reason: s.Failure, RevokedAt: s.UpdatedAt.UTC()}, nil
}

func (q QuarantineOutput) Bytes() ([]byte, error) {
	if q.Schema != QuarantineSchema || !releasepolicy.IsIdentifier(q.TransactionID) || !releasepolicy.IsVersion(q.Version) || !releasepolicy.IsDigest(q.ManifestSHA256) || strings.TrimSpace(q.Reason) == "" || q.QuarantinedAt.IsZero() || q.Until.IsZero() || !q.Until.After(q.QuarantinedAt) {
		return nil, ErrInvalidState
	}
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (r RevocationOutput) Bytes() ([]byte, error) {
	if r.Schema != RevocationSchema || !releasepolicy.IsIdentifier(r.TransactionID) || !releasepolicy.IsVersion(r.Version) || !releasepolicy.IsDigest(r.ManifestSHA256) || strings.TrimSpace(r.Reason) == "" || r.RevokedAt.IsZero() {
		return nil, ErrInvalidState
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}
