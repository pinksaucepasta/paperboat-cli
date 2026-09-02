package hostdproto

import (
	"context"
	"regexp"
	"strings"
)

const (
	UpdateGateScopeStandalone = "standalone"
	UpdateGateScopeTunnel     = "tunnel"

	UpdateGateTarget    = "target"
	UpdateGateCandidate = "candidate"
	UpdateGateDrain     = "drain"
	UpdateGateStability = "stability"
	UpdateGateRollback  = "rollback"
	UpdateGateCommit    = "commit"
)

var updateGateIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var updateGateDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// UpdateGateRequest contains only signed release policy and transaction
// identity. Stable hostd resolves the live carrier, route, and generation
// tuple itself for every call; the updater cannot supply or cache it.
type UpdateGateRequest struct {
	Operation       string                   `json:"operation"`
	TransactionID   string                   `json:"transaction_id"`
	Version         string                   `json:"version"`
	PreviousVersion string                   `json:"previous_version,omitempty"`
	ManifestSHA256  string                   `json:"manifest_sha256"`
	Path            string                   `json:"path,omitempty"`
	ExpectedStatus  int                      `json:"expected_status,omitempty"`
	Samples         uint16                   `json:"samples,omitempty"`
	TimeoutMillis   int64                    `json:"timeout_millis,omitempty"`
	WindowMillis    int64                    `json:"window_millis,omitempty"`
	IntervalMillis  int64                    `json:"interval_millis,omitempty"`
	ExpectedTarget  *UpdateGateTargetBinding `json:"expected_target,omitempty"`
}

func (UpdateGateRequest) messageType() Type { return TypeUpdateGateRequest }

// Validate checks the complete signed gate request before it crosses the
// hostd boundary. Keeping this exported lets durable gate state use the same
// strict wire contract during crash recovery.
func (m UpdateGateRequest) Validate() error { return m.validate() }

func (m UpdateGateRequest) validate() error {
	if !validUpdateOperation(m.Operation) || !updateGateIDPattern.MatchString(m.TransactionID) || !validVersion(m.Version) || !updateGateDigestPattern.MatchString(m.ManifestSHA256) {
		return ErrInvalidFrame
	}
	if m.PreviousVersion != "" && !validVersion(m.PreviousVersion) {
		return ErrInvalidFrame
	}
	switch m.Operation {
	case UpdateGateTarget:
		if m.PreviousVersion != "" || m.Path != "" || m.ExpectedStatus != 0 || m.Samples != 0 || m.TimeoutMillis != 0 || m.WindowMillis != 0 || m.IntervalMillis != 0 || m.ExpectedTarget != nil {
			return ErrInvalidFrame
		}
	case UpdateGateCandidate:
		if !validUpdatePath(m.Path) || m.ExpectedStatus < 200 || m.ExpectedStatus > 299 || m.Samples < 2 || m.Samples > 32 || !validUpdateDuration(m.TimeoutMillis) || m.PreviousVersion != "" || m.WindowMillis != 0 || m.IntervalMillis != 0 || m.ExpectedTarget == nil || m.ExpectedTarget.validate() != nil {
			return ErrInvalidFrame
		}
	case UpdateGateDrain:
		if m.PreviousVersion == "" || m.PreviousVersion == m.Version || !validUpdateDuration(m.TimeoutMillis) || m.Path != "" || m.ExpectedStatus != 0 || m.Samples != 0 || m.WindowMillis != 0 || m.IntervalMillis != 0 || m.ExpectedTarget == nil || m.ExpectedTarget.validate() != nil {
			return ErrInvalidFrame
		}
	case UpdateGateRollback:
		if m.PreviousVersion == "" || m.PreviousVersion == m.Version || !validUpdateDuration(m.TimeoutMillis) || !validUpdatePath(m.Path) || m.ExpectedStatus < 200 || m.ExpectedStatus > 299 || m.Samples < 2 || m.Samples > 32 || m.WindowMillis != 0 || m.IntervalMillis != 0 || m.ExpectedTarget == nil || m.ExpectedTarget.validate() != nil {
			return ErrInvalidFrame
		}
	case UpdateGateStability:
		if !validUpdateDuration(m.WindowMillis) || !validUpdateDuration(m.IntervalMillis) || m.IntervalMillis > m.WindowMillis || m.PreviousVersion != "" || !validUpdatePath(m.Path) || m.ExpectedStatus < 200 || m.ExpectedStatus > 299 || m.Samples < 2 || m.Samples > 32 || m.TimeoutMillis != 0 || m.ExpectedTarget == nil || m.ExpectedTarget.validate() != nil {
			return ErrInvalidFrame
		}
	case UpdateGateCommit:
		if m.PreviousVersion != "" || m.Path != "" || m.ExpectedStatus != 0 || m.Samples != 0 || m.TimeoutMillis != 0 || m.WindowMillis != 0 || m.IntervalMillis != 0 || m.ExpectedTarget == nil || m.ExpectedTarget.validate() != nil {
			return ErrInvalidFrame
		}
	}
	return nil
}

// UpdateGateTargetBinding is populated only by stable hostd from its current
// authenticated carrier and route state.
type UpdateGateTargetBinding struct {
	Scope             string `json:"scope"`
	MachineID         string `json:"machine_id"`
	AccountID         string `json:"account_id"`
	HostID            string `json:"host_id"`
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	EdgeNodeID        string `json:"edge_node_id"`
	ProcessEpoch      uint64 `json:"process_epoch"`
	SessionGeneration uint64 `json:"session_generation"`
	ConfigGeneration  uint64 `json:"config_generation"`
	RouteGeneration   uint64 `json:"route_generation"`
	FailureDomain     string `json:"failure_domain"`
}

// Validate checks the complete live target fence. It is also used to reject
// corrupted state loaded after a hostd restart.
func (m UpdateGateTargetBinding) Validate() error { return m.validate() }

func (m UpdateGateTargetBinding) validate() error { return (UpdateGateResponse{Target: m}).validate() }

type UpdateGateResponse struct {
	Target UpdateGateTargetBinding `json:"target"`
}

func (UpdateGateResponse) messageType() Type { return TypeUpdateGateResponse }
func (m UpdateGateResponse) validate() error {
	for _, value := range []string{m.Target.MachineID, m.Target.FailureDomain} {
		if !updateGateIDPattern.MatchString(value) {
			return ErrInvalidFrame
		}
	}
	switch m.Target.Scope {
	case UpdateGateScopeStandalone:
		if m.Target.AccountID != "" || m.Target.HostID != "" || m.Target.TunnelID != "" || m.Target.ConnectorID != "" || m.Target.EdgeNodeID != "" || m.Target.ProcessEpoch != 0 || m.Target.SessionGeneration != 0 || m.Target.ConfigGeneration != 0 || m.Target.RouteGeneration != 0 {
			return ErrInvalidFrame
		}
	case UpdateGateScopeTunnel:
		for _, value := range []string{m.Target.AccountID, m.Target.HostID, m.Target.TunnelID, m.Target.ConnectorID, m.Target.EdgeNodeID} {
			if !updateGateIDPattern.MatchString(value) {
				return ErrInvalidFrame
			}
		}
		if m.Target.ProcessEpoch == 0 || m.Target.SessionGeneration == 0 || m.Target.ConfigGeneration == 0 || m.Target.RouteGeneration == 0 {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	return nil
}

type UpdateGateHandler interface {
	HandleUpdateGate(context.Context, UpdateGateRequest) (UpdateGateResponse, error)
}

func validUpdateOperation(value string) bool {
	switch value {
	case UpdateGateTarget, UpdateGateCandidate, UpdateGateDrain, UpdateGateStability, UpdateGateRollback, UpdateGateCommit:
		return true
	default:
		return false
	}
}

func validUpdatePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func validUpdateDuration(value int64) bool { return value > 0 && value <= 30*60*1000 }
