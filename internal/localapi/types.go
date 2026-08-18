package localapi

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	ProtocolV1              = "paperboat.local-api/v1"
	SnapshotSchemaV1        = "paperboat.status/v1"
	StatusEventSchemaV1     = "paperboat.status-event/v1"
	ObservationSchemaV1     = "paperboat.transport-observation/v1"
	CompletionSchemaV1      = "paperboat.completion/v1"
	PeerStreamSchemaV1      = "paperboat.peer-stream-request/v1"
	FileTransferKeySchemaV1 = "paperboat.file-transfer-key-request/v1"
	maxMachines             = 10_000
	maxUnixSocketPath       = 100
)

type FileTransferKeyRequest struct {
	Schema            string    `json:"schema"`
	MachineID         string    `json:"machine_id"`
	EnvironmentID     string    `json:"environment_id"`
	MachineGeneration uint64    `json:"machine_generation"`
	Transport         string    `json:"transport"`
	OperationID       string    `json:"operation_id"`
	TransferID        string    `json:"transfer_id"`
	Generation        uint64    `json:"generation"`
	ExpiresAt         time.Time `json:"expires_at"`
	Material          []byte    `json:"material"`
}

func (r FileTransferKeyRequest) Validate(now time.Time) error {
	if r.Schema != FileTransferKeySchemaV1 || !safeValue(r.MachineID) || !safeValue(r.EnvironmentID) || r.MachineGeneration == 0 || !oneOf(r.Transport, "a", "d", "q", "w", "r") || !safeValue(r.OperationID) || !safeValue(r.TransferID) || r.Generation == 0 || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(now) > 7*24*time.Hour || len(r.Material) != 45 {
		return ErrInvalidConfig
	}
	return nil
}

type FileTransferKeyResult struct {
	PeerContext []byte
	Handle      string
}

type PeerStreamRequest struct {
	Schema            string          `json:"schema"`
	MachineID         string          `json:"machine_id"`
	EnvironmentID     string          `json:"environment_id"`
	MachineGeneration uint64          `json:"machine_generation"`
	Consumer          string          `json:"consumer"`
	OperationID       string          `json:"operation_id"`
	Credential        string          `json:"credential"`
	Deadline          time.Time       `json:"deadline"`
	MaximumBytes      uint64          `json:"maximum_bytes"`
	Transport         string          `json:"transport"`
	QUICEndpoint      string          `json:"quic_endpoint,omitempty"`
	WSSEndpoint       string          `json:"wss_endpoint,omitempty"`
	Payload           json.RawMessage `json:"payload,omitempty"`
}

type PeerTerminalPayload struct {
	Protocol            string            `json:"protocol"`
	ThreadID            string            `json:"thread_id,omitempty"`
	TerminalID          string            `json:"terminal_id,omitempty"`
	SessionID           string            `json:"session_id,omitempty"`
	CWD                 string            `json:"cwd,omitempty"`
	Environment         map[string]string `json:"environment,omitempty"`
	Columns             uint16            `json:"columns,omitempty"`
	Rows                uint16            `json:"rows,omitempty"`
	RestartIfNotRunning bool              `json:"restart_if_not_running,omitempty"`
	ReplayHistory       bool              `json:"replay_history,omitempty"`
	AfterSequence       int               `json:"after_sequence,omitempty"`
	InputAttachmentID   string            `json:"input_attachment_id,omitempty"`
}

type PeerProbeResult struct {
	Transport             string `json:"transport"`
	RelayRegion           string `json:"relay_region,omitempty"`
	ConnectionNanoseconds int64  `json:"connection_nanoseconds"`
	RTTNanoseconds        int64  `json:"rtt_nanoseconds"`
	PTOs                  uint32 `json:"ptos"`
}

type PeerPreviewPayload struct {
	Port uint16 `json:"port"`
}

func NewPeerStreamRequest(machineID, environmentID string, machineGeneration uint64, consumer, operationID, credential string, deadline time.Time, maximumBytes uint64, payload json.RawMessage) (PeerStreamRequest, error) {
	value := PeerStreamRequest{Schema: PeerStreamSchemaV1, MachineID: machineID, EnvironmentID: environmentID, MachineGeneration: machineGeneration, Consumer: consumer, OperationID: operationID, Credential: credential, Deadline: deadline.UTC(), MaximumBytes: maximumBytes, Payload: append(json.RawMessage(nil), payload...)}
	if value.Validate(time.Now().UTC()) != nil {
		return PeerStreamRequest{}, ErrInvalidConfig
	}
	return value, nil
}

func NewPendingPeerStreamRequest(machineID, environmentID string, machineGeneration uint64, consumer, operationID string, deadline time.Time, maximumBytes uint64, payload json.RawMessage) (PeerStreamRequest, error) {
	value := PeerStreamRequest{Schema: PeerStreamSchemaV1, MachineID: machineID, EnvironmentID: environmentID, MachineGeneration: machineGeneration, Consumer: consumer, OperationID: operationID, Deadline: deadline.UTC(), MaximumBytes: maximumBytes, Payload: append(json.RawMessage(nil), payload...)}
	if value.ValidatePending(time.Now().UTC()) != nil {
		return PeerStreamRequest{}, ErrInvalidConfig
	}
	return value, nil
}

func (r PeerStreamRequest) Validate(now time.Time) error {
	if r.Schema != PeerStreamSchemaV1 || !safeValue(r.MachineID) || !safeValue(r.EnvironmentID) || r.MachineGeneration == 0 || !oneOf(r.Consumer, "terminal", "exec", "ssh", "private_preview", "codex", "health_probe", "file_transfer_key") || !safeValue(r.OperationID) || !oneOf(r.Transport, "", "a", "d", "q", "w", "r") || r.Credential == "" || len(r.Credential) > 16<<10 || r.Deadline.IsZero() || !r.Deadline.After(now) || r.Deadline.Sub(now) > 24*time.Hour || r.MaximumBytes == 0 || len(r.Payload) > 64<<10 || len(r.Payload) > 0 && !json.Valid(r.Payload) {
		return ErrInvalidConfig
	}
	return nil
}

// ValidatePending permits the daemon to fill the short-lived operation
// credential immediately before opening the peer stream. Pending requests are
// accepted only by the daemon broker; they are never sent to a peer.
func (r PeerStreamRequest) ValidatePending(now time.Time) error {
	if r.Credential != "" {
		return r.Validate(now)
	}
	if r.Schema != PeerStreamSchemaV1 || !safeValue(r.MachineID) || !safeValue(r.EnvironmentID) || r.MachineGeneration == 0 || !oneOf(r.Consumer, "terminal", "exec", "ssh", "private_preview", "codex", "file_transfer_key") || !safeValue(r.OperationID) || !oneOf(r.Transport, "", "a", "d", "q", "w", "r") || r.Deadline.IsZero() || r.Deadline.Sub(now) > 24*time.Hour || r.MaximumBytes == 0 || len(r.Payload) > 64<<10 || len(r.Payload) > 0 && !json.Valid(r.Payload) {
		return ErrInvalidConfig
	}
	return nil
}

type CompletionItem struct {
	Kind          string `json:"kind"`
	Value         string `json:"value"`
	Description   string `json:"description"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

type CompletionSnapshot struct {
	Schema     string           `json:"schema"`
	ObservedAt time.Time        `json:"observed_at"`
	Items      []CompletionItem `json:"items"`
}

func (s CompletionSnapshot) Validate() error {
	if s.Schema != CompletionSchemaV1 || s.ObservedAt.IsZero() || len(s.Items) > 20_000 {
		return ErrInvalidResponse
	}
	for _, item := range s.Items {
		if !oneOf(item.Kind, "machine", "preview", "session", "transfer_target") || !safeCompletionValue(item.Value) || !safeText(item.Description) || item.EnvironmentID != "" && !safeValue(item.EnvironmentID) {
			return ErrInvalidResponse
		}
	}
	return nil
}

func safeCompletionValue(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\x00\t\r\n")
}

var (
	ErrInvalidConfig      = errors.New("invalid local API configuration")
	ErrAlreadyRunning     = errors.New("local API is already running")
	ErrUnsafeSocket       = errors.New("local API socket is unsafe")
	ErrPermission         = errors.New("local API peer is not authorized")
	ErrVersionMismatch    = errors.New("local API version mismatch")
	ErrInvalidResponse    = errors.New("invalid local API response")
	ErrStaleObservation   = errors.New("local transport observation is stale")
	ErrObservationLimit   = errors.New("local transport observation limit reached")
	ErrExecStartUncertain = errors.New("remote execution start outcome is uncertain")
)

type Peer struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
	PID int `json:"pid"`
}

type HealthItem struct {
	Code        string     `json:"code"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	BrokenSince *time.Time `json:"broken_since,omitempty"`
	Recovery    string     `json:"recovery"`
	ETag        string     `json:"etag"`
}

type MachineStatus struct {
	ID              string     `json:"id"`
	EnvironmentID   string     `json:"environment_id,omitempty"`
	WorkspaceRoot   string     `json:"workspace_root,omitempty"`
	Alias           string     `json:"alias"`
	Eligible        bool       `json:"eligible"`
	RuntimeState    string     `json:"runtime_state"`
	Generation      uint64     `json:"generation"`
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
	ActiveConsumers uint64     `json:"active_consumers"`
	SelectedPath    string     `json:"selected_path"`
	// TransportConsumers reports every active path for this machine. The
	// selected_path scalar remains for single-path callers and is "mixed" when
	// more than one path has consumers.
	TransportConsumers []TransportConsumer `json:"transport_consumers,omitempty"`
	StandbyPath        string              `json:"standby_path,omitempty"`
	RelayRegion        string              `json:"relay_region,omitempty"`
	TransferReadiness  string              `json:"transfer_readiness"`
	PreviewReadiness   string              `json:"preview_readiness"`
	SSHReadiness       string              `json:"ssh_readiness"`
	NATMappingIPv4     string              `json:"nat_mapping_ipv4"`
	NATMappingIPv6     string              `json:"nat_mapping_ipv6"`
	CaptivePortal      string              `json:"captive_portal"`
	PMTU               string              `json:"pmtu"`
	RouterProtocol     string              `json:"router_protocol"`
	RouterMapping      string              `json:"router_mapping"`
	MappingLifetime    string              `json:"mapping_lifetime"`
	UpdateHealth       string              `json:"update_health"`
	Health             []HealthItem        `json:"health"`
}

// TransportConsumer is one active path and the number of local consumers
// currently using it. It intentionally does not identify terminal sessions.
// The local status endpoint is machine-scoped and must not expose session
// metadata from other clients.
type TransportConsumer struct {
	Path            string `json:"path"`
	ActiveConsumers uint64 `json:"active_consumers"`
	RelayRegion     string `json:"relay_region,omitempty"`
}

type Snapshot struct {
	Schema      string          `json:"schema"`
	Generation  uint64          `json:"generation"`
	ObservedAt  time.Time       `json:"observed_at"`
	DaemonState string          `json:"daemon_state"`
	Health      []HealthItem    `json:"health"`
	Machines    []MachineStatus `json:"machines"`
}

type StatusEvent struct {
	Schema   string   `json:"schema"`
	Snapshot Snapshot `json:"snapshot"`
}

type TransportObservation struct {
	Schema             string              `json:"schema"`
	SourceID           string              `json:"source_id"`
	Sequence           uint64              `json:"sequence"`
	ObservedAt         time.Time           `json:"observed_at"`
	ExpiresAt          time.Time           `json:"expires_at"`
	MachineID          string              `json:"machine_id"`
	ActiveConsumers    uint64              `json:"active_consumers"`
	SelectedPath       string              `json:"selected_path"`
	TransportConsumers []TransportConsumer `json:"transport_consumers,omitempty"`
	StandbyPath        string              `json:"standby_path,omitempty"`
	RelayRegion        string              `json:"relay_region,omitempty"`
	NATMappingIPv4     string              `json:"nat_mapping_ipv4"`
	NATMappingIPv6     string              `json:"nat_mapping_ipv6"`
	CaptivePortal      string              `json:"captive_portal"`
	PMTU               string              `json:"pmtu"`
	RouterProtocol     string              `json:"router_protocol"`
	RouterMapping      string              `json:"router_mapping"`
	MappingLifetime    string              `json:"mapping_lifetime"`
}

func (o TransportObservation) Validate() error {
	if o.Schema != ObservationSchemaV1 || !safeValue(o.SourceID) || o.Sequence == 0 || o.ObservedAt.IsZero() || o.ExpiresAt.IsZero() || !o.ExpiresAt.After(o.ObservedAt) || o.ExpiresAt.Sub(o.ObservedAt) > 30*time.Second || !safeValue(o.MachineID) || o.ActiveConsumers > 1024 || !transportSummary(o.SelectedPath, o.ActiveConsumers, o.TransportConsumers, o.StandbyPath, o.RelayRegion) || !natMapping(o.NATMappingIPv4) || !natMapping(o.NATMappingIPv6) || !captivePortal(o.CaptivePortal) || !pmtu(o.PMTU) || !routerProtocol(o.RouterProtocol) || !routerMapping(o.RouterMapping) || !mappingLifetime(o.MappingLifetime) {
		return ErrInvalidResponse
	}
	return nil
}

func (s Snapshot) Validate() error {
	if s.Schema != SnapshotSchemaV1 || s.Generation == 0 || s.ObservedAt.IsZero() || !oneOf(s.DaemonState, "starting", "ready", "degraded", "draining", "stopping") || len(s.Machines) > maxMachines {
		return ErrInvalidResponse
	}
	for _, item := range s.Health {
		if !validHealth(item) {
			return ErrInvalidResponse
		}
	}
	seen := make(map[string]bool, len(s.Machines))
	for _, machine := range s.Machines {
		if !safeValue(machine.ID) || !safeText(machine.Alias) || seen[machine.ID] || !oneOf(machine.RuntimeState, "starting", "ready", "degraded", "offline", "stopped", "failed") || !transportSummary(machine.SelectedPath, machine.ActiveConsumers, machine.TransportConsumers, machine.StandbyPath, machine.RelayRegion) || !readiness(machine.TransferReadiness) || !readiness(machine.PreviewReadiness) || !readiness(machine.SSHReadiness) || !natMapping(machine.NATMappingIPv4) || !natMapping(machine.NATMappingIPv6) || !captivePortal(machine.CaptivePortal) || !pmtu(machine.PMTU) || !routerProtocol(machine.RouterProtocol) || !routerMapping(machine.RouterMapping) || !mappingLifetime(machine.MappingLifetime) || !oneOf(machine.UpdateHealth, "unknown", "healthy", "recovery_required") {
			return ErrInvalidResponse
		}
		seen[machine.ID] = true
		for _, item := range machine.Health {
			if !validHealth(item) {
				return ErrInvalidResponse
			}
		}
	}
	return nil
}

func optionalTransportPath(value string) bool {
	return value == "" || oneOf(value, "none", "direct", "relay", "wss")
}

func transportSummary(selected string, total uint64, consumers []TransportConsumer, standby, relayRegion string) bool {
	if !oneOf(selected, "none", "direct", "relay", "wss", "mixed") || !optionalTransportPath(standby) || total == 0 && standby != "" && standby != "none" || standby != "" && standby != "none" && standby == selected || selected != "relay" && selected != "wss" && relayRegion != "" || relayRegion != "" && !safeValue(relayRegion) {
		return false
	}
	if len(consumers) == 0 {
		return selected != "mixed" && !(total > 0 && selected == "none")
	}
	if len(consumers) > 3 || standby != "" && standby != "none" {
		return false
	}
	seen := make(map[string]struct{}, len(consumers))
	var counted uint64
	for _, consumer := range consumers {
		if !oneOf(consumer.Path, "direct", "relay", "wss") || consumer.ActiveConsumers == 0 || ^uint64(0)-counted < consumer.ActiveConsumers || consumer.RelayRegion != "" && (!oneOf(consumer.Path, "relay", "wss") || !safeValue(consumer.RelayRegion)) {
			return false
		}
		if _, exists := seen[consumer.Path]; exists {
			return false
		}
		seen[consumer.Path] = struct{}{}
		counted += consumer.ActiveConsumers
	}
	if counted != total {
		return false
	}
	if len(consumers) == 1 {
		return selected == consumers[0].Path && relayRegion == consumers[0].RelayRegion
	}
	return selected == "mixed" && relayRegion == ""
}

func validHealth(item HealthItem) bool {
	return safeValue(item.Code) &&
		oneOf(item.Severity, "info", "warning", "error") &&
		safeText(item.Title) &&
		safeText(item.Recovery) &&
		safeValue(item.ETag)
}

func readiness(value string) bool { return oneOf(value, "ready", "degraded", "unavailable") }
func natMapping(value string) bool {
	return oneOf(value, "unknown", "endpoint_independent", "destination_dependent")
}
func captivePortal(value string) bool { return oneOf(value, "unknown", "clear", "suspected") }
func pmtu(value string) bool {
	return oneOf(value, "unknown", "below_quic_floor", "minimum_1200", "standard", "extended")
}

func routerMapping(value string) bool {
	return oneOf(value, "unknown", "unavailable", "verified", "untrusted", "unreachable")
}

func routerProtocol(value string) bool {
	return oneOf(value, "unknown", "none", "pcp", "nat_pmp", "upnp")
}

func mappingLifetime(value string) bool {
	return oneOf(value, "unknown", "under_30s", "30s_to_2m", "2m_to_10m", "over_10m")
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func safeValue(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character)) {
			return false
		}
	}
	return true
}

func safeText(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}
