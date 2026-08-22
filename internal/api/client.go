// Package api is the Paperboat bearer-authenticated control-plane client.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/httptransport"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/remotepath"
)

// ErrUnauthenticated means the server rejected the reused credential. Callers
// should route the user through Paperboat device login.
var ErrUnauthenticated = errors.New("paperboat-server rejected the credential")

// ErrIncompatibleVersion tells callers to upgrade instead of retrying.
type ErrIncompatibleVersion struct{ Required, Message string }

func (e *ErrIncompatibleVersion) Error() string {
	message := strings.Join(strings.Fields(e.Message), " ")
	if len(message) > 500 {
		message = message[:500]
	}
	if message != "" {
		if strings.Contains(strings.ToLower(message), "upgrade") {
			return message
		}
		return message + "; upgrade pb"
	}
	if e.Required != "" {
		return fmt.Sprintf("this CLI is incompatible with the server (required protocol %s); upgrade pb", e.Required)
	}
	return "this CLI is incompatible with the server; upgrade pb"
}

func responseRequestID(header http.Header) string {
	if requestID := safeRequestID(header.Get("Request-Id")); requestID != "" {
		return requestID
	}
	return safeRequestID(header.Get("X-Request-ID"))
}

// APIError is a structured server error surfaced to the caller. It carries the
// server's stable error code so command logic can branch without string
// matching on messages.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Details   map[string]any
}

// IsNotFound reports whether the control plane explicitly rejected a request
// because its resource or route is absent. Callers use it only for additive
// capability discovery; authorization failures are never treated as absent.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// IsHostedEntitlementRequired reports the hosted-project billing gate. Callers
// that also expose separately entitled machines may skip projects
// while preserving every other API failure.
func IsHostedEntitlementRequired(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.Code == "payment_required" || apiErr.Code == "entitlement_lost")
}

func (e *APIError) Error() string {
	message := e.Message
	if message == "" {
		message = e.Code
	}
	if message == "" {
		message = fmt.Sprintf("paperboat-server returned status %d", e.Status)
	}
	if e.RequestID != "" {
		return fmt.Sprintf("%s (request %s)", message, e.RequestID)
	}
	return message
}

// Client talks to paperboat-server with a Paperboat client-session access token.
type Client struct {
	baseURL         string
	cred            config.Credential
	http            *http.Client
	accessToken     string
	sourceMachineID string
}

func (c *Client) SetSourceMachineID(machineID string) {
	c.sourceMachineID = strings.TrimSpace(machineID)
}

// New builds a client. baseURL is the paperboat-server base (e.g.
// https://api.paperboat.dev). httpClient is optional; a sane default with a
// timeout is used when nil.
func New(baseURL string, cred config.Credential, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		cred:        cred,
		http:        httpClient,
		accessToken: strings.TrimSpace(cred.AccessToken),
	}
}

// Me is the authenticated-user payload from GET /v1/me.
type Me struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	Role        string `json:"role"`
}

// Project mirrors the fields the CLI needs from the server's project payload.
// The full server shape has more; we decode only what resolution requires so
// added server fields never break the client.
type Project struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type GitHubRepository struct {
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

// ClientConfiguration contains server-owned URLs used by Paperboat clients.
type ClientConfiguration struct {
	Version            string `json:"version"`
	CLIVerificationURL string `json:"cli_verification_url"`
	MachinesURL        string `json:"machines_url"`
}

type NetworkCheckRegion struct {
	RelayID  string `json:"relay_id"`
	Region   string `json:"region"`
	Name     string `json:"name"`
	STUNURL  string `json:"stun_url"`
	HTTPSURL string `json:"https_url"`
}

type NetworkCheckRegions struct {
	Regions []NetworkCheckRegion `json:"regions"`
}

func (c *Client) NetworkCheckRegions(ctx context.Context) (NetworkCheckRegions, error) {
	var out NetworkCheckRegions
	if err := c.do(ctx, http.MethodGet, "/network-check/regions/v1", nil, &out); err != nil {
		return NetworkCheckRegions{}, err
	}
	if len(out.Regions) > 32 {
		return NetworkCheckRegions{}, errors.New("paperboat-server returned too many network-check regions")
	}
	seen := make(map[string]bool, len(out.Regions))
	for _, region := range out.Regions {
		if !validRegionCode(region.RelayID) || !validRegionCode(region.Region) || strings.TrimSpace(region.Name) == "" || len(region.Name) > 80 || seen[region.Region] || !validSTUNProbeURL(region.STUNURL) || !validHTTPSProbeURL(region.HTTPSURL) {
			return NetworkCheckRegions{}, errors.New("paperboat-server returned an invalid network-check region")
		}
		seen[region.Region] = true
	}
	return out, nil
}

func validRegionCode(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}

func validSTUNProbeURL(raw string) bool {
	if !strings.HasPrefix(raw, "stun:") || strings.ContainsAny(raw, "?#") {
		return false
	}
	value, err := url.Parse("//" + strings.TrimPrefix(raw, "stun:"))
	if err != nil || value.Hostname() == "" || value.Port() == "" || value.User != nil || value.Path != "" {
		return false
	}
	port, err := strconv.ParseUint(value.Port(), 10, 16)
	return err == nil && port > 0
}

func validHTTPSProbeURL(raw string) bool {
	value, err := url.Parse(raw)
	return err == nil && value.Scheme == "https" && value.Hostname() != "" && value.User == nil && value.Path == "/network-check/v1" && value.RawQuery == "" && value.Fragment == ""
}

func (c *Client) ClientConfiguration(ctx context.Context) (ClientConfiguration, error) {
	var out ClientConfiguration
	if err := c.do(ctx, http.MethodGet, "/v1/client-configuration", nil, &out); err != nil {
		return ClientConfiguration{}, err
	}
	if out.Version != "1" {
		return ClientConfiguration{}, fmt.Errorf("paperboat-server returned unsupported client configuration version %q", out.Version)
	}
	machinesURL, err := url.Parse(out.MachinesURL)
	if err != nil || (machinesURL.Scheme != "http" && machinesURL.Scheme != "https") || machinesURL.Host == "" {
		return ClientConfiguration{}, errors.New("paperboat-server returned an invalid machines URL")
	}
	return out, nil
}

type PeerAttemptInput struct {
	OperationID                       string               `json:"operation_id"`
	EnvironmentID                     string               `json:"environment_id"`
	Purpose                           string               `json:"purpose"`
	Consumer                          string               `json:"consumer"`
	ControllingCertificateFingerprint string               `json:"controlling_certificate_fingerprint"`
	ControlledCertificateFingerprint  string               `json:"controlled_certificate_fingerprint"`
	AttemptGeneration                 uint64               `json:"attempt_generation"`
	NetworkGeneration                 uint64               `json:"network_generation"`
	AllowedPaths                      []string             `json:"allowed_paths"`
	Transfer                          *PeerAttemptTransfer `json:"transfer,omitempty"`
	RelayLatency                      *RelayLatencyVector  `json:"relay_latency,omitempty"`
}

type RelayLatencySample struct {
	Region string `json:"region"`
	RTTMS  int64  `json:"rtt_ms"`
}

type RelayLatencyVector struct {
	Generation         uint64               `json:"generation"`
	ObservedAt         time.Time            `json:"observed_at"`
	Samples            []RelayLatencySample `json:"samples"`
	RelaySuccessRegion string               `json:"relay_success_region,omitempty"`
	RelaySuccessAt     time.Time            `json:"relay_success_at,omitempty"`
}

type PeerAttemptTransfer struct {
	TransferID string    `json:"transfer_id"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type PeerAttemptCertificate struct {
	EndpointID  string `json:"endpoint_id"`
	Certificate string `json:"certificate"`
}

type PeerAttemptDescriptor struct {
	Version                 int                      `json:"version"`
	AccountID               string                   `json:"account_id"`
	DeviceID                string                   `json:"device_id"`
	OperationID             string                   `json:"operation_id"`
	IntentID                string                   `json:"intent_id"`
	EnvironmentID           string                   `json:"environment_id"`
	Purpose                 string                   `json:"purpose"`
	Consumer                string                   `json:"consumer"`
	InitiatorEndpointID     string                   `json:"initiator_endpoint_id"`
	ResponderEndpointID     string                   `json:"responder_endpoint_id"`
	Role                    string                   `json:"role"`
	AttemptGeneration       uint64                   `json:"attempt_generation"`
	NetworkGeneration       uint64                   `json:"network_generation"`
	HostGeneration          uint64                   `json:"host_generation"`
	AuthorizationGeneration uint64                   `json:"authorization_generation"`
	IssuedAt                time.Time                `json:"issued_at"`
	ExpiresAt               time.Time                `json:"expires_at"`
	EndpointCertificates    []PeerAttemptCertificate `json:"endpoint_certificates"`
	Direct                  struct {
		ICEUfrag    string   `json:"ice_ufrag"`
		ICEPassword string   `json:"ice_password"`
		STUNURLs    []string `json:"stun_urls"`
	} `json:"direct"`
	Signaling struct {
		URL         string `json:"url"`
		Credential  string `json:"credential"`
		Subprotocol string `json:"subprotocol"`
	} `json:"signaling"`
	Relays []PeerAttemptRelay `json:"relays"`
	Policy struct {
		AllowedPaths     []string `json:"allowed_paths"`
		RelayDeadlineMS  int      `json:"relay_deadline_ms"`
		HealthIntervalMS int      `json:"health_interval_ms"`
		MaxCandidates    int      `json:"max_candidates"`
	} `json:"policy"`
	StreamPolicy *PeerAttemptStreamPolicy `json:"stream_policy,omitempty"`
	Transfer     *PeerAttemptTransfer     `json:"transfer,omitempty"`
}

type PeerAttemptStreamPolicy struct {
	Protocol         string   `json:"protocol"`
	AllowedConsumers []string `json:"allowed_consumers"`
	MaximumStreams   int      `json:"maximum_streams"`
}

type PeerAttemptRelay struct {
	Region          string    `json:"region"`
	RouteGeneration uint64    `json:"route_generation"`
	QUICURL         string    `json:"quic_url,omitempty"`
	WSSURL          string    `json:"wss_url,omitempty"`
	RouteToken      string    `json:"route_token"`
	PMTUToken       string    `json:"pmtu_token"`
	PMTUURL         string    `json:"pmtu_url"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type EndpointCertificateDocument struct {
	Version                int    `json:"version"`
	AccountID              string `json:"account_id"`
	RootFingerprint        string `json:"root_fingerprint"`
	EndpointID             string `json:"endpoint_id"`
	Role                   string `json:"role"`
	Generation             uint64 `json:"generation"`
	Serial                 uint64 `json:"serial"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	Certificate            string `json:"certificate"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

type E2EEBootstrapInput struct {
	RootPublicKey string                      `json:"root_public_key"`
	Certificate   EndpointCertificateDocument `json:"certificate"`
}

type E2EEBootstrapResult = E2EEBootstrapInput

type E2EERoot struct {
	Version     int    `json:"version"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Generation  uint64 `json:"generation"`
}

type PendingEndpointIdentity struct {
	RequestID      string    `json:"request_id"`
	EndpointID     string    `json:"endpoint_id"`
	Role           string    `json:"role,omitempty"`
	State          string    `json:"state,omitempty"`
	Generation     uint64    `json:"generation"`
	NoisePublicKey string    `json:"noise_public_key"`
	QUICPublicKey  string    `json:"quic_public_key"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	SafetyCode     string    `json:"safety_code"`
}

// CLIEndpointRequestInput contains only public endpoint keys. The request is
// signed later by an already paired CLI and never carries a root private key.
type CLIEndpointRequestInput struct {
	OperationID    string `json:"operation_id"`
	EndpointID     string `json:"endpoint_id"`
	Generation     uint64 `json:"generation"`
	NoisePublicKey string `json:"noise_public_key"`
	QUICPublicKey  string `json:"quic_public_key"`
}

func (c *Client) E2EERoot(ctx context.Context) (E2EERoot, error) {
	var out E2EERoot
	if err := c.doStrict(ctx, http.MethodGet, "/v1/e2ee/root", nil, &out); err != nil {
		return E2EERoot{}, err
	}
	return out, nil
}

func (c *Client) PendingE2EEEndpoints(ctx context.Context) ([]PendingEndpointIdentity, error) {
	var out []PendingEndpointIdentity
	if err := c.doStrict(ctx, http.MethodGet, "/v1/e2ee/pending-endpoints", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RequestCLIEndpoint creates or exactly replays a pending existing-account
// CLI endpoint enrollment request. Unlike machine endpoint enrollment this
// route uses the authenticated CLI session and carries no machine proof.
func (c *Client) RequestCLIEndpoint(ctx context.Context, input CLIEndpointRequestInput) (PendingEndpointIdentity, error) {
	if strings.TrimSpace(input.OperationID) == "" || strings.TrimSpace(input.EndpointID) == "" || input.Generation == 0 || strings.TrimSpace(input.NoisePublicKey) == "" || strings.TrimSpace(input.QUICPublicKey) == "" {
		return PendingEndpointIdentity{}, errors.New("CLI endpoint enrollment request is invalid")
	}
	var out PendingEndpointIdentity
	if err := c.doWithHeaders(ctx, http.MethodPost, "/v1/e2ee/endpoint-requests", input, &out, http.Header{"Idempotency-Key": []string{input.OperationID}}); err != nil {
		return PendingEndpointIdentity{}, err
	}
	return out, nil
}

func (c *Client) RegisterEndpointCertificate(ctx context.Context, operationID string, document EndpointCertificateDocument) (EndpointCertificateDocument, error) {
	var out EndpointCertificateDocument
	path := "/v1/endpoints/" + url.PathEscape(document.EndpointID) + "/certificates/" + fmt.Sprintf("%d", document.Generation)
	if err := c.doWithHeaders(ctx, http.MethodPut, path, document, &out, http.Header{"Idempotency-Key": []string{operationID}}); err != nil {
		return EndpointCertificateDocument{}, err
	}
	return out, nil
}

func (c *Client) EndpointCertificate(ctx context.Context, endpointID string, generation uint64) (EndpointCertificateDocument, error) {
	if strings.TrimSpace(endpointID) == "" || generation == 0 {
		return EndpointCertificateDocument{}, errors.New("endpoint certificate identity is invalid")
	}
	var out EndpointCertificateDocument
	path := "/v1/endpoints/" + url.PathEscape(endpointID) + "/certificates/" + fmt.Sprintf("%d", generation)
	if err := c.doStrict(ctx, http.MethodGet, path, nil, &out); err != nil {
		return EndpointCertificateDocument{}, err
	}
	return out, nil
}

func (c *Client) BootstrapE2EE(ctx context.Context, operationID string, input E2EEBootstrapInput) (E2EEBootstrapResult, error) {
	var out E2EEBootstrapResult
	if err := c.doWithHeaders(ctx, http.MethodPost, "/v1/e2ee/bootstrap", input, &out, http.Header{"Idempotency-Key": []string{operationID}}); err != nil {
		return E2EEBootstrapResult{}, err
	}
	return out, nil
}

func (c *Client) CreatePeerAttempt(ctx context.Context, input PeerAttemptInput) (PeerAttemptDescriptor, error) {
	var out PeerAttemptDescriptor
	if err := c.doStrict(ctx, http.MethodPost, "/v1/peer-attempts", input, &out); err != nil {
		return PeerAttemptDescriptor{}, err
	}
	return out, nil
}

func (c *Client) RevokePeerAttempt(ctx context.Context, operationID, intentID string, attemptGeneration uint64) error {
	var out struct {
		IntentID string `json:"intent_id"`
	}
	path := "/v1/peer-attempts/" + url.PathEscape(intentID) + "/" + strconv.FormatUint(attemptGeneration, 10)
	return c.doWithHeaders(ctx, http.MethodDelete, path, nil, &out, http.Header{"Idempotency-Key": []string{operationID}})
}

type CatalogMachineType struct {
	Code   string `json:"code"`
	Active bool   `json:"active"`
}
type CatalogRegion struct {
	Code    string `json:"code"`
	Enabled bool   `json:"enabled"`
}

func (c *Client) ListGitHubRepositories(ctx context.Context) ([]GitHubRepository, error) {
	var out []GitHubRepository
	err := c.do(ctx, http.MethodGet, "/v1/github/repositories", nil, &out)
	return out, err
}

func (c *Client) ListCatalogMachineTypes(ctx context.Context) ([]CatalogMachineType, error) {
	var out []CatalogMachineType
	err := c.do(ctx, http.MethodGet, "/v1/catalog/machine-types", nil, &out)
	return out, err
}

func (c *Client) ListCatalogRegions(ctx context.Context) ([]CatalogRegion, error) {
	var out []CatalogRegion
	err := c.do(ctx, http.MethodGet, "/v1/catalog/regions", nil, &out)
	return out, err
}

type CreateProjectInput struct {
	Name            string   `json:"name"`
	RepositoryURL   string   `json:"repository_url"`
	DefaultBranch   string   `json:"default_branch,omitempty"`
	StorageGB       int      `json:"storage_gb"`
	MachineTypeCode string   `json:"machine_type_code"`
	RegionCode      string   `json:"region_code"`
	PresetCodes     []string `json:"preset_codes,omitempty"`
	SetupScript     string   `json:"setup_script,omitempty"`
}

func (c *Client) CreateProject(ctx context.Context, input CreateProjectInput, idempotencyKey string) (Project, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return Project{}, errors.New("project creation idempotency key is required")
	}
	var out Project
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/projects", input, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}

type Pagination struct {
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	Total      int  `json:"total"`
	NextOffset *int `json:"next_offset"`
}

type ProjectPage struct {
	Items      []Project  `json:"items"`
	Pagination Pagination `json:"pagination"`
}

// UserMachine is a user-owned environment reached through its enrolled
// connector rather than a Paperboat-managed Fly VM. The control plane owns its
// lifecycle and authorization; the CLI only needs enough metadata to select it.
type UserMachine struct {
	ID                     string              `json:"id"`
	EnvironmentID          string              `json:"environment_id"`
	DisplayName            string              `json:"display_name"`
	Alias                  string              `json:"alias"`
	State                  string              `json:"state"`
	Online                 bool                `json:"online"`
	Platform               string              `json:"platform"`
	Architecture           string              `json:"architecture"`
	WorkspaceRoot          string              `json:"workspace_root"`
	SetupRoles             []string            `json:"setup_roles"`
	SetupMode              string              `json:"setup_mode"`
	Capabilities           MachineCapabilities `json:"capabilities"`
	PublicIdentityKey      string              `json:"public_identity_key"`
	InstallationGeneration int64               `json:"installation_generation"`
	Availability           AvailabilityPolicy  `json:"availability"`
	RuntimeDiagnostics     RuntimeDiagnostics  `json:"runtime_diagnostics"`
	Installation           *ClientInstallation `json:"installation,omitempty"`
	SSHAuthority           SSHAuthority        `json:"-"`
	SSHLocalReady          bool                `json:"-"`
	SSHLocalCode           string              `json:"-"`
	SSHUser                string              `json:"-"`
	SSHPort                uint16              `json:"-"`
}

type SSHAuthority struct {
	TargetGeneration  uint64
	HostKeyGeneration uint64
}

type ManagedSSHTarget struct {
	Type                  string `json:"type"`
	Version               int    `json:"version"`
	MachineID             string `json:"machine_id"`
	MachineGeneration     uint64 `json:"machine_generation"`
	OSUser                string `json:"os_user"`
	Port                  uint16 `json:"port"`
	ReconciliationVersion uint64 `json:"reconciliation_version"`
}

type ManagedSSHHostKeySet struct {
	Type                  string   `json:"type"`
	Version               int      `json:"version"`
	SetID                 string   `json:"set_id"`
	MachineID             string   `json:"machine_id"`
	MachineGeneration     uint64   `json:"machine_generation"`
	ObservationGeneration uint64   `json:"observation_generation"`
	Keys                  []string `json:"keys"`
	Fingerprint           string   `json:"fingerprint"`
	State                 string   `json:"state"`
	ReconciliationVersion uint64   `json:"reconciliation_version"`
}

type ManagedSSHAuthorizedKeys struct {
	Type              string   `json:"type"`
	Version           int      `json:"version"`
	MachineID         string   `json:"machine_id"`
	MachineGeneration uint64   `json:"machine_generation"`
	Keys              []string `json:"keys"`
}

type ManagedSSHClientKey struct {
	Type                  string `json:"type"`
	Version               int    `json:"version"`
	Fingerprint           string `json:"fingerprint"`
	PublicKey             string `json:"public_key"`
	State                 string `json:"state"`
	ReconciliationVersion uint64 `json:"reconciliation_version"`
}

type MachineArtifact struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	RepositoryURL string `json:"repository_url"`
	TargetPath    string `json:"target_path"`
}

type ClientInstallation struct {
	ControlURL          string          `json:"control_url"`
	HelperListenAddress string          `json:"helper_listen_address"`
	Artifact            MachineArtifact `json:"artifact"`
}

type MachineCapability struct {
	Configured bool `json:"configured"`
	Observed   bool `json:"observed"`
}

type MachineCapabilities struct {
	FileReceive   MachineCapability `json:"file_receive"`
	PreviewLaunch MachineCapability `json:"preview_launch"`
	TerminalHost  MachineCapability `json:"terminal_host"`
	CodexHost     MachineCapability `json:"codex_host"`
	SessionHost   MachineCapability `json:"session_host"`
	KeepAwake     MachineCapability `json:"keep_awake"`
}

type MachineSetupInput struct {
	SetupMode         string            `json:"setup_mode"`
	DisplayName       string            `json:"display_name"`
	Platform          string            `json:"platform"`
	Architecture      string            `json:"architecture"`
	WorkspaceRoot     string            `json:"workspace_root"`
	PublicIdentityKey string            `json:"public_identity_key"`
	RuntimeVersions   map[string]string `json:"runtime_versions"`
}

type MachineEnrollmentStart struct {
	ID             string    `json:"id"`
	BootstrapToken string    `json:"bootstrap_token"`
	ServerURL      string    `json:"server_url"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// StartMachineEnrollment creates the single-use credential used by the
// dashboard, CLI, and TUI one-shot installers.
func (c *Client) StartMachineEnrollment(ctx context.Context, idempotencyKey string, options ...string) (MachineEnrollmentStart, error) {
	var out MachineEnrollmentStart
	if strings.TrimSpace(idempotencyKey) == "" {
		return out, errors.New("machine enrollment idempotency key is required")
	}
	role, shell := "host", "posix"
	if len(options) > 0 && options[0] != "" {
		role = options[0]
	}
	if len(options) > 1 && options[1] != "" {
		shell = options[1]
	}
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/machine-enrollments", map[string]string{"role": role, "shell": shell}, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}

func (c *Client) SetupMachine(ctx context.Context, input MachineSetupInput) (UserMachine, error) {
	var out UserMachine
	err := c.do(ctx, http.MethodPost, "/v1/machines/setup", input, &out)
	return out, err
}

type MachineControlCredential struct {
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (c *Client) IssueMachineControlCredential(ctx context.Context, machineID, operationID string, proof []byte) (MachineControlCredential, error) {
	if strings.TrimSpace(machineID) == "" || len(operationID) < 8 || len(proof) == 0 {
		return MachineControlCredential{}, errors.New("machine control credential request is invalid")
	}
	var out MachineControlCredential
	path := "/v1/machines/" + url.PathEscape(machineID) + "/control-credentials"
	err := c.doWithHeaders(ctx, http.MethodPost, path, struct {
		OperationID string `json:"operation_id"`
	}{operationID}, &out, http.Header{"X-Paperboat-Machine-Proof": []string{base64.RawURLEncoding.EncodeToString(proof)}})
	return out, err
}

func (c *Client) UnpairMachine(ctx context.Context, machineID string) (UserMachine, error) {
	if strings.TrimSpace(machineID) == "" {
		return UserMachine{}, errors.New("machine ID is required")
	}
	var out UserMachine
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/unpair", nil, &out)
	return out, err
}

type RuntimeDiagnostics struct {
	WorkerGeneration    uint64     `json:"worker_generation"`
	OSBootID            string     `json:"os_boot_id,omitempty"`
	WorkerServiceScope  string     `json:"worker_service_scope"`
	ConnectorState      string     `json:"connector_state"`
	ConnectorGeneration uint64     `json:"connector_generation"`
	ObservedAt          *time.Time `json:"observed_at,omitempty"`
}

type AvailabilityPolicy struct {
	Schema             string     `json:"schema"`
	DesiredMode        string     `json:"desired_mode"`
	DesiredVersion     int64      `json:"desired_version"`
	ObservedMode       string     `json:"observed_mode,omitempty"`
	ObservedVersion    int64      `json:"observed_version"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
	Status             string     `json:"status"`
	ErrorCode          string     `json:"error_code,omitempty"`
	HostServiceVersion string     `json:"host_service_version,omitempty"`
	HostServiceScope   string     `json:"host_service_scope,omitempty"`
	UpdateRollbacks    int64      `json:"update_rollbacks"`
	UpdateHealth       string     `json:"update_health"`
}

type ConfigRepository struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	ExternalRef string `json:"external_ref"`
	DisplayName string `json:"display_name"`
}

type ConfigAssignment struct {
	ID              string  `json:"id"`
	MachineID       string  `json:"machine_id"`
	EnvironmentID   string  `json:"environment_id"`
	RepositoryID    *string `json:"repository_id"`
	ConsentState    string  `json:"consent_state"`
	Mode            string  `json:"mode"`
	WarningRevision *string `json:"warning_revision"`
	Version         int64   `json:"version"`
}

type ConfigWarningFacts struct {
	Revision             string `json:"revision"`
	MachineName          string `json:"machine_name"`
	RepositoryName       string `json:"repository_name"`
	CanonicalScope       string `json:"canonical_scope"`
	Mode                 string `json:"mode"`
	ManifestScope        string `json:"manifest_scope"`
	RepositoryVisibility string `json:"repository_visibility"`
	HistoryRetention     string `json:"history_retention"`
	ConflictBehavior     string `json:"conflict_behavior"`
	ForceBehavior        string `json:"force_behavior"`
	DisableAction        string `json:"disable_action"`
	OfflineBehavior      string `json:"offline_behavior"`
	AccessConsequence    string `json:"access_consequence"`
}

type Preview struct {
	ID              string     `json:"id"`
	EnvironmentID   string     `json:"environment_id"`
	ProjectID       string     `json:"project_id"`
	ResourceID      string     `json:"resource_id"`
	UserID          string     `json:"user_id"`
	LogicalName     string     `json:"logical_name"`
	PreviewKey      string     `json:"preview_key"`
	URL             string     `json:"url"`
	TargetPort      int32      `json:"target_port"`
	State           string     `json:"state"`
	ExpiresAt       *time.Time `json:"expires_at"`
	RemovedAt       *time.Time `json:"removed_at"`
	Version         int64      `json:"version"`
	EnvironmentName string     `json:"environment_name"`
	EnvironmentKind string     `json:"environment_kind"`
	OwnerEmail      string     `json:"owner_email"`
	SourceKind      string     `json:"source_kind"`
	OwnerMode       string     `json:"owner_mode"`
	SourcePath      string     `json:"source_path,omitempty"`
}

type Favorite struct {
	Kind       string    `json:"kind"`
	ResourceID string    `json:"resource_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func (c *Client) ListFavorites(ctx context.Context) ([]Favorite, error) {
	var out []Favorite
	err := c.do(ctx, http.MethodGet, "/v1/favorites", nil, &out)
	return out, err
}

func (c *Client) SetFavorite(ctx context.Context, kind, resourceID string, favorite bool) ([]Favorite, error) {
	var out []Favorite
	err := c.do(ctx, http.MethodPut, "/v1/favorites", map[string]any{"kind": kind, "resource_id": resourceID, "favorite": favorite}, &out)
	return out, err
}

func (c *Client) ListPreviews(ctx context.Context) ([]Preview, error) {
	var out []Preview
	err := c.do(ctx, http.MethodGet, "/v1/previews", nil, &out)
	return out, err
}

func (c *Client) RemovePreview(ctx context.Context, previewID, idempotencyKey string) (Preview, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return Preview{}, errors.New("preview idempotency key is required")
	}
	var out Preview
	path := "/v1/previews/" + url.PathEscape(previewID)
	err := c.doWithHeaders(ctx, http.MethodDelete, path, nil, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}

func (c *Client) ListConfigRepositories(ctx context.Context) ([]ConfigRepository, error) {
	var page struct {
		Items []ConfigRepository `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/config-repositories", nil, &page)
	return page.Items, err
}

func (c *Client) ConfigAssignment(ctx context.Context, machineID string) (ConfigAssignment, error) {
	var out ConfigAssignment
	err := c.do(ctx, http.MethodGet, "/v1/machines/"+url.PathEscape(machineID)+"/config-assignment", nil, &out)
	return out, err
}

func (c *Client) AssignConfig(ctx context.Context, machineID, repositoryID, mode string, expectedVersion int64) (ConfigAssignment, error) {
	var out ConfigAssignment
	err := c.do(ctx, http.MethodPut, "/v1/machines/"+url.PathEscape(machineID)+"/config-assignment", map[string]any{"repository_id": repositoryID, "mode": mode, "warning_revision": "", "expected_version": expectedVersion}, &out)
	return out, err
}

func (c *Client) UnassignConfig(ctx context.Context, machineID string, expectedVersion int64) error {
	path := fmt.Sprintf("/v1/machines/%s/config-assignment?expected_version=%d", url.PathEscape(machineID), expectedVersion)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) ConfigWarning(ctx context.Context, machineID string) (ConfigWarningFacts, error) {
	var out ConfigWarningFacts
	err := c.do(ctx, http.MethodGet, "/v1/machines/"+url.PathEscape(machineID)+"/config-assignment/warning", nil, &out)
	return out, err
}

func (c *Client) AcceptConfigConsent(ctx context.Context, machineID, warningRevision string, expectedVersion int64) (ConfigAssignment, error) {
	var out ConfigAssignment
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/config-assignment/consent", map[string]any{"warning_revision": warningRevision, "expected_version": expectedVersion}, &out)
	return out, err
}

type UserMachinePage struct {
	Items      []UserMachine `json:"items"`
	Pagination Pagination    `json:"pagination"`
}

type TransferDestinationDefault struct {
	Configured bool         `json:"configured"`
	Machine    *UserMachine `json:"machine"`
}

func (c *Client) TransferDestinationDefault(ctx context.Context) (TransferDestinationDefault, error) {
	var out TransferDestinationDefault
	err := c.do(ctx, http.MethodGet, "/v1/transfer-destination-default", nil, &out)
	return out, err
}

func (c *Client) SetTransferDestinationDefault(ctx context.Context, machineID string) (TransferDestinationDefault, error) {
	var out TransferDestinationDefault
	err := c.do(ctx, http.MethodPut, "/v1/transfer-destination-default", map[string]string{"machine_id": machineID}, &out)
	return out, err
}

func (c *Client) ClearTransferDestinationDefault(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/v1/transfer-destination-default", nil, nil)
}

func (c *Client) TerminalSessionTransferDestination(ctx context.Context, sessionID string) (TransferDestinationDefault, error) {
	var out TransferDestinationDefault
	err := c.do(ctx, http.MethodGet, "/v1/terminal-sessions/"+url.PathEscape(sessionID)+"/transfer-destination", nil, &out)
	return out, err
}

func (c *Client) SetTerminalSessionTransferDestination(ctx context.Context, sessionID, machineID string) (TransferDestinationDefault, error) {
	var out TransferDestinationDefault
	err := c.do(ctx, http.MethodPut, "/v1/terminal-sessions/"+url.PathEscape(sessionID)+"/transfer-destination", map[string]string{"machine_id": machineID}, &out)
	return out, err
}

func (c *Client) ClearTerminalSessionTransferDestination(ctx context.Context, sessionID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/terminal-sessions/"+url.PathEscape(sessionID)+"/transfer-destination", nil, nil)
}

func (c *Client) EligibleTerminalSessionTransferDestinations(ctx context.Context, sessionID string) ([]UserMachine, error) {
	var page struct {
		Items []UserMachine `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/terminal-sessions/"+url.PathEscape(sessionID)+"/transfer-destinations", nil, &page)
	return page.Items, err
}

// TerminalSession is the durable session catalog record returned by the
// control plane. Runtime-only fields may be unavailable while a VM is stopped.
type TerminalSession struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	IsDefault      bool             `json:"is_default"`
	State          string           `json:"state"`
	AttachedCount  *int             `json:"attached_count"`
	LastActiveAt   *time.Time       `json:"last_active_at"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	EvictedSession *TerminalSession `json:"evicted_session,omitempty"`
}

type TerminalSessionPage struct {
	Items      []TerminalSession `json:"items"`
	Pagination Pagination        `json:"pagination"`
}

// AuthMaterial is short-lived auth material scoped by paperboat-server for a
// specific connect descriptor. The protocol contract defines the exact token format.
type AuthMaterial struct {
	Method    string    `json:"method"`
	Ticket    string    `json:"ticket,omitempty"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes,omitempty"`
}

const ConnectionSchemaV1 = "paperboat.environment-connection/v1"

// Environment identifies either a hosted project or a machine.
type Environment struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	ResourceID    string `json:"resource_id"`
	State         string `json:"state"`
	Root          string `json:"root"`
	EnvironmentID string `json:"environment_id"`
	ProjectID     string `json:"project_id"`
	UserMachineID string `json:"machine_id"`
	DisplayName   string `json:"display_name"`
	ProjectRoot   string `json:"project_root"`
}

type CodexSession struct {
	ID                 string    `json:"id"`
	EnvironmentID      string    `json:"environment_id"`
	MachineID          string    `json:"machine_id"`
	State              string    `json:"state"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
	RemoteCodexVersion string    `json:"remote_codex_version,omitempty"`
	FailureCode        string    `json:"failure_code,omitempty"`
}
type CodexDescriptor struct {
	Session             CodexSession `json:"session"`
	MachineGeneration   uint64       `json:"machine_generation"`
	ManagementURL       string       `json:"management_url"`
	WebSocketURL        string       `json:"websocket_url"`
	ManageCredential    string       `json:"manage_credential"`
	ConnectCredential   string       `json:"connect_credential"`
	CredentialsExpireAt time.Time    `json:"credentials_expire_at"`
}

func (c *Client) CreateCodexSession(ctx context.Context, environmentID, idempotencyKey string) (CodexSession, error) {
	var out CodexSession
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/codex-sessions", map[string]string{"environment_id": environmentID}, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}
func (c *Client) CodexSessionDescriptor(ctx context.Context, id string) (CodexDescriptor, error) {
	var out CodexDescriptor
	err := c.do(ctx, http.MethodGet, "/v1/codex-sessions/"+url.PathEscape(id)+"/descriptor", nil, &out)
	return out, err
}
func (c *Client) RenewCodexSession(ctx context.Context, id string) (CodexSession, error) {
	var out CodexSession
	err := c.do(ctx, http.MethodPost, "/v1/codex-sessions/"+url.PathEscape(id)+"/renew", nil, &out)
	return out, err
}
func (c *Client) DeleteCodexSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/codex-sessions/"+url.PathEscape(id), nil, nil)
}

// Terminal is the CLI-safe Paperboat WebSocket attach descriptor from
// cli-connect. It carries client-safe Paperboat route URLs, not raw VM
// addresses or SSH credentials.
type Terminal struct {
	Protocol   string            `json:"protocol"`
	Endpoints  TerminalEndpoints `json:"endpoints"`
	SessionID  string            `json:"session_id"`
	Auth       AuthMaterial      `json:"auth"`
	ThreadID   string            `json:"thread_id"`
	TerminalID string            `json:"terminal_id"`
	CWD        string            `json:"cwd"`
}

type TerminalEndpoints struct {
	QUIC string `json:"quic"`
	WSS  string `json:"wss"`
}

type FileTransferPolicy struct {
	Revision               string `json:"revision"`
	MaxFileBytes           int64  `json:"max_file_bytes"`
	MaxBatchFiles          int    `json:"max_batch_files"`
	MaxBatchBytes          int64  `json:"max_batch_bytes"`
	MaxConcurrentTransfers int    `json:"max_concurrent_transfers"`
	RetentionSeconds       int64  `json:"retention_seconds"`
	DeliveryTimeoutSeconds int64  `json:"delivery_timeout_seconds"`
	MaxPendingSpoolBytes   int64  `json:"max_pending_spool_bytes"`
}

type FileTransfer struct {
	Endpoint             string             `json:"endpoint"`
	SourceMachineID      string             `json:"source_machine_id"`
	DestinationMachineID string             `json:"destination_machine_id"`
	InitiatingUserID     string             `json:"initiating_user_id"`
	Auth                 AuthMaterial       `json:"auth"`
	Policy               FileTransferPolicy `json:"policy"`
}

type PreviewLaunchDescriptor struct {
	Endpoint  string       `json:"endpoint"`
	MachineID string       `json:"machine_id"`
	ExpiresAt time.Time    `json:"expires_at"`
	Auth      AuthMaterial `json:"auth"`
}

type PreviewLaunchRequest struct {
	OperationID     string `json:"operation_id"`
	Name            string `json:"name"`
	Port            uint16 `json:"port"`
	DurationSeconds int64  `json:"duration_seconds,omitempty"`
	Indefinite      bool   `json:"indefinite,omitempty"`
}

type PreviewLaunchError struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	Retryable    bool   `json:"retryable"`
	MachineID    string `json:"machine_id"`
	Name         string `json:"name"`
	Port         uint16 `json:"port"`
	StateCreated bool   `json:"state_created"`
	Cleanup      string `json:"cleanup"`
	Recovery     string `json:"recovery"`
}

func (e *PreviewLaunchError) Error() string { return e.Message }

type PreviewRecord struct {
	OperationID   string     `json:"operation_id,omitempty"`
	ID            string     `json:"id"`
	EnvironmentID string     `json:"environment_id"`
	PreviewKey    string     `json:"preview_key"`
	LogicalName   string     `json:"logical_name"`
	URL           string     `json:"url"`
	TargetPort    int32      `json:"target_port"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// ConnectionDescriptor is the cli-connect / connection-status descriptor. When
// Connectable is false the machine is not ready yet; Status/Reason explain why
// and the caller should poll ConnectionReadiness.
type ConnectionDescriptor struct {
	Schema            string        `json:"schema"`
	Issuer            string        `json:"issuer,omitempty"`
	ProjectID         string        `json:"project_id"`
	ProjectState      string        `json:"project_state"`
	UserMachineID     string        `json:"machine_id"`
	UserMachineState  string        `json:"machine_state"`
	Connectable       bool          `json:"connectable"`
	ExpiresAt         time.Time     `json:"expires_at"`
	Environment       *Environment  `json:"environment,omitempty"`
	Terminal          *Terminal     `json:"terminal,omitempty"`
	FileTransfer      *FileTransfer `json:"file_transfer,omitempty"`
	Status            string        `json:"status,omitempty"`
	Reason            string        `json:"reason,omitempty"`
	RetryAfterSeconds int           `json:"retry_after_seconds,omitempty"`
	Capabilities      []string      `json:"capabilities,omitempty"`
}

type ExecDescriptor struct {
	OperationID string            `json:"operation_id"`
	Environment *Environment      `json:"environment"`
	Endpoints   TerminalEndpoints `json:"endpoints"`
	Auth        AuthMaterial      `json:"auth"`
	ExpiresAt   time.Time         `json:"expires_at"`
}

type SSHDescriptor = ExecDescriptor

// NormalizeConnectionDescriptor maps the canonical wire contract onto the
// internal transport fields.
func (r *ConnectionDescriptor) NormalizeConnectionDescriptor() error {
	if r.Schema != ConnectionSchemaV1 {
		return fmt.Errorf("unsupported connection descriptor schema %q", r.Schema)
	}
	if r.Environment == nil {
		return nil
	}
	e := r.Environment
	e.EnvironmentID, e.ProjectRoot = e.ID, e.Root
	switch e.Kind {
	case "hosted":
		e.ProjectID, r.ProjectID, r.ProjectState = e.ResourceID, e.ResourceID, e.State
	case "byod":
		e.UserMachineID, r.UserMachineID, r.UserMachineState = e.ResourceID, e.ResourceID, e.State
	default:
		return fmt.Errorf("invalid environment kind %q", e.Kind)
	}
	if r.Terminal != nil {
		if r.Terminal.Protocol != "paperboat.terminal.v1" {
			return errors.New("invalid canonical terminal protocol")
		}
	}
	if r.FileTransfer != nil {
		u, err := url.Parse(r.FileTransfer.Endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" || strings.TrimRight(u.Path, "/") == "" {
			return errors.New("invalid canonical file transfer endpoint")
		}
		r.FileTransfer.Endpoint = strings.TrimRight(r.FileTransfer.Endpoint, "/")
	}
	return nil
}

// ConfigSyncStatus is the account-wide status response. The CLI selects the
// entry matching the attached project and intentionally ignores path/error
// details when rendering its local status line.
type ConfigSyncStatus struct {
	State        string                       `json:"state"`
	Environments []ConfigSyncEnvironmentState `json:"environments"`
}

type ConfigSyncEnvironmentState struct {
	EnvironmentID         string                  `json:"environment_id"`
	DisplayName           string                  `json:"display_name"`
	State                 string                  `json:"state"`
	Mode                  string                  `json:"mode"`
	AssignmentVersion     int64                   `json:"assignment_version"`
	RemoteRevision        string                  `json:"remote_revision"`
	ManifestHealth        string                  `json:"manifest_health"`
	ManifestRevision      string                  `json:"manifest_revision"`
	ManagedPathCount      int                     `json:"managed_path_count"`
	PendingCleanPathCount int                     `json:"pending_clean_path_count"`
	LastAppliedRevision   string                  `json:"last_applied_revision"`
	LastPublishedRevision string                  `json:"last_published_revision"`
	Conflicts             []ConfigSyncPathSummary `json:"conflicts"`
}

type ConfigSyncPathSummary struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes,omitempty"`
	Reason   string `json:"reason"`
	Revision string `json:"revision,omitempty"`
}

// UsageSummary is the account-level, server-authoritative usage payload used
// by the connected terminal's optional status widgets.
type UsageSummary struct {
	Credits struct {
		Balance string `json:"balance"`
	} `json:"credits"`
	Storage struct {
		AvailableGB int `json:"available_gb"`
	} `json:"storage"`
	Projects struct {
		Running int `json:"running"`
		Total   int `json:"total"`
	} `json:"projects"`
}

// ConfigSyncStatus gets the authenticated account's configuration sync state.
func (c *Client) ConfigSyncStatus(ctx context.Context) (ConfigSyncStatus, error) {
	var out ConfigSyncStatus
	err := c.do(ctx, http.MethodGet, "/v1/config-sync/status", nil, &out)
	return out, err
}

type ConfigConflictRequest struct {
	Path                      string `json:"path"`
	ConflictRevision          string `json:"conflict_revision"`
	ExpectedRemoteRevision    string `json:"expected_remote_revision"`
	ExpectedAssignmentVersion int64  `json:"expected_assignment_version"`
	Action                    string `json:"action"`
}

type ConfigOperation struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Scope  string `json:"scope"`
	Action string `json:"action"`
}

func (c *Client) ResolveConfigConflict(ctx context.Context, machineID string, request ConfigConflictRequest) (ConfigOperation, error) {
	var out ConfigOperation
	err := c.do(ctx, http.MethodPost, "/v1/config-sync/environments/"+url.PathEscape(machineID)+"/conflict-resolutions", request, &out)
	return out, err
}

type ConfigForceRequest struct {
	Scope                     string `json:"scope"`
	Path                      string `json:"path,omitempty"`
	ConflictRevision          string `json:"conflict_revision,omitempty"`
	ExpectedRemoteRevision    string `json:"expected_remote_revision"`
	ExpectedAssignmentVersion int64  `json:"expected_assignment_version"`
	Action                    string `json:"action"`
	Confirmation              string `json:"confirmation"`
}

func (c *Client) ForceConfig(ctx context.Context, machineID string, request ConfigForceRequest) (ConfigOperation, error) {
	var out ConfigOperation
	err := c.do(ctx, http.MethodPost, "/v1/config-sync/environments/"+url.PathEscape(machineID)+"/force", request, &out)
	return out, err
}

// UsageSummary returns account credits, available storage, and project counts.
func (c *Client) UsageSummary(ctx context.Context) (UsageSummary, error) {
	var out UsageSummary
	err := c.do(ctx, http.MethodGet, "/v1/usage-summary", nil, &out)
	return out, err
}

// Me fetches the authenticated user, validating the reused credential.
func (c *Client) Me(ctx context.Context) (Me, error) {
	var out Me
	err := c.do(ctx, http.MethodGet, "/v1/me", nil, &out)
	return out, err
}

// ListProjects returns every project page using the server-authored cursor.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	const pageSize = 200
	projects := make([]Project, 0)
	offset := 0
	for {
		var page ProjectPage
		path := fmt.Sprintf("/v1/projects?limit=%d&offset=%d&sort=name", pageSize, offset)
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		projects = append(projects, page.Items...)
		if page.Pagination.NextOffset == nil {
			return projects, nil
		}
		if *page.Pagination.NextOffset <= offset {
			return nil, errors.New("project pagination did not advance")
		}
		offset = *page.Pagination.NextOffset
	}
}

// ListUserMachines returns every enrolled machine page using the
// server-authored cursor. Calling it never reveals connector credentials or
// local paths beyond the machine's declared scope.
func (c *Client) ListUserMachines(ctx context.Context) ([]UserMachine, error) {
	const pageSize = 200
	machines := make([]UserMachine, 0)
	offset := 0
	for {
		var page UserMachinePage
		path := fmt.Sprintf("/v1/machines?limit=%d&offset=%d&sort=display_name", pageSize, offset)
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		machines = append(machines, page.Items...)
		if page.Pagination.NextOffset == nil {
			return machines, nil
		}
		if *page.Pagination.NextOffset <= offset {
			return nil, errors.New("machine pagination did not advance")
		}
		offset = *page.Pagination.NextOffset
	}
}

func (c *Client) ManagedSSHTarget(ctx context.Context, machineID string, generation uint64) (ManagedSSHTarget, error) {
	if strings.TrimSpace(machineID) == "" || generation == 0 {
		return ManagedSSHTarget{}, errors.New("valid managed SSH target identity is required")
	}
	var target ManagedSSHTarget
	path := fmt.Sprintf("/v1/machines/%s/ssh-target?machine_generation=%d", url.PathEscape(machineID), generation)
	if err := c.do(ctx, http.MethodGet, path, nil, &target); err != nil {
		return ManagedSSHTarget{}, err
	}
	if target.Type != "machine_target" || target.Version != 1 || target.MachineID != machineID || target.MachineGeneration != generation || target.Port == 0 || target.ReconciliationVersion == 0 || strings.TrimSpace(target.OSUser) == "" {
		return ManagedSSHTarget{}, errors.New("paperboat-server returned an invalid managed SSH target")
	}
	return target, nil
}

func (c *Client) RegisterManagedSSHTarget(ctx context.Context, machineID string, generation uint64, osUser string, port uint16, operationID string) (ManagedSSHTarget, error) {
	if strings.TrimSpace(machineID) == "" || generation == 0 || strings.TrimSpace(osUser) == "" || port == 0 || strings.TrimSpace(operationID) == "" {
		return ManagedSSHTarget{}, errors.New("valid managed SSH target registration is required")
	}
	var target ManagedSSHTarget
	err := c.doWithHeaders(ctx, http.MethodPut, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-target", map[string]any{"machine_generation": generation, "os_user": osUser, "port": port}, &target, http.Header{"Idempotency-Key": []string{operationID}})
	if err != nil {
		return ManagedSSHTarget{}, err
	}
	if target.Type != "machine_target" || target.Version != 1 || target.MachineID != machineID || target.MachineGeneration != generation || target.OSUser != osUser || target.Port != port || target.ReconciliationVersion == 0 {
		return ManagedSSHTarget{}, errors.New("paperboat-server returned an invalid managed SSH target")
	}
	return target, nil
}

func (c *Client) UpdateManagedSSHTargetPort(ctx context.Context, machineID string, generation, expectedVersion uint64, port uint16, operationID string) (ManagedSSHTarget, error) {
	if strings.TrimSpace(machineID) == "" || generation == 0 || expectedVersion == 0 || port == 0 || strings.TrimSpace(operationID) == "" {
		return ManagedSSHTarget{}, errors.New("valid managed SSH target update is required")
	}
	var target ManagedSSHTarget
	err := c.doWithHeaders(ctx, http.MethodPut, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-target", map[string]any{"machine_generation": generation, "port": port, "expected_reconciliation_version": expectedVersion}, &target, http.Header{"Idempotency-Key": []string{operationID}})
	if err != nil {
		return ManagedSSHTarget{}, err
	}
	if target.Type != "machine_target" || target.Version != 1 || target.MachineID != machineID || target.MachineGeneration != generation || target.Port != port || target.ReconciliationVersion != expectedVersion+1 {
		return ManagedSSHTarget{}, errors.New("paperboat-server returned an invalid managed SSH target update")
	}
	return target, nil
}

func (c *Client) ObserveManagedSSHHostKeys(ctx context.Context, machineID, keyID, operationID, setID string, generation, observationGeneration uint64, publicKeys []string, proof []byte) (ManagedSSHHostKeySet, error) {
	if strings.TrimSpace(machineID) == "" || strings.TrimSpace(keyID) == "" || strings.TrimSpace(operationID) == "" || strings.TrimSpace(setID) == "" || generation == 0 || observationGeneration == 0 || len(publicKeys) == 0 || len(proof) == 0 {
		return ManagedSSHHostKeySet{}, errors.New("valid managed SSH host-key observation is required")
	}
	var set ManagedSSHHostKeySet
	err := c.doWithHeaders(ctx, http.MethodPut, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-host-keys", map[string]any{"set_id": setID, "observation_generation": observationGeneration, "public_keys": publicKeys}, &set, http.Header{"X-Paperboat-Machine-Identity": []string{keyID}, "X-Paperboat-Machine-Proof": []string{base64.RawURLEncoding.EncodeToString(proof)}})
	if err != nil {
		return ManagedSSHHostKeySet{}, err
	}
	if set.Type != "host_key_set" || set.Version != 1 || set.SetID != setID || set.MachineID != machineID || set.MachineGeneration != generation || set.ObservationGeneration == 0 || len(set.Keys) == 0 || set.ReconciliationVersion == 0 {
		return ManagedSSHHostKeySet{}, fmt.Errorf("paperboat-server returned an invalid managed SSH host-key observation: got type=%q version=%d machine=%q generation=%d observation=%d keys=%d revision=%d expected machine=%q generation=%d observation=%d", set.Type, set.Version, set.MachineID, set.MachineGeneration, set.ObservationGeneration, len(set.Keys), set.ReconciliationVersion, machineID, generation, observationGeneration)
	}
	return set, nil
}

func (c *Client) ManagedSSHAuthorizedKeys(ctx context.Context, machineID, keyID string, generation uint64, proof []byte) (ManagedSSHAuthorizedKeys, error) {
	if strings.TrimSpace(machineID) == "" || strings.TrimSpace(keyID) == "" || generation == 0 || len(proof) == 0 {
		return ManagedSSHAuthorizedKeys{}, errors.New("valid managed SSH authorized-key request is required")
	}
	var set ManagedSSHAuthorizedKeys
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-authorized-keys", map[string]any{}, &set, http.Header{"X-Paperboat-Machine-Identity": []string{keyID}, "X-Paperboat-Machine-Proof": []string{base64.RawURLEncoding.EncodeToString(proof)}})
	if err != nil {
		return ManagedSSHAuthorizedKeys{}, err
	}
	if set.Type != "authorized_key_set" || set.Version != 1 || set.MachineID != machineID || set.MachineGeneration != generation || len(set.Keys) > 64 {
		return ManagedSSHAuthorizedKeys{}, errors.New("paperboat-server returned an invalid managed SSH authorized-key set")
	}
	return set, nil
}

func (c *Client) ManagedSSHHostKeys(ctx context.Context, machineID string, generation uint64) (ManagedSSHHostKeySet, error) {
	return c.managedSSHHostKeys(ctx, machineID, generation, "active")
}

func (c *Client) ManagedSSHPendingHostKeys(ctx context.Context, machineID string, generation uint64) (ManagedSSHHostKeySet, error) {
	return c.managedSSHHostKeys(ctx, machineID, generation, "pending")
}

func (c *Client) managedSSHHostKeys(ctx context.Context, machineID string, generation uint64, state string) (ManagedSSHHostKeySet, error) {
	if strings.TrimSpace(machineID) == "" || generation == 0 {
		return ManagedSSHHostKeySet{}, errors.New("valid managed SSH host-key identity is required")
	}
	var set ManagedSSHHostKeySet
	path := fmt.Sprintf("/v1/machines/%s/ssh-host-keys?machine_generation=%d&state=%s", url.PathEscape(machineID), generation, state)
	if err := c.do(ctx, http.MethodGet, path, nil, &set); err != nil {
		return ManagedSSHHostKeySet{}, err
	}
	if set.Type != "host_key_set" || set.Version != 1 || set.SetID == "" || set.MachineID != machineID || set.MachineGeneration != generation || set.ObservationGeneration == 0 || len(set.Keys) == 0 || set.State != state || set.Fingerprint == "" || set.ReconciliationVersion == 0 {
		return ManagedSSHHostKeySet{}, errors.New("paperboat-server returned an invalid managed SSH host-key set")
	}
	return set, nil
}

func (c *Client) PromoteManagedSSHHostKeys(ctx context.Context, machineID, setID, fingerprint, operationID string, generation uint64) (ManagedSSHHostKeySet, error) {
	if strings.TrimSpace(machineID) == "" || strings.TrimSpace(setID) == "" || strings.TrimSpace(fingerprint) == "" || strings.TrimSpace(operationID) == "" || generation == 0 {
		return ManagedSSHHostKeySet{}, errors.New("valid managed SSH host-key promotion is required")
	}
	var set ManagedSSHHostKeySet
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-host-keys/"+url.PathEscape(setID)+"/promote", map[string]any{"machine_generation": generation, "expected_fingerprint": fingerprint}, &set, http.Header{"Idempotency-Key": []string{operationID}})
	if err != nil {
		return ManagedSSHHostKeySet{}, err
	}
	if set.Type != "host_key_set" || set.Version != 1 || set.SetID != setID || set.MachineID != machineID || set.MachineGeneration != generation || set.State != "active" || set.Fingerprint != fingerprint || set.ReconciliationVersion == 0 {
		return ManagedSSHHostKeySet{}, errors.New("paperboat-server returned an invalid managed SSH host-key promotion")
	}
	return set, nil
}

func (c *Client) RegisterManagedSSHClientKey(ctx context.Context, publicKey string, fingerprint [32]byte, operationID string) (ManagedSSHClientKey, error) {
	publicKey = strings.TrimSpace(publicKey)
	operationID = strings.TrimSpace(operationID)
	if publicKey == "" || fingerprint == [32]byte{} || operationID == "" {
		return ManagedSSHClientKey{}, errors.New("valid managed SSH client-key registration is required")
	}
	encodedFingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(fingerprint[:])
	var key ManagedSSHClientKey
	path := "/v1/ssh/client-keys/" + url.PathEscape(encodedFingerprint)
	err := c.doWithHeaders(ctx, http.MethodPut, path, map[string]string{"public_key": publicKey}, &key, http.Header{"Idempotency-Key": []string{operationID}})
	if err != nil {
		return ManagedSSHClientKey{}, err
	}
	if key.Type != "client_key" || key.Version != 1 || key.Fingerprint != encodedFingerprint || key.PublicKey != publicKey || key.State != "active" || key.ReconciliationVersion == 0 {
		return ManagedSSHClientKey{}, errors.New("paperboat-server returned an invalid managed SSH client key")
	}
	return key, nil
}

func (c *Client) DisconnectUserMachine(ctx context.Context, machineID string) error {
	if strings.TrimSpace(machineID) == "" {
		return errors.New("machine ID is required")
	}
	return c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/disconnect", nil, nil)
}

func (c *Client) RenameUserMachine(ctx context.Context, machineID, displayName string) (UserMachine, error) {
	machineID = strings.TrimSpace(machineID)
	displayName = strings.TrimSpace(displayName)
	if machineID == "" || displayName == "" {
		return UserMachine{}, errors.New("machine ID and display name are required")
	}
	var out UserMachine
	err := c.do(ctx, http.MethodPatch, "/v1/machines/"+url.PathEscape(machineID), map[string]string{"display_name": displayName}, &out)
	return out, err
}

func (c *Client) SetUserMachineAvailability(ctx context.Context, machineID, mode, idempotencyKey string, expectedVersion int64) (AvailabilityPolicy, error) {
	if strings.TrimSpace(machineID) == "" || (mode != "allow_sleep" && mode != "keep_awake") || strings.TrimSpace(idempotencyKey) == "" || expectedVersion < 0 {
		return AvailabilityPolicy{}, errors.New("valid machine availability input is required")
	}
	var out AvailabilityPolicy
	path := "/v1/machines/" + url.PathEscape(machineID) + "/availability-policy"
	err := c.doWithHeaders(ctx, http.MethodPut, path, map[string]any{"expected_version": expectedVersion, "mode": mode}, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}

func (c *Client) DeleteUserMachine(ctx context.Context, machineID string) error {
	if strings.TrimSpace(machineID) == "" {
		return errors.New("machine ID is required")
	}
	return c.do(ctx, http.MethodDelete, "/v1/machines/"+url.PathEscape(machineID), nil, nil)
}

// ProjectConnectionDescriptor runs the pre-connect broker: it authorizes, provisions/reconciles
// route resources, resumes an idle machine, and returns the helper
// WebSocket terminal descriptor. A not-yet-ready machine returns
// Connectable=false (HTTP 202); the caller polls ConnectionReadiness.
func (c *Client) ProjectConnectionDescriptor(ctx context.Context, projectID string) (ConnectionDescriptor, error) {
	return c.ProjectConnectionDescriptorForSession(ctx, projectID, "")
}

// ProjectConnectionDescriptorForSession connects the selected durable terminal session. An empty
// session ID preserves the default-session behavior for older servers/clients.
func (c *Client) ProjectConnectionDescriptorForSession(ctx context.Context, projectID, terminalSessionID string) (ConnectionDescriptor, error) {
	var out ConnectionDescriptor
	var values map[string]string
	if c.sourceMachineID != "" {
		values = map[string]string{"source_machine_id": c.sourceMachineID}
	}
	if terminalSessionID != "" {
		if values == nil {
			values = make(map[string]string)
		}
		values["terminal_session_id"] = terminalSessionID
	}
	var body any
	if values != nil {
		body = values
	}
	err := c.do(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(projectID)+"/connection-descriptor", body, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

// UserMachineConnectionDescriptor obtains the default terminal session's short-lived
// Paperboat descriptor. It deliberately does not accept a client-supplied
// route or connector credential.
func (c *Client) UserMachineConnectionDescriptor(ctx context.Context, machineID string) (ConnectionDescriptor, error) {
	return c.UserMachineConnectionDescriptorForSession(ctx, machineID, "")
}

// UserMachineConnectionDescriptorWithSessionCreate creates a durable terminal
// session and issues the connection descriptor in one round trip. The
// idempotency key makes retried requests resolve the same durable session.
func (c *Client) UserMachineConnectionDescriptorWithSessionCreate(ctx context.Context, machineID, name, idempotencyKey string) (ConnectionDescriptor, TerminalSession, error) {
	if strings.TrimSpace(machineID) == "" || strings.TrimSpace(idempotencyKey) == "" || c.sourceMachineID == "" {
		return ConnectionDescriptor{}, TerminalSession{}, errors.New("machine identity and idempotency key are required")
	}
	var out struct {
		Descriptor      ConnectionDescriptor `json:"descriptor"`
		TerminalSession TerminalSession      `json:"terminal_session"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/connection-descriptor", map[string]any{
		"source_machine_id": c.sourceMachineID,
		"create_session":    map[string]string{"name": name, "idempotency_key": idempotencyKey},
	}, &out)
	if err == nil {
		err = out.Descriptor.NormalizeConnectionDescriptor()
	}
	if err == nil && out.TerminalSession.ID == "" {
		err = errors.New("server did not return the created terminal session")
	}
	return out.Descriptor, out.TerminalSession, err
}

// UserMachineConnectionDescriptorForSession connects a durable terminal session belonging
// to an enrolled machine.
func (c *Client) UserMachineConnectionDescriptorForSession(ctx context.Context, machineID, terminalSessionID string) (ConnectionDescriptor, error) {
	var out ConnectionDescriptor
	var values map[string]string
	if c.sourceMachineID != "" {
		values = map[string]string{"source_machine_id": c.sourceMachineID}
	}
	if terminalSessionID != "" {
		if values == nil {
			values = make(map[string]string)
		}
		values["terminal_session_id"] = terminalSessionID
	}
	var body any
	if values != nil {
		body = values
	}
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/connection-descriptor", body, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

func (c *Client) MachineExecDescriptor(ctx context.Context, machineID, operationID string) (ExecDescriptor, error) {
	if strings.TrimSpace(machineID) == "" || len(operationID) < 8 || len(operationID) > 128 || c.sourceMachineID == "" {
		return ExecDescriptor{}, errors.New("machine, source machine, and operation IDs are required")
	}
	var out ExecDescriptor
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/exec-descriptor", map[string]string{"source_machine_id": c.sourceMachineID, "operation_id": operationID}, &out)
	if err == nil {
		err = validateOperationDescriptor(out, machineID, operationID, "exec:operate", "exec")
	}
	return out, err
}

func (c *Client) MachineSSHDescriptor(ctx context.Context, machineID, operationID string) (SSHDescriptor, error) {
	if strings.TrimSpace(machineID) == "" || len(operationID) < 8 || len(operationID) > 128 || c.sourceMachineID == "" {
		return SSHDescriptor{}, errors.New("machine, source machine, and operation IDs are required")
	}
	var out SSHDescriptor
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/ssh-descriptor", map[string]string{"source_machine_id": c.sourceMachineID, "operation_id": operationID}, &out)
	if err == nil {
		err = validateOperationDescriptor(out, machineID, operationID, "ssh:operate", "ssh")
	}
	return out, err
}

func validateOperationDescriptor(out ExecDescriptor, machineID, operationID, expectedScope, operationKind string) error {
	quic, quicErr := url.Parse(out.Endpoints.QUIC)
	wss, wssErr := url.Parse(out.Endpoints.WSS)
	if out.OperationID != operationID || out.Environment == nil || out.Environment.ID == "" || out.Environment.Kind != "byod" || out.Environment.ResourceID != machineID || out.Environment.State != "ready" || !remotepath.Absolute(out.Environment.Root) ||
		quicErr != nil || quic.Scheme != "quic" || quic.Hostname() == "" || quic.User != nil || quic.Path != "" || quic.RawQuery != "" || quic.Fragment != "" ||
		wssErr != nil || wss.Scheme != "wss" || wss.Hostname() == "" || wss.User != nil || wss.Path != "/v1/runtime" || wss.RawQuery != "" || wss.Fragment != "" ||
		out.Auth.Method != "bearer" || out.Auth.Token == "" || len(out.Auth.Scopes) != 1 || out.Auth.Scopes[0] != expectedScope || out.ExpiresAt.IsZero() || out.Auth.ExpiresAt.IsZero() || !out.ExpiresAt.Equal(out.Auth.ExpiresAt) {
		return fmt.Errorf("invalid %s descriptor", operationKind)
	}
	return nil
}

func (c *Client) MachineFileTransferDescriptor(ctx context.Context, destinationMachineID, sourceMachineID, sessionID string) (FileTransfer, error) {
	if strings.TrimSpace(destinationMachineID) == "" || strings.TrimSpace(sourceMachineID) == "" {
		return FileTransfer{}, errors.New("source and destination machine IDs are required")
	}
	var out FileTransfer
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(destinationMachineID)+"/file-transfer-descriptor", map[string]string{
		"source_machine_id": sourceMachineID,
		"session_id":        sessionID,
	}, &out)
	return out, err
}

func (c *Client) MachinePreviewLaunchDescriptor(ctx context.Context, machineID string) (PreviewLaunchDescriptor, error) {
	if strings.TrimSpace(machineID) == "" {
		return PreviewLaunchDescriptor{}, errors.New("machine ID is required")
	}
	var out PreviewLaunchDescriptor
	err := c.do(ctx, http.MethodPost, "/v1/machines/"+url.PathEscape(machineID)+"/preview-launch-descriptor", nil, &out)
	if err != nil {
		return PreviewLaunchDescriptor{}, err
	}
	u, parseErr := url.Parse(out.Endpoint)
	if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.Path != "/v1/preview-launches" || out.MachineID != machineID || out.Auth.Method != "bearer" || out.Auth.Token == "" || out.ExpiresAt.IsZero() || out.Auth.ExpiresAt.IsZero() || !out.ExpiresAt.Equal(out.Auth.ExpiresAt) || len(out.Auth.Scopes) != 1 || out.Auth.Scopes[0] != "preview:launch" {
		return PreviewLaunchDescriptor{}, errors.New("paperboat-server returned an invalid preview launch descriptor")
	}
	return out, nil
}

func LaunchMachinePreview(ctx context.Context, descriptor PreviewLaunchDescriptor, input PreviewLaunchRequest, transport http.RoundTripper) (PreviewRecord, error) {
	if transport == nil {
		transport = httptransport.Default()
	}
	body, err := json.Marshal(input)
	if err != nil {
		return PreviewRecord{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, descriptor.Endpoint, bytes.NewReader(body))
	if err != nil {
		return PreviewRecord{}, err
	}
	request.Header.Set("Authorization", "Bearer "+descriptor.Auth.Token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("preview launch endpoint redirected") }}
	response, err := client.Do(request)
	if err != nil {
		return PreviewRecord{}, fmt.Errorf("launch preview on machine: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error PreviewLaunchError `json:"error"`
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&envelope) == nil && envelope.Error.Code != "" && envelope.Error.Message != "" {
			return PreviewRecord{}, &envelope.Error
		}
		return PreviewRecord{}, fmt.Errorf("remote preview launch failed with status %d", response.StatusCode)
	}
	var record PreviewRecord
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || record.OperationID != input.OperationID || record.URL == "" || record.LogicalName == "" {
		return PreviewRecord{}, errors.New("machine returned an invalid preview launch response")
	}
	return record, nil
}

// UserMachineConnectionReadiness polls readiness without minting a fresh
// descriptor. Reconnects re-run UserMachineConnectionDescriptor after this reports
// ready, matching the hosted-project flow.
func (c *Client) UserMachineConnectionReadiness(ctx context.Context, machineID string) (ConnectionDescriptor, error) {
	return c.UserMachineConnectionReadinessForSession(ctx, machineID, "")
}

// UserMachineConnectionReadinessForSession preserves the selected terminal
// session through readiness polling, exactly as hosted-project polling does.
func (c *Client) UserMachineConnectionReadinessForSession(ctx context.Context, machineID, terminalSessionID string) (ConnectionDescriptor, error) {
	var out ConnectionDescriptor
	path := "/v1/machines/" + url.PathEscape(machineID) + "/connection-readiness"
	if terminalSessionID != "" {
		path += "?terminal_session_id=" + url.QueryEscape(terminalSessionID)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

func (c *Client) ListTerminalSessions(ctx context.Context, projectID string) ([]TerminalSession, error) {
	return c.listTerminalSessions(ctx, "/v1/projects/"+url.PathEscape(projectID)+"/terminal-sessions")
}

func (c *Client) listTerminalSessions(ctx context.Context, basePath string) ([]TerminalSession, error) {
	const pageSize = 200
	var sessions []TerminalSession
	for offset := 0; ; {
		var page TerminalSessionPage
		path := fmt.Sprintf("%s?limit=%d&offset=%d", basePath, pageSize, offset)
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		sessions = append(sessions, page.Items...)
		if page.Pagination.NextOffset == nil {
			return sessions, nil
		}
		if *page.Pagination.NextOffset <= offset {
			return nil, errors.New("terminal session pagination did not advance")
		}
		offset = *page.Pagination.NextOffset
	}
}

func (c *Client) CreateTerminalSession(ctx context.Context, projectID, name, idempotencyKey string) (TerminalSession, error) {
	var out TerminalSession
	body := map[string]string{}
	if name != "" {
		body["name"] = name
	}
	path := "/v1/projects/" + url.PathEscape(projectID) + "/terminal-sessions"
	return out, c.doWithHeaders(ctx, http.MethodPost, path, body, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
}

func (c *Client) RenameTerminalSession(ctx context.Context, projectID, sessionID, name string) (TerminalSession, error) {
	var out TerminalSession
	err := c.do(ctx, http.MethodPatch, "/v1/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID), map[string]string{"name": name}, &out)
	return out, err
}

func (c *Client) CloseTerminalSession(ctx context.Context, projectID, sessionID string) error {
	return c.do(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID)+"/close", nil, &struct{}{})
}

func (c *Client) DeleteTerminalSession(ctx context.Context, projectID, sessionID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID), nil, &struct{}{})
}

// ListUserMachineTerminalSessions lists the durable Paperboat sessions
// for a machine. Session records remain server-owned, so the CLI
// never discovers local paths or connector state through this endpoint.
func (c *Client) ListUserMachineTerminalSessions(ctx context.Context, machineID string) ([]TerminalSession, error) {
	return c.listTerminalSessions(ctx, "/v1/machines/"+url.PathEscape(machineID)+"/terminal-sessions")
}

func (c *Client) CreateUserMachineTerminalSession(ctx context.Context, machineID, name, idempotencyKey string) (TerminalSession, error) {
	var out TerminalSession
	body := map[string]string{}
	if name != "" {
		body["name"] = name
	}
	path := "/v1/machines/" + url.PathEscape(machineID) + "/terminal-sessions"
	return out, c.doWithHeaders(ctx, http.MethodPost, path, body, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
}

func (c *Client) RenameUserMachineTerminalSession(ctx context.Context, machineID, sessionID, name string) (TerminalSession, error) {
	var out TerminalSession
	path := "/v1/machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID)
	err := c.do(ctx, http.MethodPatch, path, map[string]string{"name": name}, &out)
	return out, err
}

func (c *Client) CloseUserMachineTerminalSession(ctx context.Context, machineID, sessionID string) error {
	path := "/v1/machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID) + "/close"
	return c.do(ctx, http.MethodPost, path, nil, &struct{}{})
}

func (c *Client) DeleteUserMachineTerminalSession(ctx context.Context, machineID, sessionID string) error {
	path := "/v1/machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID)
	return c.do(ctx, http.MethodDelete, path, nil, &struct{}{})
}

// ConnectionReadiness reports current tunnel readiness without re-brokering.
func (c *Client) ConnectionReadiness(ctx context.Context, projectID string) (ConnectionDescriptor, error) {
	return c.ProjectConnectionReadinessForSession(ctx, projectID, "")
}

// ProjectConnectionReadinessForSession polls readiness for the same durable terminal
// session selected for cli-connect. The returned descriptor has no credential,
// but its terminal identity must never silently fall back to the default.
func (c *Client) ProjectConnectionReadinessForSession(ctx context.Context, projectID, terminalSessionID string) (ConnectionDescriptor, error) {
	var out ConnectionDescriptor
	path := "/v1/projects/" + url.PathEscape(projectID) + "/connection-readiness"
	if terminalSessionID != "" {
		path += "?terminal_session_id=" + url.QueryEscape(terminalSessionID)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.doRequest(ctx, method, path, body, out, nil, false)
}

func (c *Client) doWithHeaders(ctx context.Context, method, path string, body, out any, headers http.Header) error {
	return c.doRequest(ctx, method, path, body, out, headers, false)
}

func (c *Client) doStrict(ctx context.Context, method, path string, body, out any) error {
	return c.doRequest(ctx, method, path, body, out, nil, true)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, out any, headers http.Header, strict bool) error {
	if strings.TrimSpace(c.baseURL) == "" {
		return errors.New("paperboat-server base URL is not configured")
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "paperboat/"+buildinfo.Version)
	req.Header.Set("X-Paperboat-Client", "paperboat")
	req.Header.Set("X-Paperboat-Protocol", buildinfo.ProtocolVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	// A body is expected for every documented response; a decode failure on a
	// 2xx is a real protocol error, so surface it rather than silently succeed.
	decodeErr := json.NewDecoder(resp.Body).Decode(&envelope)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUpgradeRequired || envelope.Error.Code == "incompatible_client_version" {
			required, _ := envelope.Error.Details["required_protocol"].(string)
			return &ErrIncompatibleVersion{Required: required, Message: envelope.Error.Message}
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrUnauthenticated
		}
		return &APIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: responseRequestID(resp.Header), Details: envelope.Error.Details}
	}
	if decodeErr != nil {
		return fmt.Errorf("decode %s %s response: %w", method, path, decodeErr)
	}
	if out == nil {
		return nil
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("%s %s returned an empty response", method, path)
	}
	if !strict {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decode %s %s data: %w", method, path, err)
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode %s %s data: %w", method, path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s %s data: trailing JSON", method, path)
	}
	return nil
}

func safeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 200 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("_.:-", r) {
			return ""
		}
	}
	return value
}
