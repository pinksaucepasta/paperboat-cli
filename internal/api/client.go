// Package api is the Paperboat bearer-authenticated control-plane client.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/buildinfo"
	"github.com/pujan-modha/paperboat-cli/internal/config"
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
// that also expose separately entitled connected machines may skip projects
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
	baseURL     string
	cred        config.Credential
	http        *http.Client
	accessToken string
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

// Me is the authenticated-user payload from GET /api/me.
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

type CatalogMachineType struct {
	Code   string `json:"code"`
	Active bool   `json:"active"`
}
type CatalogRegion struct {
	Code    string `json:"code"`
	Enabled bool   `json:"enabled"`
}
type CatalogIdleTimeout struct {
	Code   string `json:"code"`
	Active bool   `json:"active"`
}

func (c *Client) ListGitHubRepositories(ctx context.Context) ([]GitHubRepository, error) {
	var out []GitHubRepository
	err := c.do(ctx, http.MethodGet, "/api/github/repositories", nil, &out)
	return out, err
}

func (c *Client) ListCatalogMachineTypes(ctx context.Context) ([]CatalogMachineType, error) {
	var out []CatalogMachineType
	err := c.do(ctx, http.MethodGet, "/api/catalog/machine-types", nil, &out)
	return out, err
}

func (c *Client) ListCatalogRegions(ctx context.Context) ([]CatalogRegion, error) {
	var out []CatalogRegion
	err := c.do(ctx, http.MethodGet, "/api/catalog/regions", nil, &out)
	return out, err
}

func (c *Client) ListCatalogIdleTimeouts(ctx context.Context) ([]CatalogIdleTimeout, error) {
	var out []CatalogIdleTimeout
	err := c.do(ctx, http.MethodGet, "/api/catalog/idle-timeouts", nil, &out)
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
	IdleTimeoutCode string   `json:"idle_timeout_code"`
	SetupScript     string   `json:"setup_script,omitempty"`
}

func (c *Client) CreateProject(ctx context.Context, input CreateProjectInput, idempotencyKey string) (Project, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return Project{}, errors.New("project creation idempotency key is required")
	}
	var out Project
	err := c.doWithHeaders(ctx, http.MethodPost, "/api/projects", input, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
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

// ConnectedMachine is a user-owned environment reached through its enrolled
// connector rather than a Paperboat-managed Fly VM. The control plane owns its
// lifecycle and authorization; the CLI only needs enough metadata to select it.
type ConnectedMachine struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	DisplayName   string `json:"display_name"`
	State         string `json:"state"`
	Online        bool   `json:"online"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
}

type ConfigRepository struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	ExternalRef string `json:"external_ref"`
	DisplayName string `json:"display_name"`
}

type ConfigAssignment struct {
	ID              string  `json:"id"`
	EnvironmentID   string  `json:"environment_id"`
	RepositoryID    *string `json:"repository_id"`
	ConsentState    string  `json:"consent_state"`
	WarningRevision *string `json:"warning_revision"`
	Version         int64   `json:"version"`
}

type Preview struct {
	ID              string     `json:"id"`
	EnvironmentID   string     `json:"environment_id"`
	ProjectID       string     `json:"project_id"`
	MachineID       string     `json:"machine_id"`
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
}

func (c *Client) ListPreviews(ctx context.Context) ([]Preview, error) {
	var out []Preview
	err := c.do(ctx, http.MethodGet, "/api/previews", nil, &out)
	return out, err
}

func (c *Client) RemovePreview(ctx context.Context, previewID, idempotencyKey string) (Preview, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return Preview{}, errors.New("preview idempotency key is required")
	}
	var out Preview
	path := "/api/previews/" + url.PathEscape(previewID)
	err := c.doWithHeaders(ctx, http.MethodDelete, path, nil, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
	return out, err
}

func (c *Client) ListConfigRepositories(ctx context.Context) ([]ConfigRepository, error) {
	var page struct {
		Items []ConfigRepository `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/api/config-repositories", nil, &page)
	return page.Items, err
}

func (c *Client) ConfigAssignment(ctx context.Context, environmentID string) (ConfigAssignment, error) {
	var out ConfigAssignment
	err := c.do(ctx, http.MethodGet, "/api/environments/"+url.PathEscape(environmentID)+"/config-assignment", nil, &out)
	return out, err
}

func (c *Client) AssignConfig(ctx context.Context, environmentID, repositoryID string, expectedVersion int64) (ConfigAssignment, error) {
	var out ConfigAssignment
	err := c.do(ctx, http.MethodPut, "/api/environments/"+url.PathEscape(environmentID)+"/config-assignment", map[string]any{"repository_id": repositoryID, "warning_revision": "", "expected_version": expectedVersion}, &out)
	return out, err
}

func (c *Client) UnassignConfig(ctx context.Context, environmentID string, expectedVersion int64) error {
	path := fmt.Sprintf("/api/environments/%s/config-assignment?expected_version=%d", url.PathEscape(environmentID), expectedVersion)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

type ConnectedMachinePage struct {
	Items      []ConnectedMachine `json:"items"`
	Pagination Pagination         `json:"pagination"`
}

// TerminalSession is the durable session catalog record returned by the
// control plane. Runtime-only fields may be unavailable while a VM is stopped.
type TerminalSession struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	IsDefault     bool       `json:"is_default"`
	State         string     `json:"state"`
	AttachedCount *int       `json:"attached_count"`
	LastActiveAt  *time.Time `json:"last_active_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type TerminalSessionPage struct {
	Items      []TerminalSession `json:"items"`
	Pagination Pagination        `json:"pagination"`
}

// AuthMaterial is short-lived auth material scoped by paperboat-server for a
// specific connect descriptor. Phase 1 will finalize the exact token format.
type AuthMaterial struct {
	Method    string    `json:"method"`
	Ticket    string    `json:"ticket,omitempty"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes,omitempty"`
}

const ConnectionSchemaV1 = "paperboat.environment-connection/v1"

// Environment identifies either a hosted project or a BYOD machine.
type Environment struct {
	ID                 string `json:"id"`
	Kind               string `json:"kind"`
	ResourceID         string `json:"resource_id"`
	State              string `json:"state"`
	Root               string `json:"root"`
	EnvironmentID      string `json:"environment_id"`
	ProjectID          string `json:"project_id"`
	ConnectedMachineID string `json:"connected_machine_id"`
	DisplayName        string `json:"display_name"`
	ProjectRoot        string `json:"project_root"`
}

// Terminal is the CLI-safe papercode WebSocket attach descriptor from
// cli-connect. It carries client-safe Paperboat route URLs, not raw VM
// addresses or SSH credentials.
type Terminal struct {
	Endpoint         string       `json:"endpoint"`
	HTTPEndpoint     string       `json:"http_endpoint"`
	SessionID        string       `json:"session_id"`
	Kind             string       `json:"kind"`
	HTTPBaseURL      string       `json:"http_base_url"`
	WebSocketBaseURL string       `json:"websocket_base_url"`
	Auth             AuthMaterial `json:"auth"`
	ThreadID         string       `json:"thread_id"`
	TerminalID       string       `json:"terminal_id"`
	CWD              string       `json:"cwd"`
}

// Upload is the papercode image-upload endpoint hint from cli-connect.
type Upload struct {
	Endpoint         string       `json:"endpoint"`
	Kind             string       `json:"kind"`
	HTTPBaseURL      string       `json:"http_base_url"`
	Path             string       `json:"path"`
	Auth             AuthMaterial `json:"auth"`
	MaxBytes         int64        `json:"max_bytes"`
	AllowedMIMETypes []string     `json:"allowed_mime_types"`
	RetentionSeconds int64        `json:"retention_seconds"`
}

// ConnectResponse is the cli-connect / connection-status descriptor. When
// Connectable is false the machine is not ready yet; Status/Reason explain why
// and the caller should poll ConnectionStatus.
type ConnectResponse struct {
	Schema                string       `json:"schema"`
	Issuer                string       `json:"issuer,omitempty"`
	ProjectID             string       `json:"project_id"`
	ProjectState          string       `json:"project_state"`
	ConnectedMachineID    string       `json:"connected_machine_id"`
	ConnectedMachineState string       `json:"connected_machine_state"`
	Connectable           bool         `json:"connectable"`
	ExpiresAt             time.Time    `json:"expires_at"`
	Environment           *Environment `json:"environment,omitempty"`
	Terminal              *Terminal    `json:"terminal,omitempty"`
	Upload                *Upload      `json:"upload,omitempty"`
	Status                string       `json:"status,omitempty"`
	Reason                string       `json:"reason,omitempty"`
	RetryAfterSeconds     int          `json:"retry_after_seconds,omitempty"`
	Capabilities          []string     `json:"capabilities,omitempty"`
}

// NormalizeConnectionDescriptor maps the canonical wire contract onto the
// internal transport fields. Legacy fields are accepted only when Schema is
// empty, which keeps rollback compatibility from becoming a second writer.
func (r *ConnectResponse) NormalizeConnectionDescriptor() error {
	if r.Schema != "" && r.Schema != ConnectionSchemaV1 {
		return fmt.Errorf("unsupported connection descriptor schema %q", r.Schema)
	}
	if r.Schema == "" || r.Environment == nil {
		return nil
	}
	e := r.Environment
	e.EnvironmentID, e.ProjectRoot = e.ID, e.Root
	switch e.Kind {
	case "hosted":
		e.ProjectID, r.ProjectID, r.ProjectState = e.ResourceID, e.ResourceID, e.State
	case "byod":
		e.ConnectedMachineID, r.ConnectedMachineID, r.ConnectedMachineState = e.ResourceID, e.ResourceID, e.State
	default:
		return fmt.Errorf("invalid environment kind %q", e.Kind)
	}
	if r.Terminal != nil {
		r.Terminal.Kind = "paperboat_terminal_v1"
		r.Terminal.WebSocketBaseURL = r.Terminal.Endpoint
		r.Terminal.HTTPBaseURL = r.Terminal.HTTPEndpoint
	}
	if r.Upload != nil {
		r.Upload.Kind = "paperboat_staged_image_v1"
		u, err := url.Parse(r.Upload.Endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path == "" {
			return errors.New("invalid canonical upload endpoint")
		}
		r.Upload.Path = u.EscapedPath()
		u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
		r.Upload.HTTPBaseURL = strings.TrimSuffix(u.String(), "/")
	}
	return nil
}

type KeepAliveResponse struct {
	Project        Project   `json:"project"`
	KeepAliveUntil time.Time `json:"keep_alive_until,omitempty"`
}

// ConfigSyncStatus is the account-wide status response. The CLI selects the
// entry matching the attached project and intentionally ignores path/error
// details when rendering its local status line.
type ConfigSyncStatus struct {
	State    string                   `json:"state"`
	Projects []ConfigSyncProjectState `json:"projects"`
}

type ConfigSyncProjectState struct {
	ProjectID        string `json:"project_id"`
	State            string `json:"state"`
	PendingPathCount int    `json:"pending_path_count"`
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

// Activity records human/agent activity for server-owned idle detection.
func (c *Client) Activity(ctx context.Context, projectID, source string) error {
	body := map[string]any{"source": "cli_activity", "metadata": map[string]any{"event": source}}
	return c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/activity", body, nil)
}

// ConfigSyncStatus gets the authenticated account's configuration sync state.
func (c *Client) ConfigSyncStatus(ctx context.Context) (ConfigSyncStatus, error) {
	var out ConfigSyncStatus
	err := c.do(ctx, http.MethodGet, "/api/config-sync/status", nil, &out)
	return out, err
}

// UsageSummary returns account credits, available storage, and project counts.
func (c *Client) UsageSummary(ctx context.Context) (UsageSummary, error) {
	var out UsageSummary
	err := c.do(ctx, http.MethodGet, "/api/dashboard/usage-summary", nil, &out)
	return out, err
}

// Me fetches the authenticated user, validating the reused credential.
func (c *Client) Me(ctx context.Context) (Me, error) {
	var out Me
	err := c.do(ctx, http.MethodGet, "/api/me", nil, &out)
	return out, err
}

// ListProjects returns every project page using the server-authored cursor.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	const pageSize = 200
	projects := make([]Project, 0)
	offset := 0
	for {
		var page ProjectPage
		path := fmt.Sprintf("/api/projects?limit=%d&offset=%d&sort=name", pageSize, offset)
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

// ListConnectedMachines returns every enrolled machine page using the
// server-authored cursor. Calling it never reveals connector credentials or
// local paths beyond the machine's declared scope.
func (c *Client) ListConnectedMachines(ctx context.Context) ([]ConnectedMachine, error) {
	const pageSize = 200
	machines := make([]ConnectedMachine, 0)
	offset := 0
	for {
		var page ConnectedMachinePage
		path := fmt.Sprintf("/api/connected-machines?limit=%d&offset=%d&sort=display_name", pageSize, offset)
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		machines = append(machines, page.Items...)
		if page.Pagination.NextOffset == nil {
			return machines, nil
		}
		if *page.Pagination.NextOffset <= offset {
			return nil, errors.New("connected-machine pagination did not advance")
		}
		offset = *page.Pagination.NextOffset
	}
}

func (c *Client) DisconnectConnectedMachine(ctx context.Context, machineID string) error {
	if strings.TrimSpace(machineID) == "" {
		return errors.New("connected-machine ID is required")
	}
	return c.do(ctx, http.MethodPost, "/api/connected-machines/"+url.PathEscape(machineID)+"/disconnect", nil, nil)
}

func (c *Client) DeleteConnectedMachine(ctx context.Context, machineID string) error {
	if strings.TrimSpace(machineID) == "" {
		return errors.New("connected-machine ID is required")
	}
	return c.do(ctx, http.MethodDelete, "/api/connected-machines/"+url.PathEscape(machineID), nil, nil)
}

// CLIConnect runs the pre-connect broker: it authorizes, provisions/reconciles
// route resources, resumes an idle machine, and returns the helper
// WebSocket terminal descriptor. A not-yet-ready machine returns
// Connectable=false (HTTP 202); the caller polls ConnectionStatus.
func (c *Client) CLIConnect(ctx context.Context, projectID string) (ConnectResponse, error) {
	return c.CLIConnectSession(ctx, projectID, "")
}

// CLIConnectSession connects the selected durable terminal session. An empty
// session ID preserves the default-session behavior for older servers/clients.
func (c *Client) CLIConnectSession(ctx context.Context, projectID, terminalSessionID string) (ConnectResponse, error) {
	var out ConnectResponse
	var body any
	if terminalSessionID != "" {
		body = map[string]string{"terminal_session_id": terminalSessionID}
	}
	err := c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/cli-connect", body, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

// ConnectConnectedMachine obtains the default terminal session's short-lived
// papercode descriptor. It deliberately does not accept a client-supplied
// route or connector credential.
func (c *Client) ConnectConnectedMachine(ctx context.Context, machineID string) (ConnectResponse, error) {
	return c.ConnectConnectedMachineSession(ctx, machineID, "")
}

// ConnectConnectedMachineSession connects a durable terminal session belonging
// to an enrolled connected machine.
func (c *Client) ConnectConnectedMachineSession(ctx context.Context, machineID, terminalSessionID string) (ConnectResponse, error) {
	var out ConnectResponse
	var body any
	if terminalSessionID != "" {
		body = map[string]string{"terminal_session_id": terminalSessionID}
	}
	err := c.do(ctx, http.MethodPost, "/api/connected-machines/"+url.PathEscape(machineID)+"/connect", body, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

// ConnectedMachineConnectionStatus polls readiness without minting a fresh
// descriptor. Reconnects re-run ConnectConnectedMachine after this reports
// ready, matching the hosted-project flow.
func (c *Client) ConnectedMachineConnectionStatus(ctx context.Context, machineID string) (ConnectResponse, error) {
	return c.ConnectedMachineConnectionStatusSession(ctx, machineID, "")
}

// ConnectedMachineConnectionStatusSession preserves the selected terminal
// session through readiness polling, exactly as hosted-project polling does.
func (c *Client) ConnectedMachineConnectionStatusSession(ctx context.Context, machineID, terminalSessionID string) (ConnectResponse, error) {
	var out ConnectResponse
	path := "/api/connected-machines/" + url.PathEscape(machineID) + "/connection-status"
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
	return c.listTerminalSessions(ctx, "/api/projects/"+url.PathEscape(projectID)+"/terminal-sessions")
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
	path := "/api/projects/" + url.PathEscape(projectID) + "/terminal-sessions"
	return out, c.doWithHeaders(ctx, http.MethodPost, path, body, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
}

func (c *Client) RenameTerminalSession(ctx context.Context, projectID, sessionID, name string) (TerminalSession, error) {
	var out TerminalSession
	err := c.do(ctx, http.MethodPatch, "/api/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID), map[string]string{"name": name}, &out)
	return out, err
}

func (c *Client) CloseTerminalSession(ctx context.Context, projectID, sessionID string) error {
	return c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID)+"/close", nil, &struct{}{})
}

func (c *Client) DeleteTerminalSession(ctx context.Context, projectID, sessionID string) error {
	return c.do(ctx, http.MethodDelete, "/api/projects/"+url.PathEscape(projectID)+"/terminal-sessions/"+url.PathEscape(sessionID), nil, &struct{}{})
}

// ListConnectedMachineTerminalSessions lists the durable papercode sessions
// for a connected machine. Session records remain server-owned, so the CLI
// never discovers local paths or connector state through this endpoint.
func (c *Client) ListConnectedMachineTerminalSessions(ctx context.Context, machineID string) ([]TerminalSession, error) {
	return c.listTerminalSessions(ctx, "/api/connected-machines/"+url.PathEscape(machineID)+"/terminal-sessions")
}

func (c *Client) CreateConnectedMachineTerminalSession(ctx context.Context, machineID, name, idempotencyKey string) (TerminalSession, error) {
	var out TerminalSession
	body := map[string]string{}
	if name != "" {
		body["name"] = name
	}
	path := "/api/connected-machines/" + url.PathEscape(machineID) + "/terminal-sessions"
	return out, c.doWithHeaders(ctx, http.MethodPost, path, body, &out, http.Header{"Idempotency-Key": []string{idempotencyKey}})
}

func (c *Client) RenameConnectedMachineTerminalSession(ctx context.Context, machineID, sessionID, name string) (TerminalSession, error) {
	var out TerminalSession
	path := "/api/connected-machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID)
	err := c.do(ctx, http.MethodPatch, path, map[string]string{"name": name}, &out)
	return out, err
}

func (c *Client) CloseConnectedMachineTerminalSession(ctx context.Context, machineID, sessionID string) error {
	path := "/api/connected-machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID) + "/close"
	return c.do(ctx, http.MethodPost, path, nil, &struct{}{})
}

func (c *Client) DeleteConnectedMachineTerminalSession(ctx context.Context, machineID, sessionID string) error {
	path := "/api/connected-machines/" + url.PathEscape(machineID) + "/terminal-sessions/" + url.PathEscape(sessionID)
	return c.do(ctx, http.MethodDelete, path, nil, &struct{}{})
}

// ConnectionStatus reports current tunnel readiness without re-brokering.
func (c *Client) ConnectionStatus(ctx context.Context, projectID string) (ConnectResponse, error) {
	return c.ConnectionStatusSession(ctx, projectID, "")
}

// ConnectionStatusSession polls readiness for the same durable terminal
// session selected for cli-connect. The returned descriptor has no credential,
// but its terminal identity must never silently fall back to the default.
func (c *Client) ConnectionStatusSession(ctx context.Context, projectID, terminalSessionID string) (ConnectResponse, error) {
	var out ConnectResponse
	path := "/api/projects/" + url.PathEscape(projectID) + "/connection-status"
	if terminalSessionID != "" {
		path += "?terminal_session_id=" + url.QueryEscape(terminalSessionID)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	if err == nil {
		err = out.NormalizeConnectionDescriptor()
	}
	return out, err
}

func (c *Client) SetKeepAlive(ctx context.Context, projectID string, durationSeconds int, clear bool) (KeepAliveResponse, error) {
	var out KeepAliveResponse
	body := map[string]any{
		"duration_seconds": durationSeconds,
		"clear":            clear,
	}
	err := c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/keep-alive", body, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.doWithHeaders(ctx, method, path, body, out, nil)
}

func (c *Client) doWithHeaders(ctx context.Context, method, path string, body, out any, headers http.Header) error {
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
	req.Header.Set("User-Agent", "paperboat-cli/"+buildinfo.Version)
	req.Header.Set("X-Paperboat-Client", "paperboat-cli")
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
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("decode %s %s data: %w", method, path, err)
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
