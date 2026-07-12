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

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

// ErrUnauthenticated means the server rejected the reused credential. Callers
// should route the user through Paperboat device login.
var ErrUnauthenticated = errors.New("paperboat-server rejected the credential")

// APIError is a structured server error surfaced to the caller. It carries the
// server's stable error code so command logic can branch without string
// matching on messages.
type APIError struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("paperboat-server returned status %d", e.Status)
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
		httpClient = &http.Client{Timeout: 30 * time.Second}
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

// AuthMaterial is short-lived auth material scoped by paperboat-server for a
// specific connect descriptor. Phase 1 will finalize the exact token format.
type AuthMaterial struct {
	Method    string    `json:"method"`
	Ticket    string    `json:"ticket,omitempty"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes,omitempty"`
}

// Environment is the papercode environment metadata returned by cli-connect.
type Environment struct {
	EnvironmentID string `json:"environment_id"`
	ProjectID     string `json:"project_id"`
	DisplayName   string `json:"display_name"`
	ProjectRoot   string `json:"project_root"`
}

// Terminal is the CLI-safe papercode WebSocket attach descriptor from
// cli-connect. It carries client-safe agentunnel route URLs, not raw VM
// addresses or SSH credentials.
type Terminal struct {
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
	Issuer            string       `json:"issuer,omitempty"`
	ProjectID         string       `json:"project_id"`
	ProjectState      string       `json:"project_state"`
	Connectable       bool         `json:"connectable"`
	ExpiresAt         time.Time    `json:"expires_at"`
	Environment       *Environment `json:"environment,omitempty"`
	Terminal          *Terminal    `json:"terminal,omitempty"`
	Upload            *Upload      `json:"upload,omitempty"`
	Status            string       `json:"status,omitempty"`
	Reason            string       `json:"reason,omitempty"`
	RetryAfterSeconds int          `json:"retry_after_seconds,omitempty"`
}

type KeepAliveResponse struct {
	Project        Project   `json:"project"`
	KeepAliveUntil time.Time `json:"keep_alive_until,omitempty"`
}

// Activity records human/agent activity for server-owned idle detection.
func (c *Client) Activity(ctx context.Context, projectID, source string) error {
	body := map[string]any{"source": "cli_activity", "metadata": map[string]any{"event": source}}
	return c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/activity", body, nil)
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

// CLIConnect runs the pre-connect broker: it authorizes, provisions/reconciles
// agentunnel resources, resumes an idle machine, and returns the papercode
// WebSocket terminal descriptor. A not-yet-ready machine returns
// Connectable=false (HTTP 202); the caller polls ConnectionStatus.
func (c *Client) CLIConnect(ctx context.Context, projectID string) (ConnectResponse, error) {
	var out ConnectResponse
	err := c.do(ctx, http.MethodPost, "/api/projects/"+url.PathEscape(projectID)+"/cli-connect", nil, &out)
	return out, err
}

// ConnectionStatus reports current tunnel readiness without re-brokering.
func (c *Client) ConnectionStatus(ctx context.Context, projectID string) (ConnectResponse, error) {
	var out ConnectResponse
	err := c.do(ctx, http.MethodGet, "/api/projects/"+url.PathEscape(projectID)+"/connection-status", nil, &out)
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

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
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrUnauthenticated
		}
		return &APIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, Details: envelope.Error.Details}
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
