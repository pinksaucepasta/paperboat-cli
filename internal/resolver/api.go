package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
)

// ErrProjectNotFound means no project matched the requested name or id for this
// user. Surfaced distinctly so the CLI can guide the user to `pb` project list
// / the dashboard rather than a generic failure.
var ErrProjectNotFound = errors.New("project not found")
var ErrProjectAmbiguous = errors.New("project name is ambiguous")

// connectClient is the subset of the paperboat-server client the resolver
// needs. Defined here so the resolver can be unit-tested with a fake.
type connectClient interface {
	ListProjects(ctx context.Context) ([]api.Project, error)
	CLIConnect(ctx context.Context, projectID string) (api.ConnectResponse, error)
	ConnectionStatus(ctx context.Context, projectID string) (api.ConnectResponse, error)
}

// APIResolver resolves projects against paperboat-server: it matches the
// requested name/id to one of the user's projects, runs the pre-connect broker
// (which authorizes, reconciles agentunnel resources, and resumes an idle
// machine), and polls until the tunnel is connectable — then hands the tunnel
// layer a client-safe papercode WebSocket descriptor.
type APIResolver struct {
	client       connectClient
	cfg          *config.Config
	readyTimeout time.Duration
	pollInterval time.Duration
	// sleep is injectable for tests; nil uses a real timer honoring ctx.
	sleep     func(ctx context.Context, d time.Duration) error
	Progress  func(status, reason string, retryAfter time.Duration)
	Telemetry telemetry.Sink
	Now       func() time.Time
}

// NewAPIResolver builds a resolver bound to a paperboat-server client.
func NewAPIResolver(client connectClient, cfg *config.Config) *APIResolver {
	return &APIResolver{
		client:       client,
		cfg:          cfg,
		readyTimeout: time.Duration(cfg.Connect.ReadyTimeoutSeconds) * time.Second,
		pollInterval: time.Duration(cfg.Connect.PollIntervalSeconds) * time.Second,
	}
}

// Resolve implements ProjectResolver against the real backend.
func (r *APIResolver) Resolve(ctx context.Context, req ConnectRequest) (ConnectInfo, error) {
	started := r.now()
	projectID := ""
	environmentID := ""
	outcome := "failure"
	defer func() { r.record("connect.result", outcome, projectID, environmentID, "", started) }()
	if err := r.validatePolicy(); err != nil {
		return ConnectInfo{}, err
	}
	project, err := r.findProject(ctx, req.Project)
	if err != nil {
		return ConnectInfo{}, err
	}
	projectID = project.ID

	resp, err := r.client.CLIConnect(ctx, project.ID)
	if err != nil {
		return ConnectInfo{}, fmt.Errorf("connect to project %q: %w", req.Project, err)
	}

	resp, err = r.waitConnectable(ctx, project.ID, resp)
	if err != nil {
		return ConnectInfo{}, err
	}
	if resp.Environment != nil {
		environmentID = resp.Environment.EnvironmentID
	}

	if !completeTerminalDescriptor(resp.Terminal) {
		return ConnectInfo{}, fmt.Errorf("connect to project %q: server did not return a terminal endpoint", req.Project)
	}

	info := ConnectInfo{
		ProjectID:    project.ID,
		Project:      project.Name,
		ProjectState: resp.ProjectState,
		TunnelTarget: resp.Terminal.WebSocketBaseURL,
		Local:        false,
		Terminal: &TerminalTarget{
			Kind:             resp.Terminal.Kind,
			EnvironmentID:    resp.Environment.EnvironmentID,
			HTTPBaseURL:      resp.Terminal.HTTPBaseURL,
			WebSocketBaseURL: resp.Terminal.WebSocketBaseURL,
			Auth:             mapAuth(resp.Terminal.Auth),
			ThreadID:         resp.Terminal.ThreadID,
			TerminalID:       resp.Terminal.TerminalID,
			CWD:              resp.Terminal.CWD,
			ReplayHistory:    true,
		},
	}
	if resp.Upload != nil && strings.TrimSpace(resp.Upload.HTTPBaseURL) != "" {
		info.Upload = &UploadTarget{
			HTTPBaseURL:      resp.Upload.HTTPBaseURL,
			Path:             resp.Upload.Path,
			Auth:             mapAuth(resp.Upload.Auth),
			MaxBytes:         resp.Upload.MaxBytes,
			AllowedMIMETypes: resp.Upload.AllowedMIMETypes,
			RetentionSeconds: resp.Upload.RetentionSeconds,
		}
	}
	outcome = "success"
	return info, nil
}

func (r *APIResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *APIResolver) record(name, outcome, projectID, environmentID, stage string, started time.Time) {
	if r.Telemetry == nil {
		return
	}
	ended := r.now()
	e := telemetry.Event{Name: name, At: ended, Outcome: outcome, ProjectID: projectID, EnvironmentID: environmentID, Stage: stage, LatencyMS: ended.Sub(started).Milliseconds()}
	if e.Validate() == nil {
		r.Telemetry.Record(e)
	}
}

func (r *APIResolver) validatePolicy() error {
	if r.cfg.Connect.ReadyTimeoutSeconds <= 0 {
		return errors.New("connect.ready_timeout_seconds must be configured and positive")
	}
	if r.cfg.Connect.PollIntervalSeconds <= 0 {
		return errors.New("connect.poll_interval_seconds must be configured and positive")
	}
	if len(r.cfg.Connect.AcceptedTerminalKinds) == 0 {
		return errors.New("connect.accepted_terminal_kinds must be configured")
	}
	if r.cfg.Connect.DialRetries < 0 {
		return errors.New("connect.dial_retries cannot be negative")
	}
	if r.cfg.Connect.DialRetries > 0 && r.cfg.Connect.DialRetrySeconds <= 0 {
		return errors.New("connect.dial_retry_seconds must be positive when retries are enabled")
	}
	return nil
}

// findProject matches the requested token against the user's projects by id
// first (exact) then by name (case-insensitive). Matching by id keeps scripts
// stable; matching by name keeps the interactive `pb <name>` UX.
func (r *APIResolver) findProject(ctx context.Context, requested string) (api.Project, error) {
	want := strings.TrimSpace(requested)
	if want == "" {
		return api.Project{}, errors.New("missing project name")
	}
	projects, err := r.client.ListProjects(ctx)
	if err != nil {
		return api.Project{}, fmt.Errorf("list projects: %w", err)
	}
	for _, p := range projects {
		if p.ID == want {
			return p, nil
		}
	}
	var matches []api.Project
	for _, p := range projects {
		if strings.EqualFold(p.Name, want) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.ID)
		}
		return api.Project{}, fmt.Errorf("%w: %q matches project IDs %s; connect using an exact ID", ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return api.Project{}, fmt.Errorf("%w: %q", ErrProjectNotFound, requested)
}

// waitConnectable polls connection-status until the tunnel is connectable or the
// configured timeout elapses. cli-connect already queued any needed machine
// resume, so this only waits for readiness; it never re-brokers.
func (r *APIResolver) waitConnectable(ctx context.Context, projectID string, resp api.ConnectResponse) (api.ConnectResponse, error) {
	if resp.Connectable {
		return r.validateDescriptor(resp, projectID)
	}
	deadline := time.Now().Add(r.readyTimeout)
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		if time.Now().After(deadline) {
			return api.ConnectResponse{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
		}
		interval := r.pollInterval
		if resp.RetryAfterSeconds > 0 {
			interval = time.Duration(resp.RetryAfterSeconds) * time.Second
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return api.ConnectResponse{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
		}
		if interval > remaining {
			interval = remaining
		}
		if r.Progress != nil {
			r.Progress(resp.Status, resp.Reason, interval)
		}
		r.record("connect.stage", "waiting", projectID, "", resp.Status, r.now())
		if err := r.wait(pollCtx, interval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return api.ConnectResponse{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
			}
			return api.ConnectResponse{}, err
		}
		next, err := r.client.ConnectionStatus(pollCtx, projectID)
		if err != nil {
			return api.ConnectResponse{}, fmt.Errorf("poll connection status: %w", err)
		}
		if next.Connectable {
			// connection-status omits the terminal descriptor's routing detail;
			// re-broker once now that the machine is ready to get a fresh,
			// fully-populated WebSocket descriptor and access session.
			if !completeTerminalDescriptor(next.Terminal) {
				fresh, err := r.client.CLIConnect(pollCtx, projectID)
				if err != nil {
					return api.ConnectResponse{}, err
				}
				return r.validateDescriptor(fresh, projectID)
			}
			return r.validateDescriptor(next, projectID)
		}
		resp = next
	}
}

func (r *APIResolver) validateDescriptor(resp api.ConnectResponse, projectID string) (api.ConnectResponse, error) {
	wantIssuer, err := config.NormalizeIssuer(r.cfg.ServerURL)
	if err != nil {
		return api.ConnectResponse{}, fmt.Errorf("normalize configured issuer: %w", err)
	}
	gotIssuer, err := config.NormalizeIssuer(resp.Issuer)
	if err != nil || gotIssuer != wantIssuer {
		return api.ConnectResponse{}, errors.New("server returned a descriptor for an unexpected issuer")
	}
	if !resp.Connectable || (resp.ProjectID != "" && resp.ProjectID != projectID) {
		return api.ConnectResponse{}, errors.New("server returned a descriptor for the wrong project")
	}
	if resp.ExpiresAt.IsZero() || !time.Now().Before(resp.ExpiresAt) {
		return api.ConnectResponse{}, errors.New("server returned an expired connection descriptor")
	}
	if !completeTerminalDescriptor(resp.Terminal) {
		return api.ConnectResponse{}, errors.New("server returned an incomplete terminal descriptor")
	}
	if !supportedTerminalKind(resp.Terminal.Kind) || len(r.cfg.Connect.AcceptedTerminalKinds) == 0 || !hasScope(r.cfg.Connect.AcceptedTerminalKinds, resp.Terminal.Kind) || resp.Environment == nil || strings.TrimSpace(resp.Environment.EnvironmentID) == "" || resp.Environment.ProjectID != projectID {
		return api.ConnectResponse{}, errors.New("server returned an invalid environment descriptor")
	}
	if strings.TrimSpace(resp.Environment.ProjectRoot) == "" || strings.TrimSpace(resp.Terminal.ThreadID) == "" || strings.TrimSpace(resp.Terminal.TerminalID) == "" || strings.TrimSpace(resp.Terminal.CWD) == "" {
		return api.ConnectResponse{}, errors.New("server returned incomplete environment or terminal identity")
	}
	wsURL, err := secureEndpoint(resp.Terminal.WebSocketBaseURL, "wss")
	if err != nil {
		return api.ConnectResponse{}, fmt.Errorf("invalid terminal WebSocket endpoint: %w", err)
	}
	if resp.Terminal.HTTPBaseURL != "" {
		httpURL, httpErr := secureEndpoint(resp.Terminal.HTTPBaseURL, "https")
		if httpErr != nil || endpointAuthority(httpURL) != endpointAuthority(wsURL) {
			return api.ConnectResponse{}, errors.New("terminal HTTP and WebSocket hosts do not match")
		}
	}
	if len(r.cfg.Connect.AllowedRouteHosts) > 0 {
		if !allowedHost(resp.Terminal.WebSocketBaseURL, r.cfg.Connect.AllowedRouteHosts) || (resp.Terminal.HTTPBaseURL != "" && !allowedHost(resp.Terminal.HTTPBaseURL, r.cfg.Connect.AllowedRouteHosts)) {
			return api.ConnectResponse{}, errors.New("terminal descriptor host is not allowed by local policy")
		}
	}
	if resp.Terminal.Auth.Method != "websocket_ticket" || !exactScopes(resp.Terminal.Auth.Scopes, "terminal:operate") {
		return api.ConnectResponse{}, errors.New("terminal descriptor has invalid scope or auth")
	}
	if resp.Terminal.Auth.ExpiresAt.IsZero() || !time.Now().Before(resp.Terminal.Auth.ExpiresAt) || resp.Terminal.Auth.ExpiresAt.After(resp.ExpiresAt) {
		return api.ConnectResponse{}, errors.New("terminal credential is expired")
	}
	if err := r.validateUpload(resp.Upload, wsURL, resp.ExpiresAt); err != nil {
		return api.ConnectResponse{}, err
	}
	return resp, nil
}

func supportedTerminalKind(kind string) bool { return kind == "papercode_websocket" }

func (r *APIResolver) validateUpload(up *api.Upload, terminalURL *url.URL, descriptorExpiry time.Time) error {
	if up == nil || up.Kind != "papercode_staged_image" || up.Path == "" || up.MaxBytes <= 0 || up.RetentionSeconds <= 0 {
		return errors.New("server returned an incomplete upload descriptor")
	}
	u, err := secureEndpoint(up.HTTPBaseURL, "https")
	if err != nil || endpointAuthority(u) != endpointAuthority(terminalURL) {
		return errors.New("upload endpoint is not on the validated terminal route")
	}
	if len(r.cfg.Connect.AllowedRouteHosts) > 0 && !allowedHost(up.HTTPBaseURL, r.cfg.Connect.AllowedRouteHosts) {
		return errors.New("upload descriptor host is not allowed by local policy")
	}
	if up.Auth.Method != "bearer" || strings.TrimSpace(up.Auth.Token) == "" || !exactScopes(up.Auth.Scopes, "file:stage") {
		return errors.New("upload descriptor has invalid scope or auth")
	}
	if up.Auth.ExpiresAt.IsZero() || !time.Now().Before(up.Auth.ExpiresAt) || up.Auth.ExpiresAt.After(descriptorExpiry) {
		return errors.New("upload credential is expired")
	}
	if len(up.AllowedMIMETypes) == 0 {
		return errors.New("upload descriptor has no allowed MIME types")
	}
	seen := map[string]bool{}
	for _, mime := range up.AllowedMIMETypes {
		mime = strings.TrimSpace(mime)
		if !strings.HasPrefix(mime, "image/") || seen[mime] {
			return errors.New("upload descriptor has invalid MIME policy")
		}
		seen[mime] = true
	}
	path, err := url.Parse(up.Path)
	if err != nil || path.IsAbs() || path.Host != "" || path.RawQuery != "" || path.Fragment != "" || !strings.HasPrefix(path.Path, "/") {
		return errors.New("upload descriptor has invalid path")
	}
	return nil
}

func endpointAuthority(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		}
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + port
}

func secureEndpoint(raw, scheme string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != scheme || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("endpoint must use %s without credentials, query, or fragment", scheme)
	}
	return u, nil
}

func hasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}

func exactScopes(scopes []string, want string) bool { return len(scopes) == 1 && scopes[0] == want }

func allowedHost(raw string, allowed []string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(candidate), "."))
		if candidate != "" && host == candidate {
			return true
		}
	}
	return false
}

func (r *APIResolver) wait(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func statusReason(resp api.ConnectResponse) string {
	parts := make([]string, 0, 2)
	if resp.Status != "" {
		parts = append(parts, resp.Status)
	}
	if resp.Reason != "" {
		parts = append(parts, resp.Reason)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ": ")
}

func mapAuth(auth api.AuthMaterial) AuthTarget {
	return AuthTarget{
		Method:    auth.Method,
		Ticket:    auth.Ticket,
		Token:     auth.Token,
		ExpiresAt: auth.ExpiresAt.Format(time.RFC3339),
		Scopes:    auth.Scopes,
	}
}

func completeTerminalDescriptor(term *api.Terminal) bool {
	if term == nil || strings.TrimSpace(term.WebSocketBaseURL) == "" {
		return false
	}
	if strings.TrimSpace(term.Auth.Method) == "" {
		return false
	}
	return strings.TrimSpace(term.Auth.Ticket) != "" || strings.TrimSpace(term.Auth.Token) != ""
}
