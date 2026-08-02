package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/telemetry"
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
	ProjectConnectionDescriptor(ctx context.Context, projectID string) (api.ConnectionDescriptor, error)
	ConnectionReadiness(ctx context.Context, projectID string) (api.ConnectionDescriptor, error)
}

type userMachineClient interface {
	ListUserMachines(context.Context) ([]api.UserMachine, error)
	UserMachineConnectionDescriptor(context.Context, string) (api.ConnectionDescriptor, error)
	UserMachineConnectionReadiness(context.Context, string) (api.ConnectionDescriptor, error)
}

type userMachineSessionClient interface {
	UserMachineConnectionDescriptorForSession(context.Context, string, string) (api.ConnectionDescriptor, error)
	UserMachineConnectionReadinessForSession(context.Context, string, string) (api.ConnectionDescriptor, error)
}

type target struct {
	kind  string
	id    string
	name  string
	state string
}

type EnvironmentIdentity struct {
	Kind          string
	ResourceID    string
	EnvironmentID string
	Name          string
}

func (r *APIResolver) ResolveEnvironment(ctx context.Context, requested string) (EnvironmentIdentity, error) {
	target, err := r.findTarget(ctx, requested)
	if err != nil {
		return EnvironmentIdentity{}, err
	}
	environmentID := target.id
	if target.kind == targetUserMachine {
		machines, listErr := r.client.(userMachineClient).ListUserMachines(ctx)
		if listErr != nil {
			return EnvironmentIdentity{}, listErr
		}
		for _, machine := range machines {
			if machine.ID == target.id {
				environmentID = machine.EnvironmentID
				break
			}
		}
	}
	return EnvironmentIdentity{Kind: target.kind, ResourceID: target.id, EnvironmentID: environmentID, Name: target.name}, nil
}

const (
	targetProject     = "project"
	targetUserMachine = "machine"
)

// APIResolver resolves projects against paperboat-server: it matches the
// requested name/id to one of the user's projects, runs the pre-connect broker
// (which authorizes, reconciles Paperboat routes, and resumes an idle
// machine), and polls until the tunnel is connectable — then hands the tunnel
// layer a client-safe Paperboat WebSocket descriptor.
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
	target, err := r.findTarget(ctx, req.Project)
	if err != nil {
		return ConnectInfo{}, err
	}
	projectID = target.id

	resp, err := r.connect(ctx, target, req.TerminalSessionID)
	if err != nil {
		return ConnectInfo{}, fmt.Errorf("connect to environment %q: %w", req.Project, err)
	}

	resp, err = r.waitConnectable(ctx, target, req.TerminalSessionID, resp)
	if err != nil {
		return ConnectInfo{}, err
	}
	if resp.Environment != nil {
		environmentID = resp.Environment.EnvironmentID
	}

	if !completeTerminalDescriptor(resp.Terminal) {
		return ConnectInfo{}, fmt.Errorf("connect to environment %q: server did not return a terminal endpoint", req.Project)
	}

	info := ConnectInfo{
		TargetKind:   target.kind,
		ProjectID:    target.id,
		Project:      target.name,
		ProjectState: targetState(target, resp),
		TunnelTarget: resp.Terminal.Endpoints.WSS,
		Local:        false,
		Terminal: &TerminalTarget{
			Protocol:      resp.Terminal.Protocol,
			EnvironmentID: resp.Environment.EnvironmentID,
			QUICEndpoint:  resp.Terminal.Endpoints.QUIC,
			WSSEndpoint:   resp.Terminal.Endpoints.WSS,
			Auth:          mapAuth(resp.Terminal.Auth),
			ThreadID:      resp.Terminal.ThreadID,
			TerminalID:    resp.Terminal.TerminalID,
			SessionID:     resp.Terminal.SessionID,
			CWD:           resp.Terminal.CWD,
			ReplayHistory: true,
		},
	}
	if resp.FileTransfer != nil {
		info.FileTransfer = &FileTransferTarget{Endpoint: resp.FileTransfer.Endpoint, SourceMachineID: resp.FileTransfer.SourceMachineID, DestinationMachineID: resp.FileTransfer.DestinationMachineID, InitiatingUserID: resp.FileTransfer.InitiatingUserID, Auth: mapAuth(resp.FileTransfer.Auth), Policy: resp.FileTransfer.Policy}
	}
	outcome = "success"
	return info, nil
}

type sessionConnectClient interface {
	ProjectConnectionDescriptorForSession(context.Context, string, string) (api.ConnectionDescriptor, error)
}

type sessionStatusClient interface {
	ProjectConnectionReadinessForSession(context.Context, string, string) (api.ConnectionDescriptor, error)
}

func (r *APIResolver) connect(ctx context.Context, target target, terminalSessionID string) (api.ConnectionDescriptor, error) {
	switch target.kind {
	case targetProject:
		if terminalSessionID == "" {
			return r.client.ProjectConnectionDescriptor(ctx, target.id)
		}
		client, ok := r.client.(sessionConnectClient)
		if !ok {
			return api.ConnectionDescriptor{}, errors.New("this server client does not support selected terminal sessions")
		}
		return client.ProjectConnectionDescriptorForSession(ctx, target.id, terminalSessionID)
	case targetUserMachine:
		client, ok := r.client.(userMachineClient)
		if !ok {
			return api.ConnectionDescriptor{}, errors.New("this server client does not support machines")
		}
		if terminalSessionID != "" {
			sessionClient, ok := r.client.(userMachineSessionClient)
			if !ok {
				return api.ConnectionDescriptor{}, errors.New("this server client does not support selected machine terminal sessions")
			}
			return sessionClient.UserMachineConnectionDescriptorForSession(ctx, target.id, terminalSessionID)
		}
		return client.UserMachineConnectionDescriptor(ctx, target.id)
	default:
		return api.ConnectionDescriptor{}, errors.New("unknown environment target")
	}
}

func (r *APIResolver) connectionStatus(ctx context.Context, target target, terminalSessionID string) (api.ConnectionDescriptor, error) {
	switch target.kind {
	case targetProject:
		if terminalSessionID == "" {
			return r.client.ConnectionReadiness(ctx, target.id)
		}
		client, ok := r.client.(sessionStatusClient)
		if !ok {
			return api.ConnectionDescriptor{}, errors.New("this server client does not support selected terminal sessions")
		}
		return client.ProjectConnectionReadinessForSession(ctx, target.id, terminalSessionID)
	case targetUserMachine:
		client, ok := r.client.(userMachineClient)
		if !ok {
			return api.ConnectionDescriptor{}, errors.New("this server client does not support machines")
		}
		if terminalSessionID != "" {
			sessionClient, ok := r.client.(userMachineSessionClient)
			if !ok {
				return api.ConnectionDescriptor{}, errors.New("this server client does not support selected machine terminal sessions")
			}
			return sessionClient.UserMachineConnectionReadinessForSession(ctx, target.id, terminalSessionID)
		}
		return client.UserMachineConnectionReadiness(ctx, target.id)
	default:
		return api.ConnectionDescriptor{}, errors.New("unknown environment target")
	}
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

func (r *APIResolver) findTarget(ctx context.Context, requested string) (target, error) {
	project, err := r.findProject(ctx, requested)
	if err == nil {
		return target{kind: targetProject, id: project.ID, name: project.Name, state: project.State}, nil
	}
	if !errors.Is(err, ErrProjectNotFound) && !api.IsHostedEntitlementRequired(err) {
		return target{}, err
	}
	projectErr := err
	client, ok := r.client.(userMachineClient)
	if !ok {
		return target{}, projectErr
	}
	machines, listErr := client.ListUserMachines(ctx)
	if listErr != nil {
		// Machines are additive. Older control planes do not expose
		// this catalog yet, so preserve the historical project-not-found result.
		if api.IsNotFound(listErr) {
			return target{}, projectErr
		}
		return target{}, fmt.Errorf("list machines: %w", listErr)
	}
	want := strings.TrimSpace(requested)
	for _, machine := range machines {
		if machine.ID == want {
			if err := terminalCapabilityError(machine); err != nil {
				return target{}, err
			}
			return target{kind: targetUserMachine, id: machine.ID, name: machine.DisplayName, state: machine.State}, nil
		}
	}
	var matches []api.UserMachine
	for _, machine := range machines {
		if strings.EqualFold(machine.DisplayName, want) {
			matches = append(matches, machine)
		}
	}
	if len(matches) == 1 {
		machine := matches[0]
		if err := terminalCapabilityError(machine); err != nil {
			return target{}, err
		}
		return target{kind: targetUserMachine, id: machine.ID, name: machine.DisplayName, state: machine.State}, nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, machine := range matches {
			ids = append(ids, machine.ID)
		}
		return target{}, fmt.Errorf("%w: %q matches machine IDs %s; connect using an exact ID", ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return target{}, projectErr
}

func terminalCapabilityError(machine api.UserMachine) error {
	if !machine.Capabilities.TerminalHost.Configured {
		return &api.APIError{Code: "machine_capability_unavailable", Message: "This machine is not configured to host terminals."}
	}
	if slices.Contains([]string{"revoked", "disconnected", "deleted"}, machine.State) {
		return nil
	}
	if !machine.Online || !machine.Capabilities.TerminalHost.Observed {
		return &api.APIError{Code: "machine_offline", Message: "This terminal host is offline."}
	}
	return nil
}

// waitConnectable polls connection-status until the tunnel is connectable or the
// configured timeout elapses. cli-connect already queued any needed machine
// resume, so this only waits for readiness; it never re-brokers.
func (r *APIResolver) waitConnectable(ctx context.Context, target target, terminalSessionID string, resp api.ConnectionDescriptor) (api.ConnectionDescriptor, error) {
	if err := terminalConnectionError(resp); err != nil {
		return api.ConnectionDescriptor{}, err
	}
	if resp.Connectable {
		return r.validateDescriptor(resp, target)
	}
	deadline := time.Now().Add(r.readyTimeout)
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		if time.Now().After(deadline) {
			return api.ConnectionDescriptor{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
		}
		interval := r.pollInterval
		if resp.RetryAfterSeconds > 0 {
			interval = time.Duration(resp.RetryAfterSeconds) * time.Second
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return api.ConnectionDescriptor{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
		}
		if interval > remaining {
			interval = remaining
		}
		if r.Progress != nil {
			r.Progress(resp.Status, resp.Reason, interval)
		}
		r.record("connect.stage", "waiting", target.id, "", resp.Status, r.now())
		if err := r.wait(pollCtx, interval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return api.ConnectionDescriptor{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
			}
			return api.ConnectionDescriptor{}, err
		}
		next, err := r.connectionStatus(pollCtx, target, terminalSessionID)
		if err != nil {
			return api.ConnectionDescriptor{}, fmt.Errorf("poll connection status: %w", err)
		}
		if next.Connectable {
			// connection-status omits the terminal descriptor's routing detail;
			// re-broker once now that the machine is ready to get a fresh,
			// fully-populated WebSocket descriptor and access session.
			if !completeTerminalDescriptor(next.Terminal) {
				fresh, err := r.connect(pollCtx, target, terminalSessionID)
				if err != nil {
					return api.ConnectionDescriptor{}, err
				}
				if !fresh.Connectable {
					resp = fresh
					continue
				}
				return r.validateDescriptor(fresh, target)
			}
			return r.validateDescriptor(next, target)
		}
		if err := terminalConnectionError(next); err != nil {
			return api.ConnectionDescriptor{}, err
		}
		resp = next
	}
}

func terminalConnectionError(resp api.ConnectionDescriptor) error {
	switch resp.Status {
	case "machine_revoked":
		return &api.APIError{Code: resp.Status, Message: "machine access was revoked"}
	}
	return nil
}

func (r *APIResolver) validateDescriptor(resp api.ConnectionDescriptor, target target) (api.ConnectionDescriptor, error) {
	wantIssuer, err := config.NormalizeIssuer(r.cfg.ServerURL)
	if err != nil {
		return api.ConnectionDescriptor{}, fmt.Errorf("normalize configured issuer: %w", err)
	}
	gotIssuer, err := config.NormalizeIssuer(resp.Issuer)
	if err != nil || gotIssuer != wantIssuer {
		return api.ConnectionDescriptor{}, errors.New("server returned a descriptor for an unexpected issuer")
	}
	if !resp.Connectable {
		return api.ConnectionDescriptor{}, errors.New("server returned a non-connectable descriptor")
	}
	if target.kind == targetProject && resp.ProjectID != "" && resp.ProjectID != target.id {
		return api.ConnectionDescriptor{}, errors.New("server returned a descriptor for the wrong project")
	}
	if target.kind == targetUserMachine && resp.UserMachineID != target.id {
		return api.ConnectionDescriptor{}, errors.New("server returned a descriptor for the wrong machine")
	}
	if resp.ExpiresAt.IsZero() || !time.Now().Before(resp.ExpiresAt) {
		return api.ConnectionDescriptor{}, errors.New("server returned an expired connection descriptor")
	}
	if !completeTerminalDescriptor(resp.Terminal) {
		return api.ConnectionDescriptor{}, errors.New("server returned an incomplete terminal descriptor")
	}
	if resp.Terminal.Protocol != "paperboat.terminal.v1" || resp.Environment == nil || strings.TrimSpace(resp.Environment.EnvironmentID) == "" || !environmentMatchesTarget(resp.Environment, target) {
		return api.ConnectionDescriptor{}, errors.New("server returned an invalid environment descriptor")
	}
	if strings.TrimSpace(resp.Environment.ProjectRoot) == "" || strings.TrimSpace(resp.Terminal.ThreadID) == "" || strings.TrimSpace(resp.Terminal.TerminalID) == "" || strings.TrimSpace(resp.Terminal.CWD) == "" {
		return api.ConnectionDescriptor{}, errors.New("server returned incomplete environment or terminal identity")
	}
	wsURL, err := secureEndpoint(resp.Terminal.Endpoints.WSS, "wss")
	if err != nil {
		return api.ConnectionDescriptor{}, fmt.Errorf("invalid terminal WebSocket endpoint: %w", err)
	}
	quicURL, quicErr := secureEndpoint(resp.Terminal.Endpoints.QUIC, "quic")
	if quicErr != nil || endpointAuthority(quicURL) != endpointAuthority(wsURL) {
		return api.ConnectionDescriptor{}, errors.New("terminal QUIC and WSS hosts do not match")
	}
	if len(r.cfg.Connect.AllowedRouteHosts) > 0 {
		if !allowedHost(resp.Terminal.Endpoints.WSS, r.cfg.Connect.AllowedRouteHosts) || !allowedHost(resp.Terminal.Endpoints.QUIC, r.cfg.Connect.AllowedRouteHosts) {
			return api.ConnectionDescriptor{}, errors.New("terminal descriptor host is not allowed by local policy")
		}
	}
	validTerminalAuth := resp.Terminal.Auth.Method == "websocket_ticket" && resp.Terminal.Auth.Ticket != "" || resp.Terminal.Auth.Method == "bearer" && resp.Terminal.Auth.Token != ""
	if !validTerminalAuth || !exactScopes(resp.Terminal.Auth.Scopes, "terminal:operate") {
		return api.ConnectionDescriptor{}, errors.New("terminal descriptor has invalid scope or auth")
	}
	if resp.Terminal.Auth.ExpiresAt.IsZero() || !time.Now().Before(resp.Terminal.Auth.ExpiresAt) || resp.Terminal.Auth.ExpiresAt.After(resp.ExpiresAt) {
		return api.ConnectionDescriptor{}, errors.New("terminal credential is expired")
	}
	if err := r.validateFileTransfer(resp.FileTransfer, wsURL, resp.ExpiresAt); err != nil {
		return api.ConnectionDescriptor{}, err
	}
	return resp, nil
}

func (r *APIResolver) validateFileTransfer(transfer *api.FileTransfer, terminalURL *url.URL, descriptorExpiry time.Time) error {
	if transfer == nil {
		return errors.New("server returned an incomplete file transfer descriptor")
	}
	u, err := secureEndpoint(transfer.Endpoint, "https")
	if err != nil || endpointAuthority(u) != endpointAuthority(terminalURL) || strings.TrimRight(u.Path, "/") != "/v1/file-transfers" {
		return errors.New("file transfer endpoint is not on the validated terminal route")
	}
	if len(r.cfg.Connect.AllowedRouteHosts) > 0 && !allowedHost(transfer.Endpoint, r.cfg.Connect.AllowedRouteHosts) {
		return errors.New("file transfer descriptor host is not allowed by local policy")
	}
	if transfer.Auth.Method != "bearer" || strings.TrimSpace(transfer.Auth.Token) == "" || !exactScopes(transfer.Auth.Scopes, "file:transfer") {
		return errors.New("file transfer descriptor has invalid scope or auth")
	}
	if transfer.Auth.ExpiresAt.IsZero() || !time.Now().Before(transfer.Auth.ExpiresAt) || transfer.Auth.ExpiresAt.After(descriptorExpiry) {
		return errors.New("file transfer credential is expired")
	}
	p := transfer.Policy
	if p.Revision == "" || p.MaxFileBytes <= 0 || p.MaxFileBytes > 50<<20 || p.MaxBatchFiles < 1 || p.MaxBatchFiles > 10 || p.MaxBatchBytes < p.MaxFileBytes || p.MaxBatchBytes > 500<<20 || p.MaxConcurrentTransfers < 1 || p.MaxConcurrentTransfers > 2 || p.RetentionSeconds != 7*24*60*60 || p.DeliveryTimeoutSeconds != 600 || p.MaxPendingSpoolBytes != 1<<30 {
		return errors.New("file transfer descriptor has invalid policy")
	}
	return nil
}

func environmentMatchesTarget(environment *api.Environment, target target) bool {
	switch target.kind {
	case targetProject:
		return environment.ProjectID == target.id && environment.UserMachineID == ""
	case targetUserMachine:
		return environment.UserMachineID == target.id && environment.ProjectID == ""
	default:
		return false
	}
}

func targetState(target target, resp api.ConnectionDescriptor) string {
	if target.kind == targetUserMachine && strings.TrimSpace(resp.UserMachineState) != "" {
		return resp.UserMachineState
	}
	if target.kind == targetProject && strings.TrimSpace(resp.ProjectState) != "" {
		return resp.ProjectState
	}
	return target.state
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

func statusReason(resp api.ConnectionDescriptor) string {
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
	if term == nil || strings.TrimSpace(term.Protocol) == "" || strings.TrimSpace(term.Endpoints.QUIC) == "" || strings.TrimSpace(term.Endpoints.WSS) == "" {
		return false
	}
	if strings.TrimSpace(term.Auth.Method) == "" {
		return false
	}
	return strings.TrimSpace(term.Auth.Ticket) != "" || strings.TrimSpace(term.Auth.Token) != ""
}
