package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
)

// ErrProjectNotFound means no project matched the requested name or id for this
// user. Surfaced distinctly so the CLI can guide the user to `pb` project list
// / the dashboard rather than a generic failure.
var ErrProjectNotFound = errors.New("project not found")

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
	sleep func(ctx context.Context, d time.Duration) error
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
	project, err := r.findProject(ctx, req.Project)
	if err != nil {
		return ConnectInfo{}, err
	}

	resp, err := r.client.CLIConnect(ctx, project.ID)
	if err != nil {
		return ConnectInfo{}, fmt.Errorf("connect to project %q: %w", req.Project, err)
	}

	resp, err = r.waitConnectable(ctx, project.ID, resp)
	if err != nil {
		return ConnectInfo{}, err
	}

	if !completeTerminalDescriptor(resp.Terminal) {
		return ConnectInfo{}, fmt.Errorf("connect to project %q: server did not return a terminal endpoint", req.Project)
	}

	info := ConnectInfo{
		Project:      project.Name,
		TunnelTarget: resp.Terminal.WebSocketBaseURL,
		Agent:        firstNonEmpty(req.Agent, r.cfg.DefaultAgent),
		Size:         firstNonEmpty(req.Size, r.cfg.DefaultSize),
		Local:        false,
		Terminal: &TerminalTarget{
			HTTPBaseURL:      resp.Terminal.HTTPBaseURL,
			WebSocketBaseURL: resp.Terminal.WebSocketBaseURL,
			Auth:             mapAuth(resp.Terminal.Auth),
			ThreadID:         resp.Terminal.ThreadID,
			TerminalID:       resp.Terminal.TerminalID,
			CWD:              resp.Terminal.CWD,
		},
	}
	if resp.Upload != nil && strings.TrimSpace(resp.Upload.HTTPBaseURL) != "" {
		info.Upload = &UploadTarget{
			HTTPBaseURL:      resp.Upload.HTTPBaseURL,
			Auth:             mapAuth(resp.Upload.Auth),
			MaxBytes:         resp.Upload.MaxBytes,
			AllowedMIMETypes: resp.Upload.AllowedMIMETypes,
		}
	}
	return info, nil
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
	for _, p := range projects {
		if strings.EqualFold(p.Name, want) {
			return p, nil
		}
	}
	return api.Project{}, fmt.Errorf("%w: %q", ErrProjectNotFound, requested)
}

// waitConnectable polls connection-status until the tunnel is connectable or the
// configured timeout elapses. cli-connect already queued any needed machine
// resume, so this only waits for readiness; it never re-brokers.
func (r *APIResolver) waitConnectable(ctx context.Context, projectID string, resp api.ConnectResponse) (api.ConnectResponse, error) {
	if resp.Connectable {
		return resp, nil
	}
	deadline := time.Now().Add(r.readyTimeout)
	for {
		if time.Now().After(deadline) {
			return api.ConnectResponse{}, fmt.Errorf("timed out waiting for the machine to become ready (last status: %s)", statusReason(resp))
		}
		if err := r.wait(ctx, r.pollInterval); err != nil {
			return api.ConnectResponse{}, err
		}
		next, err := r.client.ConnectionStatus(ctx, projectID)
		if err != nil {
			return api.ConnectResponse{}, fmt.Errorf("poll connection status: %w", err)
		}
		if next.Connectable {
			// connection-status omits the terminal descriptor's routing detail;
			// re-broker once now that the machine is ready to get a fresh,
			// fully-populated WebSocket descriptor and access session.
			if !completeTerminalDescriptor(next.Terminal) {
				return r.client.CLIConnect(ctx, projectID)
			}
			return next, nil
		}
		resp = next
	}
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
