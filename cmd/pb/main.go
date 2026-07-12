// Command pb (alias: paperboat) is the invisible terminal wrapper for the
// Paperboat platform. `pb <project>` resumes the project VM and attaches its
// terminal, using Paperboat auth and bridging local image pastes into remote
// TUIs. Cross-service calls run behind interfaces so protocol behavior remains
// independently testable.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	sessionauth "github.com/pujan-modha/paperboat-cli/internal/auth"
	"github.com/pujan-modha/paperboat-cli/internal/buildinfo"
	"github.com/pujan-modha/paperboat-cli/internal/catalog"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/paste"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
	"github.com/pujan-modha/paperboat-cli/internal/session"
	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
	"github.com/pujan-modha/paperboat-cli/internal/upload"
	"github.com/urfave/cli/v2"
)

func main() {
	app := newApp()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := app.RunContext(ctx, normalizeArgs(os.Args)); err != nil {
		fmt.Fprintln(os.Stderr, "pb:", err)
		os.Exit(1)
	}
}

// valueFlags are flags that consume the following token as their value. Used by
// normalizeArgs so users can put flags after the project name.
var valueFlags = map[string]bool{
	"--config": true, "--server": true,
}

var subcommands = map[string]bool{
	"connect":    true,
	"projects":   true,
	"agents":     true,
	"sizes":      true,
	"keep-alive": true,
	"config":     true,
	"doctor":     true,
	"auth":       true,
}

var subcommandValueFlags = map[string]bool{
	"--hours": true,
}

// normalizeArgs moves flags ahead of positional arguments. urfave/cli stops
// parsing flags at the first positional, so we reorder to keep the UX flexible.
func normalizeArgs(args []string) []string {
	if len(args) <= 1 {
		return args
	}
	var flags, positionals []string
	rest := make([]string, 0, len(args)-1)
	for i := 1; i < len(args); i++ {
		tok := args[i]
		if valueFlags[tok] && i+1 < len(args) {
			flags = append(flags, tok, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(tok, "--config=") || strings.HasPrefix(tok, "--server=") {
			flags = append(flags, tok)
			continue
		}
		rest = append(rest, tok)
	}
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		switch {
		case subcommands[tok]:
			out := make([]string, 0, len(args))
			out = append(out, args[0])
			out = append(out, flags...)
			out = append(out, tok)
			cmdFlags, cmdPositionals := reorderFlags(rest[i+1:], subcommandValueFlags)
			out = append(out, cmdFlags...)
			out = append(out, cmdPositionals...)
			return out
		case tok == "--":
			positionals = append(positionals, rest[i+1:]...)
			i = len(rest)
		case len(tok) > 1 && tok[0] == '-':
			flags = append(flags, tok)
			// Consume a separate value token for known value flags (unless the
			// value was already attached with =).
			if valueFlags[tok] && i+1 < len(rest) {
				flags = append(flags, rest[i+1])
				i++
			}
		default:
			positionals = append(positionals, tok)
		}
	}
	out := make([]string, 0, len(args))
	out = append(out, args[0])
	out = append(out, flags...)
	out = append(out, positionals...)
	return out
}

func reorderFlags(tokens []string, values map[string]bool) ([]string, []string) {
	var flags, positionals []string
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "--" {
			positionals = append(positionals, tokens[i+1:]...)
			break
		}
		if len(tok) > 1 && tok[0] == '-' {
			flags = append(flags, tok)
			if values[tok] && i+1 < len(tokens) {
				flags = append(flags, tokens[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, tok)
	}
	return flags, positionals
}

func newApp() *cli.App {
	rootFlags := []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to the CLI config file"},
		&cli.StringFlag{Name: "server", Usage: "paperboat-server base URL override"},
	}
	return &cli.App{
		Name:                   "pb",
		Usage:                  "Connect to your Paperboat project VM terminal",
		Version:                buildinfo.Version,
		UseShortOptionHandling: true,
		HideHelpCommand:        true,
		Flags:                  rootFlags,
		ArgsUsage:              "<project>",
		Description:            "Run `pb <project>` to attach your project's remote terminal.",
		Action:                 actionConnect,
		Commands: []*cli.Command{
			connectCommand(),
			projectsCommand(),
			agentsCommand(),
			sizesCommand(),
			keepAliveCommand(),
			authCommand(),
			configCommand(),
			doctorCommand(),
		},
	}
}

func authCommand() *cli.Command {
	return &cli.Command{Name: "auth", Usage: "Manage Paperboat sign-in", Subcommands: []*cli.Command{
		{Name: "login", Usage: "Sign in through the Paperboat dashboard", Action: authLogin},
		{Name: "switch", Usage: "Replace the active account for this server", Action: func(c *cli.Context) error { return authLoginMode(c, true) }},
		{Name: "status", Usage: "Show the active Paperboat account", Action: authStatus},
		{Name: "logout", Usage: "Revoke and remove the active client session", Action: authLogout},
	}}
}

func requireAuthConfig(c *cli.Context) (*config.Config, config.ProfileStore, error) {
	d, err := buildDeps(c)
	if err != nil {
		return nil, config.ProfileStore{}, err
	}
	if strings.TrimSpace(d.cfg.ServerURL) == "" {
		return nil, config.ProfileStore{}, errors.New("Paperboat server is not configured; set server_url or use --server")
	}
	if d.cfg.PapercodeConfigPath != "" {
		return nil, config.ProfileStore{}, errors.New("papercode_config_path is obsolete and cannot be migrated as a Paperboat session; run `pb auth login`")
	}
	s, err := config.ProfileStoreFor(d.cfg)
	if err != nil {
		return nil, config.ProfileStore{}, err
	}
	return d.cfg, s, nil
}

func warnPlaintextCredentialStorage(cfg *config.Config, output io.Writer) {
	if cfg.Auth.AllowFileFallback {
		fmt.Fprintln(output, "WARNING: OS secure credential storage is disabled; Paperboat access and refresh tokens are stored as plaintext in local files restricted to mode 0600")
	}
}

func authLogin(c *cli.Context) error {
	return authLoginMode(c, false)
}

func authLoginMode(c *cli.Context, replace bool) error {
	cfg, store, err := requireAuthConfig(c)
	if err != nil {
		return err
	}
	if err := drainPendingRevocations(c.Context, cfg.ServerURL, store); err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: an earlier session revocation remains pending:", err)
	}
	var previous *config.Profile
	if existingProfile, existingErr := store.Load(cfg.ServerURL); existingErr == nil {
		if !replace {
			return errors.New("already signed in for this Paperboat server; use `pb auth switch` to change accounts")
		}
		previous = &existingProfile
	} else if !errors.Is(existingErr, config.ErrNoCredentials) {
		return existingErr
	}
	host, _ := os.Hostname()
	label := strings.TrimSpace(host)
	if label == "" {
		label = "Paperboat CLI"
	}
	deviceType := "desktop"
	if os.Getenv("SSH_CONNECTION") != "" {
		deviceType = "server"
	}
	if _, ok := os.LookupEnv("container"); ok {
		deviceType = "container"
	}
	grant, err := api.DeviceAuthorize(c.Context, cfg.ServerURL, label, deviceType, runtime.GOOS, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Open %s\nEnter code: %s\n", grant.VerificationURI, grant.UserCode)
	complete := grant.VerificationURIComplete
	if complete == "" {
		complete = grant.VerificationURI
	}
	_ = openBrowser(complete)
	interval := time.Duration(grant.Interval) * time.Second
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.NewTimer(time.Duration(grant.ExpiresIn) * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-c.Context.Done():
			return errors.New("login cancelled")
		case <-deadline.C:
			return errors.New("device authorization expired")
		case <-time.After(interval):
		}
		tokens, pollErr := api.DeviceToken(c.Context, cfg.ServerURL, grant.DeviceCode, nil)
		if pollErr != nil {
			var ae *api.APIError
			if errors.As(pollErr, &ae) {
				switch ae.Code {
				case "authorization_pending":
					continue
				case "slow_down":
					if next, ok := ae.Details["interval"].(float64); ok && next > 0 {
						interval = time.Duration(next) * time.Second
					} else {
						interval += 5 * time.Second
					}
					continue
				case "access_denied":
					return errors.New("login denied")
				case "expired_token":
					return errors.New("device authorization expired")
				}
			}
			return pollErr
		}
		expires := time.Now().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		cred := config.Credential{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, TokenType: tokens.TokenType, ExpiresAt: expires}
		me, err := api.New(cfg.ServerURL, cred, nil).Me(c.Context)
		if err != nil {
			return errors.Join(fmt.Errorf("validate new session: %w", err), cleanupIssuedSession(cfg.ServerURL, tokens.ClientSessionID, tokens.RefreshToken, store))
		}
		p := config.Profile{Issuer: cfg.ServerURL, ClientSessionID: tokens.ClientSessionID, AccessExpiresAt: expires, Account: config.Account{ID: me.ID, Email: me.Email, DisplayName: me.DisplayName}}
		var saveErr error
		if previous != nil {
			saveErr = store.Switch(previous.ClientSessionID, p, cred)
		} else {
			saveErr = store.Save(p, cred)
		}
		if saveErr != nil {
			return errors.Join(saveErr, cleanupIssuedSession(cfg.ServerURL, tokens.ClientSessionID, tokens.RefreshToken, store))
		}
		if previous != nil {
			if err := drainPendingRevocations(context.Background(), cfg.ServerURL, store); err != nil {
				fmt.Fprintln(os.Stderr, "WARNING: account switched; previous session revocation remains pending:", err)
			}
		}
		fmt.Fprintf(os.Stdout, "Signed in as %s\n", firstNonEmpty(me.Email, me.DisplayName, me.ID))
		return nil
	}
}

func cleanupIssuedSession(issuer, clientSessionID, refreshToken string, store config.ProfileStore) error {
	if err := store.QueueRevocation(issuer, clientSessionID, refreshToken); err != nil {
		if revokeErr := api.RevokeToken(context.Background(), issuer, refreshToken, nil); revokeErr != nil {
			return errors.Join(fmt.Errorf("retain failed session for revocation: %w", err), fmt.Errorf("revoke unretained session: %w", revokeErr))
		}
		return nil
	}
	_ = drainPendingRevocations(context.Background(), issuer, store)
	return nil
}

func authStatus(c *cli.Context) error {
	cfg, store, err := requireAuthConfig(c)
	if err != nil {
		return err
	}
	p, err := store.Load(cfg.ServerURL)
	if errors.Is(err, config.ErrNoCredentials) {
		fmt.Println("Not signed in")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("Signed in as %s\nServer: %s\nSession: %s\nAccess expires: %s\n", firstNonEmpty(p.Account.Email, p.Account.DisplayName, p.Account.ID), p.Issuer, p.ClientSessionID, p.AccessExpiresAt.Format(time.RFC3339))
	return nil
}

func authLogout(c *cli.Context) error {
	cfg, store, err := requireAuthConfig(c)
	if err != nil {
		return err
	}
	if err := store.QueueActiveRevocation(cfg.ServerURL); err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if err := drainPendingRevocations(c.Context, cfg.ServerURL, store); err != nil {
		return fmt.Errorf("sign-out revocation remains pending; retry `pb auth logout`: %w", err)
	}
	fmt.Println("Signed out")
	return nil
}

func drainPendingRevocations(ctx context.Context, issuer string, store config.ProfileStore) error {
	records, err := store.PendingRevocations(issuer)
	if err != nil {
		return err
	}
	var errs []error
	for _, record := range records {
		if record.Cancelled {
			if err := store.CompleteRevocation(record); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if record.ServerRevoked {
			if err := store.CompleteRevocation(record); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		cred, err := store.PendingRevocationCredential(record)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := api.RevokeToken(ctx, issuer, cred.RefreshToken, nil); err != nil {
			errs = append(errs, fmt.Errorf("revoke client session %s: %w", record.ClientSessionID, err))
			continue
		}
		record, err = store.MarkRevocationSucceeded(record)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := store.CompleteRevocation(record); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

func keepAliveCommand() *cli.Command {
	return &cli.Command{
		Name:      "keep-alive",
		Usage:     "Keep a project VM running temporarily",
		ArgsUsage: "<project>",
		Flags: []cli.Flag{
			&cli.Float64Flag{Name: "hours", Usage: "hours to keep the project running"},
			&cli.BoolFlag{Name: "clear", Usage: "clear the current keep-alive pin"},
		},
		Action: func(c *cli.Context) error {
			project := c.Args().First()
			if project == "" {
				return errors.New("missing project name; usage: pb keep-alive <project> --hours <n>")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			clear := c.Bool("clear")
			hours := c.Float64("hours")
			if !clear && hours <= 0 {
				return errors.New("set --hours to a positive value, or use --clear")
			}
			if clear && hours > 0 {
				return errors.New("use either --hours or --clear, not both")
			}
			resolved, err := resolveProjectID(c.Context, client, project)
			if err != nil {
				return err
			}
			seconds := int(math.Ceil((time.Duration(hours * float64(time.Hour))).Seconds()))
			resp, err := client.SetKeepAlive(c.Context, resolved.ID, seconds, clear)
			if err != nil {
				if msg := friendlyAPIError(err); msg != "" {
					return errors.New(msg)
				}
				return err
			}
			if clear {
				fmt.Fprintf(os.Stdout, "Keep-alive cleared for %s\n", firstNonEmpty(resp.Project.Name, resolved.Name, resolved.ID))
				return nil
			}
			fmt.Fprintf(os.Stdout, "Keeping %s running until %s\n", firstNonEmpty(resp.Project.Name, resolved.Name, resolved.ID), resp.KeepAliveUntil.Local().Format(time.RFC1123))
			return nil
		},
	}
}

func backendClient(c *cli.Context) (*api.Client, error) {
	d, err := buildDeps(c)
	if err != nil {
		return nil, err
	}
	if d.cfg.ServerURL == "" {
		return nil, errors.New("server_url is not configured; set --server or configure Paperboat server_url")
	}
	cred, err := d.auth.Credential()
	if errors.Is(err, config.ErrNoCredentials) {
		return nil, errors.New("not signed in to Paperboat; run `pb auth login`, then retry")
	}
	if err != nil {
		return nil, err
	}
	return api.New(d.cfg.ServerURL, cred, nil), nil
}

func resolveProjectID(ctx context.Context, client *api.Client, requested string) (api.Project, error) {
	projects, err := client.ListProjects(ctx)
	if err != nil {
		if errors.Is(err, api.ErrUnauthenticated) {
			return api.Project{}, errors.New("your Paperboat session was rejected; run `pb auth login`, then retry")
		}
		if msg := friendlyAPIError(err); msg != "" {
			return api.Project{}, errors.New(msg)
		}
		return api.Project{}, err
	}
	for _, p := range projects {
		if p.ID == requested {
			return p, nil
		}
	}
	var matches []api.Project
	for _, p := range projects {
		if strings.EqualFold(p.Name, requested) {
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
		return api.Project{}, fmt.Errorf("%w: %q matches project IDs %s; use an exact ID", resolver.ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return api.Project{}, fmt.Errorf("%w: %q", resolver.ErrProjectNotFound, requested)
}

// deps bundles production dependencies for a command.
type deps struct {
	cfg      *config.Config
	auth     config.AuthSource
	catalog  catalog.Catalog
	resolver resolver.ProjectResolver
	tunnel   tunnel.Tunnel
	uploader upload.Uploader
}

func buildDeps(c *cli.Context) (*deps, error) {
	cfg, err := config.Load(c.String("config"))
	if err != nil {
		return nil, err
	}
	if s := c.String("server"); s != "" {
		cfg.ServerURL = s
	}
	var termTunnel tunnel.Tunnel = tunnel.NewPapercodeWSTunnel()
	var uploader upload.Uploader = upload.NewDisabledUploader()
	var authSource config.AuthSource = config.NoCredentialsSource{}
	if cfg.ServerURL != "" {
		warnPlaintextCredentialStorage(cfg, os.Stderr)
		authSource, err = sessionauth.NewSource(cfg)
		if err != nil {
			return nil, err
		}
	}
	return &deps{
		cfg:      cfg,
		auth:     authSource,
		catalog:  catalog.NewStubCatalog(),
		resolver: nil,
		tunnel:   termTunnel,
		uploader: uploader,
	}, nil
}

func connectCommand() *cli.Command {
	return &cli.Command{
		Name:      "connect",
		Usage:     "Attach to a project VM terminal (default action)",
		ArgsUsage: "<project>",
		Action:    actionConnect,
	}
}

func projectsCommand() *cli.Command {
	return &cli.Command{
		Name:  "projects",
		Usage: "List projects available to this account",
		Action: func(c *cli.Context) error {
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			projects, err := client.ListProjects(c.Context)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tID\tSTATE")
			for _, project := range projects {
				fmt.Fprintf(w, "%s\t%s\t%s\n", project.Name, project.ID, project.State)
			}
			return w.Flush()
		},
	}
}

func actionConnect(c *cli.Context) error {
	project := c.Args().First()
	if project == "" {
		return errors.New("missing project name; usage: pb <project>")
	}

	d, err := buildDeps(c)
	if err != nil {
		return err
	}
	ctx := c.Context
	if strings.TrimSpace(d.cfg.ServerURL) == "" {
		return errors.New("Paperboat server is not configured; set server_url or use --server")
	}

	cred, err := d.auth.Credential()
	if err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if errors.Is(err, config.ErrNoCredentials) {
		return errors.New("not signed in to Paperboat; run `pb auth login`, then retry")
	}
	d.resolver = resolver.NewAPIResolver(api.New(d.cfg.ServerURL, cred, nil), d.cfg)
	if apiResolver, ok := d.resolver.(*resolver.APIResolver); ok {
		apiResolver.Progress = func(status, reason string, retryAfter time.Duration) {
			fmt.Fprintf(os.Stderr, "Connecting: %s (%s), retrying in %s...\n", status, reason, retryAfter.Round(time.Second))
		}
	}

	var info resolver.ConnectInfo
	var conn tunnel.Conn
	configureUploadRefresh := func(u upload.Uploader, r resolver.ProjectResolver) {
		httpUploader, ok := u.(*upload.HTTPUploader)
		if !ok {
			return
		}
		httpUploader.RefreshAuth = func(refreshCtx context.Context) (upload.Auth, error) {
			freshCred, credErr := d.auth.Credential()
			if credErr != nil {
				return upload.Auth{}, credErr
			}
			freshInfo, resolveErr := r.Resolve(refreshCtx, resolver.ConnectRequest{Project: project, Credential: freshCred})
			if resolveErr != nil {
				return upload.Auth{}, fmt.Errorf("refresh upload descriptor: %w", resolveErr)
			}
			if freshInfo.Upload == nil {
				return upload.Auth{}, errors.New("refresh upload descriptor: upload target missing")
			}
			return upload.Auth{Method: freshInfo.Upload.Auth.Method, Token: freshInfo.Upload.Auth.Token, Ticket: freshInfo.Upload.Auth.Ticket}, nil
		}
	}
	for attempt := 0; attempt <= d.cfg.Connect.DialRetries; attempt++ {
		info, err = d.resolver.Resolve(ctx, resolver.ConnectRequest{Project: project, Credential: cred})
		if err == nil {
			d.uploader = uploaderForTarget(info.Upload)
			configureUploadRefresh(d.uploader, d.resolver)
			conn, err = d.tunnel.Dial(ctx, info)
		}
		if err == nil {
			break
		}
		if errors.Is(err, api.ErrUnauthenticated) {
			return errors.New("your Paperboat session was rejected; run `pb auth login`, then retry")
		}
		if attempt == d.cfg.Connect.DialRetries || !retryableInitialConnectError(err) {
			break
		}
		fmt.Fprintf(os.Stderr, "Connection attempt %d failed; refreshing the descriptor in %ds...\n", attempt+1, d.cfg.Connect.DialRetrySeconds)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(d.cfg.Connect.DialRetrySeconds) * time.Second):
		}
	}
	if err != nil {
		if msg := friendlyAPIError(err); msg != "" {
			return errors.New(msg)
		}
		return fmt.Errorf("connect to %q: %w", project, err)
	}
	var pastePolicy *paste.Policy
	conn = tunnel.NewReconnectingConn(ctx, conn, d.cfg.Connect.DialRetries, time.Duration(d.cfg.Connect.DialRetrySeconds)*time.Second, func(reconnectCtx context.Context) (tunnel.Conn, error) {
		freshCred, credErr := d.auth.Credential()
		if credErr != nil {
			return nil, credErr
		}
		freshResolver := resolver.NewAPIResolver(api.New(d.cfg.ServerURL, freshCred, nil), d.cfg)
		freshInfo, resolveErr := freshResolver.Resolve(reconnectCtx, resolver.ConnectRequest{Project: info.ProjectID, Credential: freshCred})
		if resolveErr != nil {
			return nil, resolveErr
		}
		freshConn, dialErr := d.tunnel.Dial(reconnectCtx, freshInfo)
		if dialErr != nil {
			return nil, dialErr
		}
		if pastePolicy != nil {
			freshUploader := uploaderForTarget(freshInfo.Upload)
			configureUploadRefresh(freshUploader, freshResolver)
			pastePolicy.Update(freshUploader, uploadLimits(d.cfg, freshInfo.Upload))
		}
		return freshConn, nil
	})

	// Wrap remote input with the image-paste interceptor.
	pastePolicy = paste.NewPolicy(d.uploader, uploadLimits(d.cfg, info.Upload))
	interceptor := paste.NewWithPolicy(conn, pastePolicy,
		paste.WithNotifier(os.Stderr),
		paste.WithWatchDirs(expandDirs(d.cfg.Upload.WatchDirs)),
		paste.WithTempFilePatterns(d.cfg.Upload.TempFilePatterns),
		paste.WithMaxQueuedBytes(d.cfg.Upload.MaxQueuedInputBytes),
	)

	code, err := session.RunWithActivity(ctx, conn, interceptor, func(source string) {
		activityCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		activityErr := reportActivity(activityCtx, d.cfg.ServerURL, d.auth, info.ProjectID, source)
		if activityErr != nil {
			fmt.Fprintf(os.Stderr, "warning: activity report failed: %v\n", activityErr)
		}
	})
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func retryableInitialConnectError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "machine_not_ready" || apiErr.Code == "tunnel_unavailable"
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timed out waiting for the machine") ||
		strings.Contains(msg, "dial papercode websocket") ||
		strings.Contains(msg, "websocket route") ||
		strings.Contains(msg, "transport lost")
}

type refreshableAuthSource interface {
	config.AuthSource
	Refresh() (config.Credential, error)
}

func reportActivity(ctx context.Context, serverURL string, source config.AuthSource, projectID, event string) error {
	cred, err := source.Credential()
	if err != nil {
		return err
	}
	err = api.New(serverURL, cred, nil).Activity(ctx, projectID, event)
	if !errors.Is(err, api.ErrUnauthenticated) {
		return err
	}
	refreshable, ok := source.(refreshableAuthSource)
	if !ok {
		return err
	}
	cred, refreshErr := refreshable.Refresh()
	if refreshErr != nil {
		return errors.Join(err, refreshErr)
	}
	return api.New(serverURL, cred, nil).Activity(ctx, projectID, event)
}

func friendlyAPIError(err error) string {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	switch apiErr.Code {
	case "credits_exhausted":
		return "credits are exhausted; top up credits in Paperboat, then retry"
	case "entitlement_lost", "payment_required":
		return "your Paperboat plan is inactive; restore billing access, then retry"
	case "idle_timeout":
		return "the project stopped after reaching its idle timeout; retry to resume it"
	case "activity_reporter_lost":
		return "the project stopped because activity reporting was lost; retry after the VM restarts"
	case "tunnel_unavailable":
		return "the secure tunnel is not available yet; retry in a moment"
	case "machine_not_ready":
		return "the project machine is not ready yet; retry in a moment"
	}
	return ""
}

func uploaderForTarget(target *resolver.UploadTarget) upload.Uploader {
	if target == nil || target.HTTPBaseURL == "" {
		return upload.NewDisabledUploader()
	}
	return upload.NewHTTPUploader(target.HTTPBaseURL, target.Path, upload.Auth{
		Method: target.Auth.Method,
		Token:  target.Auth.Token,
		Ticket: target.Auth.Ticket,
	})
}

func uploadLimits(cfg *config.Config, target *resolver.UploadTarget) upload.Limits {
	limits := upload.Limits{
		MaxImageBytes:       cfg.Upload.MaxImageBytes,
		MaxDataURLChars:     cfg.Upload.MaxDataURLChars,
		MaxAttachments:      cfg.Upload.MaxAttachments,
		AllowedMimePrefixes: cfg.Upload.AllowedMimePrefixes,
	}
	if target != nil {
		if target.MaxBytes > 0 {
			limits.MaxImageBytes = target.MaxBytes
		}
		if len(target.AllowedMIMETypes) > 0 {
			limits.AllowedMimePrefixes = nil
			limits.AllowedMIMETypes = append([]string(nil), target.AllowedMIMETypes...)
		}
	}
	return limits
}

func expandDirs(dirs []string) []string {
	if len(dirs) == 0 {
		return nil
	}
	home, _ := os.UserHomeDir()
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if home != "" && len(d) >= 1 && d[0] == '~' {
			d = home + d[1:]
		}
		out = append(out, d)
	}
	return out
}

func agentsCommand() *cli.Command {
	return &cli.Command{
		Name:  "agents",
		Usage: "List available agent presets",
		Action: func(c *cli.Context) error {
			d, err := buildDeps(c)
			if err != nil {
				return err
			}
			agents, err := d.catalog.Agents(c.Context)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tDEFAULT")
			for _, a := range agents {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", a.ID, a.DisplayName, mark(a.Default))
			}
			return tw.Flush()
		},
	}
}

func sizesCommand() *cli.Command {
	return &cli.Command{
		Name:  "sizes",
		Usage: "List available machine shapes",
		Action: func(c *cli.Context) error {
			d, err := buildDeps(c)
			if err != nil {
				return err
			}
			sizes, err := d.catalog.Sizes(c.Context)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tvCPU\tMEM(MB)\tWEIGHT\tDEFAULT")
			for _, s := range sizes {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%.1f\t%s\n", s.ID, s.VCPUs, s.MemoryMB, s.Weight, mark(s.Default))
			}
			return tw.Flush()
		},
	}
}

func configCommand() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Inspect the local CLI config",
		Subcommands: []*cli.Command{
			{
				Name:  "path",
				Usage: "Print the config file path",
				Action: func(c *cli.Context) error {
					d, err := buildDeps(c)
					if err != nil {
						return err
					}
					fmt.Println(d.cfg.Path())
					return nil
				},
			},
			{
				Name:  "show",
				Usage: "Print the effective config",
				Action: func(c *cli.Context) error {
					d, err := buildDeps(c)
					if err != nil {
						return err
					}
					fmt.Printf("server_url: %s\n", orNone(d.cfg.ServerURL))
					fmt.Printf("auth.file_fallback: %t\n", d.cfg.Auth.AllowFileFallback)
					fmt.Printf("upload.endpoint: %s\n", orNone(d.cfg.Upload.Endpoint))
					fmt.Printf("upload.max_image_bytes: %d\n", d.cfg.Upload.MaxImageBytes)
					fmt.Printf("upload.max_attachments: %d\n", d.cfg.Upload.MaxAttachments)
					return nil
				},
			},
		},
	}
}

func doctorCommand() *cli.Command {
	return &cli.Command{
		Name:      "doctor",
		Usage:     "Check authentication and connectivity",
		ArgsUsage: "[project]",
		Action: func(c *cli.Context) error {
			d, err := buildDeps(c)
			if err != nil {
				return err
			}
			project := c.Args().First()
			fmt.Printf("config:      %s\n", d.cfg.Path())
			fmt.Printf("server:      %s\n", orLocal(d.cfg.ServerURL))
			cred, credErr := d.auth.Credential()
			if credErr != nil {
				if errors.Is(credErr, config.ErrNoCredentials) {
					fmt.Println("auth:        not signed in (run `pb auth login`)")
				} else {
					fmt.Printf("auth:        error: %v\n", credErr)
				}
			} else {
				fmt.Println("auth:        Paperboat credentials found ✓")
			}

			if d.cfg.ServerURL == "" {
				fmt.Println("backend:     unavailable (set server_url or use --server)")
				return errors.New("doctor: Paperboat server is not configured")
			}
			if credErr != nil {
				fmt.Println("backend:     skipped (no credentials to authenticate)")
				return errors.New("doctor: Paperboat credentials are unavailable")
			}
			me, err := api.New(d.cfg.ServerURL, cred, nil).Me(c.Context)
			if errors.Is(err, api.ErrUnauthenticated) {
				fmt.Println("backend:     credential rejected; run `pb auth login`")
				return errors.New("doctor: Paperboat credentials were rejected")
			}
			if err != nil {
				fmt.Printf("backend:     unreachable: %v\n", err)
				return fmt.Errorf("doctor: backend check failed: %w", err)
			}
			fmt.Printf("backend:     authenticated as %s ✓\n", firstNonEmpty(me.Email, me.DisplayName, me.ID))
			if project == "" {
				fmt.Println("entitlement: not checked (provide a project to verify connect access)")
				return nil
			}
			info, err := resolver.NewAPIResolver(api.New(d.cfg.ServerURL, cred, nil), d.cfg).Resolve(c.Context, resolver.ConnectRequest{
				Project:    project,
				Credential: cred,
			})
			if err != nil {
				fmt.Printf("papercode:   descriptor unavailable: %v\n", err)
				return fmt.Errorf("doctor: descriptor check failed: %w", err)
			}
			if info.Terminal == nil {
				fmt.Println("papercode:   descriptor missing terminal endpoint")
				return errors.New("doctor: descriptor missing terminal endpoint")
			}
			fmt.Printf("project:      %s (%s) ✓\n", info.ProjectID, firstNonEmpty(info.ProjectState, "ready"))
			fmt.Println("entitlement:  connect authorization accepted ✓")
			fmt.Println("fly readiness: ready ✓")
			fmt.Println("agentunnel:   route descriptor ready ✓")
			if err := tunnel.NewPapercodeWSTunnel().Check(c.Context, info.Terminal); err != nil {
				fmt.Printf("papercode:   websocket unavailable: %v\n", err)
				return fmt.Errorf("doctor: papercode protocol check failed: %w", err)
			}
			fmt.Printf("papercode:   websocket route/auth ready for %s ✓\n", info.Project)
			fmt.Println("protocol:    paperboat-terminal-rpc/v1 ✓")
			return nil
		},
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mark(b bool) string {
	if b {
		return "✓"
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

func orLocal(s string) string {
	if s == "" {
		return "(local dev stub)"
	}
	return s
}
