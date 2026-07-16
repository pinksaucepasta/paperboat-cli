// Command pb (alias: paperboat) is the invisible terminal wrapper for the
// Paperboat platform. `pb <environment>` attaches a hosted project or enrolled
// connected machine through Paperboat auth and bridges local image pastes into
// remote TUIs. Cross-service calls run behind interfaces so protocol behavior
// remains independently testable.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	sessionauth "github.com/pujan-modha/paperboat-cli/internal/auth"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	cli "github.com/pujan-modha/paperboat-cli/internal/legacycli"
	"github.com/pujan-modha/paperboat-cli/internal/paste"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
	"github.com/pujan-modha/paperboat-cli/internal/session"
	"github.com/pujan-modha/paperboat-cli/internal/statusbar"
	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
	"github.com/pujan-modha/paperboat-cli/internal/upload"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

var errUsage = errors.New("command usage error")

type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return "" }
func (e exitCodeError) ExitCode() int { return e.code }

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return errUsage }

func invocationError(err error) error {
	if err == nil {
		return nil
	}
	return usageError{err: err}
}

func commandArgs(args cobra.PositionalArgs) cobra.PositionalArgs {
	return func(command *cobra.Command, values []string) error {
		return invocationError(args(command, values))
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := newRootCommand()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if errors.Is(err, errUsage) || isCobraUsageError(err) {
		fmt.Fprintln(stderr, "pb:", err)
		root.SetOut(stderr)
		_ = root.Usage()
		return 2
	}
	if exitErr, ok := err.(interface{ ExitCode() int }); ok {
		return exitErr.ExitCode()
	}
	if err.Error() != "" {
		fmt.Fprintln(stderr, "pb:", err)
	}
	return 1
}

func isCobraUsageError(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "unknown command ") ||
		strings.HasPrefix(message, "unknown flag: ") ||
		strings.Contains(message, " accepts ") ||
		strings.Contains(message, " requires at least ") ||
		strings.Contains(message, " requires at most ")
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "pb [environment]",
		Short: "Connect to a Paperboat environment terminal",
		Args:  commandArgs(cobra.MaximumNArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			if err := validateConnectInvocation(command); err != nil {
				return err
			}
			server, _ := command.Flags().GetString("server")
			if len(args) == 0 && strings.TrimSpace(server) == "" {
				return command.Help()
			}
			return actionConnect(legacyContext(command, args))
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invocationError(err) })
	root.PersistentFlags().String("config", "", "path to the CLI config file")
	root.PersistentFlags().String("server", "", "paperboat-server base URL override")
	addConnectFlags(root)

	connect := &cobra.Command{Use: "connect <environment>", Short: "Attach to an environment terminal", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		if err := validateConnectInvocation(command); err != nil {
			return err
		}
		return actionConnect(legacyContext(command, args))
	}}
	addConnectFlags(connect)
	root.AddCommand(connect)

	projects := &cobra.Command{Use: "projects", Short: "List projects available to this account", Args: commandArgs(cobra.NoArgs), RunE: legacyRun(projectsCommand().Action)}
	projects.Flags().Bool("json", false, "print JSON")
	root.AddCommand(projects)

	environments := &cobra.Command{Use: "environments", Short: "List hosted projects and connected machines", Args: commandArgs(cobra.NoArgs), RunE: legacyRun(environmentsCommand().Action)}
	environments.Flags().Bool("json", false, "print JSON")
	root.AddCommand(environments)

	keepAlive := &cobra.Command{Use: "keep-alive <project>", Args: commandArgs(cobra.ExactArgs(1)), RunE: legacyRun(keepAliveCommand().Action)}
	keepAlive.Flags().Float64("hours", 0, "duration in hours")
	keepAlive.Flags().Bool("clear", false, "clear keep-alive")
	root.AddCommand(keepAlive)

	doctor := &cobra.Command{Use: "doctor [project]", Short: "Check authentication and connectivity", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: legacyRun(doctorCommand().Action)}
	doctor.Flags().Bool("json", false, "print JSON")
	root.AddCommand(doctor)

	root.AddCommand(legacyTree(authCommand(), "auth"))
	root.AddCommand(legacyTree(configCommand(), "config"))
	root.AddCommand(sessionsCobraCommand())
	return root
}

func addConnectFlags(command *cobra.Command) {
	command.Flags().Bool("new", false, "create a new terminal session")
	command.Flags().String("name", "", "name for a new terminal session")
	command.Flags().String("session", "", "attach an existing terminal session by name or ID")
}

func validateConnectInvocation(command *cobra.Command) error {
	newSession, _ := command.Flags().GetBool("new")
	name, _ := command.Flags().GetString("name")
	ref, _ := command.Flags().GetString("session")
	if newSession && strings.TrimSpace(ref) != "" {
		return invocationError(errors.New("--new and --session cannot be used together"))
	}
	if !newSession && strings.TrimSpace(name) != "" {
		return invocationError(errors.New("--name requires --new"))
	}
	server, _ := command.Flags().GetString("server")
	if strings.TrimSpace(server) != "" {
		if _, err := config.NormalizeServerURL(server); err != nil {
			return invocationError(err)
		}
	}
	return nil
}

func legacyTree(source *cli.Command, use string) *cobra.Command {
	command := &cobra.Command{Use: use, Short: source.Usage, Args: commandArgs(cobra.NoArgs)}
	if source.Action != nil {
		command.RunE = legacyRun(source.Action)
	} else {
		command.RunE = func(command *cobra.Command, _ []string) error { return command.Help() }
	}
	for _, child := range source.Subcommands {
		child := child
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(legacyCommandArgs(use, child.Name)), RunE: legacyRun(child.Action)}
		if (use == "auth" && child.Name == "status") || (use == "config" && child.Name == "show") {
			entry.Flags().Bool("json", false, "print JSON")
		}
		command.AddCommand(entry)
	}
	return command
}

func legacyCommandArgs(parent, name string) cobra.PositionalArgs {
	if parent == "config" {
		switch name {
		case "set":
			return cobra.ExactArgs(2)
		case "unset":
			return cobra.ExactArgs(1)
		}
	}
	return cobra.NoArgs
}

func sessionsCobraCommand() *cobra.Command {
	source := sessionsCommand()
	command := &cobra.Command{Use: "sessions <environment>", Args: commandArgs(cobra.ExactArgs(1)), RunE: legacyRun(source.Action)}
	command.Flags().Bool("wide", false, "include immutable IDs")
	command.Flags().Bool("json", false, "print JSON")
	for _, child := range source.Subcommands {
		child := child
		var args cobra.PositionalArgs
		switch child.Name {
		case "rename":
			args = cobra.ExactArgs(3)
		case "close", "delete":
			args = cobra.ExactArgs(2)
		}
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(args), RunE: legacyRun(child.Action)}
		if child.Name == "delete" {
			entry.Flags().Bool("yes", false, "confirm deletion")
		}
		command.AddCommand(entry)
	}
	return command
}

func legacyRun(action cli.ActionFunc) func(*cobra.Command, []string) error {
	return func(command *cobra.Command, args []string) error { return action(legacyContext(command, args)) }
}

func legacyContext(command *cobra.Command, args []string) *cli.Context {
	set := flag.NewFlagSet("pb", flag.ContinueOnError)
	values := map[string]string{}
	for _, name := range []string{"config", "server", "name", "session"} {
		value, _ := command.Flags().GetString(name)
		values[name] = value
		set.String(name, value, "")
	}
	hours, _ := command.Flags().GetFloat64("hours")
	set.Float64("hours", hours, "")
	for _, name := range []string{"new", "json", "wide", "yes", "clear"} {
		value, _ := command.Flags().GetBool(name)
		values[name] = strconv.FormatBool(value)
		set.Bool(name, value, "")
	}
	_ = set.Parse(args)
	context := cli.NewContext(newApp(), set, nil)
	context.Context = command.Context()
	return context
}

func newApp() *cli.App {
	rootFlags := []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to the CLI config file"},
		&cli.StringFlag{Name: "server", Usage: "paperboat-server base URL override"},
		&cli.BoolFlag{Name: "new", Usage: "create a new terminal session"},
		&cli.StringFlag{Name: "name", Usage: "name for a new terminal session"},
		&cli.StringFlag{Name: "session", Usage: "attach an existing terminal session by name or ID"},
	}
	_ = rootFlags
	app := &cli.App{}
	app.RunFunc = func(args []string) error {
		root := newRootCommand()
		if app.Writer != nil {
			root.SetOut(app.Writer)
		}
		if app.ErrWriter != nil {
			root.SetErr(app.ErrWriter)
		}
		if len(args) > 0 {
			args = args[1:]
		}
		root.SetArgs(args)
		return root.ExecuteContext(context.Background())
	}
	return app
}

func authCommand() *cli.Command {
	return &cli.Command{Name: "auth", Usage: "Manage Paperboat sign-in", Subcommands: []*cli.Command{
		{Name: "login", Usage: "Sign in through the Paperboat dashboard", Action: authLogin},
		{Name: "switch", Usage: "Replace the active account for this server", Action: func(c *cli.Context) error { return authLoginMode(c, true) }},
		{Name: "status", Usage: "Show the active Paperboat account", Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}}, Action: authStatus},
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
		if c.Bool("json") {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"signed_in": false})
		}
		fmt.Println("Not signed in")
		return nil
	}
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"signed_in": true, "issuer": p.Issuer, "client_session_id": p.ClientSessionID, "access_expires_at": p.AccessExpiresAt, "account": p.Account})
	}
	fmt.Printf("Signed in as %s\nServer: %s\nSession: %s\nAccess expires: %s\n", firstNonEmpty(p.Account.Email, p.Account.DisplayName, p.Account.ID), p.Issuer, p.ClientSessionID, p.AccessExpiresAt.Format(time.RFC3339))
	return nil
}

func authLogout(c *cli.Context) error {
	cfg, store, err := requireAuthConfig(c)
	if err != nil {
		return err
	}
	active, loadErr := store.Load(cfg.ServerURL)
	if loadErr != nil && !errors.Is(loadErr, config.ErrNoCredentials) {
		return loadErr
	}
	if err := store.QueueActiveRevocation(cfg.ServerURL); err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if err := drainPendingRevocations(c.Context, cfg.ServerURL, store); err != nil {
		if loadErr == nil {
			records, listErr := store.PendingRevocations(cfg.ServerURL)
			if listErr != nil {
				return errors.Join(err, listErr)
			}
			currentPending := false
			for _, record := range records {
				if record.ClientSessionID == active.ClientSessionID {
					currentPending = true
					break
				}
			}
			if !currentPending {
				fmt.Fprintln(os.Stderr, "WARNING: an earlier session revocation remains pending:", err)
				fmt.Println("Signed out")
				return nil
			}
		}
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
		if api.IsHostedEntitlementRequired(err) {
			return api.Project{}, err
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

type environmentTarget struct {
	kind string
	id   string
	name string
}

const (
	environmentProject          = "project"
	environmentConnectedMachine = "connected_machine"
)

func resolveEnvironmentTarget(ctx context.Context, client *api.Client, requested string) (environmentTarget, error) {
	project, err := resolveProjectID(ctx, client, requested)
	if err == nil {
		return environmentTarget{kind: environmentProject, id: project.ID, name: project.Name}, nil
	}
	if !errors.Is(err, resolver.ErrProjectNotFound) && !api.IsHostedEntitlementRequired(err) {
		return environmentTarget{}, err
	}
	machine, machineErr := resolveConnectedMachine(ctx, client, requested)
	if machineErr != nil {
		if api.IsNotFound(machineErr) {
			return environmentTarget{}, err
		}
		return environmentTarget{}, machineErr
	}
	return environmentTarget{kind: environmentConnectedMachine, id: machine.ID, name: machine.DisplayName}, nil
}

func listTerminalSessionsForTarget(ctx context.Context, client *api.Client, target environmentTarget) ([]api.TerminalSession, error) {
	if target.kind == environmentConnectedMachine {
		return client.ListConnectedMachineTerminalSessions(ctx, target.id)
	}
	return client.ListTerminalSessions(ctx, target.id)
}

func createTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, name, idempotencyKey string) (api.TerminalSession, error) {
	if target.kind == environmentConnectedMachine {
		return client.CreateConnectedMachineTerminalSession(ctx, target.id, name, idempotencyKey)
	}
	return client.CreateTerminalSession(ctx, target.id, name, idempotencyKey)
}

func renameTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID, name string) (api.TerminalSession, error) {
	if target.kind == environmentConnectedMachine {
		return client.RenameConnectedMachineTerminalSession(ctx, target.id, sessionID, name)
	}
	return client.RenameTerminalSession(ctx, target.id, sessionID, name)
}

func closeTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID string) error {
	if target.kind == environmentConnectedMachine {
		return client.CloseConnectedMachineTerminalSession(ctx, target.id, sessionID)
	}
	return client.CloseTerminalSession(ctx, target.id, sessionID)
}

func deleteTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID string) error {
	if target.kind == environmentConnectedMachine {
		return client.DeleteConnectedMachineTerminalSession(ctx, target.id, sessionID)
	}
	return client.DeleteTerminalSession(ctx, target.id, sessionID)
}

// deps bundles production dependencies for a command.
type deps struct {
	cfg       *config.Config
	auth      config.AuthSource
	resolver  resolver.ProjectResolver
	tunnel    tunnel.Tunnel
	uploader  upload.Uploader
	telemetry telemetry.Sink
}

func buildDeps(c *cli.Context) (*deps, error) {
	cfg, err := config.Load(c.String("config"))
	if err != nil {
		return nil, err
	}
	if s := c.String("server"); s != "" {
		normalized, err := config.NormalizeServerURL(s)
		if err != nil {
			return nil, err
		}
		cfg.ServerURL = normalized
	} else if cfg.ServerURL != "" {
		normalized, err := config.NormalizeServerURL(cfg.ServerURL)
		if err != nil {
			return nil, fmt.Errorf("invalid configured Paperboat server: %w", err)
		}
		cfg.ServerURL = normalized
	}
	papercodeTunnel := tunnel.NewPapercodeWSTunnel()
	papercodeTunnel.OutputQueueChunks = cfg.Connect.TerminalOutputQueueChunks
	var termTunnel tunnel.Tunnel = papercodeTunnel
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
		resolver: nil,
		tunnel:   termTunnel,
		uploader: uploader,
	}, nil
}

func connectCommand() *cli.Command {
	return &cli.Command{
		Name:      "connect",
		Usage:     "Attach to an environment terminal (default action)",
		ArgsUsage: "<environment>",
		Flags:     connectFlags(),
		Action:    actionConnect,
	}
}

func connectFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "new", Usage: "create a new terminal session"},
		&cli.StringFlag{Name: "name", Usage: "name for a new terminal session"},
		&cli.StringFlag{Name: "session", Usage: "attach an existing terminal session by name or ID"},
	}
}

func projectsCommand() *cli.Command {
	return &cli.Command{
		Name:  "projects",
		Usage: "List projects available to this account",
		Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}},
		Action: func(c *cli.Context) error {
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			projects, err := client.ListProjects(c.Context)
			if err != nil && !api.IsHostedEntitlementRequired(err) {
				return err
			}
			if err != nil {
				projects = nil
			}
			if c.Bool("json") {
				return json.NewEncoder(os.Stdout).Encode(projects)
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

func environmentsCommand() *cli.Command {
	return &cli.Command{
		Name:  "environments",
		Usage: "List hosted projects and connected machines",
		Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}},
		Action: func(c *cli.Context) error {
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			projects, err := client.ListProjects(c.Context)
			if err != nil && !api.IsHostedEntitlementRequired(err) {
				return err
			}
			if err != nil {
				projects = nil
			}
			machines, err := client.ListConnectedMachines(c.Context)
			if err != nil {
				return err
			}
			if c.Bool("json") {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"projects": projects, "connected_machines": machines})
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tNAME\tID\tSTATE")
			for _, project := range projects {
				fmt.Fprintf(w, "project\t%s\t%s\t%s\n", project.Name, project.ID, project.State)
			}
			for _, machine := range machines {
				state := machine.State
				if machine.Online && state == "" {
					state = "online"
				}
				fmt.Fprintf(w, "connected_machine\t%s\t%s\t%s\n", machine.DisplayName, machine.ID, state)
			}
			return w.Flush()
		},
	}
}

func sessionsCommand() *cli.Command {
	list := func(c *cli.Context) error {
		client, err := backendClient(c)
		if err != nil {
			return err
		}
		target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
		if err != nil {
			return err
		}
		sessions, err := listTerminalSessionsForTarget(c.Context, client, target)
		if err != nil {
			return friendlyCommandError(err)
		}
		if c.Bool("json") {
			return json.NewEncoder(os.Stdout).Encode(sessions)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		if c.Bool("wide") {
			fmt.Fprintln(w, "NAME\tID\tSTATE\tATTACHED\tLAST ACTIVE")
		} else {
			fmt.Fprintln(w, "NAME\tSTATE\tATTACHED\tLAST ACTIVE")
		}
		for _, s := range sessions {
			attached := "-"
			if s.AttachedCount != nil {
				attached = fmt.Sprintf("%d", *s.AttachedCount)
			}
			if c.Bool("wide") {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.ID, s.State, attached, relativeTime(s.LastActiveAt))
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.State, attached, relativeTime(s.LastActiveAt))
			}
		}
		return w.Flush()
	}
	return &cli.Command{Name: "sessions", Usage: "Manage environment terminal sessions", ArgsUsage: "<environment>", Flags: []cli.Flag{&cli.BoolFlag{Name: "wide"}, &cli.BoolFlag{Name: "json"}}, Action: list, Subcommands: []*cli.Command{
		{Name: "rename", ArgsUsage: "<environment> <session> <new-name>", Action: func(c *cli.Context) error {
			if c.Args().Len() != 3 {
				return errors.New("usage: pb sessions rename <environment> <session> <new-name>")
			}
			if err := validateSessionName(c.Args().Get(2)); err != nil {
				return err
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			session, err := resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			if err != nil {
				return err
			}
			if session.IsDefault {
				return errors.New("the default session cannot be renamed")
			}
			_, err = renameTerminalSessionForTarget(c.Context, client, target, session.ID, c.Args().Get(2))
			return friendlyCommandError(err)
		}},
		{Name: "close", ArgsUsage: "<environment> <session>", Action: func(c *cli.Context) error {
			if c.Args().Len() != 2 {
				return errors.New("usage: pb sessions close <environment> <session>")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			session, err := resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			if err != nil {
				return err
			}
			return friendlyCommandError(closeTerminalSessionForTarget(c.Context, client, target, session.ID))
		}},
		{Name: "delete", ArgsUsage: "<environment> <session>", Flags: []cli.Flag{&cli.BoolFlag{Name: "yes", Usage: "confirm deletion"}}, Action: func(c *cli.Context) error {
			if c.Args().Len() != 2 {
				return errors.New("usage: pb sessions delete <environment> <session> [--yes]")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			session, err := resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			if err != nil {
				return err
			}
			if session.IsDefault {
				return errors.New("the default session cannot be deleted")
			}
			if !c.Bool("yes") {
				if !term.IsTerminal(int(os.Stdin.Fd())) {
					return errors.New("refusing non-interactive deletion without --yes")
				}
				fmt.Fprintf(os.Stderr, "Delete terminal session %q? [y/N] ", session.Name)
				var answer string
				if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil || !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					return errors.New("deletion cancelled")
				}
			}
			return friendlyCommandError(deleteTerminalSessionForTarget(c.Context, client, target, session.ID))
		}},
	}}
}

func selectTerminalSession(ctx context.Context, client *api.Client, projectRef string, create bool, name, ref string) (string, error) {
	target, err := resolveEnvironmentTarget(ctx, client, projectRef)
	if err != nil {
		return "", err
	}
	if create {
		if err := validateSessionNameOptional(name); err != nil {
			return "", err
		}
		session, err := createTerminalSessionForTarget(ctx, client, target, name, newIdempotencyKey())
		if err != nil {
			return "", friendlyCommandError(err)
		}
		if name == "" {
			fmt.Fprintf(os.Stderr, "Session: %s\n", session.Name)
		}
		return session.ID, nil
	}
	if strings.TrimSpace(ref) == "" {
		return "", nil
	}
	session, err := resolveTerminalSession(ctx, client, target, ref)
	if err != nil {
		return "", err
	}
	return session.ID, nil
}

func resolveConnectedMachine(ctx context.Context, client *api.Client, requested string) (api.ConnectedMachine, error) {
	machines, err := client.ListConnectedMachines(ctx)
	if err != nil {
		return api.ConnectedMachine{}, err
	}
	for _, machine := range machines {
		if machine.ID == requested {
			return machine, nil
		}
	}
	var matches []api.ConnectedMachine
	for _, machine := range machines {
		if strings.EqualFold(machine.DisplayName, requested) {
			matches = append(matches, machine)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, machine := range matches {
			ids = append(ids, machine.ID)
		}
		return api.ConnectedMachine{}, fmt.Errorf("%w: %q matches connected-machine IDs %s; use an exact ID", resolver.ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return api.ConnectedMachine{}, fmt.Errorf("%w: %q", resolver.ErrProjectNotFound, requested)
}

func resolveTerminalSession(ctx context.Context, client *api.Client, target environmentTarget, ref string) (api.TerminalSession, error) {
	sessions, err := listTerminalSessionsForTarget(ctx, client, target)
	if err != nil {
		return api.TerminalSession{}, friendlyCommandError(err)
	}
	for _, s := range sessions {
		if s.ID == ref || strings.EqualFold(s.Name, ref) {
			return s, nil
		}
	}
	var suggestions []string
	for _, s := range sessions {
		if strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(ref)) || editDistance(strings.ToLower(s.Name), strings.ToLower(ref)) <= 2 {
			suggestions = append(suggestions, s.Name)
			if len(suggestions) == 3 {
				break
			}
		}
	}
	message := fmt.Sprintf("terminal session %q was not found", ref)
	if len(suggestions) > 0 {
		message += "; did you mean " + strings.Join(suggestions, ", ") + "?"
	}
	message += "; create one with --new --name"
	return api.TerminalSession{}, errors.New(message)
}

var sessionNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var automaticSessionNamePattern = regexp.MustCompile(`^shell-[0-9]+$`)

func validateSessionNameOptional(name string) error {
	if name == "" {
		return nil
	}
	return validateSessionName(name)
}
func validateSessionName(name string) error {
	if name == "default" || automaticSessionNamePattern.MatchString(name) || !sessionNamePattern.MatchString(name) {
		return errors.New("session names must be lowercase 1-64 character values matching [a-z0-9][a-z0-9._-]{0,63}; default and shell-N are reserved")
	}
	return nil
}

func newIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pb-%d", time.Now().UnixNano())
	}
	return "pb-" + hex.EncodeToString(b[:])
}
func relativeTime(at *time.Time) string {
	if at == nil {
		return "-"
	}
	d := time.Since(*at)
	if d < time.Minute {
		return "now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, ra := range a {
		current := make([]int, len(b)+1)
		current[0] = i + 1
		for j, rb := range b {
			cost := 0
			if ra != rb {
				cost = 1
			}
			current[j+1] = minInt(current[j]+1, prev[j+1]+1, prev[j]+cost)
		}
		prev = current
	}
	return prev[len(b)]
}
func minInt(values ...int) int {
	value := values[0]
	for _, candidate := range values[1:] {
		if candidate < value {
			value = candidate
		}
	}
	return value
}
func friendlyCommandError(err error) error {
	if err == nil {
		return nil
	}
	if msg := friendlyAPIError(err); msg != "" {
		return errors.New(msg)
	}
	return err
}

func actionConnect(c *cli.Context) error {
	project := c.Args().First()
	if project == "" {
		if server := strings.TrimSpace(c.String("server")); server != "" {
			cfg, err := config.Load(c.String("config"))
			if err != nil {
				return err
			}
			normalized, err := config.NormalizeServerURL(server)
			if err != nil {
				return err
			}
			cfg.ServerURL = normalized
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, cfg.Path())
			return nil
		}
		return errors.New("missing environment name; usage: pb <environment>")
	}
	if c.Args().Len() > 1 {
		return errors.New("expected exactly one environment name")
	}
	if c.Bool("new") && strings.TrimSpace(c.String("session")) != "" {
		return errors.New("--new and --session cannot be used together")
	}
	if !c.Bool("new") && strings.TrimSpace(c.String("name")) != "" {
		return errors.New("--name requires --new")
	}

	d, err := buildDeps(c)
	if err != nil {
		return err
	}
	ctx := c.Context
	if strings.TrimSpace(d.cfg.ServerURL) == "" {
		return errors.New("Paperboat server is not configured; set server_url or use --server")
	}
	bar := statusbar.New(statusbar.Options{
		Mode:           d.cfg.StatusBar.Mode,
		NoticeDuration: time.Duration(d.cfg.StatusBar.NoticeSeconds) * time.Second,
		Layout: statusbar.Layout{
			Left:   d.cfg.StatusBar.Left,
			Center: d.cfg.StatusBar.Center,
			Right:  d.cfg.StatusBar.Right,
		},
	})
	bar.SetIdentity(project, requestedSessionLabel(c))
	defer func() { _ = bar.Close() }()
	useStatusBar := bar.Enabled()
	var closeTelemetry func()
	d.telemetry, closeTelemetry = connectTelemetry(d.cfg, os.Stderr)
	defer closeTelemetry()

	cred, err := d.auth.Credential()
	if err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if errors.Is(err, config.ErrNoCredentials) {
		return errors.New("not signed in to Paperboat; run `pb auth login`, then retry")
	}
	backend := api.New(d.cfg.ServerURL, cred, nil)
	terminalSessionID, err := selectTerminalSession(c.Context, backend, project, c.Bool("new"), c.String("name"), c.String("session"))
	if err != nil {
		return err
	}
	newResolver := func(credential config.Credential) *resolver.APIResolver {
		apiResolver := resolver.NewAPIResolver(api.New(d.cfg.ServerURL, credential, nil), d.cfg)
		apiResolver.Telemetry = d.telemetry
		return apiResolver
	}
	d.resolver = newResolver(cred)
	if apiResolver, ok := d.resolver.(*resolver.APIResolver); ok {
		apiResolver.Progress = func(status, reason string, retryAfter time.Duration) {
			if useStatusBar {
				bar.SetConnection("connecting")
				bar.Loading("Preparing connection")
				return
			}
			fmt.Fprintf(os.Stderr, "Connecting: %s (%s), retrying in %s...\n", status, reason, retryAfter.Round(time.Second))
		}
	}
	remoteSize := func() (uint16, uint16) {
		if useStatusBar {
			if cols, rows := bar.RemoteSize(); cols > 0 && rows > 0 {
				return cols, rows
			}
		}
		return localTerminalSize()
	}

	var info resolver.ConnectInfo
	var conn tunnel.Conn
	var lastTerminalSequence atomic.Int64
	recordTerminalSequence := func(sequence int) {
		for {
			current := lastTerminalSequence.Load()
			if int64(sequence) <= current || lastTerminalSequence.CompareAndSwap(current, int64(sequence)) {
				return
			}
		}
	}
	configureUploadRefresh := func(u upload.Uploader) {
		httpUploader, ok := u.(*upload.HTTPUploader)
		if !ok {
			return
		}
		projectID, environmentID := info.ProjectID, ""
		if info.Terminal != nil {
			environmentID = info.Terminal.EnvironmentID
		}
		httpUploader.ConfigureTelemetry(d.telemetry, projectID, environmentID)
		httpUploader.RefreshAuth = func(refreshCtx context.Context) (upload.Auth, error) {
			return refreshUploadAuthorization(refreshCtx, d.auth, func(credential config.Credential) resolver.ProjectResolver {
				return newResolver(credential)
			}, project, info.ProjectID, terminalSessionID)
		}
	}
	for attempt := 0; attempt <= d.cfg.Connect.DialRetries; attempt++ {
		info, err = d.resolver.Resolve(ctx, resolver.ConnectRequest{Project: project, Credential: cred, TerminalSessionID: terminalSessionID})
		if err == nil {
			if info.Terminal != nil {
				info.Terminal.ReplayHistory = true
				info.Terminal.SequenceSink = recordTerminalSequence
				info.Terminal.Env = forwardedTerminalEnv(d.cfg.Connect.ForwardTerminalEnv)
				info.Terminal.Cols, info.Terminal.Rows = remoteSize()
			}
			d.uploader = uploaderForTarget(info.Upload)
			configureUploadRefresh(d.uploader)
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
		if useStatusBar {
			bar.SetConnection("reconnecting")
			bar.Loading("Retrying connection")
		} else {
			fmt.Fprintf(os.Stderr, "Connection attempt %d failed; refreshing the descriptor in %ds...\n", attempt+1, d.cfg.Connect.DialRetrySeconds)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(d.cfg.Connect.DialRetrySeconds) * time.Second):
		}
	}
	if err != nil {
		if useStatusBar {
			bar.SetConnection("failed")
			bar.FailureFor("connection", "Connection failed")
		}
		if msg := friendlyAPIError(err); msg != "" {
			return errors.New(msg)
		}
		return fmt.Errorf("connect to %q: %w", project, err)
	}
	if useStatusBar {
		bar.SetConnection("connected")
		bar.Notice("Connected")
		bar.PrepareRemoteViewport()
	}
	var pastePolicy *paste.Policy
	conn = tunnel.NewObservedReconnectingConn(ctx, conn, d.cfg.Connect.DialRetries, time.Duration(d.cfg.Connect.DialRetrySeconds)*time.Second, func(reconnectCtx context.Context) (tunnel.Conn, error) {
		freshCred, credErr := d.auth.Credential()
		if credErr != nil {
			return nil, credErr
		}
		freshResolver := newResolver(freshCred)
		freshInfo, resolveErr := freshResolver.Resolve(reconnectCtx, resolver.ConnectRequest{Project: info.ProjectID, Credential: freshCred, TerminalSessionID: terminalSessionID})
		if resolveErr != nil {
			return nil, resolveErr
		}
		if freshInfo.Terminal != nil {
			freshInfo.Terminal.ReplayHistory = false
			freshInfo.Terminal.AfterSequence = int(lastTerminalSequence.Load())
			freshInfo.Terminal.SequenceSink = recordTerminalSequence
			freshInfo.Terminal.Env = forwardedTerminalEnv(d.cfg.Connect.ForwardTerminalEnv)
			freshInfo.Terminal.Cols, freshInfo.Terminal.Rows = remoteSize()
		}
		freshConn, dialErr := d.tunnel.Dial(reconnectCtx, freshInfo)
		if dialErr != nil {
			return nil, dialErr
		}
		if pastePolicy != nil {
			freshUploader := uploaderForTarget(freshInfo.Upload)
			configureUploadRefresh(freshUploader)
			pastePolicy.Update(freshUploader, uploadLimits(d.cfg, freshInfo.Upload))
		}
		return freshConn, nil
	}, d.telemetry, nil, tunnel.TelemetryContext{ProjectID: info.ProjectID, EnvironmentID: info.Terminal.EnvironmentID}, tunnel.WithReconnectingOutput(
		d.cfg.Connect.TerminalOutputQueueChunks,
		time.Duration(d.cfg.Connect.TerminalOutputBatchMilliseconds)*time.Millisecond,
	), tunnel.WithReconnectObserver(func(event tunnel.ReconnectEvent) {
		if !useStatusBar {
			return
		}
		switch event {
		case tunnel.ReconnectStarted:
			bar.SetConnection("reconnecting")
			bar.Loading("Reconnecting")
		case tunnel.ReconnectRecovered:
			bar.RecoverFailureFor("connection")
			bar.SetConnection("connected")
			bar.Notice("Reconnected")
		case tunnel.ReconnectFailed:
			bar.SetConnection("failed")
			bar.FailureFor("connection", "Connection lost")
		}
	}))

	// Wrap remote input with the image-paste interceptor.
	pastePolicy = paste.NewPolicy(d.uploader, uploadLimits(d.cfg, info.Upload))
	interceptor := paste.NewWithPolicy(conn, pastePolicy,
		paste.WithNotifier(statusNotifier(useStatusBar)),
		paste.WithLifecycle(func(event paste.LifecycleEvent) {
			if !useStatusBar {
				return
			}
			switch event {
			case paste.ImageDetected:
				bar.Loading("Image detected")
			case paste.ImageUploading:
				bar.Loading("Uploading image")
			case paste.ImageComplete:
				bar.RecoverFailureFor("upload")
				bar.Notice("Image uploaded")
			case paste.ImageFailed:
				bar.FailureFor("upload", "Image upload failed; pasted original")
			}
		}),
		paste.WithWatchDirs(expandDirs(d.cfg.Upload.WatchDirs)),
		paste.WithTempFilePatterns(d.cfg.Upload.TempFilePatterns),
		paste.WithMaxQueuedBytes(d.cfg.Upload.MaxQueuedInputBytes),
		paste.WithPartialFlushDelay(time.Duration(d.cfg.Connect.InputPartialFlushMilliseconds)*time.Millisecond),
	)

	if useStatusBar && info.TargetKind == "project" {
		pollCtx, cancelPoll := context.WithCancel(ctx)
		defer cancelPoll()
		go pollConfigSync(pollCtx, d.cfg.ServerURL, d.auth, info.ProjectID, time.Duration(d.cfg.StatusBar.SyncPollSeconds)*time.Second, bar)
	}
	runOptions := []session.RunOption{session.WithOutputBufferBytes(d.cfg.Connect.TerminalOutputBufferBytes)}
	if useStatusBar {
		runOptions = append(runOptions, session.WithOutput(bar), session.WithRemoteSize(remoteSize))
	}
	code, err := session.RunWithActivity(ctx, conn, interceptor, func(source string) {
		if info.TargetKind != "project" {
			return
		}
		activityCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		activityErr := reportActivity(activityCtx, d.cfg.ServerURL, d.auth, info.ProjectID, source)
		if activityErr != nil {
			if useStatusBar {
				bar.Notice("Activity reporting unavailable")
			} else {
				fmt.Fprintf(os.Stderr, "warning: activity report failed: %v\n", activityErr)
			}
		}
	}, runOptions...)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCodeError{code: code}
	}
	return nil
}

func requestedSessionLabel(c *cli.Context) string {
	if c.Bool("new") {
		if name := strings.TrimSpace(c.String("name")); name != "" {
			return name
		}
		return "new session"
	}
	if session := strings.TrimSpace(c.String("session")); session != "" {
		return session
	}
	return "default"
}

func statusNotifier(enabled bool) io.Writer {
	if enabled {
		return io.Discard
	}
	return os.Stderr
}

func pollConfigSync(ctx context.Context, serverURL string, source config.AuthSource, projectID string, interval time.Duration, bar *statusbar.Bar) {
	if interval <= 0 {
		return
	}
	poll := func() bool {
		credential, err := source.Credential()
		if err != nil {
			bar.FailureFor("config-sync", "Config sync status unavailable")
			return true
		}
		client := api.New(serverURL, credential, nil)
		status, err := client.ConfigSyncStatus(ctx)
		if err != nil {
			bar.FailureFor("config-sync", "Config sync status unavailable")
			bar.SetConfigSync("error")
			return true
		}
		state := ""
		found := false
		for _, candidate := range status.Projects {
			if candidate.ProjectID == projectID {
				state = candidate.State
				found = true
				break
			}
		}
		if !found {
			bar.RecoverFailureFor("config-sync")
			bar.SetConfigSync("waiting")
			bar.Loading("Config sync awaiting status")
		} else {
			bar.SetConfigSync(state)
			switch state {
			case "healthy", "watching", "idle":
				bar.RecoverFailureFor("config-sync")
				bar.Notice("Config synced")
			case "pending":
				bar.RecoverFailureFor("config-sync")
				bar.Loading("Config sync pending")
			case "syncing", "restoring":
				bar.RecoverFailureFor("config-sync")
				bar.Loading("Config sync in progress")
			case "warning":
				bar.FailureFor("config-sync", "Config sync needs attention")
			case "conflict":
				bar.FailureFor("config-sync", "Config sync conflict")
			case "error":
				bar.FailureFor("config-sync", "Config sync failed")
			case "offline":
				bar.FailureFor("config-sync", "Config sync offline")
			default:
				bar.FailureFor("config-sync", "Config sync status unavailable")
			}
		}
		usage, usageErr := client.UsageSummary(ctx)
		if usageErr == nil {
			bar.SetUsage(formatStatusCredits(usage.Credits.Balance), fmt.Sprintf("%d GB", usage.Storage.AvailableGB))
		}
		return true
	}
	if !poll() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}

func formatStatusCredits(raw string) string {
	value := strings.TrimSpace(raw)
	if whole, fraction, ok := strings.Cut(value, "."); ok {
		fraction = strings.TrimRight(fraction, "0")
		if fraction == "" {
			value = whole
		} else {
			value = whole + "." + fraction
		}
	}
	if value == "" || value == "-0" {
		return "0"
	}
	return value
}

func connectTelemetry(cfg *config.Config, warnings io.Writer) (telemetry.Sink, func()) {
	if path := cfg.TelemetryPath(); path != "" {
		fileSink, err := telemetry.NewJSONFileSinkWithLimit(path, cfg.Observability.MaxEventLogBytes)
		if err == nil {
			return fileSink, func() { _ = fileSink.Close() }
		}
		fmt.Fprintln(warnings, "warning: telemetry disabled: local event log unavailable")
	}
	return telemetry.NopSink{}, func() {}
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
	case "connected_machine_offline":
		return "the connected machine is offline; start or repair its Paperboat connector, then retry"
	case "connected_machine_revoked":
		return "this connected machine has been disconnected or revoked; repair or reconnect it in the Paperboat dashboard"
	}
	return ""
}

// refreshUploadAuthorization re-brokers an upload descriptor with a newly
// constructed control-plane client. API clients bind their bearer token at
// construction, so reusing the resolver from the initial terminal attach
// would retry with an expired credential.
func refreshUploadAuthorization(ctx context.Context, source config.AuthSource, newResolver func(config.Credential) resolver.ProjectResolver, project, projectID, terminalSessionID string) (upload.Auth, error) {
	freshCred, err := source.Credential()
	if err != nil {
		return upload.Auth{}, err
	}
	projectToken := project
	if projectID != "" {
		projectToken = projectID
	}
	freshInfo, err := newResolver(freshCred).Resolve(ctx, resolver.ConnectRequest{Project: projectToken, Credential: freshCred, TerminalSessionID: terminalSessionID})
	if err != nil {
		return upload.Auth{}, fmt.Errorf("refresh upload descriptor: %w", err)
	}
	if freshInfo.Upload == nil {
		return upload.Auth{}, errors.New("refresh upload descriptor: upload target missing")
	}
	return upload.Auth{Method: freshInfo.Upload.Auth.Method, Token: freshInfo.Upload.Auth.Token, Ticket: freshInfo.Upload.Auth.Ticket}, nil
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

// terminalEnvKeyPattern mirrors the papercode terminal env schema; an invalid
// key or oversized value would reject the whole attach, so filter locally.
var terminalEnvKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const maxTerminalEnvValueChars = 8_192

// forwardedTerminalEnv snapshots the configured local environment variables so
// the remote PTY spawns with the client terminal's capabilities.
func forwardedTerminalEnv(keys []string) map[string]string {
	env := make(map[string]string, len(keys))
	for _, key := range keys {
		if !terminalEnvKeyPattern.MatchString(key) {
			continue
		}
		value, ok := os.LookupEnv(key)
		if !ok || value == "" || len(value) > maxTerminalEnvValueChars {
			continue
		}
		env[key] = value
	}
	return env
}

// localTerminalSize returns the current terminal geometry, clamped to the
// papercode schema bounds, or zeros when stdout is not a terminal.
func localTerminalSize() (cols, rows uint16) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 0, 0
	}
	if w > 1000 {
		w = 1000
	}
	if h > 500 {
		h = 500
	}
	return uint16(w), uint16(h)
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

func configCommand() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Inspect the local CLI config",
		Subcommands: []*cli.Command{
			{
				Name: "set", ArgsUsage: "server <url>", Usage: "Set a local configuration value",
				Action: func(c *cli.Context) error {
					if c.Args().Len() != 2 || c.Args().First() != "server" {
						return errors.New("usage: pb config set server <url>")
					}
					cfg, err := config.Load(c.String("config"))
					if err != nil {
						return err
					}
					server, err := config.NormalizeServerURL(c.Args().Get(1))
					if err != nil {
						return err
					}
					cfg.ServerURL = server
					if err := cfg.Save(); err != nil {
						return err
					}
					fmt.Fprintln(os.Stdout, cfg.Path())
					return nil
				},
			},
			{
				Name: "unset", ArgsUsage: "server", Usage: "Remove a local configuration value",
				Action: func(c *cli.Context) error {
					if c.Args().Len() != 1 || c.Args().First() != "server" {
						return errors.New("usage: pb config unset server")
					}
					cfg, err := config.Load(c.String("config"))
					if err != nil {
						return err
					}
					cfg.ServerURL = ""
					if err := cfg.Save(); err != nil {
						return err
					}
					fmt.Fprintln(os.Stdout, cfg.Path())
					return nil
				},
			},
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
				Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}},
				Action: func(c *cli.Context) error {
					d, err := buildDeps(c)
					if err != nil {
						return err
					}
					if c.Bool("json") {
						return json.NewEncoder(os.Stdout).Encode(map[string]any{"path": d.cfg.Path(), "server_url": d.cfg.ServerURL, "auth_file_fallback": d.cfg.Auth.AllowFileFallback, "upload_endpoint": d.cfg.Upload.Endpoint, "upload_max_image_bytes": d.cfg.Upload.MaxImageBytes, "upload_max_attachments": d.cfg.Upload.MaxAttachments})
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
		Flags:     []cli.Flag{&cli.BoolFlag{Name: "json"}},
		Action: func(c *cli.Context) error {
			d, err := buildDeps(c)
			if err != nil {
				return err
			}
			if c.Bool("json") {
				return doctorJSON(c, d)
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
				fmt.Println("entitlement: not checked (provide an environment to verify connect access)")
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
			fmt.Printf("environment:  %s (%s) ✓\n", info.ProjectID, firstNonEmpty(info.ProjectState, "ready"))
			fmt.Println("entitlement:  connect authorization accepted ✓")
			if info.TargetKind == "connected_machine" {
				fmt.Println("connector:    connected machine route ready ✓")
			} else {
				fmt.Println("fly readiness: ready ✓")
			}
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

func doctorJSON(c *cli.Context, d *deps) error {
	result := map[string]any{"config_path": d.cfg.Path(), "server": d.cfg.ServerURL, "auth": "unknown", "backend": "skipped"}
	cred, credErr := d.auth.Credential()
	if errors.Is(credErr, config.ErrNoCredentials) {
		result["auth"] = "not_signed_in"
	} else if credErr != nil {
		result["auth"] = "error"
		result["auth_error"] = credErr.Error()
	} else {
		result["auth"] = "available"
	}
	if d.cfg.ServerURL == "" {
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return errors.New("doctor: Paperboat server is not configured")
	}
	if credErr != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return errors.New("doctor: Paperboat credentials are unavailable")
	}
	client := api.New(d.cfg.ServerURL, cred, nil)
	me, err := client.Me(c.Context)
	if err != nil {
		result["backend"] = "error"
		result["backend_error"] = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return fmt.Errorf("doctor: backend check failed: %w", err)
	}
	result["backend"] = "authenticated"
	result["account"] = firstNonEmpty(me.Email, me.DisplayName, me.ID)
	project := c.Args().First()
	if project == "" {
		result["project"] = nil
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	info, err := resolver.NewAPIResolver(client, d.cfg).Resolve(c.Context, resolver.ConnectRequest{Project: project, Credential: cred})
	if err != nil {
		result["project"] = project
		result["connect"] = "error"
		result["connect_error"] = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return fmt.Errorf("doctor: descriptor check failed: %w", err)
	}
	if info.Terminal == nil {
		result["project"] = info.ProjectID
		result["connect"] = "missing_terminal"
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return errors.New("doctor: descriptor missing terminal endpoint")
	}
	if err := tunnel.NewPapercodeWSTunnel().Check(c.Context, info.Terminal); err != nil {
		result["project"] = info.ProjectID
		result["connect"] = "websocket_error"
		result["connect_error"] = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return fmt.Errorf("doctor: papercode protocol check failed: %w", err)
	}
	result["project"] = map[string]string{"id": info.ProjectID, "name": info.Project, "state": info.ProjectState}
	result["environment_type"] = info.TargetKind
	result["connect"] = "ready"
	result["protocol"] = "paperboat-terminal-rpc/v1"
	return json.NewEncoder(os.Stdout).Encode(result)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
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
		return "(unset)"
	}
	return s
}
