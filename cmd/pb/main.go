// Command pb (alias: paperboat) is the invisible terminal wrapper for the
// Paperboat platform. `pb <project>` resumes the project VM and attaches its
// terminal, reusing papercode auth and bridging local image pastes into remote
// TUIs. Cross-service calls run behind interfaces with local dev stubs until
// paperboat-server and the agentunnel/papercode wiring land.
package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
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
	if err := app.Run(normalizeArgs(os.Args)); err != nil {
		fmt.Fprintln(os.Stderr, "pb:", err)
		os.Exit(1)
	}
}

// valueFlags are flags that consume the following token as their value. Used by
// normalizeArgs so users can put flags after the project name.
var valueFlags = map[string]bool{
	"--config": true, "--server": true,
	"--agent": true, "-a": true,
	"--size": true, "-s": true,
}

var subcommands = map[string]bool{
	"connect":    true,
	"agents":     true,
	"sizes":      true,
	"keep-alive": true,
	"config":     true,
	"doctor":     true,
}

var subcommandValueFlags = map[string]bool{
	"--hours": true,
}

// normalizeArgs moves flags ahead of positional arguments so `pb <project>
// --agent x` works as well as `pb --agent x <project>`. urfave/cli stops
// parsing flags at the first positional, so we reorder to keep the UX flexible.
func normalizeArgs(args []string) []string {
	if len(args) <= 1 {
		return args
	}
	var flags, positionals []string
	rest := args[1:]
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
	rootFlags = append(rootFlags, connectFlags()...)

	return &cli.App{
		Name:                   "pb",
		Usage:                  "Connect to your Paperboat project VM terminal",
		Version:                buildinfo.Version,
		UseShortOptionHandling: true,
		HideHelpCommand:        true,
		Flags:                  rootFlags,
		ArgsUsage:              "<project> [--agent <name>] [--size <shape>]",
		Description: "Run `pb <project>` to attach your project's remote terminal.\n" +
			"Flags select a different agent or machine shape for this session.",
		Action: actionConnect,
		Commands: []*cli.Command{
			connectCommand(),
			agentsCommand(),
			sizesCommand(),
			keepAliveCommand(),
			configCommand(),
			doctorCommand(),
		},
	}
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
		return nil, errors.New("no papercode credentials found — sign in with papercode first, then retry")
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
			return api.Project{}, errors.New("your papercode session was rejected — sign in again with papercode, then retry")
		}
		if msg := friendlyAPIError(err); msg != "" {
			return api.Project{}, errors.New(msg)
		}
		return api.Project{}, err
	}
	for _, p := range projects {
		if p.ID == requested || strings.EqualFold(p.Name, requested) {
			return p, nil
		}
	}
	return api.Project{}, fmt.Errorf("%w: %q", resolver.ErrProjectNotFound, requested)
}

// deps bundles the wired (stubbed) dependencies for a command.
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
	var termTunnel tunnel.Tunnel = tunnel.NewStubTunnel()
	var uploader upload.Uploader = upload.NewStubUploader(cfg.Upload.Endpoint)
	if cfg.ServerURL != "" {
		termTunnel = tunnel.NewPapercodeWSTunnel()
		uploader = upload.NewDisabledUploader()
	}
	return &deps{
		cfg:      cfg,
		auth:     config.AuthSourceFor(cfg),
		catalog:  catalog.NewStubCatalog(),
		resolver: resolver.NewStubResolver(cfg),
		tunnel:   termTunnel,
		uploader: uploader,
	}, nil
}

func connectCommand() *cli.Command {
	return &cli.Command{
		Name:      "connect",
		Usage:     "Attach to a project VM terminal (default action)",
		ArgsUsage: "<project>",
		Flags:     connectFlags(),
		Action:    actionConnect,
	}
}

func connectFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "agent", Aliases: []string{"a"}, Usage: "agent to launch this session (overrides project config)"},
		&cli.StringFlag{Name: "size", Aliases: []string{"s"}, Usage: "machine shape to boot on resume (e.g. 1x, 2x)"},
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

	// Reuse papercode auth; guide the user rather than prompting for a login.
	cred, err := d.auth.Credential()
	if err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if errors.Is(err, config.ErrNoCredentials) {
		if d.cfg.ServerURL != "" {
			// Real backend configured: a credential is required. Route the user
			// to papercode rather than prompting for a separate login.
			return errors.New("no papercode credentials found — sign in with papercode first, then retry")
		}
		fmt.Fprintln(os.Stderr, "pb: no papercode credentials found — sign in with papercode first.")
		fmt.Fprintln(os.Stderr, "    (running in local dev mode against a stub target)")
	}
	if d.cfg.ServerURL != "" {
		d.resolver = resolver.NewAPIResolver(api.New(d.cfg.ServerURL, cred, nil), d.cfg)
	}

	// Validate flag values against the dynamic catalog.
	agent := c.String("agent")
	if agent != "" && shouldValidateLocalCatalog(d.cfg) {
		if _, err := catalog.ValidateAgent(ctx, d.catalog, agent); err != nil {
			return err
		}
	}
	size := c.String("size")
	if size != "" && d.cfg.ServerURL != "" {
		return errors.New("--size is not supported with server_url until paperboat-server exposes a machine-shape override contract")
	}
	if size != "" && shouldValidateLocalCatalog(d.cfg) {
		if _, err := catalog.ValidateSize(ctx, d.catalog, size); err != nil {
			return err
		}
	}

	info, err := d.resolver.Resolve(ctx, resolver.ConnectRequest{
		Project:    project,
		Agent:      agent,
		Size:       size,
		Credential: cred,
	})
	if err != nil {
		if errors.Is(err, api.ErrUnauthenticated) {
			return errors.New("your papercode session was rejected — sign in again with papercode, then retry")
		}
		if msg := friendlyAPIError(err); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	if d.cfg.ServerURL != "" {
		d.uploader = uploaderForTarget(info.Upload)
	}

	conn, err := d.tunnel.Dial(ctx, info)
	if err != nil {
		if msg := friendlyAPIError(err); msg != "" {
			return errors.New(msg)
		}
		return fmt.Errorf("connect to %q: %w", project, err)
	}

	// Wrap remote input with the image-paste interceptor.
	interceptor := paste.New(conn, d.uploader, uploadLimits(d.cfg, info.Upload),
		paste.WithNotifier(os.Stderr),
		paste.WithWatchDirs(expandDirs(d.cfg.Upload.WatchDirs)),
	)

	code, err := session.Run(ctx, conn, interceptor)
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
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

func shouldValidateLocalCatalog(cfg *config.Config) bool {
	return cfg.ServerURL == ""
}

func uploaderForTarget(target *resolver.UploadTarget) upload.Uploader {
	if target == nil || target.HTTPBaseURL == "" {
		return upload.NewDisabledUploader()
	}
	return upload.NewHTTPUploader(target.HTTPBaseURL, upload.Auth{
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
					fmt.Printf("papercode_config: %s\n", orNone(d.cfg.PapercodeConfigPath))
					fmt.Printf("default_agent: %s\n", orNone(d.cfg.DefaultAgent))
					fmt.Printf("default_size: %s\n", orNone(d.cfg.DefaultSize))
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
		Usage:     "Check auth reuse and connectivity",
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
					fmt.Println("papercode:   not signed in (sign in with papercode)")
				} else {
					fmt.Printf("papercode:   error: %v\n", credErr)
				}
			} else {
				fmt.Println("papercode:   credentials found ✓")
			}

			if d.cfg.ServerURL == "" {
				fmt.Println("backend:     local dev stub (set server_url to connect)")
				return nil
			}
			if credErr != nil {
				fmt.Println("backend:     skipped (no credentials to authenticate)")
				return nil
			}
			me, err := api.New(d.cfg.ServerURL, cred, nil).Me(c.Context)
			if errors.Is(err, api.ErrUnauthenticated) {
				fmt.Println("backend:     credential rejected — sign in again with papercode")
				return nil
			}
			if err != nil {
				fmt.Printf("backend:     unreachable: %v\n", err)
				return nil
			}
			fmt.Printf("backend:     authenticated as %s ✓\n", firstNonEmpty(me.Email, me.DisplayName, me.ID))
			if project == "" {
				return nil
			}
			info, err := resolver.NewAPIResolver(api.New(d.cfg.ServerURL, cred, nil), d.cfg).Resolve(c.Context, resolver.ConnectRequest{
				Project:    project,
				Credential: cred,
			})
			if err != nil {
				fmt.Printf("papercode:   descriptor unavailable: %v\n", err)
				return nil
			}
			if info.Terminal == nil {
				fmt.Println("papercode:   descriptor missing terminal endpoint")
				return nil
			}
			if err := tunnel.NewPapercodeWSTunnel().Check(c.Context, info.Terminal); err != nil {
				fmt.Printf("papercode:   websocket unavailable: %v\n", err)
				return nil
			}
			fmt.Printf("papercode:   websocket route/auth ready for %s ✓\n", info.Project)
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
