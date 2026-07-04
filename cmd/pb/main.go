// Command pb (alias: paperboat) is the invisible terminal wrapper for the
// Paperboat platform. `pb <project>` resumes the project VM and attaches its
// terminal, reusing papercode auth and bridging local image pastes into remote
// TUIs. Cross-service calls run behind interfaces with local dev stubs until
// paperboat-server and the agentunnel/papercode wiring land.
package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

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
			configCommand(),
			doctorCommand(),
		},
	}
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
	return &deps{
		cfg:      cfg,
		auth:     config.AuthSourceFor(cfg),
		catalog:  catalog.NewStubCatalog(),
		resolver: resolver.NewStubResolver(cfg),
		tunnel:   tunnel.NewStubTunnel(),
		uploader: upload.NewStubUploader(cfg.Upload.Endpoint),
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
		fmt.Fprintln(os.Stderr, "pb: no papercode credentials found — sign in with papercode first.")
		fmt.Fprintln(os.Stderr, "    (running in local dev mode against a stub target)")
	}

	// Validate flag values against the dynamic catalog.
	agent := c.String("agent")
	if agent != "" {
		if _, err := catalog.ValidateAgent(ctx, d.catalog, agent); err != nil {
			return err
		}
	}
	size := c.String("size")
	if size != "" {
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
		return err
	}

	conn, err := d.tunnel.Dial(ctx, info)
	if err != nil {
		return fmt.Errorf("connect to %q: %w", project, err)
	}

	// Wrap remote input with the image-paste interceptor.
	interceptor := paste.New(conn, d.uploader, uploadLimits(d.cfg),
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

func uploadLimits(cfg *config.Config) upload.Limits {
	return upload.Limits{
		MaxImageBytes:       cfg.Upload.MaxImageBytes,
		MaxDataURLChars:     cfg.Upload.MaxDataURLChars,
		MaxAttachments:      cfg.Upload.MaxAttachments,
		AllowedMimePrefixes: cfg.Upload.AllowedMimePrefixes,
	}
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
		Name:  "doctor",
		Usage: "Check auth reuse and connectivity",
		Action: func(c *cli.Context) error {
			d, err := buildDeps(c)
			if err != nil {
				return err
			}
			fmt.Printf("config:      %s\n", d.cfg.Path())
			fmt.Printf("server:      %s\n", orLocal(d.cfg.ServerURL))
			if _, err := d.auth.Credential(); err != nil {
				if errors.Is(err, config.ErrNoCredentials) {
					fmt.Println("papercode:   not signed in (sign in with papercode)")
				} else {
					fmt.Printf("papercode:   error: %v\n", err)
				}
			} else {
				fmt.Println("papercode:   credentials found ✓")
			}
			return nil
		},
	}
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
