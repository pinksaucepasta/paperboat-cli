// Command pb is the invisible terminal wrapper for the
// Paperboat platform. `pb <environment>` attaches a hosted project or enrolled
// user machine through Paperboat auth and bridges local file pastes into
// remote TUIs. Cross-service calls run behind interfaces so protocol behavior
// remains independently testable.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/pinksaucepasta/paperboat-cli/internal/api"
	sessionauth "github.com/pinksaucepasta/paperboat-cli/internal/auth"
	"github.com/pinksaucepasta/paperboat-cli/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat-cli/internal/command"
	"github.com/pinksaucepasta/paperboat-cli/internal/config"
	filetransfer "github.com/pinksaucepasta/paperboat-cli/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat-cli/internal/inbox"
	"github.com/pinksaucepasta/paperboat-cli/internal/paste"
	"github.com/pinksaucepasta/paperboat-cli/internal/resolver"
	"github.com/pinksaucepasta/paperboat-cli/internal/session"
	"github.com/pinksaucepasta/paperboat-cli/internal/statusbar"
	"github.com/pinksaucepasta/paperboat-cli/internal/telemetry"
	"github.com/pinksaucepasta/paperboat-cli/internal/tunnel"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, commandLineArgs(runtime.GOOS, os.Getenv("TERMUX_EXEC__PROC_SELF_EXE"), os.Args), os.Stdout, os.Stderr))
}

func commandLineArgs(goos, termuxExecutable string, argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	args := argv[1:]
	if goos == "android" && len(args) > 0 && termuxExecutable != "" && args[0] == termuxExecutable {
		return args[1:]
	}
	return args
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
			return actionConnect(actionContext(command, args))
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = buildinfo.Version
	root.SetVersionTemplate("pb {{.Version}}\n")
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("version").Shorthand = "v"
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invocationError(err) })
	root.PersistentFlags().String("config", "", "path to the CLI config file")
	root.PersistentFlags().String("server", "", "paperboat-server base URL override")
	addConnectFlags(root)

	connect := &cobra.Command{Use: "connect <environment>", Short: "Attach to an environment terminal", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		if err := validateConnectInvocation(command); err != nil {
			return err
		}
		return actionConnect(actionContext(command, args))
	}}
	addConnectFlags(connect)
	root.AddCommand(connect)

	projects := &cobra.Command{Use: "projects", Short: "List projects available to this account", Args: commandArgs(cobra.NoArgs), RunE: actionRun(projectsCommand().Action)}
	projects.Flags().Bool("json", false, "print JSON")
	root.AddCommand(projects)

	environments := &cobra.Command{Use: "environments", Short: "List hosted projects and user machines", Args: commandArgs(cobra.NoArgs), RunE: actionRun(environmentsCommand().Action)}
	environments.Flags().Bool("json", false, "print JSON")
	root.AddCommand(environments)

	doctor := &cobra.Command{Use: "doctor [project]", Short: "Check authentication and connectivity", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: actionRun(doctorCommand().Action)}
	doctor.Flags().Bool("json", false, "print JSON")
	root.AddCommand(doctor)

	root.AddCommand(specTree(authCommand(), "auth"))
	root.AddCommand(&cobra.Command{Use: "login", Short: "Sign in through the Paperboat dashboard", Args: commandArgs(cobra.NoArgs), RunE: actionRun(authLogin)})
	root.AddCommand(&cobra.Command{Use: "logout", Short: "Revoke and remove the active client session", Args: commandArgs(cobra.NoArgs), RunE: actionRun(authLogout)})
	root.AddCommand(&cobra.Command{Use: "create [name]", Short: "Create and attach to a hosted project", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: actionRun(createProject)})
	configTree := specTree(configCommand(), "config")
	configTree.AddCommand(statusBarConfigCommand())
	root.AddCommand(configTree)
	root.AddCommand(specTree(previewCommand(), "preview"))
	root.AddCommand(sessionsCobraCommand())
	root.AddCommand(sessionCobraCommand())
	root.AddCommand(userMachineCobraCommand())
	return root
}

func addConnectFlags(command *cobra.Command) {
	command.Flags().String("transport", "", "terminal transport for this attach: auto, quic, or wss")
	command.Flags().Bool("new", false, "create a new terminal session")
	command.Flags().String("name", "", "name for a new terminal session")
	command.Flags().String("session", "", "attach an existing terminal session by name or ID")
	addStatusBarFlags(command)
}

func addStatusBarFlags(command *cobra.Command) {
	command.Flags().String("status-bar", "", "status bar for this attach: auto, on, or off")
	command.Flags().String("status-bar-fullscreen", "", "status bar in full-screen applications: hide or show")
	command.Flags().String("status-bar-theme", "", "status bar theme: terminal, dark, light, or mono")
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
	for name, allowed := range map[string][]string{
		"transport":             {"auto", "quic", "wss"},
		"status-bar":            {"auto", "on", "off"},
		"status-bar-fullscreen": {"hide", "show"},
		"status-bar-theme":      {"terminal", "dark", "light", "mono"},
	} {
		value, _ := command.Flags().GetString(name)
		if value != "" && !containsString(allowed, strings.ToLower(strings.TrimSpace(value))) {
			return invocationError(fmt.Errorf("--%s must be one of %s", name, strings.Join(allowed, ", ")))
		}
	}
	server, _ := command.Flags().GetString("server")
	if strings.TrimSpace(server) != "" {
		if _, err := config.NormalizeServerURL(server); err != nil {
			return invocationError(err)
		}
	}
	return nil
}

func specTree(source *command.Spec, use string) *cobra.Command {
	command := &cobra.Command{Use: use, Short: source.Usage, Args: commandArgs(cobra.NoArgs)}
	if source.Action != nil {
		command.RunE = actionRun(source.Action)
	} else {
		command.RunE = func(command *cobra.Command, _ []string) error { return command.Help() }
	}
	for _, child := range source.Subcommands {
		child := child
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(specCommandArgs(use, child.Name)), RunE: actionRun(child.Action)}
		if (use == "auth" && child.Name == "status") || (use == "config" && child.Name == "show") {
			entry.Flags().Bool("json", false, "print JSON")
		}
		if use == "config" && (child.Name == "assign" || child.Name == "unassign") {
			entry.Flags().Bool("json", false, "print JSON")
		}
		if use == "config" && child.Name == "unassign" {
			entry.Flags().Bool("yes", false, "confirm removal")
		}
		if use == "preview" {
			if child.Name == "list" {
				entry.Flags().Bool("json", false, "print JSON")
			}
			if child.Name == "create" {
				entry.Flags().Bool("yes", false, "acknowledge public access")
				entry.Flags().Bool("json", false, "print JSON")
			}
			if child.Name == "revoke" {
				entry.Flags().Bool("yes", false, "confirm removal")
				entry.Flags().Bool("json", false, "print JSON")
			}
		}
		command.AddCommand(entry)
	}
	return command
}

func specCommandArgs(parent, name string) cobra.PositionalArgs {
	if parent == "config" {
		switch name {
		case "set":
			return cobra.ExactArgs(2)
		case "unset":
			return cobra.ExactArgs(1)
		case "assign":
			return cobra.ExactArgs(2)
		case "unassign":
			return cobra.ExactArgs(1)
		}
	}
	if parent == "preview" {
		switch name {
		case "list":
			return cobra.NoArgs
		case "revoke":
			return cobra.ExactArgs(1)
		}
	}
	return cobra.NoArgs
}

func sessionsCobraCommand() *cobra.Command {
	source := sessionsCommand()
	command := &cobra.Command{Use: "sessions [environment]", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: actionRun(source.Action)}
	command.Flags().Bool("wide", false, "include immutable IDs")
	command.Flags().Bool("json", false, "print JSON")
	for _, child := range source.Subcommands {
		child := child
		var args cobra.PositionalArgs
		switch child.Name {
		case "rename":
			args = cobra.ExactArgs(3)
		case "close":
			args = cobra.RangeArgs(1, 2)
		case "delete":
			args = cobra.ExactArgs(2)
		}
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(args), RunE: actionRun(child.Action)}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("yes", false, "confirm "+child.Name)
		}
		if child.Name == "close" {
			entry.Flags().Bool("all", false, "close all sessions in the environment")
		}
		command.AddCommand(entry)
	}
	return command
}

func sessionCobraCommand() *cobra.Command {
	source := sessionsCommand()
	command := &cobra.Command{Use: "session", Short: source.Usage, Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error { return command.Help() }}
	attach := &cobra.Command{Use: "attach <name>", Short: "Attach to a durable terminal session", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(cobraCommand *cobra.Command, args []string) error {
		if err := validateConnectInvocation(cobraCommand); err != nil {
			return err
		}
		if err := cobraCommand.Flags().Set("session", args[0]); err != nil {
			return err
		}
		return actionConnect(actionContext(cobraCommand, nil))
	}}
	attach.Flags().String("session", "", "")
	_ = attach.Flags().MarkHidden("session")
	addStatusBarFlags(attach)
	command.AddCommand(attach)
	list := &cobra.Command{Use: "list [environment]", Short: "List durable terminal sessions", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: actionRun(source.Action)}
	list.Flags().Bool("wide", false, "include immutable IDs")
	list.Flags().Bool("json", false, "print JSON")
	command.AddCommand(list)
	for _, child := range source.Subcommands {
		child := child
		var args cobra.PositionalArgs
		switch child.Name {
		case "rename":
			args = cobra.ExactArgs(3)
		case "close":
			args = cobra.RangeArgs(1, 2)
		case "delete":
			args = cobra.ExactArgs(2)
		}
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(args), RunE: actionRun(child.Action)}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("yes", false, "confirm "+child.Name)
		}
		if child.Name == "close" {
			entry.Flags().Bool("all", false, "close all sessions in the environment")
		}
		command.AddCommand(entry)
	}
	return command
}

func userMachineCobraCommand() *cobra.Command {
	machine := &cobra.Command{Use: "user-machine", Short: "Manage user machines", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error { return command.Help() }}
	add := &cobra.Command{Use: "add", Short: "Start user-machine enrollment in the dashboard", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		ctx := actionContext(command, args)
		cfg, err := config.Load(ctx.String("config"))
		if err != nil {
			return err
		}
		if server := strings.TrimSpace(ctx.String("server")); server != "" {
			cfg.ServerURL, err = config.NormalizeServerURL(server)
			if err != nil {
				return err
			}
		}
		if strings.TrimSpace(cfg.ServerURL) == "" {
			return errors.New("Paperboat server is not configured; set server_url or use --server")
		}
		clientConfiguration, err := api.New(cfg.ServerURL, config.Credential{}, nil).ClientConfiguration(ctx.Context)
		if err != nil {
			return friendlyCommandError(fmt.Errorf("load Paperboat client configuration: %w", err))
		}
		target := clientConfiguration.UserMachinesURL
		if err := openBrowser(target); err != nil {
			fmt.Fprintf(command.ErrOrStderr(), "Could not open a browser: %v\n", err)
		}
		fmt.Fprintf(command.OutOrStdout(), "Continue user-machine enrollment at %s\n", target)
		return nil
	}}
	list := &cobra.Command{Use: "list", Short: "List enrolled user machines", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		ctx := actionContext(command, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		machines, err := client.ListUserMachines(ctx.Context)
		if err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"version": "1", "user_machines": machines})
		}
		writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "NAME\tKIND\tSTATE\tID")
		for _, item := range machines {
			state := item.State
			if item.Online {
				state = "online"
			}
			fmt.Fprintf(writer, "%s\tBYOD\t%s\t%s\n", item.DisplayName, state, item.ID)
		}
		return writer.Flush()
	}}
	list.Flags().Bool("json", false, "print JSON")
	revoke := &cobra.Command{Use: "revoke <user-machine>", Short: "Disconnect and revoke a user machine", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(cobraCommand *cobra.Command, args []string) error {
		if confirmed, _ := cobraCommand.Flags().GetBool("yes"); !confirmed {
			return errors.New("user-machine revocation requires --yes")
		}
		ctx := actionContext(cobraCommand, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		userMachineID, displayName, err := resolveUserMachineTarget(ctx.Context, client, args[0])
		if err != nil {
			return err
		}
		if err := client.DisconnectUserMachine(ctx.Context, userMachineID); err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := cobraCommand.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(cobraCommand.OutOrStdout()).Encode(map[string]any{"version": "1", "user_machine": map[string]string{"id": userMachineID, "display_name": displayName, "state": "disconnected"}, "outcome": "confirmed", "retry": "not_required"})
		}
		fmt.Fprintf(cobraCommand.OutOrStdout(), "Disconnected user machine %s (%s).\n", displayName, userMachineID)
		return nil
	}}
	revoke.Flags().Bool("yes", false, "confirm revocation")
	revoke.Flags().Bool("json", false, "print JSON")
	availability := &cobra.Command{Use: "availability <user-machine>", Short: "Set user-machine sleep availability", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		modeFlag, _ := command.Flags().GetString("mode")
		mode := strings.ReplaceAll(strings.TrimSpace(modeFlag), "-", "_")
		if mode != "allow_sleep" && mode != "keep_awake" {
			return errors.New("availability --mode must be allow-sleep or keep-awake")
		}
		confirmed, _ := command.Flags().GetBool("yes")
		if mode == "keep_awake" && !confirmed {
			return errors.New("keep-awake availability requires --yes because it can increase battery use and heat and may keep a closed-lid machine awake")
		}
		ctx := actionContext(command, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		machine, err := resolveUserMachine(ctx.Context, client, args[0])
		if err != nil {
			return friendlyCommandError(err)
		}
		fmt.Fprintf(command.ErrOrStderr(), "User machine: %s (%s)\n", machine.DisplayName, machine.ID)
		policy, err := client.SetUserMachineAvailability(ctx.Context, machine.ID, mode, newIdempotencyKey(), machine.Availability.DesiredVersion)
		if err != nil {
			return friendlyCommandError(err)
		}
		policy = waitForAvailabilityObservation(ctx.Context, client, machine.ID, policy, 5*time.Second)
		outcome := "pending"
		if policy.Status == "applied" && policy.ObservedVersion == policy.DesiredVersion && policy.ObservedMode == policy.DesiredMode {
			outcome = "applied"
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"version": "1", "user_machine": map[string]string{"id": machine.ID, "display_name": machine.DisplayName}, "availability": policy, "outcome": outcome, "retry": "automatic"})
		}
		if outcome == "applied" {
			fmt.Fprintf(command.OutOrStdout(), "Availability %s applied to %s.\n", strings.ReplaceAll(mode, "_", "-"), machine.DisplayName)
		} else {
			fmt.Fprintf(command.OutOrStdout(), "Availability %s saved for %s; application is durably %s.\n", strings.ReplaceAll(mode, "_", "-"), machine.DisplayName, policy.Status)
		}
		return nil
	}}
	availability.Flags().String("mode", "", "availability mode: allow-sleep or keep-awake")
	availability.Flags().Bool("yes", false, "confirm keep-awake power behavior")
	availability.Flags().Bool("json", false, "print JSON")
	machine.AddCommand(add, list, revoke, availability)
	return machine
}

func waitForAvailabilityObservation(ctx context.Context, client *api.Client, machineID string, current api.AvailabilityPolicy, timeout time.Duration) api.AvailabilityPolicy {
	if current.Status == "applied" && current.ObservedVersion == current.DesiredVersion && current.ObservedMode == current.DesiredMode {
		return current
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return current
		case <-ticker.C:
			machines, err := client.ListUserMachines(waitCtx)
			if err != nil {
				continue
			}
			for _, machine := range machines {
				if machine.ID != machineID || machine.Availability.DesiredVersion != current.DesiredVersion {
					continue
				}
				current = machine.Availability
				if current.Status == "applied" || current.Status == "unsupported" || current.Status == "error" || current.Status == "offline" {
					return current
				}
			}
		}
	}
}

func resolveUserMachineTarget(ctx context.Context, client *api.Client, requested string) (string, string, error) {
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return "", "", friendlyCommandError(err)
	}
	for _, machine := range machines {
		if machine.ID == requested {
			return machine.ID, machine.DisplayName, nil
		}
	}
	matches := make([]api.UserMachine, 0, 1)
	for _, machine := range machines {
		if strings.EqualFold(machine.DisplayName, requested) {
			matches = append(matches, machine)
		}
	}
	if len(matches) == 1 {
		return matches[0].ID, matches[0].DisplayName, nil
	}
	if len(matches) > 1 {
		return "", "", fmt.Errorf("machine name %q is ambiguous; use a stable machine ID", requested)
	}
	return "", "", fmt.Errorf("machine %q was not found", requested)
}

func actionRun(action command.Action) func(*cobra.Command, []string) error {
	return func(command *cobra.Command, args []string) error { return action(actionContext(command, args)) }
}

func actionContext(cobraCommand *cobra.Command, args []string) *command.Context {
	set := flag.NewFlagSet("pb", flag.ContinueOnError)
	values := map[string]string{}
	for _, name := range []string{"config", "server", "name", "session", "transport", "status-bar", "status-bar-fullscreen", "status-bar-theme"} {
		value, _ := cobraCommand.Flags().GetString(name)
		values[name] = value
		set.String(name, value, "")
	}
	hours, _ := cobraCommand.Flags().GetFloat64("hours")
	set.Float64("hours", hours, "")
	for _, name := range []string{"new", "json", "wide", "yes", "clear", "all"} {
		value, _ := cobraCommand.Flags().GetBool(name)
		values[name] = strconv.FormatBool(value)
		set.Bool(name, value, "")
	}
	_ = set.Parse(args)
	context := command.NewContext(set)
	context.Context = cobraCommand.Context()
	context.Writer = cobraCommand.OutOrStdout()
	context.ErrWriter = cobraCommand.ErrOrStderr()
	return context
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func newApp() *command.App {
	app := &command.App{}
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

func authCommand() *command.Spec {
	return &command.Spec{Name: "auth", Usage: "Manage Paperboat sign-in", Subcommands: []*command.Spec{
		{Name: "login", Usage: "Sign in through the Paperboat dashboard", Action: authLogin},
		{Name: "switch", Usage: "Replace the active account for this server", Action: func(c *command.Context) error { return authLoginMode(c, true) }},
		{Name: "status", Usage: "Show the active Paperboat account", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: authStatus},
		{Name: "logout", Usage: "Revoke and remove the active client session", Action: authLogout},
	}}
}

func requireAuthConfig(c *command.Context) (*config.Config, config.ProfileStore, error) {
	d, err := buildDeps(c)
	if err != nil {
		return nil, config.ProfileStore{}, err
	}
	if strings.TrimSpace(d.cfg.ServerURL) == "" {
		return nil, config.ProfileStore{}, errors.New("Paperboat server is not configured; set server_url or use --server")
	}
	s, err := config.ProfileStoreFor(d.cfg)
	if err != nil {
		return nil, config.ProfileStore{}, err
	}
	return d.cfg, s, nil
}

func authLogin(c *command.Context) error {
	return authLoginMode(c, false)
}

func authLoginMode(c *command.Context, replace bool) error {
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
			return errors.Join(fmt.Errorf("validate new session: %w", err), cleanupIssuedSession(cfg.ServerURL, tokens.CLIClientSessionID, tokens.RefreshToken, store))
		}
		p := config.Profile{Issuer: cfg.ServerURL, CLIClientSessionID: tokens.CLIClientSessionID, AccessExpiresAt: expires, Account: config.Account{ID: me.ID, Email: me.Email, DisplayName: me.DisplayName}}
		var saveErr error
		if previous != nil {
			saveErr = store.Switch(previous.CLIClientSessionID, p, cred)
		} else {
			saveErr = store.Save(p, cred)
		}
		if errors.Is(saveErr, config.ErrCredentialStoreUnavailable) && previous == nil && !cfg.Auth.AllowFileFallback {
			fallbackStore, fallbackErr := fileCredentialFallback(cfg)
			if fallbackErr == nil {
				store = fallbackStore
				saveErr = store.Save(p, cred)
			} else {
				saveErr = errors.Join(saveErr, fallbackErr)
			}
		}
		if saveErr != nil {
			return errors.Join(saveErr, cleanupIssuedSession(cfg.ServerURL, tokens.CLIClientSessionID, tokens.RefreshToken, store))
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

func fileCredentialFallback(cfg *config.Config) (config.ProfileStore, error) {
	cfg.Auth.AllowFileFallback = true
	if err := cfg.Save(); err != nil {
		return config.ProfileStore{}, fmt.Errorf("enable protected file credential storage: %w", err)
	}
	return config.ProfileStoreFor(cfg)
}

func cleanupIssuedSession(issuer, cliClientSessionID, refreshToken string, store config.ProfileStore) error {
	if err := store.QueueRevocation(issuer, cliClientSessionID, refreshToken); err != nil {
		if revokeErr := api.RevokeToken(context.Background(), issuer, refreshToken, nil); revokeErr != nil {
			return errors.Join(fmt.Errorf("retain failed session for revocation: %w", err), fmt.Errorf("revoke unretained session: %w", revokeErr))
		}
		return nil
	}
	_ = drainPendingRevocations(context.Background(), issuer, store)
	return nil
}

func authStatus(c *command.Context) error {
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
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"signed_in": true, "issuer": p.Issuer, "cli_client_session_id": p.CLIClientSessionID, "access_expires_at": p.AccessExpiresAt, "account": p.Account})
	}
	fmt.Printf("Signed in as %s\nServer: %s\nSession: %s\nAccess expires: %s\n", firstNonEmpty(p.Account.Email, p.Account.DisplayName, p.Account.ID), p.Issuer, p.CLIClientSessionID, p.AccessExpiresAt.Format(time.RFC3339))
	return nil
}

func authLogout(c *command.Context) error {
	cfg, store, err := requireAuthConfig(c)
	if err != nil {
		return err
	}
	var refreshTokens []string
	if credential, credentialErr := store.CredentialFor(cfg.ServerURL); credentialErr == nil && strings.TrimSpace(credential.RefreshToken) != "" {
		refreshTokens = append(refreshTokens, credential.RefreshToken)
	}
	if records, recordsErr := store.PendingRevocations(cfg.ServerURL); recordsErr == nil {
		for _, record := range records {
			credential, credentialErr := store.PendingRevocationCredential(record)
			if credentialErr == nil && strings.TrimSpace(credential.RefreshToken) != "" {
				refreshTokens = append(refreshTokens, credential.RefreshToken)
			}
		}
	}
	if _, removeErr := store.Remove(cfg.ServerURL); removeErr != nil && !errors.Is(removeErr, config.ErrNoCredentials) {
		// Remove may report an unreadable credential after successfully deleting
		// the profile. Only fail when local profile metadata still exists.
		if _, remainingErr := store.Load(cfg.ServerURL); !errors.Is(remainingErr, config.ErrNoCredentials) {
			return fmt.Errorf("remove local Paperboat session: %w", removeErr)
		}
	}
	if err := store.DiscardPendingRevocations(cfg.ServerURL); err != nil {
		return fmt.Errorf("clear local pending revocations: %w", err)
	}
	if len(refreshTokens) > 0 {
		revokeCtx, cancel := context.WithTimeout(c.Context, 2*time.Second)
		done := make(chan struct{}, len(refreshTokens))
		for _, refreshToken := range refreshTokens {
			go func(token string) {
				_ = api.RevokeToken(revokeCtx, cfg.ServerURL, token, nil)
				done <- struct{}{}
			}(refreshToken)
		}
		for range refreshTokens {
			select {
			case <-done:
			case <-revokeCtx.Done():
				cancel()
				fmt.Println("Signed out")
				return nil
			}
		}
		cancel()
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
			errs = append(errs, fmt.Errorf("revoke client session %s: %w", record.CLIClientSessionID, err))
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

var openBrowser = func(target string) error {
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

func backendClient(c *command.Context) (*api.Client, error) {
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
	environmentProject     = "project"
	environmentUserMachine = "user_machine"
)

func defaultEnvironment(ctx context.Context, client *api.Client, rememberedID string) (string, error) {
	if rememberedID = strings.TrimSpace(rememberedID); rememberedID != "" {
		return rememberedID, nil
	}
	projects, err := client.ListProjects(ctx)
	if err != nil && !api.IsHostedEntitlementRequired(err) {
		return "", friendlyCommandError(err)
	}
	if api.IsHostedEntitlementRequired(err) {
		projects = nil
	}
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return "", friendlyCommandError(err)
	}
	if len(projects)+len(machines) == 1 {
		if len(projects) == 1 {
			return projects[0].ID, nil
		}
		return machines[0].ID, nil
	}
	if len(projects)+len(machines) == 0 {
		return "", errors.New("no Paperboat environments are available; run `pb create` or `pb user-machine add`")
	}
	choices := make([]string, 0, len(projects)+len(machines))
	for _, project := range projects {
		choices = append(choices, fmt.Sprintf("%s (hosted, %s)", project.Name, project.ID))
	}
	for _, machine := range machines {
		choices = append(choices, fmt.Sprintf("%s (BYOD, %s)", machine.DisplayName, machine.ID))
	}
	return "", fmt.Errorf("multiple environments are available: %s; choose one with `pb <environment>`", strings.Join(choices, ", "))
}

func resolveEnvironmentTarget(ctx context.Context, client *api.Client, requested string) (environmentTarget, error) {
	project, err := resolveProjectID(ctx, client, requested)
	if err == nil {
		return environmentTarget{kind: environmentProject, id: project.ID, name: project.Name}, nil
	}
	if !errors.Is(err, resolver.ErrProjectNotFound) && !api.IsHostedEntitlementRequired(err) {
		return environmentTarget{}, err
	}
	machine, machineErr := resolveUserMachine(ctx, client, requested)
	if machineErr != nil {
		if api.IsNotFound(machineErr) {
			return environmentTarget{}, err
		}
		return environmentTarget{}, machineErr
	}
	return environmentTarget{kind: environmentUserMachine, id: machine.ID, name: machine.DisplayName}, nil
}

func listTerminalSessionsForTarget(ctx context.Context, client *api.Client, target environmentTarget) ([]api.TerminalSession, error) {
	if target.kind == environmentUserMachine {
		return client.ListUserMachineTerminalSessions(ctx, target.id)
	}
	return client.ListTerminalSessions(ctx, target.id)
}

func createTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, name, idempotencyKey string) (api.TerminalSession, error) {
	if target.kind == environmentUserMachine {
		return client.CreateUserMachineTerminalSession(ctx, target.id, name, idempotencyKey)
	}
	return client.CreateTerminalSession(ctx, target.id, name, idempotencyKey)
}

func renameTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID, name string) (api.TerminalSession, error) {
	if target.kind == environmentUserMachine {
		return client.RenameUserMachineTerminalSession(ctx, target.id, sessionID, name)
	}
	return client.RenameTerminalSession(ctx, target.id, sessionID, name)
}

func closeTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID string) error {
	if target.kind == environmentUserMachine {
		return client.CloseUserMachineTerminalSession(ctx, target.id, sessionID)
	}
	return client.CloseTerminalSession(ctx, target.id, sessionID)
}

func deleteTerminalSessionForTarget(ctx context.Context, client *api.Client, target environmentTarget, sessionID string) error {
	if target.kind == environmentUserMachine {
		return client.DeleteUserMachineTerminalSession(ctx, target.id, sessionID)
	}
	return client.DeleteTerminalSession(ctx, target.id, sessionID)
}

// deps bundles production dependencies for a command.
type deps struct {
	cfg              *config.Config
	auth             config.AuthSource
	resolver         resolver.ProjectResolver
	tunnel           tunnel.Tunnel
	terminalSelector *tunnel.TerminalTransportSelector
	telemetry        telemetry.Sink
}

func buildDeps(c *command.Context) (*deps, error) {
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
	websocketTunnel := tunnel.NewWebSocketTunnel()
	websocketTunnel.OutputQueueChunks = cfg.Connect.TerminalOutputQueueChunks
	quicTunnel := tunnel.NewQUICTunnel()
	quicTunnel.OutputQueueChunks = cfg.Connect.TerminalOutputQueueChunks
	transportMode := cfg.Connect.TerminalTransport
	if override := strings.TrimSpace(c.String("transport")); override != "" {
		transportMode = override
	}
	mode, err := tunnel.ParseTerminalTransport(transportMode)
	if err != nil {
		return nil, err
	}
	termTunnel, err := tunnel.NewTerminalTransportSelector(mode, quicTunnel, websocketTunnel)
	if err != nil {
		return nil, err
	}
	if err := termTunnel.SetPreferencePath(filepath.Join(filepath.Dir(cfg.Path()), "terminal-transport.json")); err != nil {
		return nil, fmt.Errorf("load terminal transport preference: %w", err)
	}
	var authSource config.AuthSource = config.NoCredentialsSource{}
	if cfg.ServerURL != "" {
		authSource, err = sessionauth.NewSource(cfg)
		if err != nil {
			return nil, err
		}
	}
	return &deps{
		cfg:              cfg,
		auth:             authSource,
		resolver:         nil,
		tunnel:           termTunnel,
		terminalSelector: termTunnel,
	}, nil
}

func projectsCommand() *command.Spec {
	return &command.Spec{
		Name:  "projects",
		Usage: "List projects available to this account",
		Flags: []command.Flag{&command.BoolFlag{Name: "json"}},
		Action: func(c *command.Context) error {
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

func environmentsCommand() *command.Spec {
	return &command.Spec{
		Name:  "environments",
		Usage: "List hosted projects and user machines",
		Flags: []command.Flag{&command.BoolFlag{Name: "json"}},
		Action: func(c *command.Context) error {
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
			machines, err := client.ListUserMachines(c.Context)
			if err != nil {
				return err
			}
			if c.Bool("json") {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"projects": projects, "user_machines": machines})
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
				fmt.Fprintf(w, "user_machine\t%s\t%s\t%s\n", machine.DisplayName, machine.ID, state)
			}
			return w.Flush()
		},
	}
}

func previewCommand() *command.Spec {
	return &command.Spec{Name: "preview", Usage: "Manage public previews", Subcommands: []*command.Spec{
		{Name: "list", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: previewListCommand},
		{Name: "revoke", ArgsUsage: "<preview-id>", Flags: []command.Flag{&command.BoolFlag{Name: "yes"}, &command.BoolFlag{Name: "json"}}, Action: previewRemoveCommand},
	}}
}

func previewListCommand(c *command.Context) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	items, err := client.ListPreviews(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"previews": items}})
	}
	w := tabwriter.NewWriter(c.Writer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPROJECT\tRESOURCE\tENVIRONMENT\tTYPE\tUSER\tOWNER\tSTATE\tURL\tPORT")
	for _, item := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", item.LogicalName, item.ProjectID, item.ResourceID, item.EnvironmentName, item.EnvironmentKind, item.UserID, item.OwnerEmail, item.State, item.URL, item.TargetPort)
	}
	return w.Flush()
}

func previewRemoveCommand(c *command.Context) error {
	if c.Args().Len() != 1 {
		return errors.New("usage: pb preview revoke <preview-id> --yes")
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	previewID := c.Args().First()
	items, err := client.ListPreviews(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	var selected api.Preview
	for _, item := range items {
		if item.ID == previewID {
			selected = item
			break
		}
	}
	if selected.ID == "" {
		return friendlyCommandError(fmt.Errorf("preview %q was not found", previewID))
	}
	fmt.Fprintf(c.ErrWriter, "Preview: %s (%s, %s)\n", selected.LogicalName, selected.EnvironmentName, selected.EnvironmentKind)
	fmt.Fprintf(c.ErrWriter, "Project: %s  Resource: %s  User: %s\n", selected.ProjectID, selected.ResourceID, selected.UserID)
	if !c.Bool("yes") {
		return errors.New("preview removal requires --yes")
	}
	item, err := client.RemovePreview(c.Context, previewID, newIdempotencyKey())
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"preview_id": item.ID, "state": item.State}})
	}
	fmt.Fprintf(c.Writer, "Removed preview %s.\n", item.LogicalName)
	return nil
}

func sessionsCommand() *command.Spec {
	list := func(c *command.Context) error {
		client, err := backendClient(c)
		if err != nil {
			return err
		}
		requested := strings.TrimSpace(c.Args().First())
		if requested == "" {
			cfg, loadErr := config.Load(c.String("config"))
			if loadErr != nil {
				return loadErr
			}
			requested, err = defaultEnvironment(c.Context, client, cfg.LastEnvironmentID)
			if err != nil {
				return err
			}
		}
		target, err := resolveEnvironmentTarget(c.Context, client, requested)
		if err != nil {
			return err
		}
		sessions, err := listTerminalSessionsForTarget(c.Context, client, target)
		if err != nil {
			return friendlyCommandError(err)
		}
		if c.Bool("json") {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "sessions": sessions})
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
	return &command.Spec{Name: "sessions", Usage: "Manage environment terminal sessions", ArgsUsage: "<environment>", Flags: []command.Flag{&command.BoolFlag{Name: "wide"}, &command.BoolFlag{Name: "json"}}, Action: list, Subcommands: []*command.Spec{
		{Name: "rename", ArgsUsage: "<environment> <session> <new-name>", Action: func(c *command.Context) error {
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
		{Name: "close", ArgsUsage: "<environment> [<session>]", Action: func(c *command.Context) error {
			all := c.Bool("all")
			if c.Args().Len() < 1 || c.Args().Len() > 2 || all == (c.Args().Len() == 2) {
				return errors.New("usage: pb session close <environment> <session> --yes OR pb session close <environment> --all --yes")
			}
			if !c.Bool("yes") {
				return errors.New("session close requires --yes")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			if all {
				sessions, err := listTerminalSessionsForTarget(c.Context, client, target)
				if err != nil {
					return friendlyCommandError(err)
				}
				var closeErrors []error
				closed := 0
				for _, session := range sessions {
					if session.State == "closed" {
						continue
					}
					if err := closeTerminalSessionForTarget(c.Context, client, target, session.ID); err != nil {
						closeErrors = append(closeErrors, fmt.Errorf("close session %s: %w", session.Name, err))
						continue
					}
					closed++
				}
				if len(closeErrors) > 0 {
					return fmt.Errorf("closed %d sessions in %s; remote state changed: %w", closed, target.name, errors.Join(closeErrors...))
				}
				fmt.Fprintf(c.Writer, "Closed %d sessions in %s.\n", closed, target.name)
				return nil
			}
			session, err := resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			if err != nil {
				return err
			}
			return friendlyCommandError(closeTerminalSessionForTarget(c.Context, client, target, session.ID))
		}, Flags: []command.Flag{&command.BoolFlag{Name: "yes", Usage: "confirm close"}, &command.BoolFlag{Name: "all", Usage: "close all sessions in the environment"}}},
		{Name: "delete", ArgsUsage: "<environment> <session>", Flags: []command.Flag{&command.BoolFlag{Name: "yes", Usage: "confirm deletion"}}, Action: func(c *command.Context) error {
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
	if !create && strings.TrimSpace(ref) == "" {
		// The descriptor endpoint owns default-session resolution. Avoid resolving
		// the environment once here and again immediately before dialing.
		return "", nil
	}
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
		if session.EvictedSession != nil {
			fmt.Fprintf(os.Stderr, "Session limit reached; removed least-recent session %q (%s).\n", session.EvictedSession.Name, session.EvictedSession.State)
		}
		return session.ID, nil
	}
	session, err := resolveTerminalSession(ctx, client, target, ref)
	if err != nil {
		return "", err
	}
	return session.ID, nil
}

func resolveUserMachine(ctx context.Context, client *api.Client, requested string) (api.UserMachine, error) {
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return api.UserMachine{}, err
	}
	for _, machine := range machines {
		if machine.ID == requested {
			return machine, nil
		}
	}
	var matches []api.UserMachine
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
		return api.UserMachine{}, fmt.Errorf("%w: %q matches user-machine IDs %s; use an exact ID", resolver.ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return api.UserMachine{}, fmt.Errorf("%w: %q", resolver.ErrProjectNotFound, requested)
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

func actionConnect(c *command.Context) error {
	return actionConnectTarget(c, "")
}

func actionConnectTarget(c *command.Context, requested string) error {
	project := strings.TrimSpace(requested)
	if project == "" {
		project = c.Args().First()
	}
	if project == "" && strings.TrimSpace(c.String("server")) != "" {
		cfg, err := config.Load(c.String("config"))
		if err != nil {
			return err
		}
		cfg.ServerURL, err = config.NormalizeServerURL(c.String("server"))
		if err != nil {
			return err
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, cfg.Path())
		return nil
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
	cred, err := d.auth.Credential()
	if err != nil && !errors.Is(err, config.ErrNoCredentials) {
		return err
	}
	if errors.Is(err, config.ErrNoCredentials) {
		return errors.New("not signed in to Paperboat; run `pb login`, then retry")
	}
	backend := api.New(d.cfg.ServerURL, cred, nil)
	if project == "" {
		project, err = defaultEnvironment(c.Context, backend, d.cfg.LastEnvironmentID)
		if err != nil {
			return err
		}
	}
	statusConfig := d.cfg.StatusBar
	if value := strings.TrimSpace(c.String("status-bar")); value != "" {
		statusConfig.Mode = strings.ToLower(value)
	}
	if value := strings.TrimSpace(c.String("status-bar-fullscreen")); value != "" {
		statusConfig.Fullscreen = strings.ToLower(value)
	}
	if value := strings.TrimSpace(c.String("status-bar-theme")); value != "" {
		statusConfig.Theme = strings.ToLower(value)
	}
	bar := statusbar.New(statusbar.Options{
		Mode:          statusConfig.Mode,
		Fullscreen:    statusConfig.Fullscreen,
		Theme:         statusConfig.Theme,
		Privacy:       statusConfig.Privacy,
		TerminalTitle: statusConfig.TerminalTitle,
		Colors: statusbar.Colors{
			Foreground: statusConfig.Colors.Foreground,
			Background: statusConfig.Colors.Background,
			Accent:     statusConfig.Colors.Accent,
			Warning:    statusConfig.Colors.Warning,
			Error:      statusConfig.Colors.Error,
		},
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
	d.terminalSelector.Observer = func(selection tunnel.TerminalTransportSelection, outcome string) {
		stage := fmt.Sprintf("requested.%s.selected.%s.fallback.%s", selection.Requested, firstNonEmpty(selection.Selected, "none"), selection.Fallback)
		event := telemetry.Event{Name: "terminal.transport", At: time.Now(), Outcome: outcome, Stage: stage}
		if event.Validate() == nil {
			d.telemetry.Record(event)
		}
	}

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
	recordReplayGap := func(requested, earliest, _ uint64) {
		missing := uint64(0)
		if earliest > requested {
			missing = earliest - requested
		}
		event := telemetry.Event{Name: "terminal.replay_gap", At: time.Now(), Outcome: "recovered", ProjectID: info.ProjectID, Count: int64(min(missing, math.MaxInt64))}
		if info.Terminal != nil {
			event.EnvironmentID = info.Terminal.EnvironmentID
		}
		if event.Validate() == nil {
			d.telemetry.Record(event)
		}
	}
	configureFileTransferRefresh := func(client *filetransfer.Client) {
		if client == nil {
			return
		}
		client.RefreshAuth = func(refreshCtx context.Context) (filetransfer.Auth, error) {
			freshCred, err := d.auth.Credential()
			if err != nil {
				return filetransfer.Auth{}, err
			}
			projectToken := project
			if info.ProjectID != "" {
				projectToken = info.ProjectID
			}
			freshInfo, err := newResolver(freshCred).Resolve(refreshCtx, resolver.ConnectRequest{Project: projectToken, Credential: freshCred, TerminalSessionID: terminalSessionID})
			if err != nil {
				return filetransfer.Auth{}, fmt.Errorf("refresh file transfer descriptor: %w", err)
			}
			if freshInfo.FileTransfer == nil {
				return filetransfer.Auth{}, errors.New("refresh file transfer descriptor: target missing")
			}
			return filetransfer.Auth{Token: freshInfo.FileTransfer.Auth.Token, ExpiresAt: parseAuthExpiry(freshInfo.FileTransfer.Auth.ExpiresAt)}, nil
		}
	}
	var transferClient *filetransfer.Client
	for attempt := 0; attempt <= d.cfg.Connect.DialRetries; attempt++ {
		info, err = d.resolver.Resolve(ctx, resolver.ConnectRequest{Project: project, Credential: cred, TerminalSessionID: terminalSessionID})
		if err == nil {
			if info.Terminal != nil {
				info.Terminal.RestartIfNotRunning = true
				info.Terminal.ReplayHistory = true
				info.Terminal.SequenceSink = recordTerminalSequence
				info.Terminal.ReplayGapSink = recordReplayGap
				info.Terminal.Env = forwardedTerminalEnv(config.TerminalEnv)
				info.Terminal.Cols, info.Terminal.Rows = remoteSize()
			}
			if transferClient != nil {
				_ = transferClient.Close()
			}
			transferClient = fileTransferClientForTarget(info.FileTransfer)
			configureFileTransferRefresh(transferClient)
			if transferClient != nil {
				if policyErr := transferClient.VerifyPolicy(ctx, descriptorFileTransferPolicy(info.FileTransfer)); policyErr != nil {
					transferClient = nil
					if useStatusBar {
						bar.FailureFor("file_transfer", "File transfer unavailable")
					} else {
						fmt.Fprintln(os.Stderr, "File transfer unavailable:", policyErr)
					}
				}
			}
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
	defer func() {
		if transferClient != nil {
			_ = transferClient.Close()
		}
	}()
	if d.cfg.LastEnvironmentID != info.ProjectID {
		d.cfg.LastEnvironmentID = info.ProjectID
		if err := d.cfg.Save(); err != nil {
			_ = conn.Close()
			return fmt.Errorf("remember connected environment: %w", err)
		}
	}
	if useStatusBar {
		bar.SetConnection("connected")
		bar.Notice("Connected")
		bar.ClearRemoteViewport()
	} else if term.IsTerminal(int(os.Stdout.Fd())) {
		_, _ = fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H")
	}
	var inboxMu sync.Mutex
	var cancelInbox context.CancelFunc
	stopInbox := func() {
		inboxMu.Lock()
		if cancelInbox != nil {
			cancelInbox()
			cancelInbox = nil
		}
		inboxMu.Unlock()
	}
	startInbox := func(client *filetransfer.Client, sessionID string) {
		stopInbox()
		if client == nil || sessionID == "" {
			return
		}
		notify := func(message string) {
			if useStatusBar {
				bar.Notice(message)
				return
			}
			fmt.Fprintln(os.Stderr, message)
		}
		receiver, inboxErr := inbox.New(inbox.Config{Client: client, SessionID: sessionID, Notify: notify})
		if inboxErr != nil {
			notify("File delivery unavailable: " + inboxErr.Error())
			return
		}
		pollCtx, cancel := context.WithCancel(ctx)
		inboxMu.Lock()
		cancelInbox = cancel
		inboxMu.Unlock()
		go func() { _ = receiver.Run(pollCtx) }()
	}
	defer stopInbox()
	var pastePolicy *paste.Policy
	conn = tunnel.NewObservedReconnectingConn(ctx, conn, d.cfg.Connect.DialRetries, time.Duration(d.cfg.Connect.DialRetrySeconds)*time.Second, func(reconnectCtx context.Context) (tunnel.Conn, error) {
		freshCred, credErr := d.auth.Credential()
		if credErr != nil {
			return nil, credErr
		}
		freshResolver := newResolver(freshCred)
		freshInfo, resolveErr := freshResolver.Resolve(reconnectCtx, resolver.ConnectRequest{Project: info.ProjectID, Credential: freshCred, TerminalSessionID: terminalSessionID})
		if resolveErr != nil {
			var apiErr *api.APIError
			if errors.As(resolveErr, &apiErr) && apiErr.Code == "user_machine_revoked" {
				resolveErr = tunnel.StopReconnect(resolveErr)
			}
			return nil, resolveErr
		}
		if freshInfo.Terminal != nil {
			freshInfo.Terminal.RestartIfNotRunning = false
			freshInfo.Terminal.ReplayHistory = false
			freshInfo.Terminal.AfterSequence = int(lastTerminalSequence.Load())
			freshInfo.Terminal.SequenceSink = recordTerminalSequence
			freshInfo.Terminal.ReplayGapSink = recordReplayGap
			freshInfo.Terminal.Env = forwardedTerminalEnv(config.TerminalEnv)
			freshInfo.Terminal.Cols, freshInfo.Terminal.Rows = remoteSize()
		}
		freshConn, dialErr := d.tunnel.Dial(reconnectCtx, freshInfo)
		if dialErr != nil {
			if !tunnel.FallbackEligible(dialErr) {
				return nil, tunnel.StopReconnect(dialErr)
			}
			return nil, dialErr
		}
		if pastePolicy != nil {
			freshTransfer := transferClient
			if freshInfo.FileTransfer == nil {
				freshTransfer = nil
			} else if freshTransfer == nil {
				freshTransfer = fileTransferClientForTarget(freshInfo.FileTransfer)
				transferClient = freshTransfer
				configureFileTransferRefresh(freshTransfer)
			} else {
				freshTransfer.UpdateAuth(filetransfer.Auth{Token: freshInfo.FileTransfer.Auth.Token, ExpiresAt: parseAuthExpiry(freshInfo.FileTransfer.Auth.ExpiresAt)})
				if policyErr := freshTransfer.VerifyPolicy(reconnectCtx, descriptorFileTransferPolicy(freshInfo.FileTransfer)); policyErr != nil {
					freshTransfer = nil
				}
			}
			pastePolicy.Update(freshTransfer, freshInfo.Terminal.SessionID, fileTransferLimits(freshInfo.FileTransfer))
			startInbox(freshTransfer, freshInfo.Terminal.SessionID)
		}
		return freshConn, nil
	}, d.telemetry, nil, tunnel.TelemetryContext{ProjectID: info.ProjectID, EnvironmentID: info.Terminal.EnvironmentID}, tunnel.WithReconnectingOutput(
		d.cfg.Connect.TerminalOutputQueueChunks,
		time.Duration(d.cfg.Connect.TerminalOutputBatchMilliseconds)*time.Millisecond,
	), tunnel.WithReconnectObserver(func(event tunnel.ReconnectEvent) {
		if event == tunnel.ReconnectRecovered {
			bar.ResetRemoteState()
			cols, rows := remoteSize()
			forceTerminalRedraw(conn, rows, cols)
		}
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

	// Wrap remote input with the file-paste interceptor.
	pastePolicy = paste.NewPolicy(transferClient, info.Terminal.SessionID, fileTransferLimits(info.FileTransfer))
	interceptor := paste.NewWithPolicy(conn, pastePolicy,
		paste.WithDirectInput(),
		paste.WithNotifier(statusNotifier(useStatusBar)),
		paste.WithLifecycle(func(event paste.LifecycleEvent) {
			if !useStatusBar {
				return
			}
			switch event {
			case paste.FileDetected:
				bar.LoadingPersistent("Preparing file")
			case paste.FileUploading:
				bar.LoadingPersistent("Uploading file")
			case paste.FileComplete:
				bar.RecoverFailureFor("upload")
				bar.Notice("File uploaded")
			case paste.FileFailed:
				bar.FailureFor("upload", "File upload failed; pasted original")
			}
		}),
		paste.WithWatchDirs(expandDirs(d.cfg.FilePaste.WatchDirs)),
		paste.WithTempFilePatterns(d.cfg.FilePaste.TempFilePatterns),
		paste.WithMaxQueuedBytes(d.cfg.FilePaste.MaxQueuedInputBytes),
		paste.WithPartialFlushDelay(time.Duration(d.cfg.Connect.InputPartialFlushMilliseconds)*time.Millisecond),
	)
	startInbox(transferClient, info.Terminal.SessionID)

	if useStatusBar && info.TargetKind == "project" {
		pollCtx, cancelPoll := context.WithCancel(ctx)
		defer cancelPoll()
		go pollConfigSync(pollCtx, d.cfg.ServerURL, d.auth, info.ProjectID, 30*time.Second, bar)
	}
	runOptions := []session.RunOption{
		session.WithOutputBufferBytes(d.cfg.Connect.TerminalOutputBufferBytes),
		session.WithBracketedPaste(),
	}
	if useStatusBar {
		bar.SetViewportChanged(func(cols, rows uint16) {
			if cols > 0 && rows > 0 {
				_ = conn.Resize(rows, cols)
			}
		})
		runOptions = append(runOptions, session.WithOutput(bar), session.WithRemoteSize(remoteSize))
	}
	code, err := session.Run(ctx, conn, interceptor, runOptions...)
	if err == nil {
		if useStatusBar {
			bar.ClearForExit()
		} else if term.IsTerminal(int(os.Stdout.Fd())) {
			_, _ = fmt.Fprint(os.Stdout, "\x1b[r\x1b[2J\x1b[H")
		}
	}
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCodeError{code: code}
	}
	return nil
}

func forceTerminalRedraw(conn tunnel.Conn, rows, cols uint16) {
	probeRows, probeCols := rows, cols
	if probeRows > 1 {
		probeRows--
	} else if probeCols > 1 {
		probeCols--
	}
	if probeRows != rows || probeCols != cols {
		_ = conn.Resize(probeRows, probeCols)
	}
	_ = conn.Resize(rows, cols)
}

func createProject(c *command.Context) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("pb create requires an interactive terminal")
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	repositories, err := client.ListGitHubRepositories(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	machineTypes, err := client.ListCatalogMachineTypes(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	regions, err := client.ListCatalogRegions(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	if len(repositories) == 0 {
		return errors.New("no GitHub repositories are available; connect GitHub in the Paperboat dashboard")
	}
	reader := bufio.NewReader(os.Stdin)
	repositoryIndex, err := promptChoice(reader, "Repository", len(repositories), func(index int) string { return repositories[index].FullName })
	if err != nil {
		return err
	}
	machineCodes := activeMachineCodes(machineTypes)
	regionCodes := enabledRegionCodes(regions)
	if len(machineCodes) == 0 || len(regionCodes) == 0 {
		return errors.New("hosted project catalog has no available machine type or region")
	}
	machineIndex, err := promptChoice(reader, "Machine type", len(machineCodes), func(index int) string { return machineCodes[index] })
	if err != nil {
		return err
	}
	regionIndex, err := promptChoice(reader, "Region", len(regionCodes), func(index int) string { return regionCodes[index] })
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Storage (GB): ")
	storageText, err := reader.ReadString('\n')
	if err != nil {
		return errors.New("project creation cancelled")
	}
	storageGB, err := strconv.Atoi(strings.TrimSpace(storageText))
	if err != nil || storageGB <= 0 {
		return errors.New("storage must be a positive whole number of GB")
	}
	repository := repositories[repositoryIndex]
	project, err := client.CreateProject(c.Context, api.CreateProjectInput{
		Name: c.Args().First(), RepositoryURL: repository.CloneURL, DefaultBranch: repository.DefaultBranch,
		StorageGB: storageGB, MachineTypeCode: machineCodes[machineIndex], RegionCode: regionCodes[regionIndex],
	}, newIdempotencyKey())
	if err != nil {
		return friendlyCommandError(err)
	}
	fmt.Fprintf(os.Stderr, "Created hosted project %s (%s).\n", project.Name, project.ID)
	return actionConnectTarget(c, project.ID)
}

func promptChoice(reader *bufio.Reader, label string, count int, value func(int) string) (int, error) {
	for index := 0; index < count; index++ {
		fmt.Fprintf(os.Stderr, "%d. %s\n", index+1, value(index))
	}
	fmt.Fprintf(os.Stderr, "%s [1-%d]: ", label, count)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, errors.New("project creation cancelled")
	}
	selection, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || selection < 1 || selection > count {
		return 0, fmt.Errorf("%s selection must be between 1 and %d", strings.ToLower(label), count)
	}
	return selection - 1, nil
}

func activeMachineCodes(items []api.CatalogMachineType) []string {
	var out []string
	for _, item := range items {
		if item.Active {
			out = append(out, item.Code)
		}
	}
	return out
}

func enabledRegionCodes(items []api.CatalogRegion) []string {
	var out []string
	for _, item := range items {
		if item.Enabled {
			out = append(out, item.Code)
		}
	}
	return out
}

func requestedSessionLabel(c *command.Context) string {
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
		strings.Contains(msg, "dial terminal websocket") ||
		strings.Contains(msg, "websocket route") ||
		strings.Contains(msg, "transport lost")
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
	case "tunnel_unavailable":
		return "the secure tunnel is not available yet; retry in a moment"
	case "machine_not_ready":
		return "the project machine is not ready yet; retry in a moment"
	case "user_machine_offline":
		return "the user machine is offline; start or repair its Paperboat connector, then retry"
	case "user_machine_revoked":
		return "this user machine has been disconnected or revoked; repair or reconnect it in the Paperboat dashboard"
	}
	return ""
}

func fileTransferClientForTarget(target *resolver.FileTransferTarget) *filetransfer.Client {
	if target == nil || target.Endpoint == "" || target.Auth.Method != "bearer" || target.Auth.Token == "" {
		return nil
	}
	selector, err := filetransfer.NewTransportSelector(filetransfer.TransportSelectorConfig{})
	if err != nil {
		return nil
	}
	client := &http.Client{Transport: selector, Timeout: 5 * time.Minute}
	return filetransfer.NewClient(target.Endpoint, filetransfer.Auth{Token: target.Auth.Token, ExpiresAt: parseAuthExpiry(target.Auth.ExpiresAt)}, client)
}

func fileTransferLimits(target *resolver.FileTransferTarget) filetransfer.Limits {
	if target == nil {
		return filetransfer.Limits{MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20}
	}
	return filetransfer.Limits{MaxFileBytes: target.Policy.MaxFileBytes, MaxBatchFiles: target.Policy.MaxBatchFiles, MaxBatchBytes: target.Policy.MaxBatchBytes}
}

func descriptorFileTransferPolicy(target *resolver.FileTransferTarget) filetransfer.Policy {
	if target == nil {
		return filetransfer.Policy{}
	}
	policy := target.Policy
	return filetransfer.Policy{Revision: policy.Revision, MaxFileBytes: policy.MaxFileBytes, MaxBatchFiles: policy.MaxBatchFiles, MaxBatchBytes: policy.MaxBatchBytes, MaxConcurrentTransfers: policy.MaxConcurrentTransfers, RetentionSeconds: policy.RetentionSeconds, DeliveryTimeoutSeconds: policy.DeliveryTimeoutSeconds, MaxPendingSpoolBytes: policy.MaxPendingSpoolBytes}
}

func parseAuthExpiry(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

// terminalEnvKeyPattern mirrors the terminal RPC environment schema; an invalid
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
// terminal RPC schema bounds, or zeros when stdout is not a terminal.
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

func configCommand() *command.Spec {
	return &command.Spec{
		Name:  "config",
		Usage: "Inspect the local CLI config",
		Subcommands: []*command.Spec{
			{
				Name: "assign", ArgsUsage: "<repository> <environment>", Usage: "Assign a config repository to a hosted environment",
				Action: configAssign,
			},
			{
				Name: "unassign", ArgsUsage: "<environment>", Usage: "Remove a config repository assignment",
				Action: configUnassign,
			},
			{
				Name: "set", ArgsUsage: "<key> <value>", Usage: "Set a local configuration value",
				Action: func(c *command.Context) error {
					if c.Args().Len() != 2 {
						return errors.New("usage: pb config set server <url>")
					}
					cfg, err := config.Load(c.String("config"))
					if err != nil {
						return err
					}
					switch c.Args().First() {
					case "server":
						server, err := config.NormalizeServerURL(c.Args().Get(1))
						if err != nil {
							return err
						}
						cfg.ServerURL = server
					default:
						return errors.New("usage: pb config set server <url>")
					}
					if err := cfg.Save(); err != nil {
						return err
					}
					fmt.Fprintln(os.Stdout, cfg.Path())
					return nil
				},
			},
			{
				Name: "unset", ArgsUsage: "server", Usage: "Remove a local configuration value",
				Action: func(c *command.Context) error {
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
				Action: func(c *command.Context) error {
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
				Flags: []command.Flag{&command.BoolFlag{Name: "json"}},
				Action: func(c *command.Context) error {
					d, err := buildDeps(c)
					if err != nil {
						return err
					}
					if c.Bool("json") {
						return json.NewEncoder(os.Stdout).Encode(map[string]any{"path": d.cfg.Path(), "server_url": d.cfg.ServerURL, "auth_file_fallback": d.cfg.Auth.AllowFileFallback, "file_paste": d.cfg.FilePaste, "status_bar": d.cfg.StatusBar})
					}
					fmt.Printf("server_url: %s\n", orNone(d.cfg.ServerURL))
					fmt.Printf("auth.file_fallback: %t\n", d.cfg.Auth.AllowFileFallback)
					fmt.Printf("file_paste.max_queued_input_bytes: %d\n", d.cfg.FilePaste.MaxQueuedInputBytes)
					fmt.Printf("status_bar.mode: %s\n", d.cfg.StatusBar.Mode)
					fmt.Printf("status_bar.fullscreen: %s\n", d.cfg.StatusBar.Fullscreen)
					fmt.Printf("status_bar.theme: %s\n", d.cfg.StatusBar.Theme)
					return nil
				},
			},
		},
	}
}

func statusBarConfigCommand() *cobra.Command {
	status := &cobra.Command{
		Use:   "status-bar",
		Short: "Configure the interactive terminal status bar",
		Args:  commandArgs(cobra.NoArgs),
		RunE:  func(command *cobra.Command, _ []string) error { return command.Help() },
	}
	show := &cobra.Command{Use: "show", Short: "Show the effective status-bar configuration", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPathFlag(command))
		if err != nil {
			return err
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(cfg.StatusBar)
		}
		return printStatusBarConfig(command.OutOrStdout(), cfg.StatusBar)
	}}
	show.Flags().Bool("json", false, "print JSON")
	set := &cobra.Command{Use: "set <key> <value>", Short: "Set a status-bar preference", Args: commandArgs(cobra.ExactArgs(2)), RunE: func(command *cobra.Command, args []string) error {
		cfg, err := config.Load(configPathFlag(command))
		if err != nil {
			return err
		}
		if err := setStatusBarValue(&cfg.StatusBar, args[0], args[1]); err != nil {
			return invocationError(err)
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Fprintln(command.OutOrStdout(), cfg.Path())
		return nil
	}}
	reset := &cobra.Command{Use: "reset", Short: "Restore status-bar defaults", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPathFlag(command))
		if err != nil {
			return err
		}
		cfg.StatusBar = config.DefaultStatusBarConfig()
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Fprintln(command.OutOrStdout(), cfg.Path())
		return nil
	}}
	preview := &cobra.Command{Use: "preview", Short: "Preview the configured status bar", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPathFlag(command))
		if err != nil {
			return err
		}
		width, _ := command.Flags().GetInt("width")
		if width == 0 {
			width = 80
			if term.IsTerminal(int(os.Stdout.Fd())) {
				if detected, _, sizeErr := term.GetSize(int(os.Stdout.Fd())); sizeErr == nil {
					width = detected
				}
			}
		}
		bar := newConfiguredStatusBar(cfg.StatusBar, statusbar.ModeOff)
		defer bar.Close()
		bar.SetIdentity("paperboat", "default")
		bar.SetUsage("100", "12 GB")
		bar.SetConfigSync("healthy")
		bar.SetConnection("connected")
		fmt.Fprintln(command.OutOrStdout(), bar.Render(width))
		bar.SetConnection("reconnecting")
		bar.Loading("Reconnecting")
		fmt.Fprintln(command.OutOrStdout(), bar.Render(width))
		bar.SetConnection("failed")
		bar.FailureFor("preview", "Connection lost")
		fmt.Fprintln(command.OutOrStdout(), bar.Render(width))
		return nil
	}}
	preview.Flags().Int("width", 0, "preview width (20-500 columns)")
	preview.PreRunE = func(command *cobra.Command, _ []string) error {
		width, _ := command.Flags().GetInt("width")
		if width != 0 && (width < 20 || width > 500) {
			return invocationError(errors.New("--width must be between 20 and 500"))
		}
		return nil
	}
	status.AddCommand(show, set, reset, preview)
	return status
}

func configPathFlag(command *cobra.Command) string {
	value, _ := command.Flags().GetString("config")
	return value
}

func printStatusBarConfig(writer io.Writer, value config.StatusBarConfig) error {
	_, err := fmt.Fprintf(writer, "mode: %s\nfullscreen: %s\ntheme: %s\nprivacy: %t\nterminal_title: %t\nnotice_seconds: %d\nleft: %s\ncenter: %s\nright: %s\nforeground: %s\nbackground: %s\naccent: %s\nwarning: %s\nerror: %s\n",
		value.Mode, value.Fullscreen, value.Theme, value.Privacy, value.TerminalTitle, value.NoticeSeconds,
		formatWidgetList(value.Left), formatWidgetList(value.Center), formatWidgetList(value.Right),
		inheritedColor(value.Colors.Foreground), inheritedColor(value.Colors.Background), inheritedColor(value.Colors.Accent), inheritedColor(value.Colors.Warning), inheritedColor(value.Colors.Error))
	return err
}

func inheritedColor(value string) string {
	if value == "" {
		return "inherit"
	}
	return value
}

func formatWidgetList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

func setStatusBarValue(value *config.StatusBarConfig, key, raw string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	raw = strings.TrimSpace(raw)
	switch key {
	case "mode":
		value.Mode = strings.ToLower(raw)
	case "fullscreen":
		value.Fullscreen = strings.ToLower(raw)
	case "theme":
		value.Theme = strings.ToLower(raw)
	case "privacy", "terminal-title":
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("%s must be true or false", key)
		}
		if key == "privacy" {
			value.Privacy = parsed
		} else {
			value.TerminalTitle = parsed
		}
	case "notice-seconds":
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 60 {
			return errors.New("notice-seconds must be between 1 and 60")
		}
		value.NoticeSeconds = parsed
	case "left", "center", "right":
		widgets := parseWidgetList(raw)
		switch key {
		case "left":
			value.Left = widgets
		case "center":
			value.Center = widgets
		case "right":
			value.Right = widgets
		}
	case "foreground", "background", "accent", "warning", "error":
		switch key {
		case "foreground":
			value.Colors.Foreground = raw
		case "background":
			value.Colors.Background = raw
		case "accent":
			value.Colors.Accent = raw
		case "warning":
			value.Colors.Warning = raw
		case "error":
			value.Colors.Error = raw
		}
	default:
		return fmt.Errorf("unknown status-bar key %q", key)
	}
	probe := &config.Config{Connect: config.ConnectConfig{TerminalTransport: config.DefaultTerminalTransport}, StatusBar: *value}
	return probe.Validate()
}

func parseWidgetList(raw string) []string {
	if raw == "" || strings.EqualFold(raw, "none") {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, strings.ToLower(strings.TrimSpace(part)))
	}
	return result
}

func newConfiguredStatusBar(value config.StatusBarConfig, mode string) *statusbar.Bar {
	return statusbar.New(statusbar.Options{
		Mode: mode, Fullscreen: value.Fullscreen, Theme: value.Theme, Privacy: value.Privacy, TerminalTitle: false,
		Colors:         statusbar.Colors{Foreground: value.Colors.Foreground, Background: value.Colors.Background, Accent: value.Colors.Accent, Warning: value.Colors.Warning, Error: value.Colors.Error},
		NoticeDuration: time.Duration(value.NoticeSeconds) * time.Second,
		Layout:         statusbar.Layout{Left: value.Left, Center: value.Center, Right: value.Right},
	})
}

func configAssign(c *command.Context) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	target, err := resolveEnvironmentTarget(c.Context, client, c.Args().Get(1))
	if err != nil {
		return err
	}
	if target.kind == environmentUserMachine {
		return errors.New("config assignment for BYOD environments requires dashboard consent and is not available in this release")
	}
	repositories, err := client.ListConfigRepositories(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	repository, err := resolveConfigRepository(repositories, c.Args().First())
	if err != nil {
		return err
	}
	expectedVersion := int64(0)
	current, getErr := client.ConfigAssignment(c.Context, target.id)
	if getErr == nil {
		expectedVersion = current.Version
	} else if !api.IsNotFound(getErr) {
		return friendlyCommandError(getErr)
	}
	assignment, err := client.AssignConfig(c.Context, target.id, repository.ID, expectedVersion)
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": "hosted", "display_name": target.name}, "repository": repository, "assignment": assignment, "outcome": "confirmed"})
	}
	fmt.Fprintf(c.Writer, "Assigned config repository %s to %s.\n", repository.DisplayName, target.name)
	return nil
}

func configUnassign(c *command.Context) error {
	if !c.Bool("yes") {
		return errors.New("config unassign requires --yes")
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
	if err != nil {
		return err
	}
	environmentID := target.id
	if target.kind == environmentUserMachine {
		machines, listErr := client.ListUserMachines(c.Context)
		if listErr != nil {
			return friendlyCommandError(listErr)
		}
		for _, machine := range machines {
			if machine.ID == target.id {
				environmentID = machine.EnvironmentID
				break
			}
		}
		if environmentID == target.id {
			return errors.New("user machine does not expose its environment identity; update paperboat-server")
		}
	}
	assignment, err := client.ConfigAssignment(c.Context, environmentID)
	if err != nil {
		return friendlyCommandError(err)
	}
	if err := client.UnassignConfig(c.Context, environmentID, assignment.Version); err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "state": "unassigned", "outcome": "confirmed"})
	}
	fmt.Fprintf(c.Writer, "Removed config assignment from %s.\n", target.name)
	return nil
}

func resolveConfigRepository(items []api.ConfigRepository, requested string) (api.ConfigRepository, error) {
	for _, item := range items {
		if item.ID == requested {
			return item, nil
		}
	}
	matches := make([]api.ConfigRepository, 0, 1)
	for _, item := range items {
		if strings.EqualFold(item.DisplayName, requested) || strings.EqualFold(item.ExternalRef, requested) {
			matches = append(matches, item)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return api.ConfigRepository{}, fmt.Errorf("config repository %q is ambiguous; use a stable repository ID", requested)
	}
	return api.ConfigRepository{}, fmt.Errorf("config repository %q was not found", requested)
}

func doctorCommand() *command.Spec {
	return &command.Spec{
		Name:      "doctor",
		Usage:     "Check authentication and connectivity",
		ArgsUsage: "[project]",
		Flags:     []command.Flag{&command.BoolFlag{Name: "json"}},
		Action: func(c *command.Context) error {
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
				fmt.Printf("terminal:    descriptor unavailable: %v\n", err)
				return fmt.Errorf("doctor: descriptor check failed: %w", err)
			}
			if info.Terminal == nil {
				fmt.Println("terminal:    descriptor missing terminal endpoint")
				return errors.New("doctor: descriptor missing terminal endpoint")
			}
			fmt.Printf("environment:  %s (%s) ✓\n", info.ProjectID, firstNonEmpty(info.ProjectState, "ready"))
			fmt.Println("entitlement:  connect authorization accepted ✓")
			diagnosticState := "ready"
			if info.TargetKind == "user_machine" {
				machine, machineErr := doctorUserMachine(c.Context, api.New(d.cfg.ServerURL, cred, nil), info.ProjectID)
				if machineErr != nil {
					fmt.Printf("diagnostics:  unavailable: %v\n", machineErr)
					return fmt.Errorf("doctor: user-machine diagnostics failed: %w", machineErr)
				}
				printUserMachineDoctor(machine)
				diagnosticState, _ = userMachineDoctorState(machine)
			} else {
				fmt.Println("fly readiness: ready ✓")
			}
			selection, err := d.terminalSelector.Check(c.Context, info.Terminal)
			if err != nil {
				fmt.Printf("transport:    requested %s, selected %s, fallback %s\n", selection.Requested, firstNonEmpty(selection.Selected, "none"), selection.Fallback)
				return errors.New("doctor: terminal transport or protocol check failed")
			}
			fmt.Printf("transport:    requested %s, selected %s, fallback %s ✓\n", selection.Requested, selection.Selected, selection.Fallback)
			fmt.Printf("terminal:    route/auth ready for %s ✓\n", info.Project)
			fmt.Println("protocol:    paperboat.terminal.v2 ✓")
			if diagnosticState != "ready" {
				return errors.New("doctor: user-machine runtime diagnostics require attention")
			}
			return nil
		},
	}
}

func doctorJSON(c *command.Context, d *deps) error {
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
	selection, err := d.terminalSelector.Check(c.Context, info.Terminal)
	result["terminal_transport"] = map[string]string{"requested": string(selection.Requested), "selected": selection.Selected, "fallback": selection.Fallback}
	if err != nil {
		result["project"] = info.ProjectID
		result["connect"] = "transport_error"
		result["connect_error"] = "terminal transport or protocol check failed"
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return errors.New("doctor: terminal transport or protocol check failed")
	}
	result["project"] = map[string]string{"id": info.ProjectID, "name": info.Project, "state": info.ProjectState}
	result["environment_type"] = info.TargetKind
	diagnosticState := "ready"
	if info.TargetKind == "user_machine" {
		machine, machineErr := doctorUserMachine(c.Context, client, info.ProjectID)
		if machineErr != nil {
			result["user_machine_diagnostics"] = map[string]any{"state": "error", "error_code": "diagnostics_unavailable"}
			_ = json.NewEncoder(os.Stdout).Encode(result)
			return fmt.Errorf("doctor: user-machine diagnostics failed: %w", machineErr)
		}
		result["user_machine_diagnostics"] = userMachineDoctorJSON(machine)
		diagnosticState, _ = userMachineDoctorState(machine)
	}
	result["connect"] = "ready"
	result["protocol"] = "paperboat-terminal-rpc/v1"
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if diagnosticState != "ready" {
		return errors.New("doctor: user-machine runtime diagnostics require attention")
	}
	return nil
}

func doctorUserMachine(ctx context.Context, client *api.Client, machineID string) (api.UserMachine, error) {
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return api.UserMachine{}, err
	}
	for _, machine := range machines {
		if machine.ID == machineID {
			return machine, nil
		}
	}
	return api.UserMachine{}, errors.New("resolved user machine is missing from the account")
}

func printUserMachineDoctor(machine api.UserMachine) {
	diagnostics := machine.RuntimeDiagnostics
	availability := machine.Availability
	fmt.Printf("boot service: %s\n", firstNonEmpty(diagnostics.WorkerServiceScope, "unknown"))
	fmt.Printf("worker:      generation %d, OS boot %s\n", diagnostics.WorkerGeneration, firstNonEmpty(diagnostics.OSBootID, "unknown"))
	fmt.Printf("connector:   %s (generation %d)\n", firstNonEmpty(diagnostics.ConnectorState, "unavailable"), diagnostics.ConnectorGeneration)
	fmt.Printf("availability: desired %s v%d, observed %s v%d (%s)\n", availability.DesiredMode, availability.DesiredVersion, firstNonEmpty(availability.ObservedMode, "unknown"), availability.ObservedVersion, availability.Status)
	if diagnostics.WorkerServiceScope != "system" {
		fmt.Println("recovery:     run pbh bootstrap to install the boot-level system service")
	}
	if availability.Status != "applied" || availability.ObservedVersion != availability.DesiredVersion || availability.ObservedMode != availability.DesiredMode {
		fmt.Println("recovery:     inspect pbh doctor --json and paperboat-host-service logs; policy retry is automatic")
	}
}

func userMachineDoctorJSON(machine api.UserMachine) map[string]any {
	diagnostics := machine.RuntimeDiagnostics
	availability := machine.Availability
	state, errorCode := userMachineDoctorState(machine)
	return map[string]any{
		"state": state, "error_code": errorCode,
		"boot_service_scope": diagnostics.WorkerServiceScope,
		"worker_generation":  diagnostics.WorkerGeneration, "os_boot_id": diagnostics.OSBootID,
		"connector_state": diagnostics.ConnectorState, "connector_generation": diagnostics.ConnectorGeneration,
		"availability": availability,
	}
}

func userMachineDoctorState(machine api.UserMachine) (string, string) {
	diagnostics := machine.RuntimeDiagnostics
	availability := machine.Availability
	if diagnostics.WorkerServiceScope != "system" || diagnostics.WorkerGeneration < 1 {
		return "error", "boot_service_not_system"
	} else if diagnostics.ConnectorState != "ready" {
		return "degraded", "connector_recovering"
	} else if availability.Status != "applied" || availability.ObservedVersion != availability.DesiredVersion || availability.ObservedMode != availability.DesiredMode {
		return "degraded", "availability_drift"
	}
	return "ready", ""
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
