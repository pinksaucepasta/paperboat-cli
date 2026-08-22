// Command pb is the invisible terminal wrapper for the
// Paperboat platform. `pb <environment>` attaches a hosted project or enrolled
// machine through Paperboat auth and bridges local file pastes into
// remote TUIs. Cross-service calls run behind interfaces so protocol behavior
// remains independently testable.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/pinksaucepasta/paperboat/internal/api"
	sessionauth "github.com/pinksaucepasta/paperboat/internal/auth"
	bugreportpkg "github.com/pinksaucepasta/paperboat/internal/bugreport"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	codexsession "github.com/pinksaucepasta/paperboat/internal/codexsession"
	"github.com/pinksaucepasta/paperboat/internal/command"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	doctorpkg "github.com/pinksaucepasta/paperboat/internal/doctor"
	"github.com/pinksaucepasta/paperboat/internal/fileindex"
	filetransfer "github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	helperconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/servelease"
	service "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
	"github.com/pinksaucepasta/paperboat/internal/hostruntimecmd"
	"github.com/pinksaucepasta/paperboat/internal/hostruntimeentry"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/inbox"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"github.com/pinksaucepasta/paperboat/internal/localwait"
	"github.com/pinksaucepasta/paperboat/internal/machinename"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/paste"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/recoverykey"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
	"github.com/pinksaucepasta/paperboat/internal/processlifetime"
	"github.com/pinksaucepasta/paperboat/internal/prompt"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/pinksaucepasta/paperboat/internal/selector"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
	"github.com/pinksaucepasta/paperboat/internal/session"
	"github.com/pinksaucepasta/paperboat/internal/statusbar"
	"github.com/pinksaucepasta/paperboat/internal/telemetry"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
	"github.com/pinksaucepasta/paperboat/internal/userpaths"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
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

func terminalArgs(minimum int) cobra.PositionalArgs {
	return func(_ *cobra.Command, values []string) error {
		if len(values) < minimum || len(values) > 2 {
			return fmt.Errorf("accepts between %d and 2 arg(s), received %d", minimum, len(values))
		}
		if len(values) == 2 && values[1] != "new" {
			return fmt.Errorf("second argument must be `new`")
		}
		return nil
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
	if errors.Is(err, selector.ErrCanceled) || errors.Is(err, selector.ErrInterrupted) {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "pb: Operation canceled.")
		return 130
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
	if message := userFacingError(err); message != "" {
		fmt.Fprintln(stderr, "pb:", message)
	}
	return 1
}

func userFacingError(err error) string {
	if err == nil {
		return ""
	}
	var peerFailure *connectionmanager.Failure
	if errors.As(err, &peerFailure) {
		return "The secure connection could not be established. Retry; if this continues, run `pb doctor`."
	}
	if errors.Is(err, context.Canceled) {
		return "Operation canceled."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	if errors.Is(err, tunnel.ErrTransportLost) {
		return "The terminal connection was lost and could not be restored. Retry `pb`; if this continues, run `pb doctor`."
	}
	if errors.Is(err, api.ErrUnauthenticated) {
		return "Your Paperboat session is no longer valid. Run `pb auth login`, then retry."
	}
	if errors.Is(err, config.ErrSecretNotFound) {
		return "This CLI is signed in but not paired for private transport. Run `pb auth login --recovery-key /absolute/recovery-key-file`."
	}
	if errors.Is(err, identitybootstrap.ErrPairingRequired) {
		return "This CLI needs the account recovery key before private transport can be enabled. Rerun `pb auth login --recovery-key /absolute/recovery-key-file`."
	}
	if message := friendlyAPIError(err); message != "" {
		return sentence(message)
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		message := apiErrorFallback(apiErr)
		if apiErr.RequestID != "" {
			message += " Request ID: " + apiErr.RequestID + "."
		}
		return message
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return "Paperboat is unreachable. Check your network connection and retry; if the service is recovering, retry in a moment."
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "connection refused") || strings.Contains(message, "no such host") ||
		strings.Contains(message, "network is unreachable") || strings.Contains(message, "tls handshake") {
		return "Paperboat is unreachable. Check your network connection and retry; if the service is recovering, retry in a moment."
	}
	if strings.Contains(message, "decode ") || strings.Contains(message, "invalid response") ||
		strings.Contains(message, "empty response") || strings.Contains(message, "pagination did not advance") {
		return "Paperboat returned an unexpected response. Retry the command; if this continues, run `pb doctor`."
	}
	return err.Error()
}

func apiErrorFallback(err *api.APIError) string {
	switch err.Status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusConflict:
		if message := strings.TrimSpace(err.Message); message != "" {
			return sentence(message)
		}
	case http.StatusForbidden:
		return "You do not have permission to perform this action. Check the selected account and target."
	case http.StatusNotFound:
		return "The requested Paperboat resource was not found. Refresh the available targets and retry."
	case http.StatusTooManyRequests:
		return "Paperboat is receiving too many requests. Wait a moment, then retry."
	}
	if err.Status >= 500 || err.Status == 0 {
		return "Paperboat is temporarily unavailable. Retry in a moment; if this continues, run `pb doctor`."
	}
	return "Paperboat could not complete the request. Retry the command; if this continues, run `pb doctor`."
}

func sentence(message string) string {
	message = strings.TrimSpace(message)
	if message == "" || strings.ContainsAny(message[len(message)-1:], ".!?") {
		return message
	}
	return message + "."
}

func isCobraUsageError(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "unknown command ") ||
		strings.HasPrefix(message, "unknown flag: ") ||
		strings.Contains(message, " accepts ") ||
		strings.Contains(message, " requires at least ") ||
		strings.Contains(message, " requires at most ")
}

func hostRuntimeCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__runtime-host",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			code := hostruntimecmd.Execute(
				command.Context(), []string{"hostd"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr(),
			)
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func hostdRuntimeCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__runtime-hostd",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			code := hostruntimecmd.Execute(command.Context(), []string{"hostd"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runtimeWorkerCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "__runtime-worker",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			code := hostruntimecmd.Execute(command.Context(), append([]string{"worker"}, args...), command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func updatedRuntimeCommand() *cobra.Command {
	return &cobra.Command{Use: "__runtime-updated", Hidden: true, DisableFlagParsing: true, RunE: func(command *cobra.Command, args []string) error {
		code := hostruntimecmd.Execute(command.Context(), append([]string{"updated"}, args...), command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
		if code != 0 {
			return exitCodeError{code: code}
		}
		return nil
	}, SilenceUsage: true, SilenceErrors: true}
}

func windowsSSHDServiceCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__windows-sshd-service",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			sshdPath, err := command.Flags().GetString("sshd")
			if err != nil {
				return err
			}
			configPath, err := command.Flags().GetString("config")
			if err != nil {
				return err
			}
			return windowsopenssh.RunServiceHost(sshdPath, configPath)
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("sshd", "", "managed sshd executable")
	command.Flags().String("config", "", "managed sshd configuration")
	_ = command.MarkFlagRequired("sshd")
	_ = command.MarkFlagRequired("config")
	return command
}

func localDaemonCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__local-daemon",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPathFlag(command))
			if err != nil {
				return err
			}
			if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
				cfg.ServerURL, err = config.NormalizeServerURL(server)
				if err != nil {
					return err
				}
			}
			if strings.TrimSpace(cfg.ServerURL) == "" {
				return errors.New("Paperboat server is not configured")
			}
			authSource, err := sessionauth.NewSource(cfg)
			if err != nil {
				return err
			}
			paths, err := localdaemon.CurrentUserPaths()
			if err != nil {
				return err
			}
			source := &localdaemon.AuthenticatedMachineSource{ServerURL: cfg.ServerURL, Auth: authSource}
			source.SourceMachineID, err = configuredMachineID()
			if err != nil {
				return err
			}
			var managedConfig *localdaemon.ManagedSSHConfig
			if store, storeErr := config.ProfileStoreFor(cfg); storeErr == nil {
				if profile, profileErr := store.Load(cfg.ServerURL); profileErr == nil {
					source.AutoApprovePeerEnrollments = func(ctx context.Context, client *api.Client, machines []api.UserMachine) error {
						return localdaemon.ApproveOwnedPeerEnrollments(ctx, store, profile, client, machines)
					}
					if executable, executableErr := os.Executable(); executableErr == nil {
						home, homeErr := os.UserHomeDir()
						if homeErr == nil {
							managedConfig = &localdaemon.ManagedSSHConfig{ServerURL: cfg.ServerURL, Auth: authSource, Store: store, CLIClientSessionID: profile.CLIClientSessionID, Home: home, RuntimeDirectory: paths.RuntimeRoot, Executable: executable, OwnerUID: uint32(os.Geteuid()), InheritedAgentSocket: os.Getenv("SSH_AUTH_SOCK")}
						}
					}
				}
			}
			store, err := config.ProfileStoreFor(cfg)
			if err != nil {
				return err
			}
			transportConfig := httptransport.DevelopmentConfig()
			transportConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			peerHTTPTransport, err := httptransport.New(transportConfig)
			if err != nil {
				return err
			}
			source.HTTPClient = &http.Client{Transport: peerHTTPTransport}
			peerManager, err := transportmanager.New()
			if err != nil {
				return err
			}
			transportMode, err := tunnel.ParseTerminalTransport(cfg.Connect.TerminalTransport)
			if err != nil {
				_ = peerManager.Close()
				return err
			}
			peerTunnel, err := tunnel.NewPeerTerminalTunnel(tunnel.PeerTerminalConfig{Issuer: cfg.ServerURL, Store: store, Auth: authSource, TLS: transportConfig.TLSConfig, HTTPClient: &http.Client{Transport: peerHTTPTransport}, OutputQueueChunks: cfg.Connect.TerminalOutputQueueChunks, Mode: peerConnectionMode(transportMode), PublishLocalStatus: true, TransportManager: peerManager, Race: peerRacePolicy()})
			if err != nil {
				_ = peerManager.Close()
				return err
			}
			if err := peerTunnel.Start(command.Context()); err != nil {
				_ = peerManager.Close()
				return err
			}
			defer peerTunnel.Close()
			fileTransfers, err := localdaemon.NewFileTransferBroker(peerTunnel)
			if err != nil {
				return err
			}
			return localdaemon.Run(command.Context(), localdaemon.DaemonConfig{
				Paths: paths, Source: source, ManagedSSH: managedConfig, IssuePeerStream: source.IssuePeerStream,
				OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(),
				TransportManager: peerManager, OpenPeerStream: localdaemon.TunnelPeerStreamOpener(peerTunnel), ProbePeer: localdaemon.TunnelPeerProbe(peerTunnel), FileTransfers: fileTransfers, InvalidatePeerAuthority: peerTunnel.InvalidateMachine, WarmPeerMetadata: peerTunnel.WarmMachines,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func statusCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "status [machine]",
		Short: "Show local Paperboat machine status",
		Args:  commandArgs(cobra.MaximumNArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			_, snapshot, err := localDaemonSnapshot(command, localdaemon.InstallCurrentUserService)
			if err != nil {
				return fmt.Errorf("read local Paperboat status: %w", err)
			}
			if len(args) == 1 {
				machine, err := selectStatusMachine(snapshot.Machines, args[0])
				if err != nil {
					return err
				}
				snapshot.Machines = []localapi.MachineStatus{machine}
			}
			jsonOutput, _ := command.Flags().GetBool("json")
			if jsonOutput {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetEscapeHTML(false)
				return encoder.Encode(snapshot)
			}
			writeStatus(command.OutOrStdout(), snapshot)
			return nil
		},
	}
	command.Flags().Bool("json", false, "print JSON")
	return command
}

func selectStatusMachine(machines []localapi.MachineStatus, target string) (localapi.MachineStatus, error) {
	return localwait.ResolveMachine(machines, target)
}

func writeStatus(output io.Writer, snapshot localapi.Snapshot) {
	fmt.Fprintf(output, "Daemon: %s  Generation: %d  Observed: %s\n", snapshot.DaemonState, snapshot.Generation, snapshot.ObservedAt.Format(time.RFC3339))
	for _, health := range snapshot.Health {
		fmt.Fprintf(output, "Health: %s: %s  Recovery: %s\n", health.Severity, health.Title, health.Recovery)
	}
	for _, machine := range snapshot.Machines {
		path := machine.SelectedPath
		if machine.RelayRegion != "" {
			path += "/" + machine.RelayRegion
		}
		if len(machine.TransportConsumers) > 0 {
			path = transportConsumerSummary(machine.TransportConsumers)
		}
		observed := "never"
		if machine.LastObservedAt != nil {
			observed = machine.LastObservedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(output, "\n%s (%s)\n", machine.Alias, machine.ID)
		fmt.Fprintf(output, "  Runtime: %s  Eligible: %t  Generation: %d  Last observed: %s\n", machine.RuntimeState, machine.Eligible, machine.Generation, observed)
		fmt.Fprintf(output, "  Path: %s  Consumers: %d  Transfer: %s  Preview: %s  SSH: %s\n", path, machine.ActiveConsumers, machine.TransferReadiness, machine.PreviewReadiness, machine.SSHReadiness)
		for _, health := range machine.Health {
			fmt.Fprintf(output, "  Health: %s: %s  Recovery: %s\n", health.Severity, health.Title, health.Recovery)
		}
	}
}

func transportConsumerSummary(consumers []localapi.TransportConsumer) string {
	parts := make([]string, 0, len(consumers))
	for _, consumer := range consumers {
		path := consumer.Path
		if consumer.RelayRegion != "" {
			path += "/" + consumer.RelayRegion
		}
		parts = append(parts, fmt.Sprintf("%s=%d", path, consumer.ActiveConsumers))
	}
	return strings.Join(parts, ", ")
}

func doctorCommandV1() *cobra.Command {
	command := &cobra.Command{
		Use:   "doctor [machine]",
		Short: "Check Paperboat connectivity and readiness",
		Args:  commandArgs(cobra.MaximumNArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			repair, _ := command.Flags().GetBool("repair")
			if repair {
				if len(args) != 0 {
					return errors.New("doctor --repair does not accept a machine")
				}
				if runtime.GOOS == "windows" {
					doctorArgs := []string{"doctor", "--repair"}
					if jsonOutput, _ := command.Flags().GetBool("json"); jsonOutput {
						doctorArgs = append(doctorArgs, "--json")
					}
					if code := hostruntimecmd.Execute(command.Context(), doctorArgs, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr()); code != 0 {
						return exitCodeError{code: code}
					}
					return nil
				}
				if err := repairWindowsOpenSSH(command.Context()); err != nil {
					return err
				}
			}
			_, snapshot, err := localDaemonSnapshot(command, localdaemon.InstallCurrentUserService)
			if err != nil {
				return fmt.Errorf("read local Paperboat diagnostics: %w", err)
			}
			var machine *localapi.MachineStatus
			var reportMachine *doctorpkg.Machine
			if len(args) == 1 {
				selected, selectErr := selectStatusMachine(snapshot.Machines, args[0])
				if selectErr != nil {
					return selectErr
				}
				machine = &selected
				reportMachine = &doctorpkg.Machine{ID: selected.ID, Alias: selected.Alias}
			}
			report, err := doctorpkg.Run(command.Context(), doctorpkg.Config{
				Timeout: 20 * time.Second, ProbeTimeout: 10 * time.Second, Clock: time.Now,
				Correlation: newDoctorCorrelationID,
			}, reportMachine, doctorProbes(command, snapshot, machine))
			if err != nil {
				return err
			}
			jsonOutput, _ := command.Flags().GetBool("json")
			if jsonOutput {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(report); err != nil {
					return err
				}
			} else {
				writeDoctorReport(command.OutOrStdout(), report)
			}
			if report.Overall != "healthy" {
				return exitCodeError{code: 1}
			}
			return nil
		},
	}
	command.Flags().Bool("json", false, "print JSON")
	command.Flags().Bool("repair", false, "repair Paperboat-owned local dependencies")
	return command
}

func newDoctorCorrelationID() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "pb-doctor-" + hex.EncodeToString(value[:]), nil
}

func doctorProbes(command *cobra.Command, snapshot localapi.Snapshot, machine *localapi.MachineStatus) []doctorpkg.Probe {
	probes := []doctorpkg.Probe{
		{Code: "authentication", Run: func(ctx context.Context) doctorpkg.Check { return probeDoctorAuthentication(ctx, command) }},
		{Code: "daemon", Run: func(context.Context) doctorpkg.Check {
			status := doctorpkg.StatusPass
			recovery := ""
			if snapshot.DaemonState != "ready" {
				status = doctorpkg.StatusWarning
				recovery = "Restart the Paperboat local service and run pb doctor again."
			}
			return doctorpkg.Check{Category: "local", Code: "daemon", Status: status, Summary: "The local daemon is " + snapshot.DaemonState + ".", Recovery: recovery}
		}},
		{Code: "local_state", Run: func(context.Context) doctorpkg.Check { return probeDoctorLocalState() }},
		{Code: "udp_ipv4", Run: func(ctx context.Context) doctorpkg.Check {
			return probeDoctorUDP(ctx, "udp4", "0.0.0.0:0", "udp_ipv4", "IPv4")
		}},
		{Code: "udp_ipv6", Run: func(ctx context.Context) doctorpkg.Check {
			return probeDoctorUDP(ctx, "udp6", "[::]:0", "udp_ipv6", "IPv6")
		}},
	}
	if machine != nil {
		probes = append(probes, doctorMachineProbes(*machine)...)
		probes = append(probes, doctorPathReachabilityProbes(command, machine.ID)...)
		probes = append(probes, doctorpkg.Probe{Code: "peer_reachability", Run: func(ctx context.Context) doctorpkg.Check {
			return probeDoctorPeer(ctx, command, machine.ID)
		}})
	}
	return probes
}

func doctorPathReachabilityProbes(command *cobra.Command, machineID string) []doctorpkg.Probe {
	var once sync.Once
	results := make(map[connectionmanager.Path]tunnel.PathReachability, 3)
	load := func(ctx context.Context) {
		commandContext := actionContext(command, []string{machineID})
		commandContext.Context = ctx
		dependencies, err := buildDeps(commandContext)
		if err != nil || dependencies.peerTunnel == nil {
			return
		}
		client, err := backendClient(commandContext)
		if err != nil {
			return
		}
		machine, err := resolveUserMachine(ctx, client, machineID)
		if err != nil || !machine.Online {
			return
		}
		target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, MachineGeneration: uint64(machine.InstallationGeneration), Terminal: &resolver.TerminalTarget{Protocol: "paperboat.health-probe.v1", EnvironmentID: machine.EnvironmentID}}
		results = dependencies.peerTunnel.ProbePathReachability(ctx, target)
	}
	definitions := []struct {
		code string
		name string
		path connectionmanager.Path
	}{
		{"direct_reachability", "Direct QUIC", connectionmanager.PathDirectQUIC},
		{"relay_reachability", "Relay QUIC", connectionmanager.PathRelayQUIC},
		{"wss_reachability", "WebSocket fallback", connectionmanager.PathWSS},
	}
	probes := make([]doctorpkg.Probe, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		probes = append(probes, doctorpkg.Probe{Code: definition.code, Run: func(ctx context.Context) doctorpkg.Check {
			once.Do(func() { load(ctx) })
			return doctorPathReachabilityCheck(definition.code, definition.name, results[definition.path])
		}})
	}
	return probes
}

func doctorPathReachabilityCheck(code, name string, result tunnel.PathReachability) doctorpkg.Check {
	if result.Reachable {
		return doctorpkg.Check{Category: "transport", Code: code, Status: doctorpkg.StatusPass, Summary: name + " reached the selected machine with an authenticated health exchange."}
	}
	return doctorpkg.Check{Category: "transport", Code: code, Status: doctorpkg.StatusWarning, Summary: name + " did not reach the selected machine.", Recovery: "Check network and firewall policy; Paperboat will continue using any reachable fallback path."}
}

func probeDoctorPeer(ctx context.Context, command *cobra.Command, machineID string) doctorpkg.Check {
	failure := doctorpkg.Check{Category: "transport", Code: "peer_reachability", Status: doctorpkg.StatusFail, Summary: "No authenticated Paperboat path reached the selected machine.", Recovery: "Check the Paperboat service on the selected machine and local network access, then run pb doctor again."}
	commandContext := actionContext(command, []string{machineID})
	commandContext.Context = ctx
	dependencies, err := buildDeps(commandContext)
	if err != nil || dependencies.peerTunnel == nil {
		return failure
	}
	client, err := backendClient(commandContext)
	if err != nil {
		return failure
	}
	machine, err := resolveUserMachine(ctx, client, machineID)
	if err != nil || !machine.Online {
		return failure
	}
	target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, MachineGeneration: uint64(machine.InstallationGeneration), Terminal: &resolver.TerminalTarget{Protocol: "paperboat.health-probe.v1", EnvironmentID: machine.EnvironmentID}}
	result, err := dependencies.peerTunnel.PingOnce(ctx, target)
	if err != nil {
		return failure
	}
	return doctorPeerCheck(result)
}

func doctorPeerCheck(result tunnel.PingResult) doctorpkg.Check {
	path := strings.TrimSuffix(pingPath(result.Path), "_quic")
	status, recovery, fallback := doctorpkg.StatusPass, "", "none"
	summary := "The selected machine answered an authenticated direct health exchange."
	if result.Path == connectionmanager.PathRelayQUIC {
		status, fallback = doctorpkg.StatusWarning, "direct_not_selected"
		recovery = "Direct connectivity is retried automatically; check UDP availability if relay use persists."
		summary = "The selected machine answered through a regional relay."
	} else if result.Path == connectionmanager.PathWSS {
		status, fallback = doctorpkg.StatusWarning, "quic_not_selected"
		recovery = "Check UDP and QUIC access; Paperboat will retry stronger paths automatically."
		summary = "The selected machine answered through WebSocket fallback."
	}
	return doctorpkg.Check{Category: "transport", Code: "peer_reachability", Status: status, Summary: summary, Recovery: recovery, SelectedPath: path, RelayRegion: result.RelayRegion, RTTMS: float64(result.RTT) / float64(time.Millisecond), PTOs: result.PTOs, Fallback: fallback}
}

func probeDoctorAuthentication(ctx context.Context, command *cobra.Command) doctorpkg.Check {
	check := doctorpkg.Check{Category: "control", Code: "authentication", Status: doctorpkg.StatusFail, Summary: "Paperboat authentication is unavailable.", Recovery: "Run pb auth login, then run pb doctor again."}
	cfg, err := config.Load(configPathFlag(command))
	if err != nil {
		check.Summary = "The Paperboat configuration could not be loaded."
		check.Recovery = "Repair the Paperboat configuration and run pb doctor again."
		return check
	}
	if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
		cfg.ServerURL, err = config.NormalizeServerURL(server)
		if err != nil {
			check.Summary = "The configured Paperboat server URL is invalid."
			check.Recovery = "Correct the Paperboat server URL and run pb doctor again."
			return check
		}
	}
	if strings.TrimSpace(cfg.ServerURL) == "" {
		check.Summary = "The Paperboat server is not configured."
		check.Recovery = "Configure the Paperboat server and run pb doctor again."
		return check
	}
	auth, err := sessionauth.NewSource(cfg)
	if err != nil {
		return check
	}
	credential, err := auth.Credential()
	if err != nil {
		return check
	}
	if _, err := api.New(cfg.ServerURL, credential, nil).Me(ctx); err != nil {
		if diagnosis, ok := doctorProxyDiagnosis(err); ok {
			check.Summary = "The Paperboat server is unreachable through the configured proxy."
			check.Recovery = diagnosis.Recovery
		} else {
			check.Summary = "The Paperboat server did not accept the authenticated health check."
			check.Recovery = "Check network access and sign in again if needed, then run pb doctor again."
		}
		return check
	}
	return doctorpkg.Check{Category: "control", Code: "authentication", Status: doctorpkg.StatusPass, Summary: "The Paperboat server accepted the current credential."}
}

func probeDoctorLocalState() doctorpkg.Check {
	state := collectLocalDoctor()
	if state.SetupState == "configured" && state.IdentityState == "valid" {
		return doctorpkg.Check{Category: "local", Code: "local_state", Status: doctorpkg.StatusPass, Summary: "Local Paperboat state and identity are valid."}
	}
	recovery := "Run pb setup, then run pb doctor again."
	if len(state.RecoveryActions) > 0 {
		recovery = sentence(state.RecoveryActions[0])
	}
	return doctorpkg.Check{Category: "local", Code: "local_state", Status: doctorpkg.StatusWarning, Summary: "Local Paperboat runtime state is not fully configured.", Recovery: recovery}
}

func probeDoctorUDP(ctx context.Context, network, address, code, family string) doctorpkg.Check {
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	if err != nil {
		return doctorpkg.Check{Category: "network", Code: code, Status: doctorpkg.StatusWarning, Summary: family + " UDP sockets are unavailable.", Recovery: "Check local firewall and network settings, then run pb doctor again."}
	}
	_ = packet.Close()
	return doctorpkg.Check{Category: "network", Code: code, Status: doctorpkg.StatusPass, Summary: family + " UDP sockets are available."}
}

func doctorMachineProbes(machine localapi.MachineStatus) []doctorpkg.Probe {
	return []doctorpkg.Probe{
		{Code: "machine_runtime", Run: func(context.Context) doctorpkg.Check {
			if machine.Eligible && machine.RuntimeState == "ready" {
				return doctorpkg.Check{Category: "machine", Code: "machine_runtime", Status: doctorpkg.StatusPass, Summary: "The selected machine runtime is ready."}
			}
			return doctorpkg.Check{Category: "machine", Code: "machine_runtime", Status: doctorpkg.StatusFail, Summary: "The selected machine runtime is not ready.", Recovery: "Check the Paperboat service on the selected machine and run pb doctor again."}
		}},
		{Code: "selected_path", Run: func(context.Context) doctorpkg.Check {
			switch machine.SelectedPath {
			case "direct":
				return doctorpkg.Check{Category: "transport", Code: "selected_path", Status: doctorpkg.StatusPass, Summary: "The active Paperboat path is direct."}
			case "relay":
				return doctorpkg.Check{Category: "transport", Code: "selected_path", Status: doctorpkg.StatusWarning, Summary: "The active Paperboat path uses a regional relay.", Recovery: "Direct connectivity is retried automatically; check UDP availability if relay use persists."}
			case "wss":
				return doctorpkg.Check{Category: "transport", Code: "selected_path", Status: doctorpkg.StatusWarning, Summary: "The active Paperboat path uses WebSocket fallback.", Recovery: "Check UDP and QUIC access; Paperboat will retry stronger paths automatically."}
			default:
				return doctorpkg.Check{Category: "transport", Code: "selected_path", Status: doctorpkg.StatusUnavailable, Summary: "No active Paperboat path is currently observed."}
			}
		}},
		{Code: "nat_mapping_ipv4", Run: func(context.Context) doctorpkg.Check { return doctorNATCheck("ipv4", machine.NATMappingIPv4) }},
		{Code: "nat_mapping_ipv6", Run: func(context.Context) doctorpkg.Check { return doctorNATCheck("ipv6", machine.NATMappingIPv6) }},
		{Code: "captive_portal", Run: func(context.Context) doctorpkg.Check { return doctorCaptivePortalCheck(machine.CaptivePortal) }},
		{Code: "path_mtu", Run: func(context.Context) doctorpkg.Check { return doctorPMTUCheck(machine.PMTU) }},
		{Code: "router_protocol", Run: func(context.Context) doctorpkg.Check { return doctorRouterProtocolCheck(machine.RouterProtocol) }},
		{Code: "router_mapping", Run: func(context.Context) doctorpkg.Check { return doctorRouterMappingCheck(machine.RouterMapping) }},
		{Code: "mapping_lifetime", Run: func(context.Context) doctorpkg.Check { return doctorMappingLifetimeCheck(machine.MappingLifetime) }},
		{Code: "update_health", Run: func(context.Context) doctorpkg.Check { return doctorUpdateHealthCheck(machine.UpdateHealth) }},
		{Code: "ssh_readiness", Run: func(context.Context) doctorpkg.Check {
			switch machine.SSHReadiness {
			case "ready":
				return doctorpkg.Check{Category: "ssh", Code: "ssh_readiness", Status: doctorpkg.StatusPass, Summary: "Managed SSH is ready."}
			case "degraded":
				return doctorpkg.Check{Category: "ssh", Code: "ssh_readiness", Status: doctorpkg.StatusWarning, Summary: "Managed SSH requires attention.", Recovery: "Run pb ssh doctor for the selected machine."}
			default:
				return doctorpkg.Check{Category: "ssh", Code: "ssh_readiness", Status: doctorpkg.StatusUnavailable, Summary: "Managed SSH readiness is unavailable."}
			}
		}},
	}
}

func doctorRouterProtocolCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "network", Code: "router_protocol"}
	switch value {
	case "pcp":
		check.Status = doctorpkg.StatusPass
		check.Summary = "The verified router mapping uses PCP."
	case "nat_pmp":
		check.Status = doctorpkg.StatusPass
		check.Summary = "The verified router mapping uses NAT-PMP."
	case "upnp":
		check.Status = doctorpkg.StatusPass
		check.Summary = "The verified router mapping uses UPnP."
	case "none":
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "This network did not provide a router mapping protocol."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "The router mapping protocol could not be observed."
	}
	return check
}

func doctorMappingLifetimeCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "network", Code: "mapping_lifetime"}
	switch value {
	case "30s_to_2m", "2m_to_10m", "over_10m":
		check.Status = doctorpkg.StatusPass
		check.Summary = "The authenticated UDP mapping lifetime supports adaptive keepalive."
	case "under_30s":
		check.Status = doctorpkg.StatusWarning
		check.Summary = "The authenticated UDP mapping lifetime is short."
		check.Recovery = "Keep relay fallback available; check router UDP timeout settings if direct connections are unstable."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "An authenticated UDP mapping lifetime measurement is not available."
	}
	return check
}

func doctorRouterMappingCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "network", Code: "router_mapping"}
	switch value {
	case "verified":
		check.Status = doctorpkg.StatusPass
		check.Summary = "A router mapping was verified from the owned direct-path socket."
	case "unreachable":
		check.Status = doctorpkg.StatusWarning
		check.Summary = "A router mapping could not be verified from outside the local network."
		check.Recovery = "Check router and firewall UDP policy; relay fallback remains available."
	case "untrusted":
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "Router mapping is disabled on this network by Paperboat policy."
	case "unavailable":
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "This network does not provide a usable router mapping."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "Router mapping status could not be observed."
	}
	return check
}

func doctorUpdateHealthCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "update", Code: "update_health"}
	switch value {
	case "healthy":
		check.Status = doctorpkg.StatusPass
		check.Summary = "Signed update health is ready."
	case "recovery_required":
		check.Status = doctorpkg.StatusFail
		check.Summary = "Signed update recovery requires attention."
		check.Recovery = "Restart the Paperboat services; if the failure remains, reinstall the current signed release."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "Signed update health is unavailable."
	}
	return check
}

func doctorNATCheck(family, mapping string) doctorpkg.Check {
	base := doctorpkg.Check{Category: "network", Code: "nat_mapping_" + family}
	switch mapping {
	case "endpoint_independent":
		base.Status = doctorpkg.StatusPass
		base.Summary = "The observed " + family + " NAT mapping is endpoint-independent."
	case "destination_dependent":
		base.Status = doctorpkg.StatusWarning
		base.Summary = "The observed " + family + " NAT mapping depends on the destination."
		base.Recovery = "Keep relay fallback available and run pb doctor again from another network."
	default:
		base.Status = doctorpkg.StatusUnavailable
		base.Summary = "The " + family + " NAT mapping could not be observed."
	}
	return base
}

func doctorCaptivePortalCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "network", Code: "captive_portal"}
	switch value {
	case "clear":
		check.Status = doctorpkg.StatusPass
		check.Summary = "No captive portal was observed."
	case "suspected":
		check.Status = doctorpkg.StatusWarning
		check.Summary = "This network may require captive portal sign-in."
		check.Recovery = "Complete the network sign-in, then run pb doctor again."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "Captive portal status could not be observed."
	}
	return check
}

func doctorPMTUCheck(value string) doctorpkg.Check {
	check := doctorpkg.Check{Category: "network", Code: "path_mtu"}
	switch value {
	case "standard", "extended":
		check.Status = doctorpkg.StatusPass
		check.Summary = "The authenticated path MTU is suitable for direct QUIC."
	case "minimum_1200":
		check.Status = doctorpkg.StatusWarning
		check.Summary = "The authenticated path supports only the minimum QUIC packet size."
		check.Recovery = "Check VPN and router MTU settings; relay fallback remains available."
	case "below_quic_floor":
		check.Status = doctorpkg.StatusFail
		check.Summary = "The authenticated path MTU is below the QUIC minimum."
		check.Recovery = "Check VPN and router MTU settings, then run pb doctor again."
	default:
		check.Status = doctorpkg.StatusUnavailable
		check.Summary = "An authenticated path MTU measurement is not available."
	}
	return check
}

func writeDoctorReport(output io.Writer, report doctorpkg.Report) {
	fmt.Fprintf(output, "Paperboat doctor: %s\n", report.Overall)
	fmt.Fprintf(output, "Correlation: %s\n", report.CorrelationID)
	if report.Machine != nil {
		fmt.Fprintf(output, "Machine: %s (%s)\n", report.Machine.Alias, report.Machine.ID)
	}
	for _, check := range report.Checks {
		fmt.Fprintf(output, "%s: %s: %s\n", check.Code, check.Status, check.Summary)
		if check.Recovery != "" {
			fmt.Fprintf(output, "  Recovery: %s\n", check.Recovery)
		}
	}
}

func bugreportCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "bugreport",
		Short: "Create a redacted Paperboat diagnostic bundle",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			record, _ := command.Flags().GetBool("record")
			upload, _ := command.Flags().GetBool("upload")
			jsonOutput, _ := command.Flags().GetBool("json")
			localClient, _, err := localDaemonSnapshot(command, localdaemon.InstallCurrentUserService)
			if err != nil {
				return fmt.Errorf("start local Paperboat daemon: %w", err)
			}
			var server bugreportpkg.Server
			if upload {
				ctx := actionContext(command, nil)
				d, depErr := buildDeps(ctx)
				if depErr != nil {
					return depErr
				}
				server, err = newRefreshingBugreportServer(d.cfg.ServerURL, d.auth)
				if err != nil {
					return err
				}
			}
			result, runErr := bugreportpkg.Run(command.Context(), bugreportpkg.Options{
				Record: record, Upload: upload, Input: command.InOrStdin(), Prompt: command.ErrOrStderr(),
				Local: localClient, Server: server,
				BeforeUpload: func(result bugreportpkg.Result) error {
					_, writeErr := fmt.Fprintf(command.ErrOrStderr(), "Uploading redacted categories: %s (%d bytes)\n", strings.Join(result.Categories, ", "), result.Bytes)
					return writeErr
				},
			})
			if jsonOutput {
				if runErr != nil {
					result.Error = bugreportJSONFailure(runErr, result.BundleCreated)
				}
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetEscapeHTML(false)
				if encodeErr := encoder.Encode(result); encodeErr != nil {
					return encodeErr
				}
				if runErr != nil {
					return exitCodeError{code: 1}
				}
				return nil
			}
			if runErr != nil {
				if result.BundleCreated {
					return fmt.Errorf("%w; local bundle remains at %s", runErr, result.BundlePath)
				}
				return runErr
			}
			writeBugreportResult(command.OutOrStdout(), result)
			return nil
		},
	}
	command.Flags().Bool("record", false, "record reproduction start and end markers")
	command.Flags().Bool("upload", false, "upload the exact redacted bundle")
	command.Flags().Bool("json", false, "print JSON")
	return command
}

type refreshingBugreportServer struct {
	serverURL string
	auth      config.AuthSource
	client    *api.Client
}

func newRefreshingBugreportServer(serverURL string, auth config.AuthSource) (*refreshingBugreportServer, error) {
	credential, err := auth.Credential()
	if err != nil {
		return nil, err
	}
	return &refreshingBugreportServer{serverURL: serverURL, auth: auth, client: api.New(serverURL, credential, nil)}, nil
}

func (s *refreshingBugreportServer) refresh() bool {
	refresher, ok := s.auth.(interface {
		Refresh() (config.Credential, error)
	})
	if !ok {
		return false
	}
	credential, err := refresher.Refresh()
	if err != nil {
		return false
	}
	s.client = api.New(s.serverURL, credential, nil)
	return true
}

func (s *refreshingBugreportServer) CreateDiagnosticUploadIntent(ctx context.Context, key string, request api.DiagnosticUploadIntentRequest) (api.DiagnosticUploadIntent, error) {
	result, err := s.client.CreateDiagnosticUploadIntent(ctx, key, request)
	if errors.Is(err, api.ErrUnauthenticated) && s.refresh() {
		return s.client.CreateDiagnosticUploadIntent(ctx, key, request)
	}
	return result, err
}

func (s *refreshingBugreportServer) UploadDiagnosticBundle(ctx context.Context, intent api.DiagnosticUploadIntent, content io.Reader, bytes int64) error {
	return s.client.UploadDiagnosticBundle(ctx, intent, content, bytes)
}

func (s *refreshingBugreportServer) CompleteDiagnosticUploadIntent(ctx context.Context, intentID string) (api.DiagnosticUploadIntent, error) {
	result, err := s.client.CompleteDiagnosticUploadIntent(ctx, intentID)
	if errors.Is(err, api.ErrUnauthenticated) && s.refresh() {
		return s.client.CompleteDiagnosticUploadIntent(ctx, intentID)
	}
	return result, err
}

func writeBugreportResult(output io.Writer, result bugreportpkg.Result) {
	fmt.Fprintf(output, "Bundle: %s\n", result.BundlePath)
	fmt.Fprintf(output, "Categories: %s\n", strings.Join(result.Categories, ", "))
	fmt.Fprintf(output, "Size: %d bytes\n", result.Bytes)
	if result.Uploaded {
		fmt.Fprintf(output, "Server correlation: %s\n", result.ServerCorrelationID)
	}
}

func bugreportJSONFailure(err error, bundleCreated bool) *bugreportpkg.Failure {
	stage := "bugreport"
	var stageErr *bugreportpkg.StageError
	if errors.As(err, &stageErr) {
		stage = stageErr.Stage
	}
	code, message := "bugreport_failed", "The diagnostic bundle could not be created."
	if bundleCreated {
		code, message = "bugreport_upload_failed", "The operation did not finish; the local redacted bundle was preserved."
	}
	return &bugreportpkg.Failure{Code: code, Stage: stage, Message: message}
}

func waitCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "wait <machine>",
		Short: "Wait for a machine readiness condition",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			condition, _ := command.Flags().GetString("for")
			if condition != "runtime" && condition != "transport" && condition != "ssh" {
				return invocationError(errors.New("--for must be runtime, transport, or ssh"))
			}
			timeout, _ := command.Flags().GetDuration("timeout")
			if timeout <= 0 || timeout > 24*time.Hour {
				return invocationError(errors.New("--timeout must be greater than zero and no more than 24h"))
			}
			client, snapshot, err := localDaemonSnapshot(command, localdaemon.InstallCurrentUserService)
			if err != nil {
				return fmt.Errorf("start local Paperboat daemon: %w", err)
			}
			waitCtx, cancel := context.WithTimeout(command.Context(), timeout)
			defer cancel()
			var result localwait.Result
			if condition == "runtime" {
				result, err = localwait.WaitTargetFromSnapshot(waitCtx, client, snapshot, args[0], condition)
			} else {
				result, err = waitForAuthenticatedTransport(waitCtx, command, client, snapshot, args[0], condition)
			}
			if err != nil {
				return fmt.Errorf("wait for local Paperboat status: %w", err)
			}
			jsonOutput, _ := command.Flags().GetBool("json")
			if jsonOutput {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(result); err != nil {
					return err
				}
			} else {
				writeWaitResult(command.OutOrStdout(), command.ErrOrStderr(), result)
			}
			if code := waitExitCode(result); code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
	}
	command.Flags().String("for", "transport", "readiness condition: runtime, transport, or ssh")
	command.Flags().Duration("timeout", 5*time.Minute, "maximum time to wait")
	command.Flags().Bool("json", false, "print JSON")
	return command
}

func waitForAuthenticatedTransport(ctx context.Context, command *cobra.Command, client *localapi.Client, snapshot localapi.Snapshot, target, condition string) (localwait.Result, error) {
	dependencies, err := buildDeps(actionContext(command, []string{target}))
	if err != nil {
		return localwait.Result{}, err
	}
	if dependencies.peerTunnel == nil {
		return localwait.Result{}, errors.New("authenticated peer transport is unavailable")
	}
	backend, err := backendClient(actionContext(command, []string{target}))
	if err != nil {
		return localwait.Result{}, err
	}
	for {
		localMachine, resolveErr := localwait.ResolveMachine(snapshot.Machines, target)
		if resolveErr != nil {
			return localwait.Result{}, resolveErr
		}
		ready := localMachine.Eligible && localMachine.Generation > 0 && (localMachine.RuntimeState == "ready" || localMachine.RuntimeState == "degraded")
		if condition == "ssh" {
			ready = ready && localMachine.SSHReadiness == "ready"
		}
		if ready {
			machine, machineErr := resolveUserMachine(ctx, backend, localMachine.ID)
			if machineErr == nil && machine.Online {
				info := resolver.ConnectInfo{TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, MachineGeneration: uint64(machine.InstallationGeneration), Terminal: &resolver.TerminalTarget{Protocol: "paperboat.health-probe.v1", EnvironmentID: machine.EnvironmentID}}
				probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
				probe, probeErr := dependencies.peerTunnel.PingOnce(probeCtx, info)
				cancelProbe()
				if probeErr == nil {
					for index := range snapshot.Machines {
						if snapshot.Machines[index].ID == localMachine.ID {
							snapshot.Machines[index].SelectedPath = strings.TrimSuffix(pingPath(probe.Path), "_quic")
							snapshot.Machines[index].RelayRegion = probe.RelayRegion
						}
					}
					return localwait.WaitTargetFromSnapshot(ctx, client, snapshot, localMachine.ID, condition)
				}
				var failure *connectionmanager.Failure
				if errors.As(probeErr, &failure) && !failure.AllowsFallback() {
					return localwait.Result{}, probeErr
				}
			}
		}
		select {
		case <-ctx.Done():
			return localwait.WaitTargetFromSnapshot(ctx, client, snapshot, localMachine.ID, condition)
		case <-time.After(time.Second):
		}
		snapshot, err = client.Snapshot(ctx)
		if err != nil {
			return localwait.Result{}, err
		}
	}
}

type localDaemonServiceInstaller func(context.Context, string, string, string) error

func localDaemonSnapshot(command *cobra.Command, install localDaemonServiceInstaller) (*localapi.Client, localapi.Snapshot, error) {
	if command == nil || install == nil {
		return nil, localapi.Snapshot{}, errors.New("invalid local daemon client configuration")
	}
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		return nil, localapi.Snapshot{}, err
	}
	client, err := localapi.NewClient(paths.SocketPath, 2*time.Second)
	if err != nil {
		return nil, localapi.Snapshot{}, err
	}
	commandCtx := command.Context()
	if commandCtx == nil {
		commandCtx = context.Background()
	}
	snapshot, err := client.Snapshot(commandCtx)
	if err == nil {
		return client, snapshot, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
		return nil, localapi.Snapshot{}, err
	}
	executable, executableErr := os.Executable()
	if executableErr != nil {
		return nil, localapi.Snapshot{}, executableErr
	}
	configPath := configPathFlag(command)
	effectiveConfig, configErr := config.Load(configPath)
	if configErr != nil {
		return nil, localapi.Snapshot{}, configErr
	}
	configPath = effectiveConfig.Path()
	if configPath != "" {
		configPath, executableErr = filepath.Abs(configPath)
		if executableErr != nil {
			return nil, localapi.Snapshot{}, executableErr
		}
	}
	server, _ := command.Flags().GetString("server")
	if strings.TrimSpace(server) == "" {
		server = effectiveConfig.ServerURL
	}
	initialSocketErr := fmt.Errorf("connect local daemon at %s: %w", paths.SocketPath, err)
	if err := install(commandCtx, executable, configPath, server); err != nil {
		return nil, localapi.Snapshot{}, errors.Join(initialSocketErr, err)
	}
	readyCtx, cancel := context.WithTimeout(commandCtx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, err = client.Snapshot(readyCtx)
		if err == nil {
			return client, snapshot, nil
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, localapi.Snapshot{}, err
		}
		select {
		case <-readyCtx.Done():
			return nil, localapi.Snapshot{}, errors.Join(err, readyCtx.Err())
		case <-ticker.C:
		}
	}
}

func writeWaitResult(stdout, stderr io.Writer, result localwait.Result) {
	switch result.Outcome {
	case "ready":
		fmt.Fprintf(stdout, "%s is ready for %s (%s, generation %d).\n", result.Machine.Alias, result.Condition, result.Machine.RuntimeState, result.SnapshotGeneration)
	case "timeout":
		fmt.Fprintf(stderr, "pb: Timed out waiting for %s to become ready for %s.\n", result.Machine.Alias, result.Condition)
	case "canceled":
		fmt.Fprintln(stderr, "pb: Operation canceled.")
	case "failed":
		fmt.Fprintf(stderr, "pb: %s cannot become ready for %s (%s).\n", result.Machine.Alias, result.Condition, result.Code)
	}
}

func waitExitCode(result localwait.Result) int {
	switch result.Outcome {
	case "ready":
		return 0
	case "timeout":
		return 203
	case "canceled":
		return 205
	default:
		return 1
	}
}

func privilegedHostServiceCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "__runtime-host-service",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			code := hostruntimecmd.ExecuteHostService(command.Context(), args, command.ErrOrStderr())
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func privilegedServiceOperationCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "__runtime-service",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			code := hostruntimecmd.Execute(command.Context(), append([]string{"service"}, args...), command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func configRuntimeCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__runtime-config",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			stateRoot, err := command.Flags().GetString("state-root")
			if err != nil {
				return err
			}
			if stateRoot == "" {
				stateRoot = os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
			}
			if stateRoot == "" {
				stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
				if err != nil {
					return err
				}
			}
			handled, err := enterWindowsConfigService(stateRoot)
			if err != nil {
				return err
			}
			if handled {
				return nil
			}
			store, err := identity.Open(identity.Config{StateRoot: stateRoot})
			if err != nil {
				return fmt.Errorf("open machine identity: %w", err)
			}
			registration, err := store.Registration()
			if err != nil {
				return fmt.Errorf("load machine registration: %w", err)
			}
			homeRoot, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			chezmoi := strings.TrimSpace(os.Getenv("PAPERBOAT_CHEZMOI_PATH"))
			if chezmoi == "" {
				chezmoi = defaultChezmoiPath()
			}
			hosts := []string{"github.com"}
			if raw := strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_REPOSITORY_HOSTS")); raw != "" {
				hosts = strings.Split(raw, ",")
			}
			return hostruntimeentry.RunConfigWorker(command.Context(), hostruntimeentry.ConfigWorkerConfig{
				ControlURL: registration.ServerURL, StateRoot: stateRoot, HomeRoot: filepath.Clean(homeRoot),
				ChezmoiBinary: chezmoi, RepositoryHosts: hosts,
			})
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "runtime state directory")
	return command
}

func previewRuntimeCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__runtime-preview",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			stateRoot, _ := command.Flags().GetString("state-root")
			name, _ := command.Flags().GetString("name")
			port, _ := command.Flags().GetUint16("port")
			duration, _ := command.Flags().GetDuration("duration")
			indefinite, _ := command.Flags().GetBool("indefinite")
			expiresAtValue, _ := command.Flags().GetString("expires-at")
			descriptorPath, _ := command.Flags().GetString("descriptor")
			serviceDefinition, _ := command.Flags().GetString("service-definition")
			var expiresAt *time.Time
			if expiresAtValue != "" {
				parsed, parseErr := time.Parse(time.RFC3339Nano, expiresAtValue)
				if parseErr != nil {
					return invocationError(errors.New("invalid preview runtime expiry"))
				}
				expiresAt = &parsed
			}
			if stateRoot == "" || name == "" || port == 0 || indefinite && (duration != 0 || expiresAt != nil) || !indefinite && duration <= 0 && expiresAt == nil {
				return invocationError(errors.New("invalid preview runtime descriptor"))
			}
			if handled, serviceErr := enterWindowsPreviewService(command.Context(), stateRoot, name); handled || serviceErr != nil {
				return serviceErr
			}
			if handled, testErr := runWindowsPreviewNativeE2E(command.Context(), stateRoot, name); handled {
				return testErr
			}
			store, err := identity.Open(identity.Config{StateRoot: stateRoot})
			if err != nil {
				return err
			}
			registration, err := store.Registration()
			if err != nil {
				return err
			}
			err = hostruntimeentry.RunPreviewWorker(command.Context(), hostruntimeentry.PreviewWorkerConfig{
				ControlURL: registration.ServerURL, StateRoot: stateRoot, Name: name, Port: port,
				Duration: duration, Indefinite: indefinite, ExpiresAt: expiresAt, DescriptorPath: descriptorPath, ServiceDefinition: serviceDefinition,
				Ready: func(record preview.ControlRecord) error {
					return json.NewEncoder(command.OutOrStdout()).Encode(record)
				},
			})
			if err != nil {
				fmt.Fprintf(command.ErrOrStderr(), "preview worker: %v\n", err)
			}
			return err
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "runtime state directory")
	command.Flags().String("name", "", "preview name")
	command.Flags().Uint16("port", 0, "local target port")
	command.Flags().Duration("duration", 0, "preview lifetime")
	command.Flags().String("expires-at", "", "absolute preview expiry")
	command.Flags().String("descriptor", "", "durable preview descriptor")
	command.Flags().String("service-definition", "", "preview service definition")
	command.Flags().Bool("indefinite", false, "run until explicitly revoked")
	return command
}

func privatePreviewRuntimeCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "__runtime-private-preview", Hidden: true, Args: commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			stateRoot, _ := command.Flags().GetString("state-root")
			name, _ := command.Flags().GetString("name")
			indefinite, _ := command.Flags().GetBool("indefinite")
			expiresAtValue, _ := command.Flags().GetString("expires-at")
			var expiresAt *time.Time
			if expiresAtValue != "" {
				value, err := time.Parse(time.RFC3339Nano, expiresAtValue)
				if err != nil {
					return invocationError(errors.New("invalid private preview runtime expiry"))
				}
				expiresAt = &value
			}
			if !filepath.IsAbs(stateRoot) || name == "" || indefinite == (expiresAt != nil) {
				return invocationError(errors.New("invalid private preview runtime descriptor"))
			}
			if handled, serviceErr := enterWindowsPreviewService(command.Context(), stateRoot, name); handled || serviceErr != nil {
				return serviceErr
			}
			if handled, testErr := runWindowsPreviewNativeE2E(command.Context(), stateRoot, name); handled {
				return testErr
			}
			remote, err := hostruntimeentry.ReadPrivatePreviewService(stateRoot, name)
			if err != nil {
				return err
			}
			if err := hostruntimeentry.BeginPrivatePreviewService(stateRoot, name); err != nil {
				return err
			}
			failStartup := func(cause error) error {
				return errors.Join(cause, hostruntimeentry.MarkPrivatePreviewServiceFailed(stateRoot, name, cause))
			}
			ctx := command.Context()
			var cancel context.CancelFunc
			if expiresAt != nil {
				ctx, cancel = context.WithDeadline(ctx, *expiresAt)
				defer cancel()
			}
			action := actionContext(command, nil)
			dependencies, err := buildDeps(action)
			if err != nil || dependencies.peerApplications == nil {
				return failStartup(errors.Join(errors.New("private peer transport is unavailable"), err))
			}
			client, err := backendForCommand(command)
			if err != nil {
				return failStartup(err)
			}
			proxy, err := privatepreviewproxy.Start(ctx, privatepreviewproxy.Config{ListenPort: remote.ListenPort, Dial: func(dialCtx context.Context) (io.ReadWriteCloser, error) {
				target, targetErr := privatePreviewPeerTarget(dialCtx, client, remote.MachineID, remote.MachineName, remote.EnvironmentID, remote.MachineGeneration)
				if targetErr != nil {
					return nil, targetErr
				}
				return dependencies.peerApplications.DialPrivatePreview(dialCtx, target, remote.TargetPort)
			}})
			if err != nil {
				return failStartup(err)
			}
			defer proxy.Close()
			if err := hostruntimeentry.MarkPrivatePreviewServiceReady(stateRoot, name, proxy.URL); err != nil {
				return failStartup(err)
			}
			waitErr := proxy.Wait()
			if errors.Is(context.Cause(ctx), context.Canceled) {
				return waitErr
			}
			cleanupErr := hostruntimeentry.CompletePrivatePreviewService(context.Background(), stateRoot, name)
			return errors.Join(waitErr, cleanupErr)
		}, SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "runtime state directory")
	command.Flags().String("name", "", "preview name")
	command.Flags().String("expires-at", "", "absolute preview expiry")
	command.Flags().String("descriptor", "", "durable preview descriptor")
	command.Flags().String("service-definition", "", "preview service definition")
	command.Flags().Bool("indefinite", false, "run until explicitly revoked")
	return command
}

func serveRuntimeCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__runtime-serve",
		Hidden: true,
		Args:   commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			stateRoot, _ := command.Flags().GetString("state-root")
			name, _ := command.Flags().GetString("name")
			indefinite, _ := command.Flags().GetBool("indefinite")
			expiresAtValue, _ := command.Flags().GetString("expires-at")
			descriptorPath, _ := command.Flags().GetString("descriptor")
			serviceDefinition, _ := command.Flags().GetString("service-definition")
			var expiresAt *time.Time
			if expiresAtValue != "" {
				parsed, parseErr := time.Parse(time.RFC3339Nano, expiresAtValue)
				if parseErr != nil {
					return invocationError(errors.New("invalid serve runtime expiry"))
				}
				expiresAt = &parsed
			}
			if stateRoot == "" || name == "" || !filepath.IsAbs(descriptorPath) || indefinite == (expiresAt != nil) {
				return invocationError(errors.New("invalid serve runtime descriptor"))
			}
			if handled, serviceErr := enterWindowsPreviewService(command.Context(), stateRoot, name); handled || serviceErr != nil {
				return serviceErr
			}
			if handled, testErr := runWindowsPreviewNativeE2E(command.Context(), stateRoot, name); handled {
				return testErr
			}
			controlURL := ""
			if store, openErr := identity.Open(identity.Config{StateRoot: stateRoot}); openErr == nil {
				if registration, registrationErr := store.Registration(); registrationErr == nil {
					controlURL = registration.ServerURL
				}
			}
			err := hostruntimeentry.RunServeWorker(command.Context(), hostruntimeentry.ServeWorkerConfig{
				ControlURL: controlURL, StateRoot: stateRoot, Name: name, ExpiresAt: expiresAt,
				Indefinite: indefinite, DescriptorPath: descriptorPath, ServiceDefinition: serviceDefinition,
			})
			if err != nil {
				fmt.Fprintf(command.ErrOrStderr(), "serve worker: %v\n", err)
			}
			return err
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "runtime state directory")
	command.Flags().String("name", "", "preview name")
	command.Flags().String("expires-at", "", "absolute preview expiry")
	command.Flags().String("descriptor", "", "durable preview descriptor")
	command.Flags().String("service-definition", "", "preview service definition")
	command.Flags().Bool("indefinite", false, "run until explicitly revoked")
	return command
}

func pairCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "pair",
		Short: "Pair this machine for hosting",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			stateRoot, err := command.Flags().GetString("state-root")
			if err != nil {
				return err
			}
			if stateRoot == "" {
				stateRoot = os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
			}
			if stateRoot == "" {
				stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
				if err != nil {
					return err
				}
			}
			identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
			if err != nil {
				return fmt.Errorf("open machine identity: %w", err)
			}
			registration, err := identityStore.Registration()
			fresh := errors.Is(err, os.ErrNotExist)
			if fresh {
				registration = identity.Registration{}
			}
			if err != nil {
				if fresh {
					err = nil
				} else {
					return fmt.Errorf("load machine registration: %w", err)
				}
			}
			serverURL, err := command.Flags().GetString("server")
			if err != nil {
				return err
			}
			if serverURL != "" {
				serverURL, err = config.NormalizeServerURL(serverURL)
				if err != nil {
					return err
				}
				if !fresh && serverURL != registration.ServerURL {
					return errors.New("this machine is set up for a different Paperboat server")
				}
			}
			if fresh && serverURL == "" {
				serverURL = strings.TrimSpace(buildinfo.DefaultServerURL)
			}
			if fresh && serverURL == "" {
				return errors.New("fresh pairing requires --server")
			}
			if fresh {
				token, _ := command.Flags().GetString("enrollment-token")
				tokenFile, _ := command.Flags().GetString("enrollment-token-file")
				if strings.TrimSpace(token) == "" && strings.TrimSpace(tokenFile) == "" {
					return errors.New("fresh pairing requires --enrollment-token or --enrollment-token-file")
				}
				if runtime.GOOS == "windows" {
					if _, err := setupPlatformHostPrerequisites(command.Context()); err != nil {
						return fmt.Errorf("prepare Windows OpenSSH: %w", err)
					}
				}
			}
			publicIdentityKey := base64.RawURLEncoding.EncodeToString(identityStore.Current().Public())
			if !fresh && registration.PublicIdentityKey != publicIdentityKey {
				return errors.New("machine setup identity does not match the current key; run `pb setup` to repair it")
			}
			if !fresh {
				serverURL = registration.ServerURL
			}
			arguments := []string{"bootstrap", "--server", serverURL}
			for _, name := range []string{"enrollment-token", "enrollment-token-file", "name", "shell", "state-root", "setup-mode"} {
				value, err := command.Flags().GetString(name)
				if err != nil {
					return err
				}
				if strings.TrimSpace(value) != "" {
					arguments = append(arguments, "--"+name, value)
				}
			}
			code := hostruntimecmd.Execute(command.Context(), arguments, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			if code != 0 {
				return exitCodeError{code: code}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	command.Flags().String("enrollment-token", "", "single-use pairing token")
	command.Flags().String("enrollment-token-file", "", "absolute protected file containing a single-use pairing token")
	command.Flags().String("name", "", "machine name")
	command.Flags().String("shell", "", "absolute login shell")
	command.Flags().String("state-root", "", "runtime state directory")
	command.Flags().String("setup-mode", "host", "enrollment role: host or client")
	return command
}

func setupCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "setup",
		Short: "Set up this machine for Paperboat",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			mode, err := command.Flags().GetString("mode")
			if err != nil {
				return err
			}
			mode, err = resolveSetupMode(mode, term.IsTerminal(int(os.Stdin.Fd())), command.ErrOrStderr())
			if err != nil {
				return err
			}
			if mode == "host" && runtime.GOOS == "windows" {
				sshPort, setupErr := setupPlatformHostPrerequisites(command.Context())
				if setupErr != nil {
					return fmt.Errorf("prepare Windows OpenSSH: %w", setupErr)
				}
				if sshPort != 0 {
					if err := command.Flags().Set("ssh-port", strconv.Itoa(int(sshPort))); err != nil {
						return err
					}
				}
			}
			sshPortValue := uint(0)
			if mode == "host" {
				sshPortValue, err = command.Flags().GetUint("ssh-port")
				if err != nil || sshPortValue == 0 || sshPortValue > 65535 {
					return invocationError(errors.New("--ssh-port must be between 1 and 65535"))
				}
			} else if command.Flags().Changed("ssh-port") {
				return invocationError(errors.New("--ssh-port is available only with --mode host"))
			}
			account, err := user.Current()
			if err != nil || strings.TrimSpace(account.Username) == "" {
				return errors.New("local operating-system user is unavailable")
			}
			ctx := actionContext(command, nil)
			client, err := backendClient(ctx)
			if err != nil {
				return err
			}
			stateRoot, err := command.Flags().GetString("state-root")
			if err != nil {
				return err
			}
			if stateRoot == "" {
				stateRoot = os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
			}
			if stateRoot == "" {
				stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
				if err != nil {
					return err
				}
			}
			identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
			if err != nil {
				return fmt.Errorf("open machine identity: %w", err)
			}
			workspaceRoot, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("resolve workspace root: %w", err)
			}
			workspaceRoot = filepath.Clean(workspaceRoot)
			name, err := command.Flags().GetString("name")
			if err != nil {
				return err
			}
			if strings.TrimSpace(name) == "" {
				name, err = os.Hostname()
				if err != nil || strings.TrimSpace(name) == "" {
					return errors.New("machine name is unavailable; pass --name")
				}
			}
			key := identityStore.Current()
			publicIdentityKey := base64.RawURLEncoding.EncodeToString(key.Public())
			inboxPath, err := inbox.DefaultPath()
			if err != nil {
				return fmt.Errorf("resolve Paperboat Inbox: %w", err)
			}
			previousMode := ""
			if existing, registrationErr := identityStore.Registration(); registrationErr == nil {
				inboxPath = existing.InboxPath
				previousMode = existing.SetupMode
			}
			if err := inbox.EnsurePath(inboxPath); err != nil {
				return fmt.Errorf("prepare Paperboat Inbox: %w", err)
			}
			setupAPIMode := mode
			machine, err := client.SetupMachine(command.Context(), api.MachineSetupInput{
				SetupMode:   setupAPIMode,
				DisplayName: strings.TrimSpace(name), Platform: runtime.GOOS, Architecture: runtime.GOARCH,
				WorkspaceRoot: workspaceRoot, PublicIdentityKey: publicIdentityKey,
				RuntimeVersions: map[string]string{"pb": buildinfo.Version},
			})
			if err != nil {
				if errors.Is(err, api.ErrUnauthenticated) {
					return errors.New("your Paperboat session was rejected; run `pb auth login`, then retry")
				}
				return err
			}
			if mode == "host" {
				if _, err := client.RegisterManagedSSHTarget(command.Context(), machine.ID, uint64(machine.InstallationGeneration), account.Username, uint16(sshPortValue), "managed-ssh-target-"+strings.TrimPrefix(newIdempotencyKey(), "pb-")); err != nil {
					return fmt.Errorf("register SSH target: %w", err)
				}
			}
			d, err := buildDeps(ctx)
			if err != nil {
				return err
			}
			registration := identity.Registration{
				ServerURL: d.cfg.ServerURL, MachineID: machine.ID, EnvironmentID: machine.EnvironmentID,
				PublicKeyID: key.ID, PublicIdentityKey: publicIdentityKey,
				InboxPath:              inboxPath,
				InstallationGeneration: machine.InstallationGeneration, SetupRoles: machine.SetupRoles,
				SetupMode: setupAPIMode,
				UpdatedAt: time.Now().UTC(),
			}
			if mode == "host" {
				registration.SSHUser, registration.SSHPort = account.Username, uint16(sshPortValue)
			}
			if err := identityStore.SaveRegistration(registration); err != nil {
				return fmt.Errorf("save machine registration: %w", err)
			}
			if mode == "session" {
				if previousMode != "" && previousMode != "session" {
					if err := cleanupDurablePreviewServices(command); err != nil {
						return fmt.Errorf("stop durable previews before session-mode transition: %w", err)
					}
					if code := hostruntimecmd.Execute(command.Context(), []string{"service", "uninstall-persisted"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr()); code != 0 {
						return errors.New("session mode was saved, but persistent service removal failed; retry `pb setup --mode session`")
					}
				}
				fmt.Fprintf(command.OutOrStdout(), "Set up %s (%s) in session mode\n", machine.DisplayName, machine.ID)
				return exportSetupRecoveryKey(command)
			}
			operationID := "machine-control-" + strings.TrimPrefix(newIdempotencyKey(), "pb-")
			controlBody, err := json.Marshal(struct {
				OperationID string `json:"operation_id"`
			}{operationID})
			if err != nil {
				return err
			}
			controlPath := "/v1/machines/" + machine.ID + "/control-credentials"
			proof, err := identityStore.MachineProof(operationID, http.MethodPost, controlPath, controlBody, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("prove machine identity: %w", err)
			}
			controlCredential, err := client.IssueMachineControlCredential(command.Context(), machine.ID, operationID, proof)
			if err != nil {
				return fmt.Errorf("issue machine control credential: %w", err)
			}
			if err := identityStore.SaveMachineControl(identity.MachineControl{
				MachineID: machine.ID, EnvironmentID: machine.EnvironmentID,
				InstallationGeneration: machine.InstallationGeneration, Credential: controlCredential.Credential,
				ExpiresAt: controlCredential.ExpiresAt, KeyID: key.ID,
			}); err != nil {
				return fmt.Errorf("save machine control credential: %w", err)
			}
			if mode == "client" {
				if machine.Installation == nil {
					return errors.New("server did not return TUF client installation material")
				}
				artifact := bootstrap.ArtifactTarget{
					Schema: machine.Installation.Artifact.Schema, Kind: machine.Installation.Artifact.Kind,
					Version: machine.Installation.Artifact.Version, Platform: machine.Installation.Artifact.Platform,
					Architecture: machine.Installation.Artifact.Architecture, RepositoryURL: machine.Installation.Artifact.RepositoryURL,
					TargetPath: machine.Installation.Artifact.TargetPath,
				}
				installErr := hostruntimecmd.InstallReceive(command.Context(), hostruntimecmd.ReceiveInstallConfig{
					StateRoot: stateRoot, WorkspaceRoot: workspaceRoot, ControlURL: machine.Installation.ControlURL,
					MachineID: machine.ID, ListenAddress: machine.Installation.HelperListenAddress,
					Artifact: artifact,
				}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
				if installErr != nil {
					rollbackCtx, cancelRollback := setupRollbackContext(command.Context())
					defer cancelRollback()
					rolledBack, rollbackErr := client.SetupMachine(rollbackCtx, api.MachineSetupInput{
						SetupMode: "session", DisplayName: strings.TrimSpace(name), Platform: runtime.GOOS, Architecture: runtime.GOARCH,
						WorkspaceRoot: workspaceRoot, PublicIdentityKey: publicIdentityKey, RuntimeVersions: map[string]string{"pb": buildinfo.Version},
					})
					if rollbackErr == nil {
						registration, loadErr := identityStore.Registration()
						if loadErr == nil {
							registration.SetupMode, registration.SetupRoles = "session", append([]string(nil), rolledBack.SetupRoles...)
							registration.InstallationGeneration, registration.UpdatedAt = rolledBack.InstallationGeneration, time.Now().UTC()
							rollbackErr = identityStore.SaveRegistration(registration)
						} else {
							rollbackErr = loadErr
						}
					}
					return errors.Join(fmt.Errorf("install client service: %w", installErr), rollbackErr)
				}
			}
			if mode == "host" {
				arguments := []string{"bootstrap", "--server", d.cfg.ServerURL, "--state-root", stateRoot, "--name", strings.TrimSpace(name)}
				if code := hostruntimecmd.Execute(command.Context(), arguments, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr()); code != 0 {
					bootstrapErr := error(exitCodeError{code: code})
					if previousMode != "client" && previousMode != "host" {
						rollbackCtx, cancelRollback := setupRollbackContext(command.Context())
						defer cancelRollback()
						rolledBack, rollbackErr := client.SetupMachine(rollbackCtx, api.MachineSetupInput{
							SetupMode: "session", DisplayName: strings.TrimSpace(name), Platform: runtime.GOOS, Architecture: runtime.GOARCH,
							WorkspaceRoot: workspaceRoot, PublicIdentityKey: publicIdentityKey, RuntimeVersions: map[string]string{"pb": buildinfo.Version},
						})
						if rollbackErr == nil {
							registration, loadErr := identityStore.Registration()
							if loadErr == nil {
								registration.SetupMode, registration.SetupRoles = "session", append([]string(nil), rolledBack.SetupRoles...)
								registration.InstallationGeneration, registration.UpdatedAt = rolledBack.InstallationGeneration, time.Now().UTC()
								rollbackErr = identityStore.SaveRegistration(registration)
							} else {
								rollbackErr = loadErr
							}
						}
						bootstrapErr = errors.Join(bootstrapErr, rollbackErr)
					}
					return bootstrapErr
				}
				machine, err = doctorUserMachine(command.Context(), client, machine.ID)
				if err != nil {
					return fmt.Errorf("verify host readiness: %w", err)
				}
				registration, err := identityStore.Registration()
				if err != nil {
					return err
				}
				registration.SetupMode, registration.SetupRoles = "host", append([]string(nil), machine.SetupRoles...)
				registration.InstallationGeneration, registration.UpdatedAt = machine.InstallationGeneration, time.Now().UTC()
				if err := identityStore.SaveRegistration(registration); err != nil {
					return fmt.Errorf("save host registration: %w", err)
				}
			}
			fmt.Fprintf(command.OutOrStdout(), "Set up %s (%s) in %s mode\n", machine.DisplayName, machine.ID, mode)
			return exportSetupRecoveryKey(command)
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("name", "", "machine name")
	command.Flags().String("mode", "", "installation mode: client, session, or host")
	command.Flags().String("state-root", "", "runtime state directory")
	command.Flags().Uint("ssh-port", 22, "existing loopback sshd port")
	command.Flags().String("recovery-output", "", "new absolute file for the account recovery key")
	return command
}

func resolveSetupMode(value string, interactive bool, output io.Writer) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "" {
		if slices.Contains([]string{"client", "session", "host"}, value) {
			return value, nil
		}
		return "", invocationError(errors.New("--mode must be client, session, or host"))
	}
	if !interactive {
		return "", invocationError(errors.New("non-interactive setup requires --mode client, session, or host"))
	}
	choice, err := selector.Choose(selector.Options{
		Title: "Set up this machine", Subtitle: "Choose what Paperboat may do on this machine",
		Items: []selector.Item{
			{ID: "client", Title: "Client", Description: "Receive files and launch previews in the background"},
			{ID: "session", Title: "Session", Description: "Use only while this terminal session is attached"},
			{ID: "host", Title: "Host", Description: "Run terminals and Codex, receive files, and launch previews"},
		},
		Stdin: os.Stdin, Output: output, Footer: "enter select  esc cancel",
	})
	if err != nil {
		return "", err
	}
	return choice.ID, nil
}

func setupRollbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
}

func unpairCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "unpair",
		Short: "Stop hosting from this machine",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			ctx := actionContext(command, nil)
			client, err := backendClient(ctx)
			if err != nil {
				return err
			}
			stateRoot, err := command.Flags().GetString("state-root")
			if err != nil {
				return err
			}
			if stateRoot == "" {
				stateRoot = os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
			}
			if stateRoot == "" {
				stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
				if err != nil {
					return err
				}
			}
			identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
			if err != nil {
				return fmt.Errorf("open machine identity: %w", err)
			}
			registration, err := identityStore.Registration()
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("this machine has no local setup registration; run `pb setup`, then retry")
			}
			if err != nil {
				return fmt.Errorf("load machine registration: %w", err)
			}
			d, err := buildDeps(ctx)
			if err != nil {
				return err
			}
			if registration.ServerURL != d.cfg.ServerURL {
				return errors.New("this machine is registered to a different Paperboat server")
			}
			if err := cleanupDurablePreviewServices(command); err != nil {
				return fmt.Errorf("stop durable previews before unpairing: %w", err)
			}
			machine, err := client.UnpairMachine(command.Context(), registration.MachineID)
			if err != nil {
				return err
			}
			registration.InstallationGeneration = machine.InstallationGeneration
			registration.SetupRoles = machine.SetupRoles
			registration.SetupMode = "client"
			registration.UpdatedAt = time.Now().UTC()
			if err := identityStore.SaveRegistration(registration); err != nil {
				return fmt.Errorf("save machine registration: %w", err)
			}
			code := hostruntimecmd.Execute(command.Context(), []string{"service", "uninstall-persisted"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			if code != 0 {
				return errors.New("host authority was revoked, but local service removal failed; retry `pb unpair`")
			}
			receiveSetup := setupCommand()
			receiveSetup.SetIn(command.InOrStdin())
			receiveSetup.SetOut(command.OutOrStdout())
			receiveSetup.SetErr(command.ErrOrStderr())
			receiveSetup.SetArgs([]string{"--mode", "client", "--name", machine.DisplayName, "--state-root", stateRoot})
			if err := receiveSetup.ExecuteContext(command.Context()); err != nil {
				return fmt.Errorf("host authority was revoked, but client service setup failed: %w", err)
			}
			fmt.Fprintf(command.OutOrStdout(), "Unpaired %s (%s)\n", machine.DisplayName, machine.ID)
			return nil
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "runtime state directory")
	return command
}

func uninstallCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "uninstall",
		Short: "Completely remove Paperboat from this machine",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			hostname, err := os.Hostname()
			if err != nil || strings.TrimSpace(hostname) == "" {
				return errors.New("could not resolve this machine hostname")
			}
			reader := bufio.NewReader(command.InOrStdin())
			fmt.Fprintln(command.ErrOrStderr(), "This permanently removes Paperboat services, binaries, credentials, configuration, and runtime state. The Paperboat Inbox is preserved.")
			fmt.Fprint(command.ErrOrStderr(), "Type UNINSTALL PAPERBOAT to continue: ")
			first, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if strings.TrimSpace(first) != "UNINSTALL PAPERBOAT" {
				return errors.New("uninstall confirmation did not match")
			}
			fmt.Fprintf(command.ErrOrStderr(), "Type this machine hostname (%s) to confirm: ", hostname)
			second, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if strings.TrimSpace(second) != hostname {
				return errors.New("hostname confirmation did not match")
			}
			if err := cleanupDurablePreviewServices(command); err != nil {
				return fmt.Errorf("stop durable previews before uninstalling: %w", err)
			}
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			serviceCtx, cancelService := context.WithTimeout(context.WithoutCancel(command.Context()), 30*time.Second)
			serviceErr := localdaemon.RemoveCurrentUserService(serviceCtx, executable)
			cancelService()
			if serviceErr != nil {
				return fmt.Errorf("stop local daemon before uninstalling: %w", serviceErr)
			}
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return homeErr
			}
			if _, configErr := managedssh.UninstallOpenSSHConfig(home, uint32(os.Geteuid())); configErr != nil {
				return fmt.Errorf("remove managed OpenSSH configuration: %w", configErr)
			}
			if identityErr := managedssh.UninstallManagedIdentityPublicKey(home, uint32(os.Geteuid())); identityErr != nil {
				return fmt.Errorf("remove managed SSH public identity: %w", identityErr)
			}
			if code := hostruntimecmd.Execute(command.Context(), []string{"purge"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr()); code != 0 {
				return errors.New("system Paperboat removal failed")
			}
			if err := purgeUserPaperboatState(command); err != nil {
				return fmt.Errorf("remove user Paperboat state: %w", err)
			}
			fmt.Fprintln(command.OutOrStdout(), "Paperboat was completely removed. The Paperboat Inbox was preserved.")
			return nil
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("state-root", "", "additional Paperboat runtime state directory to remove")
	return command
}

func cleanupDurablePreviewServices(command *cobra.Command) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return nil
	}
	roots := make(map[string]struct{})
	if root := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")); root != "" {
		roots[filepath.Clean(root)] = struct{}{}
	}
	if root, err := helperconfig.DefaultStateRoot(os.Getenv); err == nil {
		roots[filepath.Clean(root)] = struct{}{}
	}
	if root, _ := command.Flags().GetString("state-root"); strings.TrimSpace(root) != "" {
		root, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		roots[filepath.Clean(root)] = struct{}{}
	}
	rootList := make([]string, 0, len(roots))
	for root := range roots {
		rootList = append(rootList, root)
	}
	sort.Strings(rootList)
	if runtime.GOOS == "windows" {
		return cleanupDurablePreviewServicesWindows(command.Context(), rootList)
	}
	var result error
	for _, root := range rootList {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(command.Context()), 30*time.Second)
		err := hostruntimeentry.RemoveAllPreviewServices(cleanupCtx, root)
		cancel()
		result = errors.Join(result, err)
	}
	return result
}

func purgeUserPaperboatState(command *cobra.Command) error {
	var paths []string
	configPath, _ := command.Flags().GetString("config")
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil && filepath.IsAbs(cfg.Auth.ProfileDir) {
			paths = append(paths, cfg.Auth.ProfileDir)
		}
		paths = append(paths, configPath)
	} else if path, err := config.DefaultPath(); err == nil {
		if cfg, loadErr := config.Load(path); loadErr == nil && filepath.IsAbs(cfg.Auth.ProfileDir) {
			paths = append(paths, cfg.Auth.ProfileDir)
		}
		paths = append(paths, filepath.Dir(path))
	}
	if dir, err := config.DefaultCredentialDir(); err == nil {
		paths = append(paths, filepath.Dir(dir))
	}
	if path, err := userpaths.Cache("paperboat"); err == nil {
		paths = append(paths, path)
	}
	if path, err := userpaths.Config("paperboat"); err == nil {
		paths = append(paths, path)
	}
	if path, err := userpaths.State("paperboat"); err == nil {
		paths = append(paths, path)
	}
	if path, err := userpaths.Data("paperboat"); err == nil {
		paths = append(paths, path)
	}
	if root, err := helperconfig.DefaultStateRoot(os.Getenv); err == nil {
		paths = append(paths, root)
	}
	if root, err := command.Flags().GetString("state-root"); err == nil && root != "" {
		paths = append(paths, filepath.Clean(root))
	}
	var result error
	for _, path := range paths {
		if !filepath.IsAbs(path) || path == string(os.PathSeparator) {
			result = errors.Join(result, errors.New("refusing unsafe Paperboat removal path"))
			continue
		}
		result = errors.Join(result, os.RemoveAll(path))
	}
	return result
}

type relayListResult struct {
	RelayID string  `json:"relay_id"`
	Name    string  `json:"name"`
	Region  string  `json:"region"`
	Status  string  `json:"status"`
	RTTMS   float64 `json:"rtt_ms,omitempty"`
}

func actionRelayList(command *cobra.Command, _ []string) error {
	cfg, err := config.Load(configPathFlag(command))
	if err != nil {
		return err
	}
	if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
		cfg.ServerURL, err = config.NormalizeServerURL(server)
		if err != nil {
			return err
		}
	}
	regions, err := api.New(cfg.ServerURL, config.Credential{}, nil).NetworkCheckRegions(command.Context())
	if err != nil {
		return err
	}
	probe, err := networkcheck.NewRegionalProbe(networkcheck.RegionalProbeConfig{
		Timeout: 3 * time.Second,
		STUN:    networkcheck.STUNRegionalLatency(net.DefaultResolver, 2*time.Second),
		HTTPS:   networkcheck.HTTPSRegionalLatency(time.Now, &http.Client{Timeout: 3 * time.Second}),
	})
	if err != nil {
		return err
	}
	results := make([]relayListResult, len(regions.Regions))
	var wait sync.WaitGroup
	for index, region := range regions.Regions {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := relayListResult{RelayID: region.RelayID, Name: region.Name, Region: region.Region, Status: "unreachable"}
			rtt, probeErr := probe.Probe(command.Context(), networkcheck.ProbeRegion{Region: region.Region, STUNURL: region.STUNURL, HTTPSURL: region.HTTPSURL})
			if probeErr == nil {
				result.Status = "healthy"
				result.RTTMS = float64(rtt) / float64(time.Millisecond)
			}
			results[index] = result
		}()
	}
	wait.Wait()
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(struct {
			Schema string            `json:"schema"`
			Relays []relayListResult `json:"relays"`
		}{Schema: "paperboat.relay-list/v1", Relays: results})
	}
	writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "RELAY\tNAME\tREGION\tSTATUS\tRTT")
	for _, result := range results {
		rtt := "-"
		if result.RTTMS > 0 {
			rtt = fmt.Sprintf("%.1fms", result.RTTMS)
		}
		_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", result.RelayID, result.Name, result.Region, result.Status, rtt)
	}
	return writer.Flush()
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "pb [environment] [new]",
		Short: "Open Paperboat or connect to an environment terminal",
		Args: commandArgs(func(command *cobra.Command, args []string) error {
			if command.ArgsLenAtDash() == 1 && len(args) >= 2 {
				return nil
			}
			return terminalArgs(0)(command, args)
		}),
		RunE: func(command *cobra.Command, args []string) error {
			if command.ArgsLenAtDash() == 1 {
				return actionExecCobra(command, args, true)
			}
			if len(args) == 0 {
				if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
					return actionConnect(actionContext(command, args))
				}
				return actionHome(command)
			}
			if err := validateConnectInvocation(command); err != nil {
				return err
			}
			return actionConnect(actionContext(command, args))
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = buildinfo.Version
	root.SetVersionTemplate(versionDisplay(buildinfo.Version))
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("version").Shorthand = "v"
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invocationError(err) })
	root.PersistentFlags().String("config", "", "path to the CLI config file")
	root.PersistentFlags().String("server", "", "paperboat-server base URL override")
	addConnectFlags(root)

	connect := &cobra.Command{Use: "connect <environment> [new]", Short: "Create and attach to an environment terminal session", Args: commandArgs(terminalArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		if err := validateConnectInvocation(command); err != nil {
			return err
		}
		return actionConnect(actionContext(command, args))
	}}
	addConnectFlags(connect)
	root.AddCommand(connect)
	execCommand := &cobra.Command{Use: "exec <machine> [flags] -- <argv...>", Short: "Execute an exact command on a machine", Args: commandArgs(cobra.ArbitraryArgs), RunE: func(command *cobra.Command, args []string) error {
		return actionExecCobra(command, args, false)
	}}
	execCommand.Flags().String("cwd", "", "absolute remote working directory")
	execCommand.Flags().Duration("timeout", 0, "remote execution timeout")
	execCommand.Flags().Bool("pty", false, "allocate a remote PTY")
	execCommand.Flags().StringArray("env", nil, "remote environment name=value")
	execCommand.Flags().Bool("json", false, "emit paperboat.exec-event/v1 JSON Lines")
	execCommand.Flags().String("transport", "", "peer transport: a, d, q, w, or r")
	root.AddCommand(execCommand)
	sshCommand := &cobra.Command{Use: "ssh [user@]<machine> [-- <OpenSSH arguments...>]", Short: "Connect to a machine with OpenSSH", Args: commandArgs(cobra.ArbitraryArgs), RunE: actionSSH}
	sshCommand.Flags().String("user", "", "remote operating-system user")
	sshCommand.Flags().String("transport", "", "peer transport: a, d, q, w, or r")
	sshTrustHost := &cobra.Command{Use: "trust-host <machine>", Short: "Approve a changed SSH host identity", Args: commandArgs(cobra.ExactArgs(1)), RunE: actionSSHTrustHost}
	sshTrustHost.Flags().String("fingerprint", "", "exact pending SHA256 fingerprint")
	sshCommand.AddCommand(sshTrustHost)
	sshCommand.AddCommand(&cobra.Command{Use: "doctor <machine>", Short: "Check SSH integration for a machine", Args: commandArgs(cobra.ExactArgs(1)), RunE: actionSSHDoctor})
	root.AddCommand(sshCommand)
	sshProxyCommand := &cobra.Command{Use: "__ssh-proxy", Hidden: true, Args: commandArgs(cobra.NoArgs), RunE: actionSSHProxy}
	sshProxyCommand.Flags().String("host", "", "")
	sshProxyCommand.Flags().String("port", "", "")
	sshProxyCommand.Flags().String("user", "", "")
	sshProxyCommand.Flags().String("transport", "", "")
	root.AddCommand(sshProxyCommand)
	sshKnownHostsCommand := &cobra.Command{Use: "__ssh-known-hosts", Hidden: true, Args: commandArgs(cobra.NoArgs), RunE: actionSSHKnownHosts}
	sshKnownHostsCommand.Flags().String("host", "", "")
	sshKnownHostsCommand.Flags().String("port", "", "")
	root.AddCommand(sshKnownHostsCommand)
	codex := &cobra.Command{Use: "codex [environment] [-- <codex-args...>]", Short: "Run local Codex against a remote environment", Args: commandArgs(cobra.ArbitraryArgs), RunE: func(command *cobra.Command, args []string) error {
		selectTarget := len(args) == 0 || command.ArgsLenAtDash() == 0
		_ = command.Flags().Set("select-environment", strconv.FormatBool(selectTarget))
		if selectTarget {
			// Preserve the omitted environment as a positional boundary so the
			// injected flag set cannot consume forwarded Codex flags.
			args = append([]string{""}, args...)
		}
		return actionRun(actionCodex)(command, args)
	}}
	codex.Flags().String("path", "", "remote working directory")
	codex.Flags().String("transport", "", "peer transport: a, d, q, w, or r")
	codex.Flags().Bool("select-environment", false, "")
	_ = codex.Flags().MarkHidden("select-environment")
	root.AddCommand(codex)

	environments := &cobra.Command{Use: "environments", Short: "List machines available to this account", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		jsonOutput, _ := command.Flags().GetBool("json")
		if !jsonOutput && term.IsTerminal(int(os.Stdin.Fd())) {
			return actionEnvironmentsList(command)
		}
		return actionRun(environmentsCommand().Action)(command, args)
	}}
	environments.Flags().Bool("json", false, "print JSON")
	root.AddCommand(environments)

	root.AddCommand(doctorCommandV1())
	ping := &cobra.Command{Use: "ping <machine>", Short: "Measure authenticated connectivity to a machine", Args: commandArgs(cobra.ExactArgs(1)), RunE: actionPing}
	ping.Flags().Int("count", 4, "number of authenticated health exchanges")
	ping.Flags().Duration("timeout", 10*time.Second, "timeout for each exchange")
	ping.Flags().String("transport", "a", "peer transport: a, d, q, w, or r")
	ping.Flags().Bool("json", false, "print JSON")
	root.AddCommand(ping)
	relay := &cobra.Command{Use: "relay", Short: "Inspect Paperboat relays"}
	relayList := &cobra.Command{Use: "list", Short: "List relays and measure current latency", Args: commandArgs(cobra.NoArgs), RunE: actionRelayList}
	relayList.Flags().Bool("json", false, "print JSON")
	relay.AddCommand(relayList)
	root.AddCommand(relay)

	authTree := specTree(authCommand(), "auth")
	authTree.RunE = func(command *cobra.Command, _ []string) error {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return command.Help()
		}
		return actionHomeAccount(command)
	}
	root.AddCommand(authTree)
	login := &cobra.Command{Use: "login", Short: "Sign in through the Paperboat dashboard", Args: commandArgs(cobra.NoArgs), RunE: actionRun(authLogin)}
	login.Flags().String("recovery-key", "", "absolute recovery-key file for restoring private transport")
	root.AddCommand(login)
	root.AddCommand(&cobra.Command{Use: "logout", Short: "Revoke and remove the active client session", Args: commandArgs(cobra.NoArgs), RunE: actionRun(authLogout)})
	configTree := specTree(configCommand(), "config")
	configTree.RunE = func(command *cobra.Command, _ []string) error {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return command.Help()
		}
		return actionHomeConfig(command)
	}
	configTree.AddCommand(statusBarConfigCommand(), configConflictCobraCommand(), configForceCobraCommand())
	root.AddCommand(configTree)
	previewTree := specTree(previewCommand(), "preview")
	previewTree.RunE = func(command *cobra.Command, _ []string) error {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return command.Help()
		}
		return actionHomePreviews(command)
	}
	root.AddCommand(previewTree)
	root.AddCommand(serveCommand())
	root.AddCommand(previewsCobraCommand())
	root.AddCommand(specTree(inboxCommand(), "inbox"))
	root.AddCommand(sessionCobraCommand())
	root.AddCommand(sessionsCobraCommand())
	root.AddCommand(userMachineCobraCommand())
	root.AddCommand(pairCommand())
	root.AddCommand(setupCommand())
	root.AddCommand(updateCommand())
	root.AddCommand(unpairCommand())
	root.AddCommand(uninstallCommand())
	root.AddCommand(sendCommand())
	root.AddCommand(transferCommand())
	root.AddCommand(hostRuntimeCommand())
	root.AddCommand(hostdRuntimeCommand())
	root.AddCommand(runtimeWorkerCommand())
	root.AddCommand(updatedRuntimeCommand())
	root.AddCommand(windowsSSHDServiceCommand())
	root.AddCommand(localDaemonCommand())
	root.AddCommand(statusCommand())
	root.AddCommand(waitCommand())
	root.AddCommand(bugreportCommand())
	root.AddCommand(previewRuntimeCommand())
	root.AddCommand(privatePreviewRuntimeCommand())
	root.AddCommand(serveRuntimeCommand())
	root.AddCommand(privilegedHostServiceCommand())
	root.AddCommand(privilegedServiceOperationCommand())
	root.AddCommand(msiCleanupCommand())
	root.AddCommand(configRuntimeCommand())
	configureShellCompletion(root)
	return root
}

type updateResult struct {
	PreviousVersion   string `json:"previous_version"`
	Version           string `json:"version"`
	CLIUpdated        bool   `json:"cli_updated"`
	RuntimeUpdated    bool   `json:"runtime_updated"`
	SupervisorUpdated bool   `json:"supervisor_updated"`
}

func updateCommand() *cobra.Command {
	command := &cobra.Command{Use: "update", Short: "Update pb from the signed Paperboat release", Args: commandArgs(cobra.NoArgs), RunE: actionUpdate}
	command.Flags().Bool("json", false, "print JSON")
	check := &cobra.Command{Use: "check", Short: "Check the signed Paperboat release without installing it", Args: commandArgs(cobra.NoArgs), RunE: actionUpdateCheck}
	check.Flags().Bool("json", false, "print JSON")
	status := &cobra.Command{Use: "status", Short: "Show installed Paperboat update state", Args: commandArgs(cobra.NoArgs), RunE: actionUpdateStatus}
	status.Flags().Bool("json", false, "print JSON")
	approve := &cobra.Command{Use: "approve-maintenance", Short: "Approve one exact supervisor release for a protected-workload interruption", Args: commandArgs(cobra.NoArgs), RunE: actionApproveMaintenance}
	approve.Flags().String("release", "", "exact signed release version to approve")
	approve.Flags().Bool("json", false, "print JSON")
	_ = approve.MarkFlagRequired("release")
	command.AddCommand(check, status, approve)
	return command
}

type updateCheckResult struct {
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	UpdateAvailable  bool   `json:"update_available"`
	Verified         bool   `json:"verified"`
}

func actionUpdateCheck(command *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(command.Context(), 30*time.Second)
	defer cancel()
	client, err := updated.NewClient(updatedControlSocket(), 30*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Check(ctx)
	if err != nil {
		return fmt.Errorf("check with paperboat-updated: %w", err)
	}
	result := updateCheckResult{InstalledVersion: buildinfo.Version, LatestVersion: response.Version, UpdateAvailable: response.Version != "" && response.Version != buildinfo.Version, Verified: true}
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": result})
	}
	if result.UpdateAvailable {
		fmt.Fprintf(command.OutOrStdout(), "Paperboat %s is available; installed version is %s.\n", result.LatestVersion, buildinfo.Version)
	} else {
		fmt.Fprintf(command.OutOrStdout(), "pb %s is up to date.\n", buildinfo.Version)
	}
	return nil
}

type updateStatusResult struct {
	CLIVersion       string    `json:"cli_version"`
	RuntimeVersion   string    `json:"runtime_version"`
	RuntimeAvailable bool      `json:"runtime_available"`
	LastCheck        time.Time `json:"last_check,omitempty"`
	NextCheck        time.Time `json:"next_check,omitempty"`
	LastFailure      string    `json:"last_failure,omitempty"`
	Supervisor       any       `json:"supervisor,omitempty"`
}

func actionUpdateStatus(command *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(command.Context(), 10*time.Second)
	defer cancel()
	client, err := updated.NewClient(updatedControlSocket(), 10*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Status(ctx)
	if err != nil {
		return fmt.Errorf("read paperboat-updated status: %w", err)
	}
	result := updateStatusResult{CLIVersion: buildinfo.Version, RuntimeVersion: response.Version, RuntimeAvailable: response.Version != "", LastCheck: response.Observation.CheckedAt, NextCheck: response.Observation.NextCheckAt, LastFailure: response.Observation.Failure, Supervisor: response.Supervisor}
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": result})
	}
	fmt.Fprintf(command.OutOrStdout(), "CLI: %s\n", result.CLIVersion)
	if result.RuntimeAvailable {
		fmt.Fprintf(command.OutOrStdout(), "Runtime: %s\n", result.RuntimeVersion)
	} else {
		fmt.Fprintln(command.OutOrStdout(), "Runtime: unavailable")
	}
	if !result.NextCheck.IsZero() {
		fmt.Fprintf(command.OutOrStdout(), "Next automatic check: %s\n", result.NextCheck.Local().Format(time.RFC3339))
	}
	if result.LastFailure != "" {
		fmt.Fprintf(command.OutOrStdout(), "Last update failure: %s\n", result.LastFailure)
	}
	if response.Supervisor.MaintenanceRequired {
		fmt.Fprintf(command.OutOrStdout(), "Supervisor %s requires maintenance approval.\n", response.Supervisor.StagedVersion)
	}
	return nil
}

func actionUpdate(command *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
	defer cancel()
	client, err := updated.NewClient(updatedControlSocket(), 15*time.Minute)
	if err != nil {
		return err
	}
	response, err := client.Update(ctx)
	if err != nil {
		return fmt.Errorf("update with paperboat-updated: %w", err)
	}
	result := updateResult{PreviousVersion: buildinfo.Version, Version: response.Version, CLIUpdated: response.Updated, RuntimeUpdated: response.Updated, SupervisorUpdated: response.Supervisor.Applied}
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": result})
	}
	if !result.RuntimeUpdated {
		fmt.Fprintf(command.OutOrStdout(), "pb runtime %s is already up to date.\n", result.Version)
		return nil
	}
	fmt.Fprintf(command.OutOrStdout(), "Updated Paperboat runtime to %s.\n", result.Version)
	return nil
}

func actionApproveMaintenance(command *cobra.Command, _ []string) error {
	release, err := command.Flags().GetString("release")
	if err != nil || release == "" {
		return errors.New("--release is required")
	}
	ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
	defer cancel()
	client, err := updated.NewClient(updatedControlSocket(), 15*time.Minute)
	if err != nil {
		return err
	}
	response, err := client.ApproveMaintenance(ctx, release)
	if err != nil {
		return fmt.Errorf("approve supervisor maintenance: %w", err)
	}
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": response.Supervisor})
	}
	if response.Supervisor.Applied {
		fmt.Fprintf(command.OutOrStdout(), "Approved and applied supervisor release %s.\n", response.Supervisor.Version)
	} else {
		fmt.Fprintf(command.OutOrStdout(), "Supervisor release %s was staged; activation is pending.\n", response.Supervisor.StagedVersion)
	}
	return nil
}

func updatedControlSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\PaperboatUpdatedControl`
	}
	if runtime.GOOS == "darwin" {
		return "/var/run/paperboat-updated/control.sock"
	}
	return "/run/paperboat-updated/control.sock"
}

const shellCompletionDeadline = 200 * time.Millisecond

func shellCompletionContext(command *cobra.Command) context.Context {
	if command != nil && command.Context() != nil {
		return command.Context()
	}
	return context.Background()
}

func configureShellCompletion(root *cobra.Command) {
	if root == nil {
		return
	}
	machine := machineCompletion
	for _, path := range [][]string{{"connect"}, {"exec"}, {"ssh"}, {"codex"}, {"ping"}, {"doctor"}, {"wait"}, {"machine", "revoke"}, {"previews", "revoke"}} {
		if command, _, err := root.Find(path); err == nil && command != nil {
			command.ValidArgsFunction = machine
		}
	}
	for _, path := range [][]string{{"session", "list"}, {"sessions"}} {
		if command, _, err := root.Find(path); err == nil && command != nil {
			command.ValidArgsFunction = sessionCompletion
		}
	}
	if command, _, err := root.Find([]string{"session", "attach"}); err == nil && command != nil {
		command.ValidArgsFunction = attachSessionCompletion
	}
	for _, parent := range []string{"session", "sessions"} {
		for _, child := range []string{"rename", "close", "delete"} {
			if command, _, err := root.Find([]string{parent, child}); err == nil && command != nil {
				command.ValidArgsFunction = sessionCompletion
			}
		}
	}
	if command, _, err := root.Find([]string{"preview", "revoke"}); err == nil && command != nil {
		command.ValidArgsFunction = previewCompletion
	}
	if command, _, err := root.Find([]string{"send"}); err == nil && command != nil {
		_ = command.RegisterFlagCompletionFunc("to", transferTargetCompletion)
		_ = command.RegisterFlagCompletionFunc("session", allSessionCompletion)
	}
	if command, _, err := root.Find([]string{"transfer", "destination", "set"}); err == nil && command != nil {
		command.ValidArgsFunction = transferTargetCompletion
	}
	root.ValidArgsFunction = machineCompletion
}

func machineCompletion(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return localCompletion(command, "machine", "", toComplete)
}

func transferTargetCompletion(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return localCompletion(command, "transfer_target", "", toComplete)
}

func previewCompletion(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return localCompletion(command, "preview", "", toComplete)
}

func sessionCompletion(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return machineCompletion(command, nil, toComplete)
	}
	if len(args) > 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return sessionsForEnvironmentCompletion(command, args[0], toComplete)
}

func allSessionCompletion(command *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return localCompletion(command, "session", "", toComplete)
}

func attachSessionCompletion(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if len(args) == 1 {
		return sessionsForEnvironmentCompletion(command, args[0], toComplete)
	}
	return localCompletionKinds(command, map[string]bool{"machine": true, "session": true}, "", toComplete)
}

func sessionsForEnvironmentCompletion(command *cobra.Command, environment, toComplete string) ([]string, cobra.ShellCompDirective) {
	return localCompletion(command, "session", environment, toComplete)
}

func localCompletion(command *cobra.Command, kind, environment, prefix string) ([]string, cobra.ShellCompDirective) {
	return localCompletionKinds(command, map[string]bool{kind: true}, environment, prefix)
}

func localCompletionKinds(command *cobra.Command, kinds map[string]bool, environment, prefix string) ([]string, cobra.ShellCompDirective) {
	ctx, cancel := context.WithTimeout(shellCompletionContext(command), shellCompletionDeadline)
	defer cancel()
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	client, err := localapi.NewClient(paths.SocketPath, shellCompletionDeadline)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	snapshot, err := client.Completions(ctx)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	environmentID := ""
	if environment != "" {
		for _, item := range snapshot.Items {
			if item.Kind == "machine" && strings.EqualFold(item.Value, environment) {
				environmentID = item.EnvironmentID
				break
			}
		}
		if environmentID == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	values := make([]string, 0)
	seen := make(map[string]bool)
	for _, item := range snapshot.Items {
		if !kinds[item.Kind] || environmentID != "" && item.EnvironmentID != environmentID || seen[item.Value] || !strings.HasPrefix(strings.ToLower(item.Value), strings.ToLower(prefix)) {
			continue
		}
		seen[item.Value] = true
		values = append(values, item.Value+"\t"+item.Description)
	}
	sort.Strings(values)
	return values, cobra.ShellCompDirectiveNoFileComp
}

func sessionCompletionValues(items []api.TerminalSession, prefix string) []string {
	values := make([]string, 0, len(items)*2)
	seen := make(map[string]bool)
	for _, item := range items {
		for _, value := range []string{item.Name, item.ID} {
			if value == "" || seen[value] || !strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
				continue
			}
			seen[value] = true
			values = append(values, value+"\t"+item.State)
		}
	}
	sort.Strings(values)
	return values
}

func actionHome(command *cobra.Command) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("pb requires a command or environment when used without an interactive terminal")
	}
	endScreen := selector.BeginScreen(command.ErrOrStderr())
	defer endScreen()
	if prefetch, prefetchErr := startHomePrefetch(command); prefetchErr == nil {
		command.SetContext(context.WithValue(command.Context(), homePrefetchContextKey{}, prefetch))
	}
	primeHomeFileIndex()
	revealEmail := false
	for {
		emailAction := "ctrl+e show email"
		if revealEmail {
			emailAction = "ctrl+e hide email"
		}
		selection, err := selector.ChooseWithAction(selector.Options{
			Header:        homeBrand(command, revealEmail),
			Title:         "What do you want to do?",
			Stdin:         os.Stdin,
			Output:        command.ErrOrStderr(),
			Footer:        "↑/↓ move  enter/click select  " + emailAction + "  esc exit",
			Actions:       map[string]string{"ctrl+e": "toggle-email"},
			HeaderActions: map[int]string{2: "toggle-email"},
			Items: []selector.Item{
				{ID: "serve", Title: "Serve a file or directory", Description: "Publish static content from this device"},
				{ID: "machines", Title: "Machines", Description: "Open terminals, run Codex, create previews, send files, or manage computers"},
				{ID: "sessions", Title: "Terminal sessions", Description: "Attach, inspect, close, rename, or delete durable sessions"},
				{ID: "previews", Title: "Public previews", Description: "Inspect or revoke application preview URLs"},
				{ID: "config", Title: "Configuration", Description: "Inspect sync status, CLI settings, and status bar preferences"},
				{ID: "doctor", Title: "Diagnostics", Description: "Check local setup, authentication, and connectivity"},
				{ID: "account", Title: "Account", Description: "View, sign in, switch, or sign out"},
			},
		})
		if err != nil {
			if errors.Is(err, selector.ErrCanceled) || errors.Is(err, selector.ErrInterrupted) {
				return nil
			}
			return err
		}
		if selection.Action == "toggle-email" {
			revealEmail = !revealEmail
			continue
		}
		err = runHomeAction(command, selection.Item.ID)
		if errors.Is(err, selector.ErrInterrupted) {
			return nil
		}
		if errors.Is(err, selector.ErrCanceled) || err == nil {
			continue
		}
		_ = showInformation(command, "Could not complete that action", sentence(userFacingError(err)), nil)
	}
}

const homePrefetchFreshness = 5 * time.Second

type homePrefetchContextKey struct{}

type asyncHomeValue[T any] struct {
	done      chan struct{}
	value     T
	err       error
	fetchedAt time.Time
}

func startAsyncHomeValue[T any](ctx context.Context, load func(context.Context) (T, error)) *asyncHomeValue[T] {
	value := &asyncHomeValue[T]{done: make(chan struct{})}
	go func() {
		defer close(value.done)
		value.value, value.err = load(ctx)
		value.fetchedAt = time.Now()
	}()
	return value
}

func (v *asyncHomeValue[T]) ready() bool {
	select {
	case <-v.done:
		return true
	default:
		return false
	}
}

func (v *asyncHomeValue[T]) await(ctx context.Context) (T, error) {
	select {
	case <-v.done:
		return v.value, v.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func (v *asyncHomeValue[T]) fresh() bool {
	return v.ready() && v.err == nil && time.Since(v.fetchedAt) <= homePrefetchFreshness
}

type homePrefetch struct {
	favorites *asyncHomeValue[favoriteSet]
	machines  *asyncHomeValue[[]api.UserMachine]
	sessions  *asyncHomeValue[[]machineSession]
	previews  *asyncHomeValue[[]api.Preview]

	machinesClaimed atomic.Bool
	sessionsClaimed atomic.Bool
	previewsClaimed atomic.Bool
}

func startHomePrefetch(command *cobra.Command) (*homePrefetch, error) {
	client, err := backendForCommand(command)
	if err != nil {
		return nil, err
	}
	ctx := command.Context()
	prefetch := &homePrefetch{
		favorites: startAsyncHomeValue(ctx, func(ctx context.Context) (favoriteSet, error) { return loadFavorites(ctx, client) }),
		machines:  startAsyncHomeValue(ctx, client.ListUserMachines),
		previews:  startAsyncHomeValue(ctx, client.ListPreviews),
	}
	prefetch.sessions = startAsyncHomeValue(ctx, func(ctx context.Context) ([]machineSession, error) {
		machines, loadErr := prefetch.machines.await(ctx)
		if loadErr != nil {
			return nil, loadErr
		}
		return listMachineSessionsForMachines(ctx, client, machines)
	})
	return prefetch, nil
}

func homePrefetchFor(command *cobra.Command) *homePrefetch {
	value, _ := command.Context().Value(homePrefetchContextKey{}).(*homePrefetch)
	return value
}

func primeHomeFileIndex() {
	go func() {
		root, rootErr := os.UserHomeDir()
		cachePath, cacheErr := fileindex.CachePath()
		if rootErr == nil && cacheErr == nil {
			fileindex.RefreshInBackground(root, cachePath)
		}
	}()
}

func runHomeAction(command *cobra.Command, action string) error {
	switch action {
	case "serve":
		return executeInteractiveCommand(command, []string{"serve"})
	case "sessions":
		return actionHomeSessions(command)
	case "previews":
		return actionHomePreviews(command)
	case "machines":
		return actionHomeMachines(command)
	case "config":
		return actionHomeConfig(command)
	case "doctor":
		return actionHomeDoctor(command)
	case "account":
		return actionHomeAccount(command)
	default:
		return errors.New("unknown Paperboat action")
	}
}

func versionDisplay(version string) string {
	return brandDisplay(version, "") + "\n"
}

func homeBrand(command *cobra.Command, revealEmail bool) string {
	account := "Not signed in"
	configPath, _ := command.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err == nil {
		if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
			cfg.ServerURL, err = config.NormalizeServerURL(server)
		}
	}
	if err == nil && cfg.ServerURL != "" {
		if store, storeErr := config.ProfileStoreFor(cfg); storeErr == nil {
			if profile, profileErr := store.Load(cfg.ServerURL); profileErr == nil {
				account = firstNonEmpty(profile.Account.Email, profile.Account.DisplayName, profile.Account.ID, account)
			}
		}
	}
	if !revealEmail {
		account = maskEmail(account)
	}
	return brandDisplay(buildinfo.Version, account)
}

func maskEmail(value string) string {
	local, domain, ok := strings.Cut(value, "@")
	if !ok {
		return value
	}
	maskPart := func(part string) string {
		return strings.Repeat("█", len([]rune(part)))
	}
	domainParts := strings.Split(domain, ".")
	for index, part := range domainParts {
		domainParts[index] = maskPart(part)
	}
	return maskPart(local) + "@" + strings.Join(domainParts, ".")
}

func brandDisplay(version, account string) string {
	art := []string{"      ▄█▄", "  ▄▄▝▀▀▀▀▀▘▄▄", "   ▀███████▀"}
	details := []string{"Paperboat", "Version " + version, account}
	artWidth := 0
	for _, line := range art {
		artWidth = max(artWidth, ansi.StringWidth(line))
	}
	lines := make([]string, len(art))
	for index, line := range art {
		lines[index] = line
		if details[index] != "" {
			lines[index] += strings.Repeat(" ", artWidth-ansi.StringWidth(line)+3) + details[index]
		}
	}
	return strings.Join(lines, "\n")
}

func actionEnvironmentsList(command *cobra.Command) error {
	client, err := backendForCommand(command)
	if err != nil {
		return err
	}
	machines, err := client.ListUserMachines(command.Context())
	if err != nil {
		return friendlyCommandError(err)
	}
	currentMachineID, _ := configuredMachineID()
	sortMachinesForDisplay(machines, nil, currentMachineID)
	items := make([]selector.Item, 0, len(machines))
	for _, machine := range machines {
		items = append(items, selector.Item{ID: machine.ID, Title: machineDisplayTitle(machine, currentMachineID), Description: machineStatusSummary(machine), Search: machine.ID + " " + machine.WorkspaceRoot + " " + machineStatusSearch(machine)})
	}
	_, err = selector.Choose(selector.Options{Title: "Machines", Subtitle: "Computers available to this account", Items: items, Empty: "No machines yet", Footer: "↑/↓ inspect  type to filter  esc back", Stdin: os.Stdin, Output: command.ErrOrStderr()})
	return err
}

func actionHomeSessions(command *cobra.Command) error {
	client, err := backendForCommand(command)
	if err != nil {
		return err
	}
	usePrefetch := true
	for {
		var favorites favoriteSet
		var sessions []machineSession
		var listErr error
		loaded := false
		if usePrefetch {
			usePrefetch = false
			if prefetch := homePrefetchFor(command); prefetch != nil && prefetch.sessionsClaimed.CompareAndSwap(false, true) {
				work := func(ctx context.Context) error {
					var loadErr error
					favorites, loadErr = prefetch.favorites.await(ctx)
					if loadErr == nil {
						sessions, loadErr = prefetch.sessions.await(ctx)
					}
					return loadErr
				}
				listErr = runPrefetchedHomeLoad(command, "Terminal sessions", "Loading sessions", prefetch.favorites.ready() && prefetch.sessions.ready(), work)
				loaded = listErr == nil && prefetch.favorites.fresh() && prefetch.sessions.fresh()
			}
		}
		if !loaded {
			listErr = homeLoading(command, "Terminal sessions", "Loading sessions", func(ctx context.Context) error {
				var err error
				favorites, err = loadFavorites(ctx, client)
				if err != nil {
					return err
				}
				sessions, err = listMachineSessions(ctx, client)
				return err
			})
		}
		if listErr != nil {
			return friendlyCommandError(listErr)
		}
		selected, selectErr := selectMachineSession(sessions, favorites)
		if errors.Is(selectErr, errFavoriteToggle) {
			if favoriteErr := setFavorite(command.Context(), client, "session", machineSessionFavoriteID(selected), !favorites.IsFavorite("session", machineSessionFavoriteID(selected))); favoriteErr != nil {
				return favoriteErr
			}
			continue
		}
		if selectErr != nil {
			return selectErr
		}
		target, session := selected.target, selected.session
		for {
			actions := []selector.Item{
				{ID: "attach", Title: "Attach", Description: "Open this durable terminal session"},
				{ID: "rename", Title: "Rename", Description: "Change the name shown in the session catalog"},
			}
			if session.State != "closed" {
				actions = append(actions, selector.Item{ID: "close", Title: "Close", Description: "Stop its process while retaining history"})
			}
			if session.State == "closed" && !session.IsDefault {
				actions = append(actions, selector.Item{ID: "delete", Title: "Delete", Description: "Permanently remove this session and its history"})
			}
			action, actionErr := chooseHomeAction(command, session.Name, actions)
			if errors.Is(actionErr, selector.ErrCanceled) {
				continue
			}
			if actionErr != nil {
				return actionErr
			}
			if action.ID == "attach" {
				if attachErr := executeInteractiveCommand(command, []string{"session", "attach", target.id, session.ID}); attachErr != nil {
					return attachErr
				}
				break
			}
			if action.ID == "rename" {
				name, promptErr := prompt.Text(prompt.TextOptions{Title: "Rename session", Description: target.name + "  ·  " + session.Name, Placeholder: session.Name, Stdin: os.Stdin, Output: command.ErrOrStderr(), Validate: func(value string) error {
					if strings.TrimSpace(value) == "" {
						return errors.New("session name is required")
					}
					return nil
				}})
				if errors.Is(promptErr, prompt.ErrCanceled) {
					continue
				}
				if promptErr != nil {
					return promptErr
				}
				if mutationErr := executeInteractiveCommand(command, []string{"sessions", "rename", target.id, session.ID, name}); mutationErr != nil {
					return mutationErr
				}
				break
			}
			if mutationErr := executeInteractiveCommand(command, []string{"sessions", action.ID, target.id, session.ID}); mutationErr != nil {
				return mutationErr
			}
			break
		}
	}
}

type machineSession struct {
	target  environmentTarget
	session api.TerminalSession
}

func listMachineSessions(ctx context.Context, client *api.Client) ([]machineSession, error) {
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return nil, err
	}
	return listMachineSessionsForMachines(ctx, client, machines)
}

func listMachineSessionsForMachines(ctx context.Context, client *api.Client, machines []api.UserMachine) ([]machineSession, error) {
	machines = slices.Clone(machines)
	machines = slices.DeleteFunc(machines, func(machine api.UserMachine) bool {
		return !machine.Capabilities.TerminalHost.Configured
	})
	results := make(chan []machineSession, len(machines))
	errorsOut := make(chan error, len(machines))
	workers := make(chan struct{}, 4)
	var group sync.WaitGroup
	for _, machine := range machines {
		machine := machine
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case workers <- struct{}{}:
				defer func() { <-workers }()
			case <-ctx.Done():
				errorsOut <- ctx.Err()
				return
			}
			items, loadErr := client.ListUserMachineTerminalSessions(ctx, machine.ID)
			if loadErr != nil {
				errorsOut <- loadErr
				return
			}
			target := environmentTarget{kind: environmentUserMachine, id: machine.ID, name: machine.DisplayName}
			mapped := make([]machineSession, 0, len(items))
			for _, session := range items {
				mapped = append(mapped, machineSession{target: target, session: session})
			}
			results <- mapped
		}()
	}
	group.Wait()
	close(results)
	close(errorsOut)
	if loadErr, ok := <-errorsOut; ok {
		return nil, loadErr
	}
	var sessions []machineSession
	for result := range results {
		sessions = append(sessions, result...)
	}
	slices.SortStableFunc(sessions, func(a, b machineSession) int {
		return b.activity().Compare(a.activity())
	})
	return sessions, nil
}

func (s machineSession) activity() time.Time {
	if s.session.LastActiveAt != nil {
		return *s.session.LastActiveAt
	}
	if !s.session.UpdatedAt.IsZero() {
		return s.session.UpdatedAt
	}
	return s.session.CreatedAt
}

func selectMachineSession(sessions []machineSession, favorites favoriteSet) (machineSession, error) {
	slices.SortStableFunc(sessions, func(a, b machineSession) int {
		return compareFavorites(favorites.IsFavorite("session", machineSessionFavoriteID(a)), favorites.IsFavorite("session", machineSessionFavoriteID(b)))
	})
	items := make([]selector.Item, 0, len(sessions))
	byID := make(map[string]machineSession, len(sessions))
	for _, entry := range sessions {
		attached := "no attachments"
		if entry.session.AttachedCount != nil {
			attached = fmt.Sprintf("%d attached", *entry.session.AttachedCount)
		}
		key := entry.target.id + ":" + entry.session.ID
		activity := entry.activity()
		description := strings.Join([]string{entry.target.name, entry.session.State, attached, "last active " + relativeTime(&activity)}, "  ·  ")
		favorite := favorites.IsFavorite("session", machineSessionFavoriteID(entry))
		items = append(items, selector.Item{ID: key, Title: entry.session.Name, Description: description, Search: entry.target.name + " " + entry.target.id + " favorite starred", Favorite: favorite})
		byID[key] = entry
	}
	selected, err := selector.ChooseWithAction(selector.Options{Title: "Terminal sessions", Subtitle: "All machine sessions, newest first", Items: items, Empty: "no terminal sessions are available", Footer: "↑/↓ move  enter open  ctrl+f favorite  esc back", Actions: map[string]string{"ctrl+f": "favorite"}, Stdin: os.Stdin, Output: os.Stderr})
	entry := byID[selected.Item.ID]
	if err == nil && selected.Action == "favorite" {
		err = errFavoriteToggle
	}
	return entry, err
}

func machineSessionFavoriteID(entry machineSession) string {
	return entry.target.id + ":" + entry.session.ID
}

func actionHomePreviews(command *cobra.Command) error {
	client, err := backendForCommand(command)
	if err != nil {
		return err
	}
	usePrefetch := true
	for {
		var favorites favoriteSet
		var previews []api.Preview
		var err error
		loaded := false
		if usePrefetch {
			usePrefetch = false
			if prefetch := homePrefetchFor(command); prefetch != nil && prefetch.previewsClaimed.CompareAndSwap(false, true) {
				work := func(ctx context.Context) error {
					var loadErr error
					favorites, loadErr = prefetch.favorites.await(ctx)
					if loadErr == nil {
						previews, loadErr = prefetch.previews.await(ctx)
					}
					return loadErr
				}
				err = runPrefetchedHomeLoad(command, "Public previews", "Loading previews", prefetch.favorites.ready() && prefetch.previews.ready(), work)
				loaded = err == nil && prefetch.favorites.fresh() && prefetch.previews.fresh()
			}
		}
		if !loaded {
			err = homeLoading(command, "Public previews", "Loading previews", func(ctx context.Context) error {
				var loadErr error
				favorites, loadErr = loadFavorites(ctx, client)
				if loadErr != nil {
					return loadErr
				}
				previews, loadErr = client.ListPreviews(ctx)
				return loadErr
			})
		}
		if err != nil {
			return friendlyCommandError(err)
		}
		previews = enrichLocalServeSources(previews)
		slices.SortStableFunc(previews, func(a, b api.Preview) int {
			return compareFavorites(favorites.IsFavorite("preview", a.ID), favorites.IsFavorite("preview", b.ID))
		})
		items := make([]selector.Item, 0, len(previews))
		byID := make(map[string]api.Preview, len(previews))
		for _, preview := range previews {
			expiry := "indefinite"
			if preview.ExpiresAt != nil {
				expiry = "expires " + relativeTime(preview.ExpiresAt)
			}
			favorite := favorites.IsFavorite("preview", preview.ID)
			source := preview.SourceKind
			if source == "" {
				source = "application"
			}
			descriptionParts := []string{preview.EnvironmentName, preview.State, source, expiry}
			if preview.SourcePath != "" {
				descriptionParts = append(descriptionParts, preview.SourcePath)
			}
			items = append(items, selector.Item{ID: preview.ID, Title: preview.LogicalName, Description: strings.Join(descriptionParts, "  ·  "), Search: preview.URL + " " + preview.EnvironmentKind + " " + preview.OwnerMode + " " + preview.SourcePath + " favorite starred", Favorite: favorite})
			byID[preview.ID] = preview
		}
		selection, selectErr := selector.ChooseWithAction(selector.Options{Title: "Public previews", Subtitle: "Anyone with a listed URL can access it", Items: items, Empty: "No public previews yet", Footer: "↑/↓ move  enter open  ctrl+f favorite  esc back", Actions: map[string]string{"ctrl+f": "favorite"}, Stdin: os.Stdin, Output: command.ErrOrStderr()})
		if selectErr != nil {
			return selectErr
		}
		preview := byID[selection.Item.ID]
		if selection.Action == "favorite" {
			if favoriteErr := setFavorite(command.Context(), client, "preview", preview.ID, !favorites.IsFavorite("preview", preview.ID)); favoriteErr != nil {
				return favoriteErr
			}
			continue
		}
		revokeTitle := "Revoke preview"
		revokeDescription := "Remove this public URL"
		if preview.SourceKind == "file" || preview.SourceKind == "directory" {
			revokeTitle = "Stop serving"
			revokeDescription = "Stop the local static server and remove its public URL"
		}
		action, actionErr := chooseHomeAction(command, preview.LogicalName, []selector.Item{
			{ID: "open", Title: "Open preview", Description: preview.URL},
			{ID: "revoke", Title: revokeTitle, Description: revokeDescription},
		})
		if errors.Is(actionErr, selector.ErrCanceled) {
			continue
		}
		if actionErr != nil {
			return actionErr
		}
		if action.ID == "open" {
			if openErr := openBrowser(preview.URL); openErr != nil {
				return openErr
			}
			continue
		}
		if revokeErr := executeInteractiveCommand(command, []string{"preview", "revoke", preview.ID}); revokeErr != nil {
			return revokeErr
		}
	}
}

func actionHomeMachines(command *cobra.Command) error {
	client, err := backendForCommand(command)
	if err != nil {
		return err
	}
	usePrefetch := true
	for {
		var favorites favoriteSet
		var machines []api.UserMachine
		var err error
		loaded := false
		if usePrefetch {
			usePrefetch = false
			if prefetch := homePrefetchFor(command); prefetch != nil && prefetch.machinesClaimed.CompareAndSwap(false, true) {
				work := func(ctx context.Context) error {
					var loadErr error
					favorites, loadErr = prefetch.favorites.await(ctx)
					if loadErr == nil {
						machines, loadErr = prefetch.machines.await(ctx)
					}
					return loadErr
				}
				err = runPrefetchedHomeLoad(command, "Machines", "Loading machines", prefetch.favorites.ready() && prefetch.machines.ready(), work)
				loaded = err == nil && prefetch.favorites.fresh() && prefetch.machines.fresh()
			}
		}
		if !loaded {
			err = homeLoading(command, "Machines", "Loading machines", func(ctx context.Context) error {
				var loadErr error
				favorites, loadErr = loadFavorites(ctx, client)
				if loadErr != nil {
					return loadErr
				}
				machines, loadErr = client.ListUserMachines(ctx)
				return loadErr
			})
		}
		if err != nil {
			return friendlyCommandError(err)
		}
		currentMachineID, _ := configuredMachineID()
		sortMachinesForDisplay(machines, favorites, currentMachineID)
		items := make([]selector.Item, 0, len(machines)+1)
		byID := make(map[string]api.UserMachine, len(machines))
		for _, machine := range machines {
			if machine.ID == currentMachineID {
				continue
			}
			favorite := favorites.IsFavorite("machine", machine.ID)
			items = append(items, selector.Item{ID: machine.ID, Title: machine.DisplayName, Description: machineStatusSummary(machine), Search: machine.WorkspaceRoot + " " + machineStatusSearch(machine) + " favorite starred", Favorite: favorite})
			byID[machine.ID] = machine
		}
		for _, machine := range machines {
			if machine.ID != currentMachineID {
				continue
			}
			favorite := favorites.IsFavorite("machine", machine.ID)
			items = append(items, selector.Item{ID: machine.ID, Title: machineDisplayTitle(machine, currentMachineID), Description: machineStatusSummary(machine), Search: machine.WorkspaceRoot + " " + machineStatusSearch(machine) + " this device favorite starred", Favorite: favorite})
			byID[machine.ID] = machine
		}
		items = append(items, selector.Item{ID: "add", Title: "+ Add machine", Description: "Set up another computer", Search: "new pair enroll", Action: true})
		selection, selectErr := selector.ChooseWithAction(selector.Options{Title: "Machines", Subtitle: "Paired computers", Items: items, Footer: "↑/↓ move  enter open  ctrl+f favorite  esc back", Actions: map[string]string{"ctrl+f": "favorite"}, Stdin: os.Stdin, Output: command.ErrOrStderr()})
		if selectErr != nil {
			return selectErr
		}
		choice := selection.Item
		if choice.ID == "add" && selection.Action == "favorite" {
			continue
		}
		if choice.ID == "add" {
			if addErr := executeInteractiveCommand(command, []string{"machine", "add"}); addErr != nil {
				return addErr
			}
			continue
		}
		machine := byID[choice.ID]
		if selection.Action == "favorite" {
			if favoriteErr := setFavorite(command.Context(), client, "machine", machine.ID, !favorites.IsFavorite("machine", machine.ID)); favoriteErr != nil {
				return favoriteErr
			}
			continue
		}
		for {
			action, actionErr := chooseMachineHomeAction(command, machine)
			if errors.Is(actionErr, selector.ErrCanceled) {
				break
			}
			if actionErr != nil {
				return actionErr
			}
			var runErr error
			switch action.ID {
			case "terminal":
				runErr = executeInteractiveCommand(command, []string{"connect", machine.ID, "new"})
			case "codex":
				runErr = executeInteractiveCommand(command, []string{"codex", machine.ID})
			case "sessions":
				runErr = actionHomeMachineSessions(command, client, machine)
				if errors.Is(runErr, selector.ErrCanceled) {
					runErr = nil
				}
			case "preview":
				runErr = actionHomeCreateMachinePreview(command, machine)
			case "previews":
				runErr = actionHomeMachinePreviews(command, client, machine)
			case "send":
				runErr = actionHomeSendToMachine(command, machine)
			case "rename":
				fmt.Fprintf(command.ErrOrStderr(), "New name for %s: ", machine.DisplayName)
				name, readErr := bufio.NewReader(io.LimitReader(command.InOrStdin(), 257)).ReadString('\n')
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					runErr = readErr
					break
				}
				name = strings.TrimSpace(name)
				if name == "" {
					runErr = errors.New("machine name must not be empty")
					break
				}
				runErr = executeInteractiveCommand(command, []string{"machine", "rename", machine.ID, name})
				if runErr == nil {
					machine.DisplayName = name
				}
			case "allow-sleep":
				runErr = executeInteractiveCommand(command, []string{"machine", "availability", machine.ID, "--mode", "allow-sleep"})
			case "keep-awake":
				runErr = executeInteractiveCommand(command, []string{"machine", "availability", machine.ID, "--mode", "keep-awake", "--yes"})
			default:
				runErr = errors.New("unknown machine action")
			}
			if errors.Is(runErr, selector.ErrCanceled) {
				continue
			}
			if runErr != nil {
				return runErr
			}
		}
	}
}

func machineHomeActions(machine api.UserMachine) []selector.Item {
	actions := make([]selector.Item, 0, 8)
	actions = append(actions, selector.Item{ID: "rename", Title: "Rename", Description: "Change this machine's display name"})
	if machine.Capabilities.TerminalHost.Configured {
		actions = append(actions,
			selector.Item{ID: "terminal", Title: "Create terminal session", Description: "Start and attach to a new durable session"},
			selector.Item{ID: "codex", Title: "Create Codex session", Description: "Choose a remote folder and start a managed Codex session"},
		)
	}
	if machine.Capabilities.FileReceive.Configured {
		if sourceMachineID, err := configuredMachineID(); err != nil || sourceMachineID != machine.ID {
			actions = append(actions, selector.Item{ID: "send", Title: "Send files", Description: "Search, select, drop, or paste files for this machine"})
		}
	}
	if machine.Capabilities.PreviewLaunch.Configured {
		actions = append(actions, selector.Item{ID: "preview", Title: "Create preview", Description: "Publish an application port from this machine"})
	}
	if machine.Capabilities.TerminalHost.Configured {
		actions = append(actions, selector.Item{ID: "sessions", Title: "Sessions", Description: "List durable terminal sessions on this machine"})
	}
	if machine.Capabilities.PreviewLaunch.Configured {
		actions = append(actions, selector.Item{ID: "previews", Title: "Previews", Description: "Open or revoke previews created on this machine"})
	}
	if machine.SetupMode == "host" {
		actions = append(actions,
			selector.Item{ID: "allow-sleep", Title: "Allow sleep", Description: "Let normal operating-system sleep policy apply"},
			selector.Item{ID: "keep-awake", Title: "Keep awake", Description: "Request availability even when idle"},
		)
	}
	return actions
}

func chooseMachineHomeAction(command *cobra.Command, machine api.UserMachine) (selector.Item, error) {
	return selector.Choose(selector.Options{Title: machine.DisplayName, Subtitle: machineStatusSummary(machine), Items: machineHomeActions(machine), Stdin: os.Stdin, Output: command.ErrOrStderr()})
}

func machineStatusSummary(machine api.UserMachine) string {
	mode := effectiveMachineMode(machine)
	if mode == "session" {
		return "Session only"
	}
	return machineAvailabilityLabel(machine) + "  ·  " + machineModeLabel(machine)
}

func machineStatusSearch(machine api.UserMachine) string {
	return strings.Join([]string{machineAvailabilityLabel(machine), machineModeLabel(machine), machine.SetupMode}, " ")
}

func machineAvailabilityLabel(machine api.UserMachine) string {
	if machine.Online {
		return "Online"
	}
	switch strings.ToLower(strings.TrimSpace(machine.State)) {
	case "revoked", "deleted":
		return "Unavailable"
	default:
		return "Offline"
	}
}

func machineModeLabel(machine api.UserMachine) string {
	switch effectiveMachineMode(machine) {
	case "host":
		return "Host"
	case "client":
		return "Client"
	case "session":
		return "Session only"
	default:
		return "Limited"
	}
}

func machineDisplayTitle(machine api.UserMachine, currentMachineID string) string {
	if machine.ID == currentMachineID {
		return machine.DisplayName + " (this device)"
	}
	return machine.DisplayName
}

func sortMachinesForDisplay(machines []api.UserMachine, favorites favoriteSet, currentMachineID string) {
	slices.SortStableFunc(machines, func(a, b api.UserMachine) int {
		aCurrent, bCurrent := a.ID == currentMachineID, b.ID == currentMachineID
		if aCurrent != bCurrent {
			if aCurrent {
				return 1
			}
			return -1
		}
		return compareFavorites(favorites.IsFavorite("machine", a.ID), favorites.IsFavorite("machine", b.ID))
	})
}

func effectiveMachineMode(machine api.UserMachine) string {
	switch machine.SetupMode {
	case "host", "client", "session":
		return machine.SetupMode
	}
	if machine.Capabilities.TerminalHost.Configured || machine.Capabilities.CodexHost.Configured {
		return "host"
	}
	if machine.Capabilities.FileReceive.Configured || machine.Capabilities.PreviewLaunch.Configured {
		return "client"
	}
	return ""
}

func actionHomeMachinePreviews(command *cobra.Command, client *api.Client, machine api.UserMachine) error {
	var previews []api.Preview
	var favorites favoriteSet
	err := homeLoading(command, "Previews", "Loading previews from "+machine.DisplayName, func(ctx context.Context) error {
		var loadErr error
		favorites, loadErr = loadFavorites(ctx, client)
		if loadErr != nil {
			return loadErr
		}
		items, loadErr := client.ListPreviews(ctx)
		if loadErr != nil {
			return loadErr
		}
		for _, preview := range items {
			if preview.EnvironmentID == machine.EnvironmentID {
				previews = append(previews, preview)
			}
		}
		return nil
	})
	if err != nil {
		return friendlyCommandError(err)
	}
	for {
		slices.SortStableFunc(previews, func(a, b api.Preview) int {
			return compareFavorites(favorites.IsFavorite("preview", a.ID), favorites.IsFavorite("preview", b.ID))
		})
		items := make([]selector.Item, 0, len(previews))
		byID := make(map[string]api.Preview, len(previews))
		for _, preview := range previews {
			favorite := favorites.IsFavorite("preview", preview.ID)
			items = append(items, selector.Item{ID: preview.ID, Title: preview.LogicalName, Description: fmt.Sprintf("%s  ·  :%d  ·  %s", preview.State, preview.TargetPort, preview.URL), Search: preview.URL, Favorite: favorite})
			byID[preview.ID] = preview
		}
		selection, selectErr := selector.ChooseWithAction(selector.Options{Title: "Previews", Subtitle: machine.DisplayName, Items: items, Empty: "No previews for this machine", Footer: "↑/↓ move  enter open  ctrl+f favorite  esc back", Actions: map[string]string{"ctrl+f": "favorite"}, Stdin: os.Stdin, Output: command.ErrOrStderr()})
		if selectErr != nil {
			return selectErr
		}
		preview := byID[selection.Item.ID]
		if selection.Action == "favorite" {
			favorite := !favorites.IsFavorite("preview", preview.ID)
			if err := setFavorite(command.Context(), client, "preview", preview.ID, favorite); err != nil {
				return err
			}
			favorites.Set("preview", preview.ID, favorite)
			continue
		}
		action, actionErr := chooseHomeAction(command, preview.LogicalName, []selector.Item{{ID: "open", Title: "Open preview", Description: preview.URL}, {ID: "revoke", Title: "Revoke preview", Description: "Remove this public URL"}})
		if actionErr != nil {
			return actionErr
		}
		if action.ID == "open" {
			if err := openBrowser(preview.URL); err != nil {
				return err
			}
			continue
		}
		return executeInteractiveCommand(command, []string{"preview", "revoke", preview.ID})
	}
}

func actionHomeCreateMachinePreview(command *cobra.Command, machine api.UserMachine) error {
	portText, err := prompt.Text(prompt.TextOptions{Title: "Application port", Description: "Port where the application is already listening on " + machine.DisplayName, Placeholder: "3000", Stdin: os.Stdin, Output: command.ErrOrStderr(), Validate: func(value string) error {
		port, parseErr := strconv.ParseUint(value, 10, 16)
		if parseErr != nil || port == 0 {
			return errors.New("port must be between 1 and 65535")
		}
		return nil
	}})
	if errors.Is(err, prompt.ErrCanceled) {
		return selector.ErrCanceled
	}
	if err != nil {
		return err
	}
	name := "preview-" + portText
	return executeInteractiveCommand(command, []string{"preview", "create", "--machine", machine.ID, "--name", name, "--port", portText, "--public"})
}

func actionHomeSendToMachine(command *cobra.Command, machine api.UserMachine) error {
	var candidates []string
	searchRoot, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cachePath, err := fileindex.CachePath()
	if err != nil {
		return err
	}
	loadIndex := func(ctx context.Context) error {
		var refreshErr error
		candidates, refreshErr = fileindex.Current(ctx, searchRoot, cachePath)
		return refreshErr
	}
	if fileindex.RefreshReady(cachePath) {
		err = loadIndex(command.Context())
	} else {
		err = homeLoading(command, "Send files", "Refreshing files", loadIndex)
	}
	if err != nil {
		return err
	}
	defer fileindex.RefreshInBackground(searchRoot, cachePath)
	items := make([]selector.Item, 0, len(candidates)+1)
	for _, path := range candidates {
		info, statErr := os.Stat(path)
		if statErr != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		display := path
		if relative, relativeErr := filepath.Rel(searchRoot, path); relativeErr == nil {
			display = filepath.Join("~", relative)
		}
		items = append(items, selector.Item{ID: path, Title: display, Description: "File"})
	}
	selection, err := selector.ChooseWithAction(selector.Options{Title: "Send files to " + machine.DisplayName, Subtitle: "Type to fuzzy-search files in your home folder", Items: items, Empty: "Start typing to search", RequireFilter: true, Footer: "type to search  enter/click send  ctrl+p paste or drop paths  esc back", Actions: map[string]string{"ctrl+p": "paths"}, Stdin: os.Stdin, Output: command.ErrOrStderr()})
	if err != nil {
		return err
	}
	if selection.Action != "paths" {
		return executeInteractiveCommand(command, []string{"send", selection.Item.ID, "--to", machine.ID})
	}
	value, err := prompt.Text(prompt.TextOptions{Title: "Send files to " + machine.DisplayName, Description: "Drag files here or paste one or more file or folder paths", Placeholder: "/path/to/file", Stdin: os.Stdin, Output: command.ErrOrStderr(), Validate: func(value string) error {
		_, parseErr := droppedFilePaths(value)
		return parseErr
	}})
	if errors.Is(err, prompt.ErrCanceled) {
		return selector.ErrCanceled
	}
	if err != nil {
		return err
	}
	paths, err := droppedFilePaths(value)
	if err != nil {
		return err
	}
	arguments := append([]string{"send"}, paths...)
	arguments = append(arguments, "--to", machine.ID)
	return executeInteractiveCommand(command, arguments)
}

func droppedFilePaths(value string) ([]string, error) {
	paths, err := splitDroppedPaths(strings.TrimSpace(value))
	if err != nil || len(paths) == 0 {
		return nil, errors.New("drop or paste at least one valid file or folder path")
	}
	for index, path := range paths {
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) {
			absolute, absoluteErr := filepath.Abs(path)
			if absoluteErr != nil {
				return nil, absoluteErr
			}
			path = absolute
		}
		if _, statErr := os.Stat(path); statErr != nil {
			return nil, fmt.Errorf("%s is not available", path)
		}
		paths[index] = path
	}
	return paths, nil
}

func homeLoading(command *cobra.Command, title, detail string, work func(context.Context) error) error {
	return selector.Loading(command.Context(), title, detail, os.Stdin, command.ErrOrStderr(), work)
}

func runPrefetchedHomeLoad(command *cobra.Command, title, detail string, ready bool, work func(context.Context) error) error {
	if ready {
		return work(command.Context())
	}
	return homeLoading(command, title, detail, work)
}

func actionHomeMachineSessions(command *cobra.Command, client *api.Client, machine api.UserMachine) error {
	target := environmentTarget{kind: environmentUserMachine, id: machine.ID, name: machine.DisplayName}
	var records []api.TerminalSession
	var favorites favoriteSet
	err := homeLoading(command, "Terminal sessions", "Loading sessions", func(ctx context.Context) error {
		var loadErr error
		favorites, loadErr = loadFavorites(ctx, client)
		if loadErr != nil {
			return loadErr
		}
		records, loadErr = listTerminalSessionsForTarget(ctx, client, target)
		return loadErr
	})
	if err != nil {
		return friendlyCommandError(err)
	}
	for {
		sessions := make([]machineSession, 0, len(records))
		for _, session := range records {
			sessions = append(sessions, machineSession{target: target, session: session})
		}
		selected, selectErr := selectMachineSession(sessions, favorites)
		if errors.Is(selectErr, errFavoriteToggle) {
			id := machineSessionFavoriteID(selected)
			favorite := !favorites.IsFavorite("session", id)
			if err := setFavorite(command.Context(), client, "session", id, favorite); err != nil {
				return err
			}
			favorites.Set("session", id, favorite)
			continue
		}
		if selectErr != nil {
			return selectErr
		}
		return executeInteractiveCommand(command, []string{"session", "attach", machine.ID, selected.session.ID})
	}
}

func actionHomeAccount(command *cobra.Command) error {
	for {
		ctx := actionContext(command, nil)
		d, err := buildDeps(ctx)
		if err != nil {
			return err
		}
		items := []selector.Item{{ID: "status", Title: "Account status", Description: "Not signed in"}, {ID: "login", Title: "Sign in", Description: "Authenticate through the Paperboat dashboard"}}
		if _, credentialErr := d.auth.Credential(); credentialErr == nil {
			items = []selector.Item{
				{ID: "status", Title: "Account status", Description: "Signed in"},
				{ID: "switch", Title: "Switch account", Description: "Replace the account used for this server"},
				{ID: "logout", Title: "Sign out", Description: "Revoke this CLI session"},
			}
		}
		choice, err := chooseHomeAction(command, "Account", items)
		if err != nil {
			return err
		}
		switch choice.ID {
		case "status":
			client, clientErr := backendForCommand(command)
			if clientErr != nil {
				if infoErr := showInformation(command, "Account", "Not signed in", nil); infoErr != nil && !errors.Is(infoErr, selector.ErrCanceled) {
					return infoErr
				}
				continue
			}
			var me api.Me
			meErr := homeLoading(command, "Account", "Loading account", func(ctx context.Context) error {
				var loadErr error
				me, loadErr = client.Me(ctx)
				return loadErr
			})
			if meErr != nil {
				return friendlyCommandError(meErr)
			}
			if infoErr := showInformation(command, "Account", firstNonEmpty(me.Email, me.DisplayName, me.ID), []selector.Item{{ID: "server", Title: "Paperboat server", Description: d.cfg.ServerURL}}); infoErr != nil && !errors.Is(infoErr, selector.ErrCanceled) {
				return infoErr
			}
		case "login":
			if err := executeInteractiveCommand(command, []string{"auth", "login"}); err != nil {
				return err
			}
		case "switch":
			if err := executeInteractiveCommand(command, []string{"auth", "switch"}); err != nil {
				return err
			}
		case "logout":
			if err := executeInteractiveCommand(command, []string{"auth", "logout"}); err != nil {
				return err
			}
		}
	}
}

func actionHomeConfig(command *cobra.Command) error {
	for {
		cfg, loadErr := config.Load(configPathFlag(command))
		if loadErr != nil {
			return loadErr
		}
		choice, err := chooseHomeAction(command, "Configuration", []selector.Item{
			{ID: "server", Title: "Paperboat server", Description: orNone(cfg.ServerURL), Search: "edit url endpoint"},
			{ID: "auth", Title: "File credential fallback", Description: onOff(cfg.Auth.AllowFileFallback), Search: "toggle auth credentials"},
			{ID: "status-bar", Title: "Status bar", Description: cfg.StatusBar.Mode + "  ·  " + cfg.StatusBar.Theme + "  ·  fullscreen " + cfg.StatusBar.Fullscreen},
			{ID: "status", Title: "Sync status", Description: "Inspect environment configuration synchronization"},
			{ID: "path", Title: "Configuration file", Description: cfg.Path()},
		})
		if err != nil {
			return err
		}
		switch choice.ID {
		case "server":
			value, inputErr := prompt.Text(prompt.TextOptions{Title: "Paperboat server", Description: "Control-plane URL used by this CLI", Placeholder: "https://api.pprbt.dev", Initial: cfg.ServerURL, Stdin: os.Stdin, Output: command.ErrOrStderr(), Validate: func(value string) error {
				if strings.TrimSpace(value) == "" {
					return nil
				}
				_, normalizeErr := config.NormalizeServerURL(value)
				return normalizeErr
			}})
			if errors.Is(inputErr, prompt.ErrCanceled) {
				continue
			}
			if inputErr != nil {
				return inputErr
			}
			if strings.TrimSpace(value) == "" {
				cfg.ServerURL = ""
			} else {
				cfg.ServerURL, loadErr = config.NormalizeServerURL(value)
				if loadErr != nil {
					return loadErr
				}
			}
			if saveErr := cfg.Save(); saveErr != nil {
				return saveErr
			}
		case "auth":
			cfg.Auth.AllowFileFallback = !cfg.Auth.AllowFileFallback
			if saveErr := cfg.Save(); saveErr != nil {
				return saveErr
			}
		case "status-bar":
			if statusErr := actionHomeStatusBar(command); !errors.Is(statusErr, selector.ErrCanceled) {
				return statusErr
			}
		case "status":
			client, clientErr := backendForCommand(command)
			if clientErr != nil {
				return clientErr
			}
			var status api.ConfigSyncStatus
			statusErr := homeLoading(command, "Configuration sync", "Loading sync status", func(ctx context.Context) error {
				var loadErr error
				status, loadErr = client.ConfigSyncStatus(ctx)
				return loadErr
			})
			if statusErr != nil {
				return friendlyCommandError(statusErr)
			}
			items := make([]selector.Item, 0, len(status.Environments))
			for _, environment := range status.Environments {
				items = append(items, selector.Item{ID: environment.EnvironmentID, Title: environment.DisplayName, Description: fmt.Sprintf("%s  ·  %s  ·  %d managed paths  ·  %d conflicts", environment.State, environment.Mode, environment.ManagedPathCount, len(environment.Conflicts))})
			}
			if infoErr := showInformation(command, "Configuration sync", "Account state  ·  "+status.State, items); infoErr != nil && !errors.Is(infoErr, selector.ErrCanceled) {
				return infoErr
			}
		case "path":
			if infoErr := showInformation(command, "Configuration file", cfg.Path(), nil); infoErr != nil && !errors.Is(infoErr, selector.ErrCanceled) {
				return infoErr
			}
		}
	}
}

func actionHomeStatusBar(command *cobra.Command) error {
	for {
		cfg, err := config.Load(configPathFlag(command))
		if err != nil {
			return err
		}
		choice, err := chooseHomeAction(command, "Status bar", []selector.Item{
			{ID: "mode", Title: "Mode", Description: cfg.StatusBar.Mode},
			{ID: "fullscreen", Title: "Full-screen applications", Description: cfg.StatusBar.Fullscreen},
			{ID: "theme", Title: "Theme", Description: cfg.StatusBar.Theme},
			{ID: "privacy", Title: "Privacy", Description: onOff(cfg.StatusBar.Privacy)},
			{ID: "title", Title: "Terminal title", Description: onOff(cfg.StatusBar.TerminalTitle)},
			{ID: "reset", Title: "Restore defaults", Description: "Reset all status-bar preferences"},
		})
		if err != nil {
			return err
		}
		switch choice.ID {
		case "mode":
			cfg.StatusBar.Mode, err = chooseValue(command, "Status bar mode", cfg.StatusBar.Mode, []string{"auto", "on", "off"})
		case "fullscreen":
			cfg.StatusBar.Fullscreen, err = chooseValue(command, "Full-screen applications", cfg.StatusBar.Fullscreen, []string{"hide", "show"})
		case "theme":
			cfg.StatusBar.Theme, err = chooseValue(command, "Status bar theme", cfg.StatusBar.Theme, []string{"terminal", "dark", "light", "mono"})
		case "privacy":
			cfg.StatusBar.Privacy = !cfg.StatusBar.Privacy
		case "title":
			cfg.StatusBar.TerminalTitle = !cfg.StatusBar.TerminalTitle
		case "reset":
			cfg.StatusBar = config.DefaultStatusBarConfig()
		}
		if errors.Is(err, selector.ErrCanceled) {
			continue
		}
		if err != nil {
			return err
		}
		if err := cfg.Save(); err != nil {
			return err
		}
	}
}

func chooseValue(command *cobra.Command, title, current string, values []string) (string, error) {
	items := make([]selector.Item, 0, len(values))
	for _, value := range values {
		description := ""
		if value == current {
			description = "Current"
		}
		items = append(items, selector.Item{ID: value, Title: value, Description: description})
	}
	choice, err := selector.Choose(selector.Options{Title: title, Subtitle: "Choose a value", Items: items, Initial: current, Stdin: os.Stdin, Output: command.ErrOrStderr()})
	return choice.ID, err
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func actionHomeDoctor(command *cobra.Command) error {
	report := collectLocalDoctor()
	items := []selector.Item{
		{ID: "setup", Title: "Local setup", Description: report.SetupState},
		{ID: "identity", Title: "Machine identity", Description: report.IdentityState},
		{ID: "credential", Title: "Machine credential", Description: report.CredentialState},
		{ID: "inbox", Title: "Paperboat Inbox", Description: report.InboxState + "  ·  " + report.InboxPath},
		{ID: "config", Title: "Configuration service", Description: report.ConfigService},
		{ID: "runtime", Title: "Host runtime", Description: report.HostRuntime},
		{ID: "workloads", Title: "Local workloads", Description: fmt.Sprintf("%s  ·  %d sessions  ·  %d previews  ·  %d transfers", report.WorkloadCounts, report.ActiveSessions, report.ActivePreviews, report.ActiveTransfers)},
	}
	ctx := actionContext(command, nil)
	d, err := buildDeps(ctx)
	if err == nil {
		credential, credentialErr := d.auth.Credential()
		if credentialErr != nil {
			items = append(items, selector.Item{ID: "auth", Title: "Account", Description: "not signed in"})
		} else if strings.TrimSpace(d.cfg.ServerURL) == "" {
			items = append(items, selector.Item{ID: "backend", Title: "Control plane", Description: "server not configured"})
		} else {
			var me api.Me
			meErr := homeLoading(command, "Diagnostics", "Checking control plane", func(ctx context.Context) error {
				var loadErr error
				me, loadErr = api.New(d.cfg.ServerURL, credential, nil).Me(ctx)
				return loadErr
			})
			if meErr != nil {
				items = append(items, selector.Item{ID: "backend", Title: "Control plane", Description: "unavailable  ·  " + meErr.Error()})
			} else {
				items = append(items, selector.Item{ID: "auth", Title: "Account", Description: firstNonEmpty(me.Email, me.DisplayName, me.ID)}, selector.Item{ID: "backend", Title: "Control plane", Description: "authenticated"})
			}
		}
	}
	for index, recovery := range report.RecoveryActions {
		items = append(items, selector.Item{ID: fmt.Sprintf("recovery-%d", index), Title: "Needs attention", Description: recovery})
	}
	return showInformation(command, "Diagnostics", "Local setup and Paperboat connectivity", items)
}

func showInformation(command *cobra.Command, title, subtitle string, items []selector.Item) error {
	_, err := selector.Choose(selector.Options{Title: title, Subtitle: subtitle, Items: items, Empty: "Press Esc to go back", Footer: "↑/↓ inspect  type to filter  esc back", Stdin: os.Stdin, Output: command.ErrOrStderr()})
	return err
}

func chooseHomeAction(command *cobra.Command, title string, items []selector.Item) (selector.Item, error) {
	choice, err := selector.Choose(selector.Options{Title: title, Subtitle: "Choose an action", Items: items, Stdin: os.Stdin, Output: command.ErrOrStderr()})
	return choice, err
}

func compareFavorites(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return -1
	}
	return 1
}

type favoriteSet map[string]struct{}

func (f favoriteSet) IsFavorite(kind, id string) bool {
	_, ok := f[kind+":"+id]
	return ok
}

func (f favoriteSet) Set(kind, id string, favorite bool) {
	key := kind + ":" + id
	if favorite {
		f[key] = struct{}{}
		return
	}
	delete(f, key)
}

func loadFavorites(ctx context.Context, client *api.Client) (favoriteSet, error) {
	items, err := client.ListFavorites(ctx)
	if err != nil {
		return nil, friendlyCommandError(err)
	}
	favorites := make(favoriteSet, len(items))
	for _, item := range items {
		favorites[item.Kind+":"+item.ResourceID] = struct{}{}
	}
	return favorites, nil
}

var errFavoriteToggle = errors.New("favorite toggle requested")

func setFavorite(ctx context.Context, client *api.Client, kind, id string, favorite bool) error {
	_, err := client.SetFavorite(ctx, kind, id, favorite)
	if err == nil {
		return nil
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.Code == "favorite_limit_reached" {
		return errors.New("you can favorite up to five items; unfavorite another machine, session, or preview first")
	}
	return friendlyCommandError(err)
}

func backendForCommand(command *cobra.Command) (*api.Client, error) {
	ctx := actionContext(command, nil)
	d, err := buildDeps(ctx)
	if err != nil {
		return nil, err
	}
	credential, err := d.auth.Credential()
	if err != nil {
		return nil, err
	}
	return api.New(d.cfg.ServerURL, credential, nil), nil
}

func executeInteractiveCommand(parent *cobra.Command, args []string) error {
	command := newRootCommand()
	command.SetOut(parent.OutOrStdout())
	command.SetErr(parent.ErrOrStderr())
	command.SetArgs(args)
	return command.ExecuteContext(parent.Context())
}

func sendCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "send <path>... --to <machine>",
		Short: "Send files to a machine's Paperboat Inbox",
		Args:  commandArgs(cobra.MinimumNArgs(1)),
		RunE: func(cobraCommand *cobra.Command, paths []string) error {
			destinationRef, _ := cobraCommand.Flags().GetString("to")
			sessionID, _ := cobraCommand.Flags().GetString("session")
			if sessionID == "" {
				sessionID = strings.TrimSpace(os.Getenv("PAPERBOAT_TERMINAL_SESSION_ID"))
			}
			ctx := actionContext(cobraCommand, paths)
			dependencies, err := buildDeps(ctx)
			if err != nil {
				return err
			}
			credential, err := dependencies.auth.Credential()
			if err != nil {
				return err
			}
			client := api.New(dependencies.cfg.ServerURL, credential, nil)
			sourceMachineID, err := configuredMachineID()
			if err != nil {
				return err
			}
			var destination api.UserMachine
			if strings.TrimSpace(destinationRef) != "" {
				destination, err = resolveUserMachine(ctx.Context, client, destinationRef)
				if err != nil {
					return friendlyCommandError(err)
				}
			} else {
				var configured api.TransferDestinationDefault
				var defaultErr error
				if strings.TrimSpace(sessionID) != "" {
					configured, defaultErr = client.TerminalSessionTransferDestination(ctx.Context, sessionID)
				}
				if defaultErr == nil && !configured.Configured {
					configured, defaultErr = client.TransferDestinationDefault(ctx.Context)
				}
				if defaultErr != nil {
					return friendlyCommandError(defaultErr)
				}
				if configured.Configured && configured.Machine != nil {
					destination = *configured.Machine
				} else if sessionID != "" {
					eligible, eligibleErr := client.EligibleTerminalSessionTransferDestinations(ctx.Context, sessionID)
					if eligibleErr != nil {
						return friendlyCommandError(eligibleErr)
					}
					eligible = slices.DeleteFunc(eligible, func(machine api.UserMachine) bool { return machine.ID == sourceMachineID })
					switch len(eligible) {
					case 0:
						return errors.New("no eligible transfer destination is attached to the session")
					case 1:
						destination = eligible[0]
					default:
						if !term.IsTerminal(int(os.Stdin.Fd())) {
							summaries := make([]string, len(eligible))
							for i, machine := range eligible {
								summaries[i] = machine.DisplayName + " (" + machine.ID + ")"
							}
							return fmt.Errorf("transfer destination is ambiguous; use --to or set a default; eligible machines: %s", strings.Join(summaries, ", "))
						}
						index, promptErr := chooseIndex("Choose a transfer destination", "Eligible machines for this session", len(eligible), func(index int) selector.Item {
							machine := eligible[index]
							return selector.Item{ID: machine.ID, Title: machine.DisplayName, Description: machineStatusSummary(machine), Search: machineStatusSearch(machine)}
						})
						if promptErr != nil {
							return promptErr
						}
						destination = eligible[index]
					}
				} else {
					return errors.New("no default transfer destination is configured; use --to or `pb transfer destination set <machine>`")
				}
			}
			if destination.ID == sourceMachineID {
				return errors.New("destination must be a different machine")
			}
			if destination.State == "revoked" || destination.State == "disconnected" || destination.State == "deleted" {
				return errors.New("destination machine is revoked")
			}
			if sessionID == "" && !destination.Capabilities.FileReceive.Configured {
				return &api.APIError{Code: "machine_capability_unavailable", Message: "This machine is not configured to receive files."}
			}
			if sessionID == "" && (!destination.Online || !destination.Capabilities.FileReceive.Observed) {
				return &api.APIError{Code: "machine_offline", Message: "The destination machine is offline."}
			}
			fmt.Fprintf(cobraCommand.ErrOrStderr(), "Sending to %s (%s)\n", destination.DisplayName, destination.ID)
			descriptor, err := client.MachineFileTransferDescriptor(ctx.Context, destination.ID, sourceMachineID, sessionID)
			if err != nil {
				return friendlyCommandError(err)
			}
			target := &resolver.FileTransferTarget{
				Endpoint: descriptor.Endpoint, SourceMachineID: descriptor.SourceMachineID,
				DestinationMachineID: descriptor.DestinationMachineID, InitiatingUserID: descriptor.InitiatingUserID,
				Auth:   resolver.AuthTarget{Method: descriptor.Auth.Method, Token: descriptor.Auth.Token, ExpiresAt: descriptor.Auth.ExpiresAt.UTC().Format(time.RFC3339Nano)},
				Policy: descriptor.Policy,
			}
			transferClient := fileTransferClientForTarget(target)
			if transferClient == nil {
				return errors.New("server returned an invalid file transfer descriptor")
			}
			preparedPaths := make([]string, len(paths))
			for i, path := range paths {
				preparedPaths[i], err = filepath.Abs(path)
				if err != nil {
					return err
				}
			}
			prepared, err := filetransfer.Prepare(preparedPaths, fileTransferLimits(target))
			if err != nil {
				return err
			}
			defer prepared.Close()
			batchID, err := filetransfer.NewBatchID()
			if err != nil {
				return err
			}
			retention := time.Duration(target.Policy.RetentionSeconds) * time.Second
			if retention <= 0 || retention > 7*24*time.Hour {
				retention = 7 * 24 * time.Hour
			}
			expiresAt := time.Now().UTC().Truncate(time.Second).Add(retention)
			var batch filetransfer.Batch
			if localSender, localErr := localFileTransferSenderFromEnvironment(); localErr != nil {
				return localErr
			} else if localSender != nil {
				if sessionID == "" {
					return errors.New("host-local file delivery requires a Paperboat terminal session")
				}
				batch, err = localSender.SendBatch(ctx.Context, batchID, sourceMachineID, destination.ID, descriptor.InitiatingUserID, sessionID, prepared.Sources, 1, expiresAt)
			} else {
				if dependencies.peerLocal == nil {
					return errors.New("local daemon transport is unavailable for encrypted file transfer")
				}
				profileStore, storeErr := config.ProfileStoreFor(dependencies.cfg)
				if storeErr != nil {
					return storeErr
				}
				keyVault, vaultErr := transfercrypto.NewKeyVault(profileStore.Secrets)
				if vaultErr != nil {
					return vaultErr
				}
				keyCoordinator, coordinatorErr := filetransfer.NewKeyCoordinator(keyVault, filetransfer.DaemonKeyDeliverer{Client: dependencies.peerLocal})
				if coordinatorErr != nil {
					return coordinatorErr
				}
				keyBinding := transfercrypto.KeyControlBinding{OperationID: filetransfer.KeyOperationID(batchID), TransferID: batchID, Generation: 1, ExpiresAt: expiresAt}
				peerTarget := resolver.ConnectInfo{TargetKind: "machine", ProjectID: destination.ID, MachineGeneration: uint64(destination.InstallationGeneration), Transport: string(tunnel.TerminalTransportAuto), Terminal: &resolver.TerminalTarget{EnvironmentID: destination.EnvironmentID}}
				preparedKey, prepareErr := keyCoordinator.Prepare(ctx.Context, peerTarget, keyBinding)
				if prepareErr != nil {
					return prepareErr
				}
				defer preparedKey.Close()
				defer preparedKey.Material.Destroy()
				batch, err = transferClient.SendEncryptedBatch(ctx.Context, batchID, sessionID, prepared.Sources, keyBinding.Generation, preparedKey)
				if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
					_ = keyCoordinator.Erase(batchID)
				}
				if err == nil {
					err = keyCoordinator.Erase(batchID)
				}
			}
			if err != nil {
				return err
			}
			jsonOutput, _ := cobraCommand.Flags().GetBool("json")
			if jsonOutput {
				return json.NewEncoder(cobraCommand.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": batch})
			}
			for i, item := range batch.Transfers {
				path := item.ReceiptPath
				if i < len(batch.Paths) && batch.Paths[i] != "" {
					path = batch.Paths[i]
				}
				fmt.Fprintf(cobraCommand.OutOrStdout(), "%s: delivered to %s on %s\n", item.Basename, path, destination.DisplayName)
			}
			return nil
		},
	}
	command.Flags().String("to", "", "destination machine name or ID")
	command.Flags().String("session", "", "terminal session ID for destination context")
	command.Flags().Bool("json", false, "print JSON")
	return command
}

func transferCommand() *cobra.Command {
	root := &cobra.Command{Use: "transfer", Short: "Manage file transfers", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error { return command.Help() }}
	destination := &cobra.Command{Use: "destination", Short: "Show the default transfer destination", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		ctx := actionContext(command, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		sessionID, _ := command.Flags().GetString("session")
		var value api.TransferDestinationDefault
		if sessionID == "" {
			value, err = client.TransferDestinationDefault(ctx.Context)
		} else {
			value, err = client.TerminalSessionTransferDestination(ctx.Context, sessionID)
		}
		if err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": value})
		}
		if !value.Configured || value.Machine == nil {
			fmt.Fprintln(command.OutOrStdout(), "No default transfer destination.")
			return nil
		}
		fmt.Fprintf(command.OutOrStdout(), "%s (%s)\n", value.Machine.DisplayName, value.Machine.ID)
		return nil
	}}
	destination.Flags().Bool("json", false, "print JSON")
	set := &cobra.Command{Use: "set <machine>", Short: "Set the default transfer destination", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		ctx := actionContext(command, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		machine, err := resolveUserMachine(ctx.Context, client, args[0])
		if err != nil {
			return friendlyCommandError(err)
		}
		sessionID, _ := command.Flags().GetString("session")
		var value api.TransferDestinationDefault
		if sessionID == "" {
			value, err = client.SetTransferDestinationDefault(ctx.Context, machine.ID)
		} else {
			value, err = client.SetTerminalSessionTransferDestination(ctx.Context, sessionID, machine.ID)
		}
		if err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": value})
		}
		fmt.Fprintf(command.OutOrStdout(), "Default transfer destination: %s (%s)\n", machine.DisplayName, machine.ID)
		return nil
	}}
	set.Flags().Bool("json", false, "print JSON")
	clear := &cobra.Command{Use: "clear", Short: "Clear the default transfer destination", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		ctx := actionContext(command, args)
		client, err := backendClient(ctx)
		if err != nil {
			return err
		}
		sessionID, _ := command.Flags().GetString("session")
		if sessionID == "" {
			err = client.ClearTransferDestinationDefault(ctx.Context)
		} else {
			err = client.ClearTerminalSessionTransferDestination(ctx.Context, sessionID)
		}
		if err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]bool{"configured": false}})
		}
		fmt.Fprintln(command.OutOrStdout(), "Default transfer destination cleared.")
		return nil
	}}
	clear.Flags().Bool("json", false, "print JSON")
	destination.AddCommand(set, clear)
	destination.PersistentFlags().String("session", "", "terminal session ID for a session-specific destination")
	status := &cobra.Command{Use: "status <transfer-id>", Short: "Inspect a file transfer", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		client, _, err := transferClientForCommand(command, args)
		if err != nil {
			return err
		}
		manifest, err := client.Status(command.Context(), args[0])
		if err != nil {
			return err
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": manifest})
		}
		fmt.Fprintf(command.OutOrStdout(), "%s  %s  %s -> %s\n", manifest.TransferID, manifest.State, manifest.SourceMachineID, manifest.DestinationMachineID)
		return nil
	}}
	cancelTransfer := &cobra.Command{Use: "cancel <transfer-id>", Short: "Cancel a file transfer batch", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		client, destination, err := transferClientForCommand(command, args)
		if err != nil {
			return err
		}
		if err := client.Cancel(command.Context(), args[0]); err != nil {
			return err
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"transfer_id": args[0], "state": "canceled", "destination_machine_id": destination.ID}})
		}
		fmt.Fprintf(command.OutOrStdout(), "%s: canceled\n", args[0])
		return nil
	}}
	list := &cobra.Command{Use: "list", Short: "List file transfers", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		client, _, err := transferClientForCommand(command, args)
		if err != nil {
			return err
		}
		sessionID, _ := command.Flags().GetString("session")
		limit, _ := command.Flags().GetInt("limit")
		items, err := client.List(command.Context(), sessionID, limit)
		if err != nil {
			return err
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"items": items}})
		}
		writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "TRANSFER\tSTATE\tFILE\tDESTINATION")
		for _, item := range items {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", item.TransferID, item.State, item.Basename, item.DestinationMachineID)
		}
		return writer.Flush()
	}}
	list.Flags().Int("limit", 50, "maximum transfers to return")
	for _, command := range []*cobra.Command{list, status, cancelTransfer} {
		command.Flags().String("on", "", "destination machine name or ID")
		command.Flags().String("session", "", "terminal session ID for destination context")
		command.Flags().Bool("json", false, "print JSON")
	}
	root.AddCommand(destination, list, status, cancelTransfer)
	return root
}

func transferClientForCommand(cobraCommand *cobra.Command, args []string) (*filetransfer.Client, api.UserMachine, error) {
	destinationRef, _ := cobraCommand.Flags().GetString("on")
	if strings.TrimSpace(destinationRef) == "" {
		return nil, api.UserMachine{}, invocationError(errors.New("--on is required"))
	}
	ctx := actionContext(cobraCommand, args)
	backend, err := backendClient(ctx)
	if err != nil {
		return nil, api.UserMachine{}, err
	}
	sourceMachineID, err := configuredMachineID()
	if err != nil {
		return nil, api.UserMachine{}, err
	}
	destination, err := resolveUserMachine(ctx.Context, backend, destinationRef)
	if err != nil {
		return nil, api.UserMachine{}, friendlyCommandError(err)
	}
	sessionID, _ := cobraCommand.Flags().GetString("session")
	descriptor, err := backend.MachineFileTransferDescriptor(ctx.Context, destination.ID, sourceMachineID, sessionID)
	if err != nil {
		return nil, api.UserMachine{}, friendlyCommandError(err)
	}
	target := &resolver.FileTransferTarget{Endpoint: descriptor.Endpoint, SourceMachineID: descriptor.SourceMachineID, DestinationMachineID: descriptor.DestinationMachineID, InitiatingUserID: descriptor.InitiatingUserID, Auth: resolver.AuthTarget{Method: descriptor.Auth.Method, Token: descriptor.Auth.Token, ExpiresAt: descriptor.Auth.ExpiresAt.UTC().Format(time.RFC3339Nano)}, Policy: descriptor.Policy}
	client := fileTransferClientForTarget(target)
	if client == nil {
		return nil, api.UserMachine{}, errors.New("server returned an invalid file transfer descriptor")
	}
	return client, destination, nil
}

func addConnectFlags(command *cobra.Command) {
	command.Flags().String("transport", "", "peer transport: a (auto), d (direct QUIC), q (relay QUIC), w (relay WSS), or r (relay race)")
	command.Flags().String("name", "", "name for the fresh terminal session")
	command.Flags().String("session", "", "attach an existing terminal session by name or ID")
	addStatusBarFlags(command)
}

func addStatusBarFlags(command *cobra.Command) {
	command.Flags().String("status-bar", "", "status bar for this attach: auto, on, or off")
	command.Flags().String("status-bar-fullscreen", "", "status bar in full-screen applications: hide or show")
	command.Flags().String("status-bar-theme", "", "status bar theme: terminal, dark, light, or mono")
}

func validateConnectInvocation(command *cobra.Command) error {
	name, _ := command.Flags().GetString("name")
	ref, _ := command.Flags().GetString("session")
	if strings.TrimSpace(name) != "" && strings.TrimSpace(ref) != "" {
		return invocationError(errors.New("--name and --session cannot be used together"))
	}
	for name, allowed := range map[string][]string{
		"transport":             {"a", "d", "q", "w", "r"},
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
	root := &cobra.Command{Use: use, Short: source.Usage, Args: commandArgs(cobra.NoArgs)}
	if source.Action != nil {
		root.RunE = actionRun(source.Action)
	} else {
		root.RunE = func(command *cobra.Command, _ []string) error { return command.Help() }
	}
	for _, child := range source.Subcommands {
		child := child
		childUse := child.Name
		if child.ArgsUsage != "" {
			childUse += " " + child.ArgsUsage
		}
		entry := &cobra.Command{Use: childUse, Short: child.Usage, Args: commandArgs(specCommandArgs(use, child.Name)), RunE: actionRun(child.Action)}
		for _, configuredFlag := range child.Flags {
			if stringFlag, ok := configuredFlag.(*command.StringFlag); ok {
				entry.Flags().String(stringFlag.Name, "", stringFlag.Usage)
			}
		}
		if (use == "auth" && child.Name == "status") || (use == "config" && child.Name == "show") {
			entry.Flags().Bool("json", false, "print JSON")
		}
		if use == "config" && child.Name == "status" {
			entry.Flags().Bool("json", false, "print JSON")
		}
		if use == "config" && (child.Name == "assign" || child.Name == "unassign") {
			entry.Flags().Bool("json", false, "print JSON")
		}
		if use == "config" && child.Name == "assign" {
			entry.Flags().String("mode", "pull-only", "sync mode: pull-only, push-only, or bidirectional")
			entry.Flags().Bool("yes", false, "acknowledge plaintext private-Git storage and history")
		}
		if use == "config" && child.Name == "unassign" {
			entry.Flags().Bool("yes", false, "confirm removal")
		}
		if use == "preview" {
			if child.Name == "list" {
				entry.Flags().Bool("json", false, "print JSON")
			}
			if child.Name == "create" {
				entry.Flags().String("name", "", "stable preview name")
				entry.Flags().Uint("port", 0, "local target port")
				entry.Flags().String("machine", "", "online paired machine")
				entry.Flags().Duration("duration", 24*time.Hour, "preview lifetime")
				entry.Flags().Bool("indefinite", false, "keep until explicitly revoked")
				entry.Flags().Bool("public", false, "acknowledge public access")
				entry.Flags().Uint("listen-port", 0, "private loopback listener port")
				entry.Flags().Bool("detach", false, "continue after this command exits")
				entry.Flags().Bool("json", false, "print JSON")
			}
			if child.Name == "revoke" {
				entry.Flags().Bool("yes", false, "confirm removal")
				entry.Flags().Bool("json", false, "print JSON")
			}
		}
		root.AddCommand(entry)
	}
	return root
}

func specCommandArgs(parent, name string) cobra.PositionalArgs {
	if parent == "config" {
		switch name {
		case "set":
			return cobra.ExactArgs(2)
		case "unset":
			return cobra.ExactArgs(1)
		case "assign", "enable":
			return cobra.ExactArgs(2)
		case "unassign", "disable":
			return cobra.ExactArgs(1)
		case "status":
			return cobra.MaximumNArgs(1)
		}
	}
	if parent == "preview" {
		switch name {
		case "create":
			return cobra.MaximumNArgs(1)
		case "list":
			return cobra.NoArgs
		case "revoke":
			return cobra.MaximumNArgs(1)
		}
	}
	return cobra.NoArgs
}

func sessionsCobraCommand() *cobra.Command {
	source := sessionsCommand()
	command := &cobra.Command{Use: "sessions [environment]", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		jsonOutput, _ := command.Flags().GetBool("json")
		if len(args) == 0 && !jsonOutput && term.IsTerminal(int(os.Stdin.Fd())) {
			return actionHomeSessions(command)
		}
		return actionRun(source.Action)(command, args)
	}}
	command.Flags().Bool("wide", false, "include immutable IDs")
	command.Flags().Bool("json", false, "print JSON")
	for _, child := range source.Subcommands {
		child := child
		var args cobra.PositionalArgs
		use := child.Name
		switch child.Name {
		case "rename":
			args = cobra.ExactArgs(3)
			use += " <environment> <session> <name>"
		case "close":
			args = cobra.RangeArgs(1, 2)
			use += " <environment> [<session>]"
		case "delete":
			args = cobra.RangeArgs(1, 2)
			use += " <environment> [<session>]"
		}
		entry := &cobra.Command{Use: use, Short: child.Usage, Args: commandArgs(args), RunE: actionRun(child.Action)}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("yes", false, "confirm "+child.Name)
			entry.Flags().Bool("json", false, "print JSON")
		}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("all", false, child.Name+" all sessions in the environment")
		}
		command.AddCommand(entry)
	}
	return command
}

func sessionCobraCommand() *cobra.Command {
	source := sessionsCommand()
	command := &cobra.Command{Use: "session", Short: source.Usage, Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return actionHomeSessions(command)
		}
		return command.Help()
	}}
	attach := &cobra.Command{Use: "attach [environment] [session]", Short: "Choose and attach to a durable terminal session", Args: commandArgs(cobra.MaximumNArgs(2)), RunE: func(cobraCommand *cobra.Command, args []string) error {
		if err := validateConnectInvocation(cobraCommand); err != nil {
			return err
		}
		ctx := actionContext(cobraCommand, args)
		d, err := buildDeps(ctx)
		if err != nil {
			return err
		}
		credential, err := d.auth.Credential()
		if err != nil {
			return err
		}
		client := api.New(d.cfg.ServerURL, credential, nil)
		environmentRef := ""
		sessionRef := ""
		switch len(args) {
		case 2:
			environmentRef, sessionRef = args[0], args[1]
		case 1:
			sessionRef = args[0]
			environmentRef, err = defaultEnvironment(ctx.Context, client, d.cfg.LastEnvironmentID)
		default:
			environmentRef, err = selectEnvironment(ctx.Context, client, "Choose an environment")
		}
		if err != nil {
			return err
		}
		target, err := resolveTerminalEnvironmentTarget(ctx.Context, client, environmentRef)
		if err != nil {
			return err
		}
		if sessionRef == "" {
			sessions, listErr := listTerminalSessionsForTarget(ctx.Context, client, target)
			if listErr != nil {
				return friendlyCommandError(listErr)
			}
			selected, selectErr := selectSession(target, sessions, "Choose a terminal session")
			if selectErr != nil {
				return selectErr
			}
			sessionRef = selected.ID
		}
		if err := cobraCommand.Flags().Set("session", sessionRef); err != nil {
			return err
		}
		return actionConnectTarget(actionContext(cobraCommand, nil), environmentRef)
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
			args = cobra.RangeArgs(1, 2)
		}
		entry := &cobra.Command{Use: child.Name, Short: child.Usage, Args: commandArgs(args), RunE: actionRun(child.Action)}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("yes", false, "confirm "+child.Name)
			entry.Flags().Bool("json", false, "print JSON")
		}
		if child.Name == "close" || child.Name == "delete" {
			entry.Flags().Bool("all", false, child.Name+" all sessions in the environment")
		}
		command.AddCommand(entry)
	}
	return command
}

func previewsCobraCommand() *cobra.Command {
	command := &cobra.Command{Use: "previews", Short: "List public previews", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
		jsonOutput, _ := command.Flags().GetBool("json")
		if !jsonOutput && term.IsTerminal(int(os.Stdin.Fd())) {
			return actionHomePreviews(command)
		}
		return actionRun(previewListCommand)(command, args)
	}}
	command.Flags().Bool("json", false, "print JSON")
	entry := &cobra.Command{Use: "revoke <environment>", Short: "Revoke previews in an environment", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
		all, _ := command.Flags().GetBool("all")
		if !all {
			return invocationError(errors.New("pb previews revoke requires --all"))
		}
		return actionRun(previewRevokeAllCommand)(command, args)
	}}
	entry.Flags().Bool("all", false, "revoke all previews in the environment")
	entry.Flags().Bool("yes", false, "confirm revocation")
	entry.Flags().Bool("json", false, "print JSON")
	command.AddCommand(entry)
	return command
}

func userMachineCobraCommand() *cobra.Command {
	machine := &cobra.Command{Use: "machine", Short: "Manage machines", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, _ []string) error {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return actionHomeMachines(command)
		}
		return command.Help()
	}}
	add := &cobra.Command{Use: "add", Short: "Print a one-shot machine enrollment command", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
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
		role, _ := command.Flags().GetString("role")
		name, _ := command.Flags().GetString("name")
		if role != "host" && role != "client" {
			return errors.New("--role must be host or client")
		}
		authSource, err := sessionauth.NewSource(cfg)
		if err != nil {
			return err
		}
		credential, err := authSource.Credential()
		if err != nil {
			return err
		}
		client := api.New(cfg.ServerURL, credential, nil)
		shell, _ := command.Flags().GetString("shell")
		result, err := client.StartMachineEnrollment(ctx.Context, fmt.Sprintf("cli-%d", time.Now().UnixNano()), role, shell)
		if err != nil {
			return friendlyCommandError(err)
		}
		parameter := result.BootstrapToken
		if name != "" {
			parameter = name + "-" + parameter
		}
		windowsURL := "https://get.pprbt.dev/install?p=" + parameter
		fmt.Fprintf(command.OutOrStdout(), "Linux/macOS:\ncurl -fsSL 'https://get.pprbt.dev/install?p=%s' | bash\n\nWindows (PowerShell or Command Prompt):\n%s\n", parameter, windowsEnrollmentCommand(windowsURL))
		return nil
	}}
	add.Flags().String("role", "host", "machine role: host or client")
	add.Flags().String("shell", "posix", "installer shell: posix or powershell")
	add.Flags().String("name", "", "optional machine hostname")
	list := &cobra.Command{Use: "list", Short: "List enrolled machines", Args: commandArgs(cobra.NoArgs), RunE: func(command *cobra.Command, args []string) error {
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
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"version": "1", "machines": machines})
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
	rename := &cobra.Command{Use: "rename <machine> <name>", Short: "Rename a machine", Args: commandArgs(cobra.ExactArgs(2)), RunE: func(command *cobra.Command, args []string) error {
		newName := strings.TrimSpace(args[1])
		if err := machinename.Validate(newName); err != nil {
			return invocationError(fmt.Errorf("invalid machine name: %w", err))
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
		fmt.Fprintf(command.ErrOrStderr(), "Machine: %s (%s)\n", machine.DisplayName, machine.ID)
		updated, err := client.RenameUserMachine(ctx.Context, machine.ID, newName)
		if err != nil {
			return friendlyCommandError(err)
		}
		jsonOutput, _ := command.Flags().GetBool("json")
		if jsonOutput {
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"version": "1", "machine": updated, "outcome": "renamed"})
		}
		fmt.Fprintf(command.OutOrStdout(), "Renamed machine %s to %s (%s).\n", machine.DisplayName, updated.DisplayName, updated.ID)
		return nil
	}}
	rename.Flags().Bool("json", false, "print JSON")
	revoke := &cobra.Command{Use: "revoke <machine>", Short: "Disconnect and revoke a machine", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(cobraCommand *cobra.Command, args []string) error {
		if confirmed, _ := cobraCommand.Flags().GetBool("yes"); !confirmed {
			return errors.New("machine revocation requires --yes")
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
			return json.NewEncoder(cobraCommand.OutOrStdout()).Encode(map[string]any{"version": "1", "machine": map[string]string{"id": userMachineID, "display_name": displayName, "state": "disconnected"}, "outcome": "confirmed", "retry": "not_required"})
		}
		fmt.Fprintf(cobraCommand.OutOrStdout(), "Disconnected machine %s (%s).\n", displayName, userMachineID)
		return nil
	}}
	revoke.Flags().Bool("yes", false, "confirm revocation")
	revoke.Flags().Bool("json", false, "print JSON")
	availability := &cobra.Command{Use: "availability <machine>", Short: "Set machine sleep availability", Args: commandArgs(cobra.ExactArgs(1)), RunE: func(command *cobra.Command, args []string) error {
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
		fmt.Fprintf(command.ErrOrStderr(), "Machine: %s (%s)\n", machine.DisplayName, machine.ID)
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
			return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"version": "1", "machine": map[string]string{"id": machine.ID, "display_name": machine.DisplayName}, "availability": policy, "outcome": outcome, "retry": "automatic"})
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
	machine.AddCommand(add, list, rename, revoke, availability)
	return machine
}

func windowsEnrollmentCommand(installerURL string) string {
	path := `"$env:TEMP\pb.ps1"`
	return "iwr '" + installerURL + "' -OutFile " + path + "; & " + path
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
	for _, name := range []string{"config", "server", "name", "machine", "session", "status-bar", "status-bar-fullscreen", "status-bar-theme", "mode", "path", "transport", "code", "input", "output", "keep", "recovery-key"} {
		value, _ := cobraCommand.Flags().GetString(name)
		values[name] = value
		set.String(name, value, "")
	}
	hours, _ := cobraCommand.Flags().GetFloat64("hours")
	set.Float64("hours", hours, "")
	for _, name := range []string{"json", "wide", "yes", "clear", "all", "indefinite", "public", "detach", "select-environment"} {
		value, _ := cobraCommand.Flags().GetBool(name)
		values[name] = strconv.FormatBool(value)
		set.Bool(name, value, "")
	}
	port, _ := cobraCommand.Flags().GetUint("port")
	set.Uint("port", port, "")
	listenPort, _ := cobraCommand.Flags().GetUint("listen-port")
	set.Uint("listen-port", listenPort, "")
	duration, _ := cobraCommand.Flags().GetDuration("duration")
	set.Duration("duration", duration, "")
	set.Bool("duration-set", cobraCommand.Flags().Changed("duration"), "")
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
		{Name: "login", Usage: "Sign in through the Paperboat dashboard", Flags: []command.Flag{&command.StringFlag{Name: "recovery-key", Usage: "absolute recovery-key file for restoring private transport"}}, Action: authLogin},
		{Name: "switch", Usage: "Replace the active account for this server", Flags: []command.Flag{&command.StringFlag{Name: "recovery-key", Usage: "absolute recovery-key file for restoring private transport"}}, Action: func(c *command.Context) error { return authLoginMode(c, true) }},
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
		fmt.Fprintln(os.Stderr, "Warning: an earlier session is still being revoked. Paperboat will retry automatically.")
	}
	var previous *config.Profile
	if existingProfile, existingErr := store.Load(cfg.ServerURL); existingErr == nil {
		if !replace {
			credential, credentialErr := store.CredentialFor(cfg.ServerURL)
			if credentialErr != nil {
				return credentialErr
			}
			if err := ensureCLIIdentityForLogin(c, store, existingProfile, credential); err != nil {
				return err
			}
			if err := ensureLocalDaemonService(c.Context, cfg); err != nil {
				return fmt.Errorf("repair local SSH integration: %w", err)
			}
			fmt.Fprintf(os.Stdout, "Signed in as %s\n", firstNonEmpty(existingProfile.Account.Email, existingProfile.Account.DisplayName, existingProfile.Account.ID))
			return nil
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
		if err := ensureCLIIdentityForLogin(c, store, p, cred); err != nil {
			return fmt.Errorf("signed in, but private transport setup is incomplete; rerun `pb auth login`: %w", err)
		}
		if err := ensureLocalDaemonService(c.Context, cfg); err != nil {
			return fmt.Errorf("signed in, but local SSH integration is incomplete; rerun `pb auth login`: %w", err)
		}
		if previous != nil {
			if err := drainPendingRevocations(context.Background(), cfg.ServerURL, store); err != nil {
				fmt.Fprintln(os.Stderr, "Warning: account switched, but the previous session is still being revoked. Paperboat will retry automatically.")
			}
		}
		fmt.Fprintf(os.Stdout, "Signed in as %s\n", firstNonEmpty(me.Email, me.DisplayName, me.ID))
		return nil
	}
}

func ensureLocalDaemonService(ctx context.Context, cfg *config.Config) error {
	if ctx == nil || cfg == nil || strings.TrimSpace(cfg.ServerURL) == "" {
		return localdaemon.ErrInvalidInventoryConfig
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	configPath := cfg.Path()
	if configPath != "" {
		configPath, err = filepath.Abs(configPath)
		if err != nil {
			return err
		}
	}
	return localdaemon.InstallCurrentUserService(ctx, executable, configPath, cfg.ServerURL)
}

func ensureCLIIdentity(ctx context.Context, store config.ProfileStore, profile config.Profile, credential config.Credential) error {
	_, err := identitybootstrap.Bootstrap(ctx, identitybootstrap.Request{Store: store, Client: api.New(profile.Issuer, credential, nil), Issuer: profile.Issuer, AccountID: profile.Account.ID, CLIClientSessionID: profile.CLIClientSessionID})
	return err
}

func ensureCLIIdentityForLogin(c *command.Context, store config.ProfileStore, profile config.Profile, credential config.Credential) error {
	if input := strings.TrimSpace(c.String("recovery-key")); input != "" {
		if err := importRecoveryKey(store, profile, input); err != nil {
			return err
		}
	}
	return ensureCLIIdentity(c.Context, store, profile, credential)
}

func importRecoveryKey(store config.ProfileStore, profile config.Profile, input string) error {
	if !filepath.IsAbs(input) {
		return invocationError(errors.New("--recovery-key must be an absolute path"))
	}
	info, err := os.Lstat(input)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("recovery-key file must be a regular owner-only file")
	}
	encoded, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	seed, err := recoverykey.Decode(strings.TrimSpace(string(encoded)))
	clear(encoded)
	if err != nil {
		return err
	}
	defer clear(seed)
	return store.ImportPeerAccountRootSeed(profile.Issuer, profile.Account.ID, seed)
}

func exportSetupRecoveryKey(command *cobra.Command) error {
	output, err := command.Flags().GetString("recovery-output")
	if err != nil || strings.TrimSpace(output) == "" {
		return err
	}
	output = strings.TrimSpace(output)
	if !filepath.IsAbs(output) {
		return invocationError(errors.New("--recovery-output must be an absolute path"))
	}
	ctx := actionContext(command, nil)
	_, store, profile, err := e2eeClient(ctx)
	if err != nil {
		return fmt.Errorf("machine setup completed, but recovery-key export failed: %w", err)
	}
	seed, err := store.ExportPeerAccountRootSeed(profile.Issuer, profile.Account.ID)
	if err != nil {
		return fmt.Errorf("machine setup completed, but recovery-key export failed: %w", err)
	}
	defer clear(seed)
	encoded, err := recoverykey.Encode(seed)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("machine setup completed, but create recovery-key file: %w", err)
	}
	if _, err = io.WriteString(file, encoded+"\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("machine setup completed, but write recovery-key file: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("machine setup completed, but close recovery-key file: %w", err)
	}
	fmt.Fprintf(command.OutOrStdout(), "Recovery key written to %s\n", output)
	return nil
}

func e2eeClient(c *command.Context) (*api.Client, config.ProfileStore, config.Profile, error) {
	cfg, err := config.Load(c.String("config"))
	if err != nil {
		return nil, config.ProfileStore{}, config.Profile{}, err
	}
	if server := strings.TrimSpace(c.String("server")); server != "" {
		cfg.ServerURL, err = config.NormalizeServerURL(server)
		if err != nil {
			return nil, config.ProfileStore{}, config.Profile{}, err
		}
	}
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, config.ProfileStore{}, config.Profile{}, errors.New("Paperboat server is not configured; set server_url or use --server")
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		return nil, config.ProfileStore{}, config.Profile{}, err
	}
	profile, err := store.Load(cfg.ServerURL)
	if errors.Is(err, config.ErrNoCredentials) {
		return nil, config.ProfileStore{}, config.Profile{}, errors.New("not signed in to Paperboat; run `pb auth login`, then retry")
	}
	if err != nil {
		return nil, config.ProfileStore{}, config.Profile{}, err
	}
	credential, err := store.CredentialFor(cfg.ServerURL)
	if err != nil {
		return nil, config.ProfileStore{}, config.Profile{}, err
	}
	return api.New(cfg.ServerURL, credential, nil), store, profile, nil
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
	environmentUserMachine = "machine"
)

func selectEnvironment(ctx context.Context, client *api.Client, title string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("an environment is required in non-interactive use")
	}
	var machines []api.UserMachine
	load := func(loadCtx context.Context) error {
		var err error
		machines, err = client.ListUserMachines(loadCtx)
		return friendlyCommandError(err)
	}
	var err error
	if selector.ScreenActive() {
		err = selector.Loading(ctx, title, "Loading environments", os.Stdin, os.Stderr, load)
	} else {
		err = load(ctx)
	}
	if err != nil {
		return "", err
	}
	machines = terminalHostMachines(machines)
	items := make([]selector.Item, 0, len(machines))
	for _, machine := range machines {
		if !machine.Capabilities.TerminalHost.Configured || !machine.Capabilities.TerminalHost.Observed {
			continue
		}
		items = append(items, selector.Item{ID: machine.ID, Title: machine.DisplayName, Description: machineStatusSummary(machine), Search: "machine " + machineStatusSearch(machine)})
	}
	selected, err := selector.Choose(selector.Options{Title: title, Subtitle: "Terminal-capable machines", Items: items, Empty: "no terminal hosts are available; run `pb setup --mode host` or `pb machine add`", Stdin: os.Stdin, Output: os.Stderr})
	return selected.ID, err
}

func selectSession(target environmentTarget, sessions []api.TerminalSession, title string) (api.TerminalSession, error) {
	items := make([]selector.Item, 0, len(sessions))
	byID := make(map[string]api.TerminalSession, len(sessions))
	for _, session := range sessions {
		attached := "no attachments"
		if session.AttachedCount != nil {
			attached = fmt.Sprintf("%d attached", *session.AttachedCount)
		}
		activity := "last active " + relativeTime(session.LastActiveAt)
		created := "created " + relativeTimestamp(session.CreatedAt)
		description := strings.Join([]string{session.State, attached, activity, created}, "  ·  ")
		items = append(items, selector.Item{ID: session.ID, Title: session.Name, Description: description, Search: target.name + " " + session.State})
		byID[session.ID] = session
	}
	selected, err := selector.Choose(selector.Options{Title: title, Subtitle: target.name + "  ·  " + target.kind, Items: items, Empty: "no terminal sessions are available", Stdin: os.Stdin, Output: os.Stderr})
	return byID[selected.ID], err
}

func relativeTimestamp(at time.Time) string {
	if at.IsZero() {
		return "unknown"
	}
	value := at
	return relativeTime(&value)
}

func defaultEnvironment(ctx context.Context, client *api.Client, rememberedID string) (string, error) {
	if rememberedID = strings.TrimSpace(rememberedID); rememberedID != "" {
		return rememberedID, nil
	}
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return "", friendlyCommandError(err)
	}
	machines = terminalHostMachines(machines)
	if len(machines) == 1 {
		return machines[0].ID, nil
	}
	if len(machines) == 0 {
		return "", errors.New("no terminal hosts are available; run `pb setup --mode host` or `pb machine add`")
	}
	choices := make([]string, 0, len(machines))
	for _, machine := range machines {
		choices = append(choices, fmt.Sprintf("%s (%s)", machine.DisplayName, machine.ID))
	}
	return "", fmt.Errorf("multiple environments are available: %s; choose one with `pb <environment>`", strings.Join(choices, ", "))
}

func resolveEnvironmentTarget(ctx context.Context, client *api.Client, requested string) (environmentTarget, error) {
	project, err := resolveProjectID(ctx, client, requested)
	if err == nil {
		return environmentTarget{kind: environmentProject, id: project.ID, name: project.Name}, nil
	}
	// Accounts without hosted projects receive a 404 from the project API. That
	// is still a valid machine-targeting path, so preserve the machine fallback.
	if !errors.Is(err, resolver.ErrProjectNotFound) && !api.IsNotFound(err) && !api.IsHostedEntitlementRequired(err) {
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

func resolveTerminalEnvironmentTarget(ctx context.Context, client *api.Client, requested string) (environmentTarget, error) {
	target, err := resolveEnvironmentTarget(ctx, client, requested)
	if err != nil || target.kind != environmentUserMachine {
		return target, err
	}
	machine, err := resolveUserMachine(ctx, client, target.id)
	if err != nil {
		return environmentTarget{}, err
	}
	if err := terminalHostError(machine); err != nil {
		return environmentTarget{}, err
	}
	return target, nil
}

func terminalHostMachines(machines []api.UserMachine) []api.UserMachine {
	eligible := make([]api.UserMachine, 0, len(machines))
	for _, machine := range machines {
		if terminalHostError(machine) == nil {
			eligible = append(eligible, machine)
		}
	}
	return eligible
}

func terminalHostError(machine api.UserMachine) error {
	if !machine.Capabilities.TerminalHost.Configured {
		return &api.APIError{Code: "machine_capability_unavailable", Message: "This machine is not configured to host terminals."}
	}
	if !machine.Online || !machine.Capabilities.TerminalHost.Observed {
		return &api.APIError{Code: "machine_offline", Message: "This terminal host is offline."}
	}
	return nil
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
	transportMode    tunnel.TerminalTransport
	auth             config.AuthSource
	resolver         resolver.ProjectResolver
	tunnel           tunnel.Tunnel
	terminalSelector *tunnel.TerminalTransportSelector
	peerTunnel       *tunnel.PeerTerminalTunnel
	peerLocal        *localapi.Client
	peerApplications peerApplicationTunnel
	telemetry        telemetry.Sink
}

type peerApplicationTunnel interface {
	Dial(context.Context, resolver.ConnectInfo) (tunnel.Conn, error)
	DialExec(context.Context, resolver.ConnectInfo, tunnel.ExecRequest) (tunnel.ExecConn, error)
	DialSSH(context.Context, resolver.ConnectInfo, string) (tunnel.Conn, error)
	DialPrivatePreview(context.Context, resolver.ConnectInfo, uint16) (tunnel.Conn, error)
	DialCodexHTTP(context.Context, resolver.ConnectInfo) (net.Conn, error)
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
	selectedTunnel := tunnel.Tunnel(termTunnel)
	var peerTunnel *tunnel.PeerTerminalTunnel
	var peerApplications peerApplicationTunnel
	var peerLocal *localapi.Client
	if cfg.ServerURL != "" {
		store, storeErr := config.ProfileStoreFor(cfg)
		if storeErr != nil {
			return nil, storeErr
		}
		transportConfig := httptransport.DevelopmentConfig()
		transportConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		peerTransport, transportErr := httptransport.New(transportConfig)
		if transportErr != nil {
			return nil, transportErr
		}
		peerMode := peerConnectionMode(mode)
		var peerErr error
		peerTunnel, peerErr = tunnel.NewPeerTerminalTunnel(tunnel.PeerTerminalConfig{Issuer: cfg.ServerURL, Store: store, Auth: authSource, TLS: transportConfig.TLSConfig, HTTPClient: &http.Client{Transport: peerTransport}, OutputQueueChunks: cfg.Connect.TerminalOutputQueueChunks, Mode: peerMode, PublishLocalStatus: true, Race: peerRacePolicy()})
		if peerErr != nil {
			return nil, peerErr
		}
		paths, pathsErr := localdaemon.CurrentUserPaths()
		if pathsErr != nil {
			return nil, pathsErr
		}
		localClient, clientErr := localapi.NewClient(paths.SocketPath, time.Duration(config.PeerConnectTimeoutMilliseconds)*time.Millisecond)
		if clientErr != nil {
			return nil, clientErr
		}
		localPeer := &tunnel.LocalPeerTunnel{Client: localClient, Transport: mode}
		peerApplications = localPeer
		peerLocal = localClient
		selectedTunnel = tunnel.TargetTunnel{Machine: localPeer, Other: termTunnel}
	}
	return &deps{
		cfg:              cfg,
		transportMode:    mode,
		auth:             authSource,
		resolver:         nil,
		tunnel:           selectedTunnel,
		terminalSelector: termTunnel,
		peerTunnel:       peerTunnel,
		peerLocal:        peerLocal,
		peerApplications: peerApplications,
	}, nil
}

func peerConnectionMode(mode tunnel.TerminalTransport) connectionmanager.Mode {
	switch mode {
	case tunnel.TerminalTransportDirect:
		return connectionmanager.ModeDirectQUIC
	case tunnel.TerminalTransportRelayQUIC:
		return connectionmanager.ModeRelayQUIC
	case tunnel.TerminalTransportRelayWSS:
		return connectionmanager.ModeWSS
	case tunnel.TerminalTransportRelay:
		return connectionmanager.ModeRelayRace
	default:
		return connectionmanager.ModeAuto
	}
}

func peerRacePolicy() connectionmanager.Config {
	return connectionmanager.Config{
		RelayDelay:     time.Duration(config.PeerRelayPreferenceMilliseconds) * time.Millisecond,
		WSSDelay:       time.Duration(config.PeerWSSStartMilliseconds) * time.Millisecond,
		ConnectTimeout: time.Duration(config.PeerConnectTimeoutMilliseconds) * time.Millisecond,
	}
}

type pingSample struct {
	Sequence     int     `json:"sequence"`
	Path         string  `json:"path,omitempty"`
	RelayRegion  string  `json:"relay_region,omitempty"`
	ConnectionMS float64 `json:"connection_ms,omitempty"`
	ExchangeMS   float64 `json:"exchange_ms,omitempty"`
	RTTMS        float64 `json:"rtt_ms,omitempty"`
	PTOs         uint32  `json:"ptos,omitempty"`
	Lost         bool    `json:"lost"`
	Transition   bool    `json:"path_transition"`
}

type pingReport struct {
	Schema       string       `json:"schema"`
	MachineID    string       `json:"machine_id"`
	MachineName  string       `json:"machine_name"`
	Sent         int          `json:"sent"`
	Received     int          `json:"received"`
	Lost         int          `json:"lost"`
	LossPercent  float64      `json:"loss_percent"`
	MinRTTMS     float64      `json:"min_rtt_ms,omitempty"`
	AverageRTTMS float64      `json:"average_rtt_ms,omitempty"`
	MaxRTTMS     float64      `json:"max_rtt_ms,omitempty"`
	Samples      []pingSample `json:"samples"`
}

func actionPing(command *cobra.Command, args []string) error {
	count, _ := command.Flags().GetInt("count")
	timeout, _ := command.Flags().GetDuration("timeout")
	transport, _ := command.Flags().GetString("transport")
	jsonOutput, _ := command.Flags().GetBool("json")
	if count < 1 || count > 100 {
		return invocationError(errors.New("--count must be between 1 and 100"))
	}
	if timeout <= 0 || timeout > time.Minute {
		return invocationError(errors.New("--timeout must be greater than zero and no more than 1m"))
	}
	if _, err := tunnel.ParseTerminalTransport(transport); err != nil {
		return invocationError(err)
	}
	ctx := actionContext(command, args)
	dependencies, err := buildDeps(ctx)
	if err != nil {
		return err
	}
	if dependencies.peerTunnel == nil {
		return errors.New("pb ping requires an authenticated Paperboat server")
	}
	client, err := backendClient(ctx)
	if err != nil {
		return err
	}
	machine, err := resolveUserMachine(command.Context(), client, args[0])
	if err != nil {
		return err
	}
	if !machine.Online {
		return &api.APIError{Code: "machine_offline", Message: "This machine is offline."}
	}
	target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, MachineGeneration: uint64(machine.InstallationGeneration), Terminal: &resolver.TerminalTarget{Protocol: "paperboat.health-probe.v1", EnvironmentID: machine.EnvironmentID}}
	report := pingReport{Schema: "paperboat.ping/v1", MachineID: machine.ID, MachineName: machine.DisplayName, Sent: count, Samples: make([]pingSample, 0, count)}
	previousSelection := ""
	var total time.Duration
	for sequence := 1; sequence <= count; sequence++ {
		sampleCtx, cancel := context.WithTimeout(command.Context(), timeout)
		var result tunnel.PingResult
		var pingErr error
		if dependencies.peerLocal != nil {
			deadline := time.Now().UTC().Add(timeout)
			request, requestErr := localapi.NewPeerStreamRequest(target.ProjectID, target.Terminal.EnvironmentID, target.MachineGeneration, "health_probe", fmt.Sprintf("ping_%d", sequence), "local-health-probe", deadline, 1<<20, nil)
			if requestErr == nil {
				request.Transport = transport
				var probe localapi.PeerProbeResult
				probe, pingErr = dependencies.peerLocal.ProbePeer(sampleCtx, request)
				if pingErr == nil {
					path, pathErr := parsePingPath(probe.Transport)
					if pathErr != nil {
						pingErr = pathErr
					} else {
						result = tunnel.PingResult{Path: path, RelayRegion: probe.RelayRegion, Connection: time.Duration(probe.ConnectionNanoseconds), RTT: time.Duration(probe.RTTNanoseconds), PTOs: probe.PTOs}
					}
				}
			} else {
				pingErr = requestErr
			}
		} else {
			result, pingErr = dependencies.peerTunnel.PingTransport(sampleCtx, target, transport)
		}
		cancel()
		if pingErr != nil {
			if command.Context().Err() != nil {
				return command.Context().Err()
			}
			if !errors.Is(pingErr, context.DeadlineExceeded) && !errors.Is(pingErr, context.Canceled) {
				return fmt.Errorf("authenticated ping sample %d: %w", sequence, pingErr)
			}
			report.Lost++
			report.Samples = append(report.Samples, pingSample{Sequence: sequence, Lost: true})
			if !jsonOutput {
				fmt.Fprintf(command.OutOrStdout(), "sample %d: timeout\n", sequence)
			}
			continue
		}
		path := pingPath(result.Path)
		selection := path + "\x00" + result.RelayRegion
		transition := previousSelection != "" && previousSelection != selection
		previousSelection = selection
		rttMS := float64(result.RTT) / float64(time.Millisecond)
		report.Received++
		total += result.RTT
		if report.MinRTTMS == 0 || rttMS < report.MinRTTMS {
			report.MinRTTMS = rttMS
		}
		if rttMS > report.MaxRTTMS {
			report.MaxRTTMS = rttMS
		}
		sample := pingSample{Sequence: sequence, Path: path, RelayRegion: result.RelayRegion, ConnectionMS: float64(result.Connection) / float64(time.Millisecond), ExchangeMS: rttMS, RTTMS: rttMS, PTOs: result.PTOs, Transition: transition}
		report.Samples = append(report.Samples, sample)
		if !jsonOutput {
			region := ""
			if result.RelayRegion != "" {
				region = " region=" + result.RelayRegion
			}
			transitionText := ""
			if transition {
				transitionText = " transition"
			}
			fmt.Fprintf(command.OutOrStdout(), "sample %d: path=%s%s connect=%.2fms exchange=%.2fms%s\n", sequence, path, region, sample.ConnectionMS, sample.ExchangeMS, transitionText)
		}
	}
	if report.Received > 0 {
		report.AverageRTTMS = float64(total) / float64(time.Millisecond) / float64(report.Received)
	}
	report.LossPercent = float64(report.Lost) * 100 / float64(report.Sent)
	if jsonOutput {
		encoder := json.NewEncoder(command.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(report)
	}
	fmt.Fprintf(command.OutOrStdout(), "summary: sent=%d received=%d loss=%.1f%%", report.Sent, report.Received, report.LossPercent)
	if report.Received > 0 {
		fmt.Fprintf(command.OutOrStdout(), " rtt min/avg/max=%.2f/%.2f/%.2fms", report.MinRTTMS, report.AverageRTTMS, report.MaxRTTMS)
	}
	fmt.Fprintln(command.OutOrStdout())
	if report.Received == 0 {
		return exitCodeError{code: 1}
	}
	return nil
}

func pingPath(path connectionmanager.Path) string {
	switch path {
	case connectionmanager.PathDirectQUIC:
		return "direct_quic"
	case connectionmanager.PathRelayQUIC:
		return "relay_quic"
	case connectionmanager.PathWSS:
		return "wss"
	default:
		return "unknown"
	}
}

func parsePingPath(value string) (connectionmanager.Path, error) {
	switch value {
	case "direct_quic":
		return connectionmanager.PathDirectQUIC, nil
	case "relay_quic":
		return connectionmanager.PathRelayQUIC, nil
	case "wss":
		return connectionmanager.PathWSS, nil
	default:
		return 0, fmt.Errorf("invalid peer probe path")
	}
}

func environmentsCommand() *command.Spec {
	return &command.Spec{
		Name:  "environments",
		Usage: "List machines available to this account",
		Flags: []command.Flag{&command.BoolFlag{Name: "json"}},
		Action: func(c *command.Context) error {
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			machines, err := client.ListUserMachines(c.Context)
			if err != nil {
				return err
			}
			if c.Bool("json") {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"machines": machines})
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATE\tPLATFORM\tID")
			for _, machine := range machines {
				state := machine.State
				if machine.Online && state == "" {
					state = "online"
				}
				platform := strings.Trim(strings.Join([]string{machine.Platform, machine.Architecture}, "/"), "/")
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", machine.DisplayName, state, platform, machine.ID)
			}
			return w.Flush()
		},
	}
}

func previewCommand() *command.Spec {
	return &command.Spec{Name: "preview", Usage: "Manage private serves and public previews", Subcommands: []*command.Spec{
		{Name: "create", Action: previewCreateCommand},
		{Name: "list", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: previewListCommand},
		{Name: "revoke", ArgsUsage: "<preview>", Flags: []command.Flag{&command.BoolFlag{Name: "yes"}, &command.BoolFlag{Name: "json"}}, Action: previewRemoveCommand},
	}}
}

func serveCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "serve [path]",
		Short: "Serve a local file or directory privately",
		Args:  commandArgs(cobra.MaximumNArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			err := runServeCommand(command, args)
			jsonOutput, _ := command.Flags().GetBool("json")
			if err == nil || !jsonOutput {
				return err
			}
			if encodeErr := json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": false, "error": serveErrorEnvelope(err)}); encodeErr != nil {
				return encodeErr
			}
			exitCode := 1
			if errors.Is(err, errUsage) {
				exitCode = 2
			}
			return exitCodeError{code: exitCode}
		},
	}
	command.Flags().String("name", "", "stable preview name")
	command.Flags().Duration("duration", 24*time.Hour, "preview lifetime")
	command.Flags().Bool("indefinite", false, "keep until explicitly revoked")
	command.Flags().Bool("detach", false, "continue serving after this command exits")
	command.Flags().Bool("spa", false, "fall back to index.html for navigation requests")
	command.Flags().Bool("public", false, "create a public preview")
	command.Flags().Uint16("listen-port", 0, "private loopback listener port")
	command.Flags().Bool("json", false, "print JSON")
	return command
}

func serveErrorEnvelope(err error) map[string]any {
	code, category, retryable, recovery := "serve_failed", "local_io", false, "Run `pb doctor`, correct the reported problem, then retry."
	switch {
	case errors.Is(err, errUsage):
		code, category, recovery = "serve_invocation_invalid", "usage", "Correct the command arguments and retry."
	case errors.Is(err, servepkg.ErrInvalidSource):
		code, recovery = "serve_source_invalid", "Select an existing regular file or directory on this device."
	case errors.Is(err, servepkg.ErrSourceChanged):
		code, recovery = "serve_source_changed", "Select the source again so Paperboat can pin its current identity."
	case errors.Is(err, errServeProtocolIncompatible):
		code, category, recovery = "protocol_incompatible", "protocol", "Upgrade and restart the local Paperboat runtime, then retry."
	case errors.Is(err, hostruntimeentry.ErrPreviewServiceMissing):
		code, category, retryable, recovery = "preview_worker_missing", "worker_failed", true, "The detached worker exited before readiness; inspect its service logs and retry."
	case errors.Is(err, hostruntimeentry.ErrPreviewServiceFailed):
		code, category, retryable, recovery = "preview_worker_failed", "worker_failed", true, "The detached worker failed before readiness; inspect its service logs and retry."
	case errors.Is(err, context.DeadlineExceeded):
		code, category, retryable, recovery = "readiness_timeout", "unavailable_retryable", true, "Inspect `pb preview list` before retrying with the same name."
	case errors.Is(err, context.Canceled):
		code, category, recovery = "serve_canceled", "canceled", "No retry is needed."
	default:
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Code != "" {
			code = apiErr.Code
			category = "unavailable_retryable"
			retryable = apiErr.Code == "machine_offline" || apiErr.Status >= 500
			if apiErr.Code == "machine_capability_unavailable" {
				category, retryable = "authorization_or_entitlement", false
			}
		}
	}
	message := sentence(userFacingError(err))
	if len(message) > 240 {
		message = message[:237] + "..."
	}
	return map[string]any{
		"code": code, "category": category, "message": message, "retryable": retryable,
		"state_changed": "unknown", "outcome_uncertain": false, "recovery": recovery,
		"public_state_created": "unknown", "local_state_created": "unknown", "cleanup": "not_required",
	}
}

var errServeProtocolIncompatible = errors.New("local runtime does not support pb serve")

func runServeCommand(command *cobra.Command, args []string) error {
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	jsonOutput, _ := command.Flags().GetBool("json")
	if jsonOutput {
		interactive = false
	}
	if len(args) == 0 && !interactive {
		return invocationError(errors.New("pb serve requires <path> without an interactive terminal"))
	}
	configPath, _ := command.Flags().GetString("config")
	cfg, configErr := config.Load(configPath)
	if configErr != nil {
		return configErr
	}
	serveTelemetry, closeTelemetry := connectTelemetry(cfg, io.Discard)
	defer closeTelemetry()
	emit := func(stage, outcome string, started time.Time) {
		event := telemetry.Event{Name: "serve.lifecycle", At: time.Now().UTC(), Stage: stage, Outcome: outcome, LatencyMS: time.Since(started).Milliseconds()}
		if event.Validate() == nil {
			serveTelemetry.Record(event)
		}
	}
	var source servepkg.Source
	var stagedDrop bool
	var err error
	selectionStarted := time.Now()
	if len(args) == 1 {
		source, err = servepkg.ResolveSource(args[0])
	} else {
		source, stagedDrop, err = selectServeSource(command)
	}
	if err != nil {
		emit("selection", eventResultForTelemetry(err), selectionStarted)
		return err
	}
	emit("selection", "ok", selectionStarted)
	validationStarted := time.Now()
	if err := source.Revalidate(); err != nil {
		emit("validation", "failed", validationStarted)
		return fmt.Errorf("validate serve source: %w", err)
	}
	emit("validation", "ok", validationStarted)
	spa, _ := command.Flags().GetBool("spa")
	if spa && source.Kind != servepkg.SourceDirectory {
		return invocationError(errors.New("--spa requires a directory source"))
	}
	duration, _ := command.Flags().GetDuration("duration")
	indefinite, _ := command.Flags().GetBool("indefinite")
	if indefinite && command.Flags().Changed("duration") || !indefinite && (duration < time.Second || duration > 365*24*time.Hour) {
		return invocationError(errors.New("use a positive --duration up to 365 days, or --indefinite"))
	}
	public, _ := command.Flags().GetBool("public")
	listenPort, _ := command.Flags().GetUint16("listen-port")
	if public && command.Flags().Changed("listen-port") {
		return invocationError(errors.New("--listen-port is available only for private serve"))
	}
	var inboxPath, plannedInboxPath string
	if stagedDrop {
		inboxPath, err = configuredInboxPath()
		if err != nil {
			return err
		}
		plannedInboxPath, err = servepkg.PlanInboxCopy(source, inboxPath)
		if err != nil {
			return err
		}
	}
	if public && interactive {
		lifetime := duration.String()
		if indefinite {
			lifetime = "until explicitly stopped"
		}
		description := source.Path + "\nPublic access: anyone with the URL can access it\nLifetime: " + lifetime
		if stagedDrop {
			description += "\nInbox copy: " + plannedInboxPath
		}
		confirmed, confirmErr := prompt.Confirm(prompt.ConfirmOptions{
			Title:       "Publish this " + string(source.Kind) + "?",
			Description: description,
			Stdin:       os.Stdin, Output: command.ErrOrStderr(),
		})
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			return selector.ErrCanceled
		}
	}
	if stagedDrop {
		copied, copyErr := servepkg.CopyFileToInbox(command.Context(), source, inboxPath)
		if copyErr != nil {
			return copyErr
		}
		if copied.Path != plannedInboxPath {
			return errors.New("the planned Inbox filename was taken before the copy completed; the collision-safe copy remains in the Inbox, so select it and retry")
		}
		source, err = servepkg.ResolveSource(copied.Path)
		if err != nil {
			return err
		}
	}
	name, _ := command.Flags().GetString("name")
	name = normalizeServeName(name, filepath.Base(source.Path))
	if name == "" {
		return invocationError(errors.New("serve preview name must contain a letter or number"))
	}
	detach, _ := command.Flags().GetBool("detach")
	if !public {
		return runPrivateServe(command, source, name, duration, indefinite, detach, spa, listenPort, emit, jsonOutput)
	}
	stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
	if stateRoot == "" {
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
	}
	registrationStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		return err
	}
	registration, err := registrationStore.Registration()
	if err != nil {
		return errors.New("run `pb setup` before serving a file or directory")
	}
	if err := validateLocalServeCapability(command, registration); err != nil {
		return err
	}
	var record preview.ControlRecord
	execution := "foreground"
	var foreground *servepkg.Foreground
	var managementLease *servelease.Keeper
	if detach {
		execution = "detached"
		executable, executableErr := os.Executable()
		if executableErr != nil {
			return executableErr
		}
		executable, executableErr = filepath.EvalSymlinks(executable)
		if executableErr != nil {
			return executableErr
		}
		var expiresAt *time.Time
		if !indefinite {
			value := time.Now().UTC().Add(duration)
			expiresAt = &value
		}
		if err := hostruntimeentry.InstallServeService(command.Context(), executable, stateRoot, name, source, spa, expiresAt, indefinite, true, 0); err != nil {
			return err
		}
		// A connector acceptance attempt is bounded at 25 seconds. Leave enough
		// startup budget for one complete retry after the supervisor backoff.
		readyCtx, cancelReady := context.WithTimeout(command.Context(), 60*time.Second)
		defer cancelReady()
		record, err = hostruntimeentry.WaitPreviewServiceReady(readyCtx, stateRoot, name)
		if err != nil {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelCleanup()
			cleanupErr := hostruntimeentry.RemovePreviewService(cleanupCtx, stateRoot, name)
			message := "serve registration timed out; the detached service was stopped"
			if cleanupErr != nil {
				message = "serve registration timed out; detached service cleanup also failed"
			}
			return errors.Join(errors.New(message), err, cleanupErr)
		}
	} else {
		managementLease, err = acquireServeManagementLease(command.Context(), stateRoot, name)
		if err != nil {
			emit("lease_acquire", "failed", time.Now())
			return fmt.Errorf("acquire foreground management lease: %w", err)
		}
		emit("lease_acquire", "ok", time.Now())
		foreground, err = servepkg.StartForeground(command.Context(), servepkg.ForegroundConfig{
			Source: source, Name: name, Duration: duration, Indefinite: indefinite, SPA: spa,
			Lease: managementLease,
			Observe: func(event servepkg.LifecycleEvent) {
				telemetryEvent := telemetry.Event{Name: "serve.lifecycle", At: time.Now().UTC(), Stage: event.Operation, Outcome: event.Result, DurationNS: event.Duration.Nanoseconds(), EnvironmentID: registration.EnvironmentID}
				if telemetryEvent.Validate() == nil {
					serveTelemetry.Record(telemetryEvent)
				}
			},
			Preview: func(ctx context.Context, run servepkg.PreviewRunConfig) error {
				return hostruntimeentry.RunPreviewWorker(ctx, hostruntimeentry.PreviewWorkerConfig{
					ControlURL: registration.ServerURL, StateRoot: stateRoot, Name: run.Name, Port: run.Port,
					Duration: run.Duration, Indefinite: run.Indefinite, Ready: run.Ready,
					SourceKind: string(source.Kind), OwnerMode: "foreground",
				})
			},
		})
		if err != nil {
			releaseCtx, cancelRelease := context.WithTimeout(context.Background(), 5*time.Second)
			_ = managementLease.Release(releaseCtx)
			cancelRelease()
			return err
		}
		record = foreground.Record
	}
	if jsonOutput {
		data := map[string]any{
			"operation_id": record.OperationID, "preview_id": record.ID,
			"name": name, "machine_id": registration.MachineID, "source_path": source.Path,
			"source_kind": source.Kind, "url": record.URL, "state": record.State,
			"execution": execution, "expires_at": record.ExpiresAt,
		}
		if err := json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": data}); err != nil {
			return err
		}
	} else {
		lifetime := duration.String()
		if indefinite {
			lifetime = "until stopped"
		}
		fmt.Fprintf(command.OutOrStdout(), "Serving: %s\nAccess:  Public for %s\nURL:     %s\n", source.Path, lifetime, record.URL)
	}
	if foreground != nil {
		return foreground.Wait()
	}
	emit("ownership_transfer", "ok", time.Now())
	return nil
}

func runPrivateServe(command *cobra.Command, source servepkg.Source, name string, duration time.Duration, indefinite, detach, spa bool, listenPort uint16, emit func(string, string, time.Time), jsonOutput bool) error {
	execution := "foreground"
	var localURL string
	var expiresAt *time.Time
	if !indefinite {
		value := time.Now().UTC().Add(duration)
		expiresAt = &value
	}
	if detach {
		execution = "detached"
		stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
		var err error
		if stateRoot == "" {
			stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
			if err != nil {
				return err
			}
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return err
		}
		if err := hostruntimeentry.InstallServeService(command.Context(), executable, stateRoot, name, source, spa, expiresAt, indefinite, false, listenPort); err != nil {
			return err
		}
		readyCtx, cancelReady := context.WithTimeout(command.Context(), 30*time.Second)
		defer cancelReady()
		record, err := hostruntimeentry.WaitPreviewServiceReady(readyCtx, stateRoot, name)
		if err != nil {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
			cleanupErr := hostruntimeentry.RemovePreviewService(cleanupCtx, stateRoot, name)
			cancelCleanup()
			return errors.Join(errors.New("private serve listener did not become ready; detached service was stopped"), err, cleanupErr)
		}
		localURL = record.URL
	} else {
		local, err := servepkg.StartLocal(command.Context(), servepkg.LocalConfig{
			Source: source, Duration: duration, Indefinite: indefinite, SPA: spa, ListenPort: listenPort,
			Observe: func(event servepkg.LifecycleEvent) {
				emit(event.Operation, event.Result, time.Now().Add(-event.Duration))
			},
		})
		if err != nil {
			return err
		}
		localURL = local.URL
		if err := printPrivateServeResult(command, source, name, localURL, execution, expiresAt, jsonOutput); err != nil {
			return err
		}
		return local.Wait()
	}
	return printPrivateServeResult(command, source, name, localURL, execution, expiresAt, jsonOutput)
}

func printPrivateServeResult(command *cobra.Command, source servepkg.Source, name, localURL, execution string, expiresAt *time.Time, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{
			"name": name, "source_path": source.Path, "source_kind": source.Kind, "url": localURL,
			"visibility": "private", "listener": "loopback", "execution": execution, "expires_at": expiresAt,
		}})
	}
	lifetime := "until stopped"
	if expiresAt != nil {
		lifetime = time.Until(*expiresAt).Round(time.Second).String()
	}
	_, err := fmt.Fprintf(command.OutOrStdout(), "Serving: %s\nAccess:  Private on this device for %s\nURL:     %s\n", source.Path, lifetime, localURL)
	return err
}

func eventResultForTelemetry(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, selector.ErrCanceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "failed"
}

func acquireServeManagementLease(ctx context.Context, stateRoot, name string) (*servelease.Keeper, error) {
	var local struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}
	if err := readOwnerOnlyJSON(filepath.Join(stateRoot, "runtime", "worker-local.json"), &local); err != nil {
		return nil, err
	}
	host, port, splitErr := net.SplitHostPort(local.ListenAddress)
	if local.Schema != "paperboat.worker-local/v1" || splitErr != nil || host != "127.0.0.1" || port == "" {
		return nil, servelease.ErrInvalid
	}
	tokenPath := filepath.Join(stateRoot, "runtime", "local-control-token")
	token, err := readOwnerOnlyFile(tokenPath, 1024)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errServeProtocolIncompatible
		}
		return nil, err
	}
	client, err := servelease.NewClient("http://"+local.ListenAddress+"/v1/serve-leases", strings.TrimSpace(string(token)), nil)
	if err != nil {
		return nil, err
	}
	lease, err := client.Acquire(ctx, name)
	if err != nil {
		if errors.Is(err, servelease.ErrInvalid) {
			return nil, errServeProtocolIncompatible
		}
		return nil, err
	}
	return &servelease.Keeper{Client: client, Lease: lease, Interval: 5 * time.Second}, nil
}

func readOwnerOnlyJSON(path string, target any) error {
	data, err := readOwnerOnlyFile(path, 16<<10)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return servelease.ErrInvalid
	}
	return nil
}

func readOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !ownerOnlyRegularFile(path, info) {
		return nil, errors.Join(servelease.ErrInvalid, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !ownerOnlyRegularFile(path, opened) {
		return nil, errors.Join(servelease.ErrInvalid, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, servelease.ErrInvalid
	}
	return data, nil
}

func validateLocalServeCapability(command *cobra.Command, registration identity.Registration) error {
	client, err := backendForCommand(command)
	if err != nil {
		return err
	}
	machines, err := client.ListUserMachines(command.Context())
	if err != nil {
		return friendlyCommandError(err)
	}
	for _, machine := range machines {
		if machine.ID != registration.MachineID {
			continue
		}
		if !machine.Capabilities.PreviewLaunch.Configured {
			return &api.APIError{Code: "machine_capability_unavailable", Message: "This device is not configured to launch previews. Run `pb setup --mode client` or `pb pair`."}
		}
		if !machine.Online || !machine.Capabilities.PreviewLaunch.Observed {
			return &api.APIError{Code: "machine_offline", Message: "This device's preview runtime is offline. Run `pb doctor`, then retry."}
		}
		return nil
	}
	return &api.APIError{Code: "machine_offline", Message: "This device is not registered with the active Paperboat account. Run `pb setup`, then retry."}
}

func selectServeSource(command *cobra.Command) (servepkg.Source, bool, error) {
	root, err := os.Getwd()
	if err != nil {
		return servepkg.Source{}, false, err
	}
	const parentID = "\x00serve-parent"
	for {
		sources, discoverErr := servepkg.DiscoverSources(command.Context(), root, servepkg.DefaultDiscoveryLimit, 1)
		if discoverErr != nil {
			return servepkg.Source{}, false, discoverErr
		}
		items := make([]selector.Item, 0, len(sources)+1)
		byPath := make(map[string]servepkg.Source, len(sources))
		parent := filepath.Dir(root)
		if parent != root {
			items = append(items, selector.Item{ID: parentID, Title: ".. (parent directory)", Description: "Open directory", Search: "parent up"})
		}
		for index, source := range sources {
			title := filepath.Base(source.Path)
			description := string(source.Kind)
			if index == 0 {
				title = ". (serve this directory)"
			} else if source.Kind == servepkg.SourceDirectory {
				description = "directory  ·  open"
			}
			items = append(items, selector.Item{ID: source.Path, Title: title, Description: description, Search: source.Path + " " + title})
			byPath[source.Path] = source
		}
		var dropped servepkg.Source
		choice, chooseErr := selector.Choose(selector.Options{
			Title: "Serve a file or directory", Subtitle: "This device  ·  " + root,
			Items: items, Empty: "No files or directories are available", Footer: "type to filter  enter select/open  esc cancel",
			Stdin: os.Stdin, Output: command.ErrOrStderr(), InputSelection: func(value string) (selector.Item, bool) {
				source, ok := servepkg.ParseDroppedFile(value)
				if !ok {
					return selector.Item{}, false
				}
				dropped = source
				return selector.Item{ID: source.Path, Title: filepath.Base(source.Path)}, true
			},
		})
		if chooseErr != nil {
			return servepkg.Source{}, false, chooseErr
		}
		if dropped.Path != "" && choice.ID == dropped.Path {
			return dropped, true, dropped.Revalidate()
		}
		if choice.ID == parentID {
			root = parent
			continue
		}
		selected, ok := byPath[choice.ID]
		if !ok {
			return servepkg.Source{}, false, errors.New("selected serve source is no longer available")
		}
		if selected.Kind == servepkg.SourceDirectory && selected.Path != root {
			root = selected.Path
			continue
		}
		if err := selected.Revalidate(); err != nil {
			return servepkg.Source{}, false, err
		}
		return selected, false, nil
	}
}

func normalizeServeName(explicit, fallback string) string {
	value := strings.ToLower(strings.TrimSpace(explicit))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(fallback))
	}
	var result strings.Builder
	lastSeparator := false
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-'
		if valid {
			if result.Len() < 128 {
				result.WriteRune(character)
			}
			lastSeparator = character == '-' || character == '_'
		} else if result.Len() > 0 && !lastSeparator {
			result.WriteByte('-')
			lastSeparator = true
		}
	}
	return strings.Trim(result.String(), "-_")
}

func previewCreateCommand(c *command.Context) error {
	name := strings.TrimSpace(c.String("name"))
	port := c.Uint("port")
	if c.Args().Len() == 1 {
		parsed, err := strconv.ParseUint(c.Args().First(), 10, 16)
		if err != nil || parsed == 0 || port != 0 {
			return invocationError(errors.New("preview create accepts one target port, either positionally or through --port"))
		}
		port = uint(parsed)
	}
	duration := c.Duration("duration")
	indefinite := c.Bool("indefinite")
	if port < 1 || port > 65535 {
		return invocationError(errors.New("preview create requires a target port"))
	}
	if name == "" {
		name = fmt.Sprintf("port-%d", port)
	}
	if indefinite && c.Bool("duration-set") || !indefinite && (duration < time.Second || duration > 365*24*time.Hour) {
		return invocationError(errors.New("use a positive --duration up to 365 days, or --indefinite"))
	}
	if !c.Bool("public") {
		return previewCreatePrivate(c, name, uint16(port), duration, indefinite)
	}
	requestedMachine := strings.TrimSpace(c.String("machine"))
	if requestedMachine != "" {
		client, err := backendClient(c)
		if err != nil {
			return err
		}
		machines, err := client.ListUserMachines(c.Context)
		if err != nil {
			return err
		}
		var matches []api.UserMachine
		for _, machine := range machines {
			if machine.ID == requestedMachine || machine.DisplayName == requestedMachine {
				matches = append(matches, machine)
			}
		}
		if len(matches) == 0 {
			return errors.New("selected paired machine was not found")
		}
		if len(matches) > 1 {
			return errors.New("machine name is ambiguous; use the machine ID")
		}
		if !matches[0].Capabilities.PreviewLaunch.Configured {
			return &api.APIError{Code: "machine_capability_unavailable", Message: "This machine is not configured to launch previews."}
		}
		if !matches[0].Online || !matches[0].Capabilities.PreviewLaunch.Observed {
			return &api.APIError{Code: "machine_offline", Message: "The selected machine is offline."}
		}
		descriptor, err := client.MachinePreviewLaunchDescriptor(c.Context, matches[0].ID)
		if err != nil {
			return err
		}
		launchCtx, cancel := context.WithTimeout(c.Context, 35*time.Second)
		defer cancel()
		record, err := api.LaunchMachinePreview(launchCtx, descriptor, api.PreviewLaunchRequest{OperationID: newIdempotencyKey(), Name: name, Port: uint16(port), DurationSeconds: int64(duration / time.Second), Indefinite: indefinite}, nil)
		if err != nil {
			var launchErr *api.PreviewLaunchError
			if errors.As(err, &launchErr) {
				if c.Bool("json") {
					if encodeErr := json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": false, "error": launchErr}); encodeErr != nil {
						return encodeErr
					}
					return exitCodeError{code: 1}
				}
				return fmt.Errorf("%s Recovery: %s", launchErr.Message, launchErr.Recovery)
			}
			return err
		}
		if c.Bool("json") {
			return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": record})
		}
		fmt.Fprintf(c.Writer, "%s\nPublic preview: anyone with this URL can access it.\n", record.URL)
		return nil
	}
	stateRoot := os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
	var err error
	if stateRoot == "" {
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
	}
	registrationStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		return err
	}
	if _, err := registrationStore.Registration(); err != nil {
		return errors.New("run `pb setup` before creating a preview")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	var expiresAt *time.Time
	if !indefinite {
		value := time.Now().UTC().Add(duration)
		expiresAt = &value
	}
	if err := hostruntimeentry.InstallPreviewService(c.Context, executable, stateRoot, name, uint16(port), expiresAt, indefinite); err != nil {
		return err
	}
	readyCtx, cancel := context.WithTimeout(c.Context, 25*time.Second)
	defer cancel()
	record, err := hostruntimeentry.WaitPreviewServiceReady(readyCtx, stateRoot, name)
	if err != nil {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		cleanupErr := hostruntimeentry.RemovePreviewService(cleanupCtx, stateRoot, name)
		cancelCleanup()
		return errors.Join(fmt.Errorf("public preview readiness failed: %w", err), cleanupErr)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": record})
	}
	fmt.Fprintf(c.Writer, "%s\nPublic preview: anyone with this URL can access it.\n", record.URL)
	return nil
}

func previewCreatePrivate(c *command.Context, name string, targetPort uint16, duration time.Duration, indefinite bool) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	machines, err := client.ListUserMachines(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	requested := strings.TrimSpace(c.String("machine"))
	eligible := make([]api.UserMachine, 0, len(machines))
	for _, machine := range machines {
		if !machine.Capabilities.PreviewLaunch.Configured || !machine.Capabilities.PreviewLaunch.Observed || !machine.Online || machine.EnvironmentID == "" || machine.InstallationGeneration < 1 {
			continue
		}
		if requested == "" || machine.ID == requested || strings.EqualFold(machine.DisplayName, requested) {
			eligible = append(eligible, machine)
		}
	}
	if len(eligible) == 0 {
		return &api.APIError{Code: "private_preview_unavailable", Message: "No matching online paired machine is ready for private previews."}
	}
	if len(eligible) > 1 {
		return invocationError(errors.New("multiple paired machines are eligible; pass --machine with the stable machine ID"))
	}
	machine := eligible[0]
	if c.Bool("detach") {
		stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
		if stateRoot == "" {
			stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
			if err != nil {
				return err
			}
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return err
		}
		var expiresAt *time.Time
		if !indefinite {
			value := time.Now().UTC().Add(duration)
			expiresAt = &value
		}
		remote := hostruntimeentry.PrivatePreviewRuntimeDescriptor{MachineID: machine.ID, MachineName: machine.DisplayName, EnvironmentID: machine.EnvironmentID, MachineGeneration: uint64(machine.InstallationGeneration), TargetPort: targetPort, ListenPort: uint16(c.Uint("listen-port"))}
		policyVersion := buildinfo.Version
		if policyVersion == "" {
			policyVersion = "development"
		}
		runtimePolicy, err := helperconfig.FromEnv(policyVersion, os.Getenv)
		if err != nil {
			return err
		}
		if err := hostruntimeentry.InstallPrivatePreviewService(c.Context, executable, stateRoot, name, remote, expiresAt, indefinite, runtimePolicy.Resources.MaxPreviewTargets); err != nil {
			return err
		}
		readyCtx, cancelReady := context.WithTimeout(c.Context, 30*time.Second)
		defer cancelReady()
		record, err := hostruntimeentry.WaitPreviewServiceReady(readyCtx, stateRoot, name)
		if err != nil {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
			cleanupErr := hostruntimeentry.RemovePreviewService(cleanupCtx, stateRoot, name)
			cancelCleanup()
			return errors.Join(errors.New("private preview readiness failed; detached service was stopped"), err, cleanupErr)
		}
		if c.Bool("json") {
			return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"name": name, "machine_id": machine.ID, "target_port": targetPort, "url": record.URL, "visibility": "private", "listener": "loopback", "execution": "detached", "expires_at": expiresAt}})
		}
		fmt.Fprintf(c.Writer, "%s\nPrivate preview: available only on this device.\n", record.URL)
		return nil
	}
	dependencies, err := buildDeps(c)
	if err != nil {
		return err
	}
	if dependencies.peerApplications == nil {
		return errors.New("private peer transport is unavailable")
	}
	proxyCtx := c.Context
	var cancel context.CancelFunc
	if !indefinite {
		proxyCtx, cancel = context.WithTimeout(proxyCtx, duration)
		defer cancel()
	}
	proxy, err := privatepreviewproxy.Start(proxyCtx, privatepreviewproxy.Config{ListenPort: uint16(c.Uint("listen-port")), Dial: func(ctx context.Context) (io.ReadWriteCloser, error) {
		target, targetErr := privatePreviewPeerTarget(ctx, client, machine.ID, machine.DisplayName, machine.EnvironmentID, uint64(machine.InstallationGeneration))
		if targetErr != nil {
			return nil, targetErr
		}
		return dependencies.peerApplications.DialPrivatePreview(ctx, target, targetPort)
	}})
	if err != nil {
		return err
	}
	defer proxy.Close()
	var expiresAt *time.Time
	if !indefinite {
		value := time.Now().UTC().Add(duration)
		expiresAt = &value
	}
	if c.Bool("json") {
		if err := json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"name": name, "machine_id": machine.ID, "target_port": targetPort, "url": proxy.URL, "visibility": "private", "listener": "loopback", "execution": "foreground", "expires_at": expiresAt}}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(c.Writer, "%s\nPrivate preview: available only on this device.\n", proxy.URL)
	}
	return proxy.Wait()
}

func privatePreviewPeerTarget(ctx context.Context, client *api.Client, machineID, machineName, environmentID string, generation uint64) (resolver.ConnectInfo, error) {
	if client == nil || machineID == "" || environmentID == "" || generation == 0 {
		return resolver.ConnectInfo{}, errors.New("private preview target is invalid")
	}
	descriptor, err := client.MachinePreviewLaunchDescriptor(ctx, machineID)
	if err != nil {
		return resolver.ConnectInfo{}, err
	}
	return resolver.ConnectInfo{
		TargetKind:        "machine",
		ProjectID:         machineID,
		Project:           machineName,
		MachineGeneration: generation,
		Transport:         string(tunnel.TerminalTransportDirect),
		Terminal: &resolver.TerminalTarget{
			Protocol:      "paperboat.private-preview.v1",
			EnvironmentID: environmentID,
			Auth: resolver.AuthTarget{
				Method:    descriptor.Auth.Method,
				Token:     descriptor.Auth.Token,
				ExpiresAt: descriptor.Auth.ExpiresAt.Format(time.RFC3339Nano),
				Scopes:    descriptor.Auth.Scopes,
			},
		},
	}, nil
}

func inboxCommand() *command.Spec {
	return &command.Spec{Name: "inbox", Usage: "Manage the Paperboat Inbox", Subcommands: []*command.Spec{
		{Name: "path", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: inboxPathCommand},
		{Name: "set", ArgsUsage: "<directory>", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: inboxSetCommand},
		{Name: "reset", Flags: []command.Flag{&command.BoolFlag{Name: "json"}}, Action: inboxResetCommand},
	}}
}

func runtimeIdentityStore() (*identity.Store, error) {
	stateRoot := os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
	var err error
	if stateRoot == "" {
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return nil, err
		}
	}
	return identity.Open(identity.Config{StateRoot: stateRoot})
}

func configuredInboxPath() (string, error) {
	store, err := runtimeIdentityStore()
	if err != nil {
		return "", err
	}
	registration, err := store.Registration()
	if err != nil {
		return "", errors.New("run `pb setup` to configure the Paperboat Inbox")
	}
	if err := inbox.ValidatePath(registration.InboxPath); err != nil {
		return "", err
	}
	return registration.InboxPath, nil
}

func configuredMachineID() (string, error) {
	store, err := runtimeIdentityStore()
	if err != nil {
		return "", err
	}
	registration, err := store.Registration()
	if err != nil || registration.MachineID == "" {
		return "", errors.New("run `pb setup` to configure this machine")
	}
	return registration.MachineID, nil
}

func inboxPathCommand(c *command.Context) error {
	path, err := configuredInboxPath()
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]string{"path": path}})
	}
	fmt.Fprintln(c.Writer, path)
	return nil
}

func inboxSetCommand(c *command.Context) error {
	if c.Args().Len() != 1 {
		return errors.New("usage: pb inbox set <directory>")
	}
	return setInboxPath(c, c.Args().First())
}

func inboxResetCommand(c *command.Context) error {
	if c.Args().Len() != 0 {
		return errors.New("pb inbox reset does not accept arguments")
	}
	path, err := inbox.DefaultPath()
	if err != nil {
		return err
	}
	return setInboxPath(c, path)
}

func setInboxPath(c *command.Context, path string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if err := inbox.EnsurePath(path); err != nil {
		return err
	}
	store, err := runtimeIdentityStore()
	if err != nil {
		return err
	}
	registration, err := store.Registration()
	if err != nil {
		return errors.New("run `pb setup` before changing the Paperboat Inbox")
	}
	registration.InboxPath = path
	registration.UpdatedAt = time.Now().UTC()
	if err := store.SaveRegistration(registration); err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]string{"path": path}})
	}
	fmt.Fprintln(c.Writer, path)
	return nil
}

func previewListCommand(c *command.Context) error {
	if stateRoot := previewRuntimeStateRoot(); stateRoot != "" {
		if err := hostruntimeentry.ReconcileExpiredPreviewServices(c.Context, stateRoot, time.Now().UTC()); err != nil {
			return friendlyCommandError(err)
		}
	}
	privateItems := listLocalPrivateServes()
	client, err := backendClient(c)
	if err != nil {
		if len(privateItems) == 0 {
			return err
		}
		return writePreviewList(c, nil, privateItems)
	}
	items, err := client.ListPreviews(c.Context)
	if err != nil {
		if len(privateItems) == 0 {
			return friendlyCommandError(err)
		}
		return writePreviewList(c, nil, privateItems)
	}
	items = enrichLocalServeSources(items)
	return writePreviewList(c, items, privateItems)
}

type localPrivateServe struct {
	Name       string     `json:"name"`
	URL        string     `json:"url"`
	SourcePath string     `json:"source_path"`
	SourceKind string     `json:"source_kind"`
	Machine    string     `json:"machine,omitempty"`
	State      string     `json:"state"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func writePreviewList(c *command.Context, items []api.Preview, privateItems []localPrivateServe) error {
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"previews": items, "private_serves": privateItems}})
	}
	w := tabwriter.NewWriter(c.Writer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVISIBILITY\tENVIRONMENT\tTYPE\tSOURCE\tOWNER\tPATH\tSTATE\tEXPIRES\tURL")
	for _, item := range privateItems {
		expires := "indefinite"
		if item.ExpiresAt != nil {
			expires = relativeTime(item.ExpiresAt)
		}
		environment := "this device"
		if item.Machine != "" {
			environment = item.Machine
		}
		fmt.Fprintf(w, "%s\tprivate\t%s\tlocal\t%s\tdetached\t%s\t%s\t%s\t%s\n", item.Name, environment, item.SourceKind, item.SourcePath, item.State, expires, item.URL)
	}
	for _, item := range items {
		expires := "indefinite"
		if item.ExpiresAt != nil {
			expires = relativeTime(item.ExpiresAt)
		}
		fmt.Fprintf(w, "%s\tpublic\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", item.LogicalName, item.EnvironmentName, item.EnvironmentKind, item.SourceKind, item.OwnerMode, item.SourcePath, item.State, expires, item.URL)
	}
	return w.Flush()
}

func listLocalPrivateServes() []localPrivateServe {
	stateRoot := previewRuntimeStateRoot()
	if stateRoot == "" {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(stateRoot, "previews", "active"))
	if err != nil {
		return nil
	}
	items := make([]localPrivateServe, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := readOwnerOnlyFile(filepath.Join(stateRoot, "previews", "active", entry.Name()), 1<<20)
		if err != nil {
			continue
		}
		var descriptor struct {
			Schema            string     `json:"schema"`
			Name              string     `json:"name"`
			BindAddress       string     `json:"bind_address"`
			Port              uint16     `json:"port"`
			ServiceGeneration uint64     `json:"service_generation"`
			Indefinite        bool       `json:"indefinite"`
			ExpiresAt         *time.Time `json:"expires_at"`
			ServiceDefinition string     `json:"service_definition"`
			Record            *struct {
				OperationID   string     `json:"operation_id"`
				ID            string     `json:"id"`
				EnvironmentID string     `json:"environment_id"`
				LogicalName   string     `json:"logical_name"`
				PreviewKey    string     `json:"preview_key"`
				URL           string     `json:"url"`
				TargetPort    int32      `json:"target_port"`
				State         string     `json:"state"`
				ExpiresAt     *time.Time `json:"expires_at"`
			} `json:"record"`
			Serve *struct {
				SourcePath     string `json:"source_path"`
				SourceKind     string `json:"source_kind"`
				SourceIdentity string `json:"source_identity"`
				SPA            bool   `json:"spa"`
				OwnerMode      string `json:"owner_mode"`
				Visibility     string `json:"visibility"`
				ListenPort     uint16 `json:"listen_port"`
			} `json:"serve"`
			PrivateRemote *struct {
				MachineID         string `json:"machine_id"`
				MachineName       string `json:"machine_name"`
				EnvironmentID     string `json:"environment_id"`
				MachineGeneration uint64 `json:"machine_generation"`
				TargetPort        uint16 `json:"target_port"`
				ListenPort        uint16 `json:"listen_port"`
			} `json:"private_remote"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&descriptor) != nil || decoder.Decode(&struct{}{}) != io.EOF || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name == "" || descriptor.BindAddress != "127.0.0.1" || descriptor.ServiceGeneration == 0 || descriptor.Record == nil || !strings.HasPrefix(descriptor.Record.URL, "http://127.0.0.1:") {
			continue
		}
		item := localPrivateServe{Name: descriptor.Name, URL: descriptor.Record.URL, State: descriptor.Record.State, ExpiresAt: descriptor.ExpiresAt}
		if descriptor.Serve != nil && descriptor.PrivateRemote == nil && descriptor.Serve.Visibility == "private" && descriptor.Serve.OwnerMode == "detached" && filepath.IsAbs(descriptor.Serve.SourcePath) {
			item.SourcePath, item.SourceKind = descriptor.Serve.SourcePath, descriptor.Serve.SourceKind
		} else if descriptor.PrivateRemote != nil && descriptor.Serve == nil && descriptor.PrivateRemote.MachineID != "" && descriptor.PrivateRemote.MachineName != "" && descriptor.PrivateRemote.EnvironmentID != "" && descriptor.PrivateRemote.MachineGeneration > 0 && descriptor.PrivateRemote.TargetPort > 0 {
			item.SourcePath, item.SourceKind, item.Machine = fmt.Sprintf("127.0.0.1:%d", descriptor.PrivateRemote.TargetPort), "remote-port", descriptor.PrivateRemote.MachineName
		} else {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func previewRuntimeStateRoot() string {
	stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
	if stateRoot != "" {
		return stateRoot
	}
	stateRoot, err := helperconfig.DefaultStateRoot(os.Getenv)
	if err != nil {
		return ""
	}
	return stateRoot
}

func enrichLocalServeSources(items []api.Preview) []api.Preview {
	stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
	if stateRoot == "" {
		var err error
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return items
		}
	}
	directory, err := os.Open(filepath.Join(stateRoot, "previews", "active"))
	if err != nil {
		return items
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return items
	}
	paths := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(stateRoot, "previews", "active", entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil || !ownerOnlyRegularFile(path, info) {
			continue
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			continue
		}
		openedInfo, openedStatErr := file.Stat()
		if openedStatErr != nil || !ownerOnlyRegularFile(path, openedInfo) || !os.SameFile(info, openedInfo) {
			file.Close()
			continue
		}
		var descriptor struct {
			Schema string `json:"schema"`
			Record *struct {
				ID string `json:"id"`
			} `json:"record"`
			Serve *struct {
				SourcePath string `json:"source_path"`
			} `json:"serve"`
		}
		decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
		decodeErr := decoder.Decode(&descriptor)
		if decodeErr == nil {
			var trailing any
			if trailingErr := decoder.Decode(&trailing); trailingErr != io.EOF {
				decodeErr = errors.New("preview descriptor contains trailing data")
			}
		}
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Record == nil || descriptor.Record.ID == "" || descriptor.Serve == nil || !filepath.IsAbs(descriptor.Serve.SourcePath) {
			continue
		}
		paths[descriptor.Record.ID] = filepath.Clean(descriptor.Serve.SourcePath)
	}
	for index := range items {
		if path := paths[items[index].ID]; path != "" && (items[index].SourceKind == "file" || items[index].SourceKind == "directory") {
			items[index].SourcePath = path
		}
	}
	return items
}

func previewRemoveCommand(c *command.Context) error {
	if c.Args().Len() > 1 {
		return errors.New("usage: pb preview revoke [preview-id] --yes")
	}
	previewID := c.Args().First()
	for _, local := range listLocalPrivateServes() {
		if previewID != local.Name {
			continue
		}
		if !c.Bool("yes") {
			confirmed, confirmErr := confirmAction(fmt.Sprintf("Stop private serve %q?", local.Name))
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				return errors.New("preview revocation canceled")
			}
		}
		stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
		if stateRoot == "" {
			var err error
			stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
			if err != nil {
				return err
			}
		}
		if err := hostruntimeentry.RemovePreviewService(c.Context, stateRoot, local.Name); err != nil {
			return err
		}
		if c.Bool("json") {
			return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"name": local.Name, "state": "removed", "visibility": "private"}})
		}
		fmt.Fprintf(c.Writer, "Stopped private serve %s.\n", local.Name)
		return nil
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	items, err := client.ListPreviews(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	var selected api.Preview
	if previewID == "" {
		choices := make([]selector.Item, 0, len(items))
		byID := make(map[string]api.Preview, len(items))
		for _, item := range items {
			expiry := "indefinite"
			if item.ExpiresAt != nil {
				expiry = "expires " + relativeTime(item.ExpiresAt)
			}
			description := fmt.Sprintf("%s  ·  %s  ·  :%d  ·  %s", item.EnvironmentName, item.State, item.TargetPort, expiry)
			choices = append(choices, selector.Item{ID: item.ID, Title: item.LogicalName, Description: description, Search: item.EnvironmentKind + " " + item.URL})
			byID[item.ID] = item
		}
		choice, selectErr := selector.Choose(selector.Options{Title: "Choose a preview to revoke", Subtitle: "Public preview URLs", Items: choices, Empty: "no previews are available", Stdin: os.Stdin, Output: os.Stderr})
		if selectErr != nil {
			if errors.Is(selectErr, selector.ErrCanceled) {
				return errors.New("preview selection canceled")
			}
			return selectErr
		}
		selected, previewID = byID[choice.ID], choice.ID
	} else {
		for _, item := range items {
			if item.ID == previewID {
				selected = item
				break
			}
		}
	}
	if selected.ID == "" {
		return friendlyCommandError(fmt.Errorf("preview %q was not found", previewID))
	}
	fmt.Fprintf(c.ErrWriter, "Preview: %s (%s, %s)\n", selected.LogicalName, selected.EnvironmentName, selected.EnvironmentKind)
	fmt.Fprintf(c.ErrWriter, "Project: %s  Resource: %s  User: %s\n", selected.ProjectID, selected.ResourceID, selected.UserID)
	if !c.Bool("yes") {
		action := "Revoke public preview"
		if selected.SourceKind == "file" || selected.SourceKind == "directory" {
			action = "Stop serving"
		}
		confirmed, confirmErr := confirmAction(fmt.Sprintf("%s %q?", action, selected.LogicalName))
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			return errors.New("preview revocation canceled")
		}
	}
	item, err := client.RemovePreview(c.Context, previewID, newIdempotencyKey())
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"preview_id": item.ID, "state": item.State}})
	}
	if selected.SourceKind == "file" || selected.SourceKind == "directory" {
		fmt.Fprintf(c.Writer, "Stopped serving %s.\n", item.LogicalName)
	} else {
		fmt.Fprintf(c.Writer, "Removed preview %s.\n", item.LogicalName)
	}
	return nil
}

func previewRevokeAllCommand(c *command.Context) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	target, err := resolveEnvironmentTarget(c.Context, client, c.Args().First())
	if err != nil {
		return err
	}
	items, err := client.ListPreviews(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	selected := make([]api.Preview, 0, len(items))
	for _, item := range items {
		if item.EnvironmentID == target.id || item.ProjectID == target.id || item.ResourceID == target.id || strings.EqualFold(item.EnvironmentName, target.name) {
			selected = append(selected, item)
		}
	}
	fmt.Fprintf(c.ErrWriter, "Environment: %s (%s)\n", target.name, target.id)
	fmt.Fprintf(c.ErrWriter, "Active previews to revoke: %d\n", len(selected))
	if !c.Bool("yes") {
		return errors.New("preview revocation requires --yes")
	}
	revoked := 0
	var revokeErrors []error
	for _, item := range selected {
		if _, err := client.RemovePreview(c.Context, item.ID, newIdempotencyKey()); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("revoke preview %s: %w", item.LogicalName, err))
			continue
		}
		revoked++
	}
	if len(revokeErrors) > 0 {
		return fmt.Errorf("revoked %d of %d previews in %s; remote state changed: %w", revoked, len(selected), target.name, errors.Join(revokeErrors...))
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"environment_id": target.id, "environment_name": target.name, "revoked": revoked}})
	}
	fmt.Fprintf(c.Writer, "Revoked %d previews in %s.\n", revoked, target.name)
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
		target, err := resolveTerminalEnvironmentTarget(c.Context, client, requested)
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
			fmt.Fprintln(w, "NAME\tID\tSTATE\tATTACHED\tLAST ACTIVE\tCREATED")
		} else {
			fmt.Fprintln(w, "NAME\tSTATE\tATTACHED\tLAST ACTIVE\tCREATED")
		}
		for _, s := range sessions {
			attached := "-"
			if s.AttachedCount != nil {
				attached = fmt.Sprintf("%d", *s.AttachedCount)
			}
			if c.Bool("wide") {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.ID, s.State, attached, relativeTime(s.LastActiveAt), relativeTimestamp(s.CreatedAt))
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.State, attached, relativeTime(s.LastActiveAt), relativeTimestamp(s.CreatedAt))
			}
		}
		return w.Flush()
	}
	return &command.Spec{Name: "sessions", Usage: "Manage environment terminal sessions", ArgsUsage: "<environment>", Flags: []command.Flag{&command.BoolFlag{Name: "wide"}, &command.BoolFlag{Name: "json"}}, Action: list, Subcommands: []*command.Spec{
		{Name: "rename", ArgsUsage: "<environment> <session> <new-name>", Usage: "Rename a terminal session", Action: func(c *command.Context) error {
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
			target, err := resolveTerminalEnvironmentTarget(c.Context, client, c.Args().First())
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
		{Name: "close", ArgsUsage: "<environment> [<session>]", Usage: "Close one or all terminal sessions", Action: func(c *command.Context) error {
			all := c.Bool("all")
			if c.Args().Len() < 1 || c.Args().Len() > 2 || all && c.Args().Len() != 1 {
				return errors.New("usage: pb session close <environment> <session> --yes OR pb session close <environment> --all --yes")
			}
			if !all && !c.Bool("yes") && !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("session close requires --yes in non-interactive use")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveTerminalEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			if all {
				sessions, err := listTerminalSessionsForTarget(c.Context, client, target)
				if err != nil {
					return friendlyCommandError(err)
				}
				open := make([]api.TerminalSession, 0, len(sessions))
				for _, session := range sessions {
					if session.State != "closed" {
						open = append(open, session)
					}
				}
				fmt.Fprintf(c.ErrWriter, "Environment: %s (%s)\n", target.name, target.id)
				fmt.Fprintf(c.ErrWriter, "Open sessions to close: %d\n", len(open))
				if !c.Bool("yes") {
					return errors.New("session close requires --yes")
				}
				var closeErrors []error
				closed := 0
				for _, session := range open {
					if err := closeTerminalSessionForTarget(c.Context, client, target, session.ID); err != nil {
						closeErrors = append(closeErrors, fmt.Errorf("close session %s: %w", session.Name, err))
						continue
					}
					closed++
				}
				if len(closeErrors) > 0 {
					return fmt.Errorf("closed %d sessions in %s; remote state changed: %w", closed, target.name, errors.Join(closeErrors...))
				}
				if c.Bool("json") {
					return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "closed": closed})
				}
				fmt.Fprintf(c.Writer, "Closed %d sessions in %s. Session history was retained.\n", closed, target.name)
				return nil
			}
			var session api.TerminalSession
			if c.Args().Len() == 1 {
				sessions, listErr := listTerminalSessionsForTarget(c.Context, client, target)
				if listErr != nil {
					return friendlyCommandError(listErr)
				}
				session, err = selectSession(target, slices.DeleteFunc(sessions, func(item api.TerminalSession) bool { return item.State == "closed" }), "Choose a session to close")
			} else {
				session, err = resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			}
			if err != nil {
				return err
			}
			if !c.Bool("yes") {
				confirmed, confirmErr := confirmAction(fmt.Sprintf("Close terminal session %q? History will be retained.", session.Name))
				if confirmErr != nil {
					return confirmErr
				}
				if !confirmed {
					return errors.New("session close canceled")
				}
			}
			if err := closeTerminalSessionForTarget(c.Context, client, target, session.ID); err != nil {
				return friendlyCommandError(err)
			}
			if c.Bool("json") {
				return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "session_id": session.ID, "state": "closed"})
			}
			return nil
		}, Flags: []command.Flag{&command.BoolFlag{Name: "yes", Usage: "confirm close"}, &command.BoolFlag{Name: "all", Usage: "close all sessions in the environment"}, &command.BoolFlag{Name: "json", Usage: "emit JSON"}}},
		{Name: "delete", ArgsUsage: "<environment> [<session>]", Usage: "Delete a terminal session and its history", Flags: []command.Flag{&command.BoolFlag{Name: "yes", Usage: "confirm deletion"}, &command.BoolFlag{Name: "all", Usage: "delete all non-default sessions in the environment"}, &command.BoolFlag{Name: "json", Usage: "emit JSON"}}, Action: func(c *command.Context) error {
			all := c.Bool("all")
			if c.Args().Len() < 1 || c.Args().Len() > 2 || all && c.Args().Len() != 1 {
				return errors.New("usage: pb session delete <environment> <session> --yes OR pb session delete <environment> --all --yes")
			}
			client, err := backendClient(c)
			if err != nil {
				return err
			}
			target, err := resolveTerminalEnvironmentTarget(c.Context, client, c.Args().First())
			if err != nil {
				return err
			}
			if all {
				sessions, err := listTerminalSessionsForTarget(c.Context, client, target)
				if err != nil {
					return friendlyCommandError(err)
				}
				selected := slices.DeleteFunc(sessions, func(item api.TerminalSession) bool { return item.IsDefault })
				fmt.Fprintf(c.ErrWriter, "Environment: %s (%s)\n", target.name, target.id)
				fmt.Fprintf(c.ErrWriter, "Non-default sessions to delete: %d\n", len(selected))
				if !c.Bool("yes") {
					return errors.New("session deletion requires --yes")
				}
				var deleteErrors []error
				deleted := 0
				for _, session := range selected {
					if err := deleteTerminalSessionForTarget(c.Context, client, target, session.ID); err != nil {
						deleteErrors = append(deleteErrors, fmt.Errorf("delete session %s: %w", session.Name, err))
						continue
					}
					deleted++
				}
				if len(deleteErrors) > 0 {
					return fmt.Errorf("deleted %d of %d sessions in %s; remote state changed: %w", deleted, len(selected), target.name, errors.Join(deleteErrors...))
				}
				if c.Bool("json") {
					return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "deleted": deleted})
				}
				fmt.Fprintf(c.Writer, "Deleted %d sessions and their history in %s.\n", deleted, target.name)
				return nil
			}
			var session api.TerminalSession
			if c.Args().Len() == 1 {
				sessions, listErr := listTerminalSessionsForTarget(c.Context, client, target)
				if listErr != nil {
					return friendlyCommandError(listErr)
				}
				session, err = selectSession(target, slices.DeleteFunc(sessions, func(item api.TerminalSession) bool { return item.IsDefault }), "Choose a session to delete")
			} else {
				session, err = resolveTerminalSession(c.Context, client, target, c.Args().Get(1))
			}
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
				confirmed, confirmErr := confirmAction(fmt.Sprintf("Delete terminal session %q and its history?", session.Name))
				if confirmErr != nil {
					return confirmErr
				}
				if !confirmed {
					return errors.New("deletion cancelled")
				}
			}
			if err := deleteTerminalSessionForTarget(c.Context, client, target, session.ID); err != nil {
				return friendlyCommandError(err)
			}
			if c.Bool("json") {
				return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "session_id": session.ID, "deleted": true})
			}
			return nil
		}},
	}}
}

func selectTerminalSession(ctx context.Context, client *api.Client, projectRef, name, ref string) (api.TerminalSession, environmentTarget, api.UserMachine, error) {
	target, machine, err := resolveEnvironmentTargetWithMachine(ctx, client, projectRef)
	if err != nil {
		return api.TerminalSession{}, environmentTarget{}, api.UserMachine{}, err
	}
	if strings.TrimSpace(ref) == "" {
		if err := validateSessionNameOptional(name); err != nil {
			return api.TerminalSession{}, environmentTarget{}, api.UserMachine{}, err
		}
		session, err := createTerminalSessionForTarget(ctx, client, target, name, newIdempotencyKey())
		if err != nil {
			return api.TerminalSession{}, environmentTarget{}, api.UserMachine{}, friendlyCommandError(err)
		}
		if session.EvictedSession != nil {
			fmt.Fprintf(os.Stderr, "Session limit reached; removed least-recent session %q (%s).\n", session.EvictedSession.Name, session.EvictedSession.State)
		}
		return session, target, machine, nil
	}
	session, err := resolveTerminalSession(ctx, client, target, ref)
	if err != nil {
		return api.TerminalSession{}, environmentTarget{}, api.UserMachine{}, friendlyCommandError(err)
	}
	return session, target, machine, nil
}

// resolveEnvironmentTargetWithMachine resolves like resolveEnvironmentTarget but
// also returns the machine catalog entry for machine targets so callers can
// reuse it without a second listing round trip. The daemon's warm inventory
// snapshot is consulted first: a machine it already tracks needs no catalog
// listing at all, and the server revalidates the machine on every session
// create and connection descriptor anyway.
func resolveEnvironmentTargetWithMachine(ctx context.Context, client *api.Client, requested string) (environmentTarget, api.UserMachine, error) {
	if machine, ok := resolveWarmUserMachine(ctx, requested); ok && machine.InstallationGeneration > 0 {
		return environmentTarget{kind: environmentUserMachine, id: machine.ID, name: machine.DisplayName}, machine, nil
	}
	project, err := resolveProjectID(ctx, client, requested)
	if err == nil {
		return environmentTarget{kind: environmentProject, id: project.ID, name: project.Name}, api.UserMachine{}, nil
	}
	// Accounts without hosted projects receive a 404 from the project API. That
	// is still a valid machine-targeting path, so preserve the machine fallback.
	if !errors.Is(err, resolver.ErrProjectNotFound) && !api.IsNotFound(err) && !api.IsHostedEntitlementRequired(err) {
		return environmentTarget{}, api.UserMachine{}, err
	}
	machine, machineErr := resolveUserMachine(ctx, client, requested)
	if machineErr != nil {
		if api.IsNotFound(machineErr) {
			return environmentTarget{}, api.UserMachine{}, err
		}
		return environmentTarget{}, api.UserMachine{}, machineErr
	}
	return environmentTarget{kind: environmentUserMachine, id: machine.ID, name: machine.DisplayName}, machine, nil
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
		return api.UserMachine{}, fmt.Errorf("%w: %q matches machine IDs %s; use an exact ID", resolver.ErrProjectAmbiguous, requested, strings.Join(ids, ", "))
	}
	return api.UserMachine{}, fmt.Errorf("%w: %q", resolver.ErrProjectNotFound, requested)
}

// resolveWarmUserMachine uses the daemon's authenticated inventory snapshot
// for selection. Operation descriptors remain fetched from the control plane;
// this only removes a redundant catalog round trip on an already-warm client.
func resolveWarmUserMachine(ctx context.Context, requested string) (api.UserMachine, bool) {
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		return api.UserMachine{}, false
	}
	client, err := localapi.NewClient(paths.SocketPath, 300*time.Millisecond)
	if err != nil {
		return api.UserMachine{}, false
	}
	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return api.UserMachine{}, false
	}
	status, err := localwait.ResolveMachine(snapshot.Machines, requested)
	if err != nil || !status.Eligible || status.Generation == 0 {
		return api.UserMachine{}, false
	}
	return api.UserMachine{ID: status.ID, EnvironmentID: status.EnvironmentID, WorkspaceRoot: status.WorkspaceRoot, Alias: status.Alias, DisplayName: status.Alias, Platform: status.Platform, State: "ready", Online: status.RuntimeState == "ready", InstallationGeneration: int64(status.Generation)}, true
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
	message += "; create one with `pb <environment> new`"
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

func actionExecCobra(cobraCommand *cobra.Command, args []string, shorthand bool) error {
	dash := cobraCommand.ArgsLenAtDash()
	if dash < 0 || dash >= len(args) || dash != 1 || len(args[dash:]) == 0 {
		return invocationError(errors.New("remote execution requires <machine> -- <argv...>"))
	}
	request := tunnel.ExecRequest{Argv: append([]string(nil), args[dash:]...)}
	jsonOutput := false
	if !shorthand {
		request.CWD, _ = cobraCommand.Flags().GetString("cwd")
		request.Timeout, _ = cobraCommand.Flags().GetDuration("timeout")
		request.PTY, _ = cobraCommand.Flags().GetBool("pty")
		jsonOutput, _ = cobraCommand.Flags().GetBool("json")
		values, _ := cobraCommand.Flags().GetStringArray("env")
		var err error
		request.Environment, err = parseExecEnvironment(values)
		if err != nil {
			return invocationError(err)
		}
	}
	return actionRemoteExec(actionContext(cobraCommand, args), args[0], request, jsonOutput)
}

func actionSSH(command *cobra.Command, args []string) error {
	dash := command.ArgsLenAtDash()
	if len(args) == 0 || dash > 1 || dash < 0 && len(args) != 1 {
		return invocationError(errors.New("SSH requires [user@]<machine> [-- <OpenSSH arguments...>]"))
	}
	targetName, targetUser, err := managedssh.ParseMachineTarget(args[0])
	if err != nil {
		return invocationError(err)
	}
	flagUser, _ := command.Flags().GetString("user")
	requestedUser, err := resolveSSHRequestedUser(targetUser, flagUser)
	if err != nil {
		return invocationError(err)
	}
	ctx := actionContext(command, args)
	client, machine, target, err := resolveSSHCommandTargetFast(ctx, targetName)
	if err != nil {
		return friendlyCommandError(err)
	}
	_ = client
	destination, err := managedssh.ResolveDestination(managedssh.DestinationInput{Alias: machine.Alias, AliasSuffix: managedssh.AliasSuffix, RegisteredPort: target.Port, RequestedUser: requestedUser, RegisteredUser: target.OSUser, HasRegisteredUser: true, Platform: machine.Platform})
	if err != nil {
		return err
	}
	arguments := openSSHArguments(destination, args[1:], dash == 1)
	environment := os.Environ()
	if transport, _ := command.Flags().GetString("transport"); transport != "" {
		environment = append(environment, "PAPERBOAT_TRANSPORT="+transport)
	}
	return (managedssh.OpenSSHExecutor{}).Execute("ssh", arguments, environment)
}

func resolveSSHRequestedUser(targetUser, flagUser string) (string, error) {
	if flagUser != "" {
		if err := managedssh.ValidateUsername(flagUser); err != nil {
			return "", err
		}
	}
	if flagUser != "" && targetUser != "" && flagUser != targetUser {
		return "", managedssh.ErrSSHUsernameConflict
	}
	if flagUser != "" {
		return flagUser, nil
	}
	return targetUser, nil
}

func openSSHArguments(destination managedssh.Destination, passthrough []string, includePassthrough bool) []string {
	arguments := []string{
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
	}
	if destination.Port != 22 {
		arguments = append(arguments, "-p", strconv.Itoa(int(destination.Port)))
	}
	arguments = append(arguments, destination.User+"@"+destination.Host)
	if includePassthrough {
		arguments = append(arguments, passthrough...)
	}
	return arguments
}

func actionSSHProxy(command *cobra.Command, _ []string) error {
	if err := processlifetime.ArmParentDeath(); err != nil {
		return err
	}
	if transport := strings.TrimSpace(os.Getenv("PAPERBOAT_TRANSPORT")); transport != "" {
		if _, err := tunnel.ParseTerminalTransport(transport); err != nil {
			return invocationError(err)
		}
		_ = command.Flags().Set("transport", transport)
	}
	host, _ := command.Flags().GetString("host")
	portText, _ := command.Flags().GetString("port")
	proxyUser, _ := command.Flags().GetString("user")
	if err := managedssh.ValidateUsername(proxyUser); err != nil {
		return err
	}
	alias, err := managedssh.ParseAliasHost(host, managedssh.AliasSuffix)
	if err != nil {
		return err
	}
	ctx := actionContext(command, nil)
	_, machine, target, err := resolveSSHCommandTargetLive(ctx, alias)
	if err != nil {
		return friendlyCommandError(err)
	}
	if _, err := managedssh.ResolveDestination(managedssh.DestinationInput{Alias: machine.Alias, AliasSuffix: managedssh.AliasSuffix, RegisteredPort: target.Port, RequestedUser: proxyUser, RegisteredUser: target.OSUser, HasRegisteredUser: true, Platform: machine.Platform}); err != nil {
		return err
	}
	if _, err := managedssh.ValidateDestinationPort(portText, target.Port); err != nil {
		return err
	}
	d, err := buildDeps(ctx)
	if err != nil {
		return err
	}
	if d.peerApplications == nil {
		return errors.New("Paperboat peer transport is unavailable")
	}
	operationID := newSSHOperationID()
	descriptor := pendingSSHDescriptor(machine, operationID)
	connection, err := d.peerApplications.DialSSH(command.Context(), sshConnectInfo(machine, descriptor), operationID)
	if err != nil {
		return err
	}
	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		_ = connection.Close()
		return tunnel.ErrInputEOFUnsupported
	}
	defer connection.Close()
	go func() {
		<-command.Context().Done()
		_ = connection.Close()
	}()
	err = copySSHProxy(connection, halfCloser, command.InOrStdin(), command.OutOrStdout())
	diagnosticlog.TryInfo("managed SSH local proxy closed", "error", err)
	return err
}

func copySSHProxy(connection io.ReadWriteCloser, halfCloser interface{ CloseWrite() error }, input io.Reader, output io.Writer) error {
	type inputResult struct {
		copyErr       error
		closeWriteErr error
	}
	inputDone := make(chan inputResult, 1)
	go func() {
		_, copyErr := io.Copy(connection, input)
		inputDone <- inputResult{copyErr: copyErr, closeWriteErr: halfCloser.CloseWrite()}
	}()
	_, outputErr := io.Copy(output, connection)
	if outputErr != nil && !errors.Is(outputErr, io.EOF) {
		return outputErr
	}
	// Remote EOF terminates ProxyCommand even when OpenSSH deliberately keeps
	// its input pipe open until the proxy exits. Input EOF still half-closes the
	// stream above and permits all remaining remote output to drain first.
	select {
	case result := <-inputDone:
		// The authenticated remote EOF is authoritative. A concurrent local
		// half-close can observe any platform-specific socket shutdown error after
		// that EOF; this is normal full-duplex shutdown, not a failed SSH
		// transport. Input-copy failures remain authoritative because bytes may
		// have been lost before the remote EOF.
		if result.copyErr != nil {
			return result.copyErr
		}
		return nil
	case <-time.After(25 * time.Millisecond):
		// Keep remote EOF bounded when OpenSSH intentionally leaves stdin open,
		// while giving an already-failed input copy a deterministic chance to
		// publish its authoritative transport error.
		return nil
	}
}

func actionSSHKnownHosts(command *cobra.Command, _ []string) error {
	host, _ := command.Flags().GetString("host")
	portText, _ := command.Flags().GetString("port")
	alias, err := managedssh.ParseAliasHost(host, managedssh.AliasSuffix)
	if err != nil {
		return err
	}
	client, machine, target, err := resolveSSHCommandTargetFast(actionContext(command, nil), alias)
	if err != nil {
		return friendlyCommandError(err)
	}
	if _, err := managedssh.ValidateDestinationPort(portText, target.Port); err != nil {
		return err
	}
	set, err := client.ManagedSSHHostKeys(command.Context(), machine.ID, uint64(machine.InstallationGeneration))
	if err != nil {
		return friendlyCommandError(err)
	}
	keys, err := managedssh.ParseHostPublicKeys(set.Keys)
	if err != nil {
		return err
	}
	knownHosts, err := managedssh.FormatKnownHosts(host, target.Port, keys)
	if err != nil {
		return err
	}
	_, err = command.OutOrStdout().Write(knownHosts)
	return err
}

func actionSSHTrustHost(command *cobra.Command, args []string) error {
	client, machine, _, err := resolveSSHCommandTarget(actionContext(command, args), args[0])
	if err != nil {
		return friendlyCommandError(err)
	}
	generation := uint64(machine.InstallationGeneration)
	active, err := client.ManagedSSHHostKeys(command.Context(), machine.ID, generation)
	if err != nil {
		return friendlyCommandError(err)
	}
	pending, err := client.ManagedSSHPendingHostKeys(command.Context(), machine.ID, generation)
	if err != nil {
		return friendlyCommandError(err)
	}
	fingerprint, _ := command.Flags().GetString("fingerprint")
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint != "" && fingerprint != pending.Fingerprint {
		return errors.New("pending SSH host fingerprint does not match --fingerprint")
	}
	if fingerprint == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("interactive confirmation is required; pass the exact --fingerprint")
		}
		fmt.Fprintf(command.ErrOrStderr(), "Current SSH host: %s\nPending SSH host: %s\nTrust the pending host identity? [y/N] ", active.Fingerprint, pending.Fingerprint)
		answer, readErr := bufio.NewReader(command.InOrStdin()).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			return errors.New("SSH host trust was not changed")
		}
		fingerprint = pending.Fingerprint
	}
	_, err = client.PromoteManagedSSHHostKeys(command.Context(), machine.ID, pending.SetID, fingerprint, "managed-ssh-promote-"+strings.TrimPrefix(newIdempotencyKey(), "pb-"), generation)
	if err != nil {
		return friendlyCommandError(err)
	}
	fmt.Fprintf(command.OutOrStdout(), "Trusted SSH host identity for %s (%s)\n", machine.DisplayName, fingerprint)
	return nil
}

func actionSSHDoctor(command *cobra.Command, args []string) error {
	capabilities, err := managedssh.ProbeOpenSSH(command.Context(), "ssh", 5*time.Second)
	if err != nil || !capabilities.Ready() {
		return errors.Join(managedssh.ErrOpenSSHUnavailable, err)
	}
	client, machine, target, err := resolveSSHCommandTarget(actionContext(command, args), args[0])
	if err != nil {
		return friendlyCommandError(err)
	}
	keys, err := client.ManagedSSHHostKeys(command.Context(), machine.ID, uint64(machine.InstallationGeneration))
	if err != nil {
		return friendlyCommandError(err)
	}
	cfg, store, err := requireAuthConfig(actionContext(command, args))
	if err != nil {
		return err
	}
	profile, err := store.Load(cfg.ServerURL)
	if err != nil {
		return err
	}
	identity, err := store.ManagedSSHIdentity(cfg.ServerURL, profile.CLIClientSessionID)
	if err != nil {
		return err
	}
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	agentSocket := filepath.Join(paths.RuntimeRoot, "paperboat-ssh-agent.sock")
	if err := managedssh.ValidateInstalledOpenSSHConfig(home, uint32(os.Geteuid()), managedssh.AliasSuffix, agentSocket); err != nil {
		return fmt.Errorf("managed OpenSSH configuration is not ready; rerun `pb auth login`: %w", err)
	}
	if err := managedssh.ValidateManagedIdentityPublicKey(home, uint32(os.Geteuid()), identity.PublicKey); err != nil {
		return fmt.Errorf("managed SSH public identity is not ready; rerun `pb auth login`: %w", err)
	}
	if err := managedssh.ProbeAgentIdentity(command.Context(), agentSocket, identity.Fingerprint, 5*time.Second); err != nil {
		return fmt.Errorf("managed SSH agent is not ready; rerun `pb auth login`: %w", err)
	}
	d, err := buildDeps(actionContext(command, args))
	if err != nil {
		return err
	}
	if d.peerApplications == nil {
		return errors.New("Paperboat peer transport is unavailable")
	}
	operationID := newSSHOperationID()
	descriptor := pendingSSHDescriptor(machine, operationID)
	probeCtx, cancel := context.WithTimeout(command.Context(), 20*time.Second)
	defer cancel()
	connection, err := d.peerApplications.DialSSH(probeCtx, sshConnectInfo(machine, descriptor), operationID)
	if err != nil {
		return fmt.Errorf("managed SSH transport or loopback target is not ready: %w", err)
	}
	host, err := managedssh.AliasHost(machine.Alias, managedssh.AliasSuffix)
	if err != nil {
		_ = connection.Close()
		return err
	}
	authErr := managedssh.ProbeSSHAuthentication(probeCtx, connection, net.JoinHostPort(host, strconv.Itoa(int(target.Port))), target.OSUser, identity.Signer, keys.Keys)
	closeErr := connection.Close()
	if authErr != nil {
		return fmt.Errorf("managed SSH host verification or key reconciliation is not ready: %w", authErr)
	}
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return fmt.Errorf("close managed SSH readiness probe: %w", closeErr)
	}
	fmt.Fprintf(command.OutOrStdout(), "OpenSSH: %s\nLocal configuration: ready\nManaged agent: ready\nMachine: %s (%s)\nTransport: ready\nTarget: ready on port %d\nHost identity: %s\nManaged keys: reconciled\n", capabilities.Version, machine.DisplayName, machine.Alias, target.Port, keys.Fingerprint)
	return nil
}

func resolveSSHCommandTarget(ctx *command.Context, requested string) (*api.Client, api.UserMachine, api.ManagedSSHTarget, error) {
	d, err := buildDeps(ctx)
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	if d.cfg.ServerURL == "" {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, errors.New("Paperboat server is required for SSH")
	}
	client, err := sshAPIClient(d)
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	machine, err := resolveSSHMachine(ctx.Context, client, requested)
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	if machine.InstallationGeneration < 1 {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, errors.New("machine has no active runtime generation")
	}
	target, err := client.ManagedSSHTarget(ctx.Context, machine.ID, uint64(machine.InstallationGeneration))
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	_ = sshTargetCacheStore(d.cfg, machine, target, time.Now())
	return client, machine, target, nil
}

// resolveSSHCommandTargetFast resolves the machine from the daemon's warm
// inventory snapshot and the SSH target from a short-lived local cache when
// fresh, avoiding catalog listing round trips on the interactive SSH path.
// Any unavailable shortcut falls back to the canonical live resolution so
// error behavior is unchanged.
func resolveSSHCommandTargetFast(ctx *command.Context, requested string) (*api.Client, api.UserMachine, api.ManagedSSHTarget, error) {
	d, err := buildDeps(ctx)
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	if d.cfg.ServerURL == "" {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, errors.New("Paperboat server is required for SSH")
	}
	machine, ok := resolveWarmUserMachine(ctx.Context, requested)
	if !ok || machine.InstallationGeneration < 1 {
		return resolveSSHCommandTarget(ctx, requested)
	}
	client, err := sshAPIClient(d)
	if err != nil {
		return resolveSSHCommandTarget(ctx, requested)
	}
	if target, fresh := sshTargetCacheLookup(d.cfg, machine, time.Now()); fresh {
		return client, machine, target, nil
	}
	target, err := client.ManagedSSHTarget(ctx.Context, machine.ID, uint64(machine.InstallationGeneration))
	if err != nil {
		return resolveSSHCommandTarget(ctx, requested)
	}
	_ = sshTargetCacheStore(d.cfg, machine, target, time.Now())
	return client, machine, target, nil
}

// resolveSSHCommandTargetLive skips the machine catalog listing through the
// daemon's warm snapshot but always validates the SSH target against fresh
// server data. The managed SSH proxy uses this so destination port validation
// can never trust a stale local cache.
func resolveSSHCommandTargetLive(ctx *command.Context, requested string) (*api.Client, api.UserMachine, api.ManagedSSHTarget, error) {
	d, err := buildDeps(ctx)
	if err != nil {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, err
	}
	if d.cfg.ServerURL == "" {
		return nil, api.UserMachine{}, api.ManagedSSHTarget{}, errors.New("Paperboat server is required for SSH")
	}
	machine, ok := resolveWarmUserMachine(ctx.Context, requested)
	if !ok || machine.InstallationGeneration < 1 {
		return resolveSSHCommandTarget(ctx, requested)
	}
	client, err := sshAPIClient(d)
	if err != nil {
		return resolveSSHCommandTarget(ctx, requested)
	}
	target, err := client.ManagedSSHTarget(ctx.Context, machine.ID, uint64(machine.InstallationGeneration))
	if err != nil {
		return resolveSSHCommandTarget(ctx, requested)
	}
	_ = sshTargetCacheStore(d.cfg, machine, target, time.Now())
	return client, machine, target, nil
}

func sshAPIClient(d *deps) (*api.Client, error) {
	credential, err := d.auth.Credential()
	if err != nil {
		return nil, err
	}
	client := api.New(d.cfg.ServerURL, credential, nil)
	sourceMachineID, err := configuredMachineID()
	if err != nil {
		return nil, err
	}
	client.SetSourceMachineID(sourceMachineID)
	return client, nil
}

func resolveSSHMachine(ctx context.Context, client *api.Client, requested string) (api.UserMachine, error) {
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return api.UserMachine{}, err
	}
	for _, machine := range machines {
		if machine.ID == requested || strings.EqualFold(machine.Alias, requested) {
			return machine, nil
		}
	}
	return resolveUserMachine(ctx, client, requested)
}

func newSSHOperationID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("operation_ssh_%d", time.Now().UnixNano())
	}
	return "operation_ssh_" + hex.EncodeToString(value)
}

func sshConnectInfo(machine api.UserMachine, descriptor api.SSHDescriptor) resolver.ConnectInfo {
	return resolver.ConnectInfo{
		TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, ProjectState: machine.State,
		MachineGeneration: uint64(machine.InstallationGeneration), TunnelTarget: descriptor.Endpoints.WSS,
		Terminal: &resolver.TerminalTarget{Protocol: "paperboat.ssh.v1", EnvironmentID: descriptor.Environment.ID, QUICEndpoint: descriptor.Endpoints.QUIC, WSSEndpoint: descriptor.Endpoints.WSS, Auth: resolver.AuthTarget{Method: descriptor.Auth.Method, Token: descriptor.Auth.Token, ExpiresAt: descriptor.Auth.ExpiresAt.Format(time.RFC3339Nano), Scopes: descriptor.Auth.Scopes}, CWD: descriptor.Environment.Root},
	}
}

func pendingSSHDescriptor(machine api.UserMachine, operationID string) api.SSHDescriptor {
	return api.SSHDescriptor{OperationID: operationID, ExpiresAt: time.Now().Add(2 * time.Minute), Auth: api.AuthMaterial{ExpiresAt: time.Now().Add(2 * time.Minute)}, Environment: &api.Environment{ID: machine.EnvironmentID, Kind: "byod", ResourceID: machine.ID, Root: machine.WorkspaceRoot}}
}

func parseExecEnvironment(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(values))
	namePattern := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for _, value := range values {
		name, item, ok := strings.Cut(value, "=")
		if !ok || !namePattern.MatchString(name) || strings.ContainsRune(item, '\x00') {
			return nil, fmt.Errorf("invalid --env %q; expected name=value", value)
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate --env name %q", name)
		}
		result[name] = item
	}
	return result, nil
}

func actionRemoteExec(c *command.Context, requested string, request tunnel.ExecRequest, jsonOutput bool) error {
	if len(request.Argv) == 0 || request.Timeout < 0 || request.Timeout > 24*time.Hour {
		return invocationError(errors.New("exec timeout must be between zero and 24h and argv must not be empty"))
	}
	request.OperationID = newExecOperationID()
	transport := c.String("transport")
	if transport == "" {
		transport = "a"
	}
	if _, err := tunnel.ParseTerminalTransport(transport); err != nil {
		return invocationError(err)
	}
	fail := func(code int, errorCode string, changed, uncertain bool, err error) error {
		if !jsonOutput {
			return err
		}
		if encodeErr := writeExecJSONFailure(c.Writer, request.OperationID, errorCode, safeExecError(err), changed, uncertain); encodeErr != nil {
			return encodeErr
		}
		return exitCodeError{code: code}
	}
	d, err := buildDeps(c)
	if err != nil {
		return fail(255, "local_configuration", false, false, err)
	}
	if d.peerApplications == nil || d.cfg.ServerURL == "" {
		err = errors.New("Paperboat server and peer transport are required for remote execution")
		return fail(255, "local_configuration", false, false, err)
	}
	credential, err := d.auth.Credential()
	if errors.Is(err, config.ErrNoCredentials) {
		err = errors.New("not signed in to Paperboat; run `pb login`, then retry")
		return fail(255, "authentication_required", false, false, err)
	}
	if err != nil {
		return fail(255, "authentication_unavailable", false, false, err)
	}
	client := api.New(d.cfg.ServerURL, credential, nil)
	sourceMachineID, err := configuredMachineID()
	if err != nil {
		return fail(255, "source_identity_unavailable", false, false, err)
	}
	client.SetSourceMachineID(sourceMachineID)
	machine, warm := resolveWarmUserMachine(c.Context, requested)
	if !warm {
		machine, err = resolveUserMachine(c.Context, client, requested)
	}
	if err != nil {
		err = friendlyCommandError(err)
		return fail(255, "machine_resolution_failed", false, false, err)
	}
	if machine.InstallationGeneration < 1 {
		err = errors.New("machine has no active runtime generation")
		return fail(255, "runtime_unavailable", false, false, err)
	}
	// The daemon owns operation-descriptor issuance. This placeholder carries
	// only inventory authority and is replaced with fresh endpoints/credentials
	// inside the authenticated local API broker.
	descriptor := api.ExecDescriptor{OperationID: request.OperationID, ExpiresAt: time.Now().Add(2 * time.Minute), Auth: api.AuthMaterial{ExpiresAt: time.Now().Add(2 * time.Minute)}, Environment: &api.Environment{ID: machine.EnvironmentID, Kind: "byod", ResourceID: machine.ID, Root: machine.WorkspaceRoot}}
	if request.CWD == "" {
		request.CWD = machine.WorkspaceRoot
	}
	if !remoteAbsolutePath(machine.Platform, machine.WorkspaceRoot, request.CWD) {
		err = invocationError(errors.New("--cwd must be an absolute path"))
		return fail(2, "invalid_request", false, false, err)
	}
	if request.PTY {
		request.Columns, request.Rows = localTerminalSize()
		if request.Columns == 0 || request.Rows == 0 {
			request.Columns, request.Rows = 80, 24
		}
	}
	dial := func(current api.ExecDescriptor) (tunnel.ExecConn, error) {
		// Keep caller cancellation attached while dialing, then detach the
		// established carrier so actionRemoteExec can complete the remote cancel
		// RPC before transport teardown.
		dialCtx, cancelDial := context.WithCancel(context.WithoutCancel(c.Context))
		stopCallerCancel := context.AfterFunc(c.Context, cancelDial)
		connection, dialErr := d.peerApplications.DialExec(dialCtx, execConnectInfo(machine, current, transport), request)
		if dialErr != nil {
			stopCallerCancel()
			cancelDial()
			return nil, dialErr
		}
		if !stopCallerCancel() || c.Context.Err() != nil {
			cancelDial()
			_ = connection.Close()
			return nil, c.Context.Err()
		}
		return connection, nil
	}
	connection, err := dial(descriptor)
	initialUncertain := false
	for attempt := 1; err != nil && attempt < 3; attempt++ {
		var uncertain *tunnel.ExecStartUncertainError
		if !errors.As(err, &uncertain) && !errors.Is(err, localapi.ErrExecStartUncertain) {
			break
		}
		initialUncertain = true
		if waitErr := waitExecRetry(c.Context, attempt); waitErr != nil {
			err = waitErr
			break
		}
		connection, err = dial(descriptor)
	}
	if err != nil {
		var uncertain *tunnel.ExecStartUncertainError
		if initialUncertain || errors.As(err, &uncertain) || errors.Is(err, localapi.ErrExecStartUncertain) {
			return fail(255, "exec_start_uncertain", true, true, err)
		}
		return fail(255, "transport_unavailable", false, false, err)
	}
	connectionRef := newExecConnectionRef(connection)
	defer func() {
		if active := connectionRef.Current(); active != nil {
			_ = active.Close()
		}
	}()
	execDone := make(chan struct{})
	defer close(execDone)
	processSignals := make(chan os.Signal, 1)
	var cancelRequested atomic.Bool
	cancelResult := make(chan error, 1)
	cancelRemote := func() error {
		// Cancellation uses a separate carrier so it cannot queue behind a
		// blocked output stream. Starting with the same operation ID is an
		// idempotent attachment, never a second process start.
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		for attempt := 0; attempt < 2; attempt++ {
			retryDescriptor, descriptorErr := client.MachineExecDescriptor(ctx, machine.ID, request.OperationID)
			if descriptorErr != nil {
				return descriptorErr
			}
			replacement, dialErr := d.peerApplications.DialExec(ctx, execConnectInfo(machine, retryDescriptor, transport), request)
			if dialErr != nil {
				continue
			}
			cancelErr := replacement.Cancel()
			_ = replacement.Detach()
			if cancelErr == nil {
				return nil
			}
		}
		return errors.New("remote execution cancellation outcome is uncertain")
	}
	requestCancel := func(active tunnel.ExecConn) {
		if active != nil {
			if err := active.Cancel(); err == nil {
				cancelResult <- nil
				return
			}
		}
		cancelResult <- cancelRemote()
	}
	// SIGINT is an explicit remote execution cancellation. SIGHUP remains an
	// explicit remote process signal; SIGTERM still arrives through c.Context.
	signal.Notify(processSignals, syscall.SIGHUP)
	signal.Notify(processSignals, os.Interrupt)
	defer signal.Stop(processSignals)
	go func() {
		for {
			select {
			case received := <-processSignals:
				if received == os.Interrupt {
					if cancelRequested.CompareAndSwap(false, true) {
						go requestCancel(connectionRef.Current())
					}
				} else {
					if active := connectionRef.Current(); active != nil {
						_ = active.Signal(received.String())
					}
				}
			case <-c.Context.Done():
				// A canceled CLI context closes the owning transport. Give the
				// remote runtime a bounded cancellation handshake first so its
				// process group is reaped and the result is certain.
				if cancelRequested.CompareAndSwap(false, true) {
					go requestCancel(connectionRef.Current())
				}
				return
			case <-execDone:
				return
			}
		}
	}()
	if request.PTY && term.IsTerminal(int(os.Stdin.Fd())) {
		state, rawErr := term.MakeRaw(int(os.Stdin.Fd()))
		if rawErr != nil {
			return rawErr
		}
		defer term.Restore(int(os.Stdin.Fd()), state)
		resizeSignals := make(chan os.Signal, 1)
		notifyResizeSignals(resizeSignals)
		defer signal.Stop(resizeSignals)
		go func() {
			for {
				select {
				case <-resizeSignals:
					cols, rows := localTerminalSize()
					if cols > 0 && rows > 0 {
						if active := connectionRef.Current(); active != nil {
							_ = active.Resize(rows, cols)
						}
					}
				case <-c.Context.Done():
					return
				case <-execDone:
					return
				}
			}
		}()
	}
	go forwardExecInput(c.Context, os.Stdin, connectionRef)
	encoder := json.NewEncoder(c.Writer)
	sawTerminalEvent := false
	emittedStarted := false
	lastEventSequence := uint64(0)
	reattachments := 0
	var code int
	contextDone := c.Context.Done()
	var cancelDeadline <-chan time.Time
	var cancelTimer *time.Timer
	defer func() {
		if cancelTimer != nil {
			cancelTimer.Stop()
		}
	}()
	for {
		events := connection.Events()
		streamEnded := false
		for !streamEnded {
			select {
			case event, ok := <-events:
				if !ok {
					streamEnded = true
					continue
				}
				if event.EventSequence > lastEventSequence {
					lastEventSequence = event.EventSequence
				}
				if event.State == "started" {
					if emittedStarted {
						continue
					}
					emittedStarted = true
				}
				terminalEvent := event.Stream == "" && event.State != "" && event.State != "started"
				if terminalEvent {
					sawTerminalEvent = true
				}
				if err := writeExecEvent(c, encoder, event, request.PTY, jsonOutput); err != nil {
					return err
				}
				if terminalEvent {
					streamEnded = true
				}
			case cancelErr := <-cancelResult:
				if cancelErr == nil {
					err = &tunnel.RemoteExecError{Code: "exec_canceled"}
				} else {
					err = fmt.Errorf("remote execution cancellation failed: %w", cancelErr)
				}
				_ = connection.Detach()
				streamEnded = true
			case <-contextDone:
				contextDone = nil
				if cancelRequested.CompareAndSwap(false, true) {
					go requestCancel(connectionRef.Current())
				}
				if cancelDeadline == nil {
					cancelTimer = time.NewTimer(30 * time.Second)
					cancelDeadline = cancelTimer.C
				}
			case <-cancelDeadline:
				err = errors.New("remote execution cancellation outcome is uncertain")
				_ = connection.Detach()
				streamEnded = true
			}
		}
		if err == nil {
			code, err = connection.Wait()
		}
		if cancelRequested.Load() || c.Context.Err() != nil {
			break
		}
		if err == nil || !errors.Is(err, tunnel.ErrTransportLost) || sawTerminalEvent || reattachments >= 2 || c.Context.Err() != nil {
			break
		}
		connectionRef.Clear(connection)
		_ = connection.Detach()
		request.FromSequence = lastEventSequence + 1
		if request.FromSequence == 0 {
			request.FromSequence = 1
		}
		var replacement tunnel.ExecConn
		for reattachments < 2 {
			reattachments++
			if waitErr := waitExecRetry(c.Context, reattachments); waitErr != nil {
				err = waitErr
				break
			}
			descriptor, err = client.MachineExecDescriptor(c.Context, machine.ID, request.OperationID)
			if err != nil {
				break
			}
			replacement, err = dial(descriptor)
			if err == nil {
				break
			}
			var uncertain *tunnel.ExecStartUncertainError
			if !errors.As(err, &uncertain) && !errors.Is(err, localapi.ErrExecStartUncertain) {
				break
			}
		}
		if err != nil || replacement == nil {
			break
		}
		connection = replacement
		if setErr := connectionRef.Set(connection); setErr != nil {
			err = setErr
			break
		}
	}
	var canceledExec *tunnel.RemoteExecError
	cancelConfirmed := errors.As(err, &canceledExec) && canceledExec.Code == "exec_canceled"
	if (cancelRequested.Load() || c.Context.Err() != nil) && err != nil && !cancelConfirmed {
		if !cancelRequested.Load() {
			cancelRequested.Store(true)
			go requestCancel(connectionRef.Current())
		}
		select {
		case cancelErr := <-cancelResult:
			if cancelErr == nil {
				err = &tunnel.RemoteExecError{Code: "exec_canceled"}
			}
		case <-time.After(15 * time.Second):
		}
	}
	return finishExecResult(c.Writer, c.ErrWriter, request.OperationID, jsonOutput, sawTerminalEvent, code, err)
}

func remoteAbsolutePath(platform, workspaceRoot, path string) bool {
	windowsTarget := strings.EqualFold(strings.TrimSpace(platform), "windows") || strings.TrimSpace(platform) == "" && windowsAbsolutePath(workspaceRoot)
	if !windowsTarget {
		return filepath.IsAbs(path)
	}
	return windowsAbsolutePath(path)
}

func windowsAbsolutePath(path string) bool {
	if strings.ContainsAny(path, "\x00\r\n") || path == "" || strings.TrimSpace(path) != path {
		return false
	}
	path = strings.ReplaceAll(path, "/", `\`)
	if len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '\\' {
		return true
	}
	if strings.HasPrefix(path, `\\`) {
		parts := strings.Split(path[2:], `\`)
		return len(parts) >= 2 && parts[0] != "" && parts[1] != ""
	}
	return false
}

func finishExecResult(stdout, stderr io.Writer, operationID string, jsonOutput, sawTerminalEvent bool, code int, err error) error {
	if err == nil && !sawTerminalEvent {
		err = tunnel.ErrTransportLost
	}
	if err == nil {
		if code != 0 {
			return exitCodeError{code: code}
		}
		return nil
	}
	var remote *tunnel.RemoteExecError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "exec_timeout":
			return exitCodeError{code: 124}
		case "exec_canceled":
			return exitCodeError{code: 130}
		default:
			if !jsonOutput {
				fmt.Fprintf(stderr, "pb: remote execution failed: %s\n", remote.Code)
			}
			return exitCodeError{code: 125}
		}
	}
	if jsonOutput {
		if !sawTerminalEvent {
			if encodeErr := writeExecJSONFailure(stdout, operationID, "transport_lost", safeExecError(err), true, true); encodeErr != nil {
				return encodeErr
			}
		}
		return exitCodeError{code: 255}
	}
	fmt.Fprintf(stderr, "pb: remote execution transport failed: %v\n", err)
	return exitCodeError{code: 255}
}

func writeExecJSONFailure(writer io.Writer, operationID, errorCode, detail string, changed, uncertain bool) error {
	return json.NewEncoder(writer).Encode(struct {
		Version     string `json:"version"`
		Event       string `json:"event"`
		OperationID string `json:"operation_id"`
		ErrorCode   string `json:"error_code"`
		Detail      string `json:"detail,omitempty"`
		Changed     bool   `json:"changed"`
		Uncertain   bool   `json:"uncertain,omitempty"`
	}{Version: "paperboat.exec-event/v1", Event: "failed", OperationID: operationID, ErrorCode: errorCode, Detail: detail, Changed: changed, Uncertain: uncertain})
}

func safeExecError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.FieldsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f }), "; ")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func execConnectInfo(machine api.UserMachine, descriptor api.ExecDescriptor, transport string) resolver.ConnectInfo {
	return resolver.ConnectInfo{
		TargetKind: "machine", ProjectID: machine.ID, Project: machine.DisplayName, ProjectState: machine.State,
		MachineGeneration: uint64(machine.InstallationGeneration), Transport: transport, TunnelTarget: descriptor.Endpoints.WSS,
		Terminal: &resolver.TerminalTarget{Protocol: "paperboat.exec.v1", EnvironmentID: descriptor.Environment.ID, QUICEndpoint: descriptor.Endpoints.QUIC, WSSEndpoint: descriptor.Endpoints.WSS, Auth: resolver.AuthTarget{Method: descriptor.Auth.Method, Token: descriptor.Auth.Token, ExpiresAt: descriptor.Auth.ExpiresAt.Format(time.RFC3339Nano), Scopes: descriptor.Auth.Scopes}, CWD: descriptor.Environment.Root},
	}
}

func waitExecRetry(ctx context.Context, attempt int) error {
	delay := time.Duration(attempt) * 100 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeExecEvent(c *command.Context, encoder *json.Encoder, event tunnel.ExecEvent, pty, jsonOutput bool) error {
	if jsonOutput {
		wire := struct {
			Version     string             `json:"version"`
			Event       string             `json:"event"`
			OperationID string             `json:"operation_id"`
			Stream      string             `json:"stream,omitempty"`
			Sequence    *uint64            `json:"sequence,omitempty"`
			Data        []byte             `json:"data,omitempty"`
			State       string             `json:"state,omitempty"`
			Result      *tunnel.ExecResult `json:"result,omitempty"`
			ErrorCode   string             `json:"error_code,omitempty"`
			Changed     *bool              `json:"changed,omitempty"`
			Uncertain   bool               `json:"uncertain,omitempty"`
		}{Version: "paperboat.exec-event/v1", Event: execEventName(event), OperationID: event.OperationID, Stream: event.Stream, Sequence: execEventSequence(event), Data: event.Data, State: event.State, Result: event.Result, ErrorCode: event.ErrorCode, Changed: execEventChanged(event)}
		return encoder.Encode(wire)
	}
	if len(event.Data) == 0 {
		return nil
	}
	writer := c.Writer
	if event.Stream == "stderr" && !pty {
		writer = c.ErrWriter
	}
	_, err := writer.Write(event.Data)
	return err
}

type execConnectionRef struct {
	mu      sync.Mutex
	conn    tunnel.ExecConn
	changed chan struct{}
	eof     bool
}

func newExecConnectionRef(connection tunnel.ExecConn) *execConnectionRef {
	return &execConnectionRef{conn: connection, changed: make(chan struct{})}
}

func (r *execConnectionRef) Current() tunnel.ExecConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conn
}

func (r *execConnectionRef) Set(connection tunnel.ExecConn) error {
	r.mu.Lock()
	r.conn = connection
	eof := r.eof
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
	if eof {
		return connection.CloseWrite()
	}
	return nil
}

func (r *execConnectionRef) Clear(connection tunnel.ExecConn) {
	r.mu.Lock()
	if r.conn == connection {
		r.conn = nil
		close(r.changed)
		r.changed = make(chan struct{})
	}
	r.mu.Unlock()
}

func (r *execConnectionRef) Wait(ctx context.Context) (tunnel.ExecConn, error) {
	for {
		r.mu.Lock()
		connection, changed := r.conn, r.changed
		r.mu.Unlock()
		if connection != nil {
			return connection, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (r *execConnectionRef) CloseInput() {
	r.mu.Lock()
	r.eof = true
	connection := r.conn
	r.mu.Unlock()
	if connection != nil {
		_ = connection.CloseWrite()
	}
}

func forwardExecInput(ctx context.Context, reader io.Reader, connections *execConnectionRef) {
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			connection, err := connections.Wait(ctx)
			if err != nil {
				return
			}
			remaining := buffer[:n]
			for len(remaining) > 0 {
				written, writeErr := connection.Write(remaining)
				if writeErr != nil || written <= 0 || written > len(remaining) {
					connections.Clear(connection)
					break
				}
				remaining = remaining[written:]
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				connections.CloseInput()
			}
			return
		}
	}
}

func execEventName(event tunnel.ExecEvent) string {
	if event.Stream != "" {
		return event.Stream
	}
	if event.State == "started" {
		return "started"
	}
	if event.State == "exited" && event.Result != nil && event.Result.Signal != "" {
		return "signaled"
	}
	if event.State == "exited" || event.State == "signaled" {
		return event.State
	}
	return "failed"
}

func execEventChanged(event tunnel.ExecEvent) *bool {
	if event.Stream != "" || event.State == "started" {
		return nil
	}
	changed := event.State == "exited" || event.State == "signaled" || event.State == "canceled" || event.Result != nil
	return &changed
}

func execEventSequence(event tunnel.ExecEvent) *uint64 {
	if event.Stream == "" {
		return nil
	}
	sequence := event.Sequence
	return &sequence
}

func newExecOperationID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	return "exec-" + hex.EncodeToString(value[:])
}

func actionCodex(c *command.Context) error {
	selectTarget := c.Bool("select-environment")
	forwardedStart := 1
	forwarded := make([]string, 0, max(0, c.Args().Len()-forwardedStart))
	for index := forwardedStart; index < c.Args().Len(); index++ {
		forwarded = append(forwarded, c.Args().Get(index))
	}
	if err := codexsession.ValidateForwardedArgs(forwarded); err != nil {
		return invocationError(err)
	}
	d, err := buildDeps(c)
	if err != nil {
		return err
	}
	credential, err := d.auth.Credential()
	if errors.Is(err, config.ErrNoCredentials) {
		return errors.New("not signed in to Paperboat; run `pb login`, then retry")
	}
	if err != nil {
		return err
	}
	backend := api.New(d.cfg.ServerURL, credential, nil)
	requested := c.Args().First()
	if selectTarget {
		requested, err = selectEnvironment(c.Context, backend, "Choose where Codex should run")
		if err != nil {
			return err
		}
	}
	identity, err := resolver.NewAPIResolver(backend, d.cfg).ResolveEnvironment(c.Context, requested)
	if err != nil {
		return friendlyCommandError(err)
	}
	if d.peerApplications == nil {
		return errors.New("private peer transport is unavailable")
	}
	return codexsession.Run(c.Context, codexsession.Options{
		Backend: backend, EnvironmentID: identity.EnvironmentID, Path: c.String("path"), Args: forwarded,
		Stdin: os.Stdin, Stdout: c.Writer, Stderr: c.ErrWriter,
		PeerDial: func(ctx context.Context, descriptor api.CodexDescriptor) (net.Conn, error) {
			if descriptor.Session.ID == "" || descriptor.Session.MachineID == "" || descriptor.Session.EnvironmentID != identity.EnvironmentID || descriptor.MachineGeneration == 0 || descriptor.ConnectCredential == "" || descriptor.CredentialsExpireAt.IsZero() {
				return nil, errors.New("Codex returned an invalid peer target")
			}
			target := resolver.ConnectInfo{TargetKind: identity.Kind, ProjectID: descriptor.Session.MachineID, Project: identity.Name, ProjectState: "running", MachineGeneration: descriptor.MachineGeneration, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.codex.v1", EnvironmentID: identity.EnvironmentID, SessionID: descriptor.Session.ID, Auth: resolver.AuthTarget{Method: "bearer", Token: descriptor.ConnectCredential, ExpiresAt: descriptor.CredentialsExpireAt.Format(time.RFC3339Nano), Scopes: []string{"codex:connect"}}}}
			target.Transport = c.String("transport")
			return d.peerApplications.DialCodexHTTP(ctx, target)
		},
	})
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
	if c.Args().Len() > 2 {
		return errors.New("expected an environment and optional `new`")
	}
	if c.Args().Len() == 2 && c.Args().Get(1) != "new" {
		return errors.New("second argument must be `new`")
	}
	if c.Args().Len() == 2 && strings.TrimSpace(c.String("session")) != "" {
		return errors.New("`new` and --session cannot be used together")
	}
	if strings.TrimSpace(c.String("name")) != "" && strings.TrimSpace(c.String("session")) != "" {
		return errors.New("--name and --session cannot be used together")
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
	sourceMachineID, err := configuredMachineID()
	if err != nil {
		return err
	}
	backend.SetSourceMachineID(sourceMachineID)
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
		updateSelectedTransport(bar, selection, outcome)
	}

	sessionName := c.String("name")
	sessionRef := c.String("session")
	target, resolvedMachine, err := resolveEnvironmentTargetWithMachine(c.Context, backend, project)
	if err != nil {
		return err
	}
	var createSession *resolver.TerminalSessionCreate
	terminalSessionID := ""
	terminalSessionName := ""
	if strings.TrimSpace(sessionRef) != "" {
		session, err := resolveTerminalSession(c.Context, backend, target, sessionRef)
		if err != nil {
			return friendlyCommandError(err)
		}
		terminalSessionID = session.ID
		terminalSessionName = session.Name
	} else if err := validateSessionNameOptional(sessionName); err != nil {
		return err
	} else if target.kind == environmentUserMachine {
		// Machine targets create the durable session and fetch its connection
		// descriptor in one round trip; the idempotency key makes descriptor
		// retries resolve the same session.
		createSession = &resolver.TerminalSessionCreate{Name: sessionName, IdempotencyKey: newIdempotencyKey()}
		terminalSessionName = sessionName
	} else {
		session, err := createTerminalSessionForTarget(c.Context, backend, target, sessionName, newIdempotencyKey())
		if err != nil {
			return friendlyCommandError(err)
		}
		if session.EvictedSession != nil {
			fmt.Fprintf(os.Stderr, "Session limit reached; removed least-recent session %q (%s).\n", session.EvictedSession.Name, session.EvictedSession.State)
		}
		terminalSessionID = session.ID
		terminalSessionName = session.Name
	}
	bar.SetIdentity(project, terminalSessionName)
	newResolver := func(credential config.Credential) *resolver.APIResolver {
		client := api.New(d.cfg.ServerURL, credential, nil)
		client.SetSourceMachineID(sourceMachineID)
		apiResolver := resolver.NewAPIResolver(client, d.cfg)
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
	var keyCoordinator *filetransfer.KeyCoordinator
	if d.peerTunnel != nil {
		profileStore, storeErr := config.ProfileStoreFor(d.cfg)
		if storeErr == nil {
			keyVault, vaultErr := transfercrypto.NewKeyVault(profileStore.Secrets)
			if vaultErr == nil {
				keyCoordinator, _ = filetransfer.NewKeyCoordinator(keyVault, d.peerTunnel)
			}
		}
	}
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
		resolveRequest := resolver.ConnectRequest{Project: project, Credential: cred, TerminalSessionID: terminalSessionID, CreateTerminalSession: createSession}
		if target.kind == environmentUserMachine && resolvedMachine.ID != "" && resolvedMachine.InstallationGeneration > 0 {
			resolveRequest.ResolvedMachine = &resolver.ResolvedMachine{ID: resolvedMachine.ID, Name: resolvedMachine.DisplayName, State: resolvedMachine.State, Generation: uint64(resolvedMachine.InstallationGeneration)}
		}
		info, err = d.resolver.Resolve(ctx, resolveRequest)
		if err == nil {
			if createSession != nil && info.TerminalSession != nil {
				created := info.TerminalSession
				if terminalSessionID == "" {
					terminalSessionID = created.ID
				}
				if created.Name != "" && created.Name != terminalSessionName {
					terminalSessionName = created.Name
					bar.SetIdentity(project, terminalSessionName)
				}
				if created.EvictedSession != nil {
					fmt.Fprintf(os.Stderr, "Session limit reached; removed least-recent session %q (%s).\n", created.EvictedSession.Name, created.EvictedSession.State)
				}
			}
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
			// The file-transfer policy check runs concurrently with the
			// transport dial. Paste availability is decided before any input
			// is accepted, but the health check round trip never delays the
			// shell becoming interactive.
			verifyDone := make(chan struct{})
			if transferClient != nil {
				go func() {
					defer close(verifyDone)
					if policyErr := transferClient.VerifyPolicy(ctx, descriptorFileTransferPolicy(info.FileTransfer)); policyErr != nil {
						transferClient = nil
						if useStatusBar {
							bar.FailureFor("file_transfer", "File transfer unavailable")
						} else {
							fmt.Fprintln(os.Stderr, "File transfer is unavailable for this connection. Terminal access will continue.")
						}
					}
				}()
			} else {
				close(verifyDone)
			}
			conn, err = d.tunnel.Dial(ctx, info)
			<-verifyDone
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
	if useStatusBar && d.peerLocal != nil && info.TargetKind == "machine" {
		go watchMachineTransportPath(ctx, d.peerLocal, info.ProjectID, d.transportMode, bar)
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
	startInbox := func(client *filetransfer.Client, target resolver.ConnectInfo, sessionID string) {
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
		inboxPath, pathErr := configuredInboxPath()
		if pathErr != nil {
			notify("File delivery unavailable: " + pathErr.Error())
			return
		}
		machineID, machineErr := configuredMachineID()
		if machineErr != nil {
			notify("File delivery unavailable: " + machineErr.Error())
			return
		}
		inboxConfig := inbox.Config{Client: client, MachineID: machineID, SessionID: sessionID, Path: inboxPath, Notify: notify}
		if keyCoordinator != nil && target.Terminal != nil {
			inboxConfig.Encrypted = client
			inboxConfig.Keys = keyCoordinator
			inboxConfig.Target = target
		}
		receiver, inboxErr := inbox.New(inboxConfig)
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
		reconnectRequest := resolver.ConnectRequest{Project: info.ProjectID, Credential: freshCred, TerminalSessionID: terminalSessionID}
		if target.kind == environmentUserMachine && info.MachineGeneration > 0 {
			reconnectRequest.ResolvedMachine = &resolver.ResolvedMachine{ID: info.ProjectID, Name: info.Project, State: info.ProjectState, Generation: info.MachineGeneration}
		}
		freshInfo, resolveErr := freshResolver.Resolve(reconnectCtx, reconnectRequest)
		if resolveErr != nil {
			var apiErr *api.APIError
			if errors.As(resolveErr, &apiErr) && apiErr.Code == "machine_revoked" {
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
			pastePolicy.Update(encryptedPasteUploader(freshTransfer, keyCoordinator, freshInfo), freshInfo.Terminal.SessionID, fileTransferLimits(freshInfo.FileTransfer))
			startInbox(freshTransfer, freshInfo, freshInfo.Terminal.SessionID)
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
	pastePolicy = paste.NewPolicy(encryptedPasteUploader(transferClient, keyCoordinator, info), info.Terminal.SessionID, fileTransferLimits(info.FileTransfer))
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
	startInbox(transferClient, info, info.Terminal.SessionID)

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

func updateSelectedTransport(bar *statusbar.Bar, selection tunnel.TerminalTransportSelection, outcome string) {
	if outcome == "selected" {
		bar.SetTransport(selection.Selected)
	}
}

// watchMachineTransportPath keeps an automatic session marker in sync with a
// uniform machine path. A daemon snapshot is machine-scoped, so it must never
// overwrite a forced session's requested path or resolve a mixed snapshot to
// an arbitrary peer's transport.
func watchMachineTransportPath(ctx context.Context, client *localapi.Client, machineID string, requested tunnel.TerminalTransport, bar *statusbar.Bar) {
	if client == nil || bar == nil || machineID == "" {
		return
	}
	if forcedTransportMarker(requested, bar) {
		return
	}
	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return
	}
	applyMachineTransportPath(snapshot, machineID, requested, bar)
	updates, watchErr := client.Watch(ctx, snapshot.Generation)
	for {
		select {
		case <-ctx.Done():
			return
		case snapshot, ok := <-updates:
			if !ok {
				return
			}
			applyMachineTransportPath(snapshot, machineID, requested, bar)
		case <-watchErr:
			return
		}
	}
}

func forcedTransportMarker(requested tunnel.TerminalTransport, bar *statusbar.Bar) bool {
	switch requested {
	case tunnel.TerminalTransportDirect:
		bar.SetTransport("direct")
	case tunnel.TerminalTransportRelayQUIC:
		bar.SetTransport("relay")
	case tunnel.TerminalTransportRelayWSS:
		bar.SetTransport("wss")
	default:
		return false
	}
	return true
}

func applyMachineTransportPath(snapshot localapi.Snapshot, machineID string, requested tunnel.TerminalTransport, bar *statusbar.Bar) {
	if forcedTransportMarker(requested, bar) {
		return
	}
	for _, machine := range snapshot.Machines {
		if machine.ID == machineID && (machine.SelectedPath == "direct" || machine.SelectedPath == "relay" || machine.SelectedPath == "wss") {
			bar.SetTransport(machine.SelectedPath)
			return
		}
	}
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

func chooseIndex(title, subtitle string, count int, item func(int) selector.Item) (int, error) {
	items := make([]selector.Item, count)
	indexes := make(map[string]int, count)
	for index := range count {
		items[index] = item(index)
		if items[index].ID == "" {
			items[index].ID = strconv.Itoa(index)
		}
		indexes[items[index].ID] = index
	}
	selected, err := selector.Choose(selector.Options{Title: title, Subtitle: subtitle, Items: items, Stdin: os.Stdin, Output: os.Stderr})
	if errors.Is(err, selector.ErrCanceled) {
		return 0, errors.New("selection canceled")
	}
	return indexes[selected.ID], err
}

func confirmAction(message string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("confirmation requires --yes in non-interactive use")
	}
	return prompt.Confirm(prompt.ConfirmOptions{Title: "Confirm action", Description: message, Stdin: os.Stdin, Output: os.Stderr})
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
		for _, candidate := range status.Environments {
			if candidate.EnvironmentID == projectID {
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
	case "machine_offline":
		return "the machine is offline; start or repair its Paperboat connector, then retry"
	case "machine_revoked":
		return "this machine has been disconnected or revoked; repair or reconnect it in the Paperboat dashboard"
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
	binding := filetransfer.Binding{SourceMachineID: target.SourceMachineID, DestinationMachineID: target.DestinationMachineID, InitiatingUserID: target.InitiatingUserID}
	transferClient := filetransfer.NewClient(target.Endpoint, filetransfer.Auth{Token: target.Auth.Token, ExpiresAt: parseAuthExpiry(target.Auth.ExpiresAt)}, binding, client)
	if target.Policy.DeliveryTimeoutSeconds > 0 {
		transferClient.DeliveryTimeout = time.Duration(target.Policy.DeliveryTimeoutSeconds) * time.Second
	}
	return transferClient
}

func localFileTransferSenderFromEnvironment() (*filetransfer.LocalSender, error) {
	endpoint := strings.TrimSpace(os.Getenv("PAPERBOAT_FILE_TRANSFER_STAGING_ENDPOINT"))
	tokenPath := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_AGENT_TOKEN_FILE"))
	if endpoint == "" && tokenPath == "" {
		return nil, nil
	}
	if endpoint == "" || !filepath.IsAbs(tokenPath) {
		return nil, errors.New("Paperboat host-local file transfer environment is invalid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "/v1/local-file-transfers" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Paperboat host-local file transfer endpoint is invalid")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" {
		return nil, errors.New("Paperboat host-local file transfer endpoint is not loopback")
	}
	token, err := readOwnerOnlyFile(tokenPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read Paperboat host-local file transfer token: %w", err)
	}
	value := strings.TrimSpace(string(token))
	clear(token)
	if len(value) < 32 || strings.ContainsAny(value, " \t\r\n") {
		return nil, errors.New("Paperboat host-local file transfer token is invalid")
	}
	return &filetransfer.LocalSender{Endpoint: endpoint, Token: value}, nil
}

func encryptedPasteUploader(client *filetransfer.Client, keys *filetransfer.KeyCoordinator, target resolver.ConnectInfo) paste.BatchUploader {
	if client == nil || keys == nil || target.FileTransfer == nil || target.Terminal == nil {
		return nil
	}
	retention := time.Duration(target.FileTransfer.Policy.RetentionSeconds) * time.Second
	return &filetransfer.EncryptedUploader{Client: client, Keys: keys, Target: target, Retention: retention, Generation: 1}
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
			{Name: "status", ArgsUsage: "[environment]", Usage: "Show configuration synchronization status", Action: configStatus},
			{
				Name: "assign", ArgsUsage: "<repository> <machine>", Usage: "Assign a config repository to a machine",
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
					case "ssh-target-port":
						port, parseErr := strconv.ParseUint(c.Args().Get(1), 10, 16)
						if parseErr != nil || port == 0 {
							return errors.New("ssh-target-port must be between 1 and 65535")
						}
						return configSetSSHTargetPort(c, uint16(port))
					default:
						return errors.New("usage: pb config set server <url> or pb config set ssh-target-port <1-65535>")
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

func configSetSSHTargetPort(c *command.Context, port uint16) error {
	stateRoot := os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
	var err error
	if stateRoot == "" {
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
	}
	store, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		return err
	}
	registration, err := store.Registration()
	if err != nil || registration.SetupMode != "host" || registration.InstallationGeneration < 1 {
		return errors.New("this machine is not configured as an SSH host")
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	generation := uint64(registration.InstallationGeneration)
	current, err := client.ManagedSSHTarget(c.Context, registration.MachineID, generation)
	if err != nil {
		return err
	}
	if current.Port != port {
		if _, err := client.UpdateManagedSSHTargetPort(c.Context, registration.MachineID, generation, current.ReconciliationVersion, port, "managed-ssh-port-"+strings.TrimPrefix(newIdempotencyKey(), "pb-")); err != nil {
			return err
		}
	}
	registration.SSHPort = port
	registration.UpdatedAt = time.Now().UTC()
	if err := store.SaveRegistration(registration); err != nil {
		return err
	}
	fmt.Fprintf(c.Writer, "SSH target port set to %d\n", port)
	return nil
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
	if target.kind != environmentUserMachine {
		return errors.New("config assignments require a machine target")
	}
	machineID := target.id
	repositories, err := client.ListConfigRepositories(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	repository, err := resolveConfigRepository(repositories, c.Args().First())
	if err != nil {
		return err
	}
	mode := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(c.String("mode"))), "-", "_")
	if mode != "pull_only" && mode != "push_only" && mode != "bidirectional" {
		return errors.New("config assign --mode must be pull-only, push-only, or bidirectional")
	}
	if target.kind == environmentUserMachine && !c.Bool("yes") {
		fmt.Fprintf(c.ErrWriter, "Machine: %s (%s)\nRepository: %s\n", target.name, target.id, repository.DisplayName)
		return errors.New("config enablement requires --yes: selected content is ordinary plaintext in the private Git repository, Git history may retain removed versions, and repository access can expose that history")
	}
	expectedVersion := int64(0)
	current, getErr := client.ConfigAssignment(c.Context, machineID)
	if getErr == nil {
		expectedVersion = current.Version
	} else if !api.IsNotFound(getErr) {
		return friendlyCommandError(getErr)
	}
	assignment, err := client.AssignConfig(c.Context, machineID, repository.ID, mode, expectedVersion)
	if err != nil {
		return friendlyCommandError(err)
	}
	if target.kind == environmentUserMachine && assignment.ConsentState == "pending" {
		warning, warningErr := client.ConfigWarning(c.Context, machineID)
		if warningErr != nil {
			return friendlyCommandError(warningErr)
		}
		if warning.Revision == "" || warning.RepositoryVisibility == "" || warning.HistoryRetention == "" || warning.AccessConsequence == "" {
			return errors.New("server returned an incomplete configuration consent warning")
		}
		assignment, err = client.AcceptConfigConsent(c.Context, machineID, warning.Revision, assignment.Version)
		if err != nil {
			return friendlyCommandError(err)
		}
	}
	if err := manageConfigService(c.Context, machineID, true); err != nil {
		return fmt.Errorf("start config sync service: %w", err)
	}
	if c.Bool("json") {
		result := map[string]any{"version": "1", "repository": repository, "assignment": assignment, "outcome": "confirmed"}
		if target.kind == environmentUserMachine {
			result["machine"] = map[string]string{"id": target.id, "display_name": target.name}
		} else {
			result["environment"] = map[string]string{"id": target.id, "kind": "hosted", "display_name": target.name}
		}
		return json.NewEncoder(c.Writer).Encode(result)
	}
	fmt.Fprintf(c.Writer, "Assigned config repository %s to %s in %s mode.\n", repository.DisplayName, target.name, strings.ReplaceAll(mode, "_", "-"))
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
	if target.kind != environmentUserMachine {
		return errors.New("config assignments require a machine target")
	}
	machineID := target.id
	assignment, err := client.ConfigAssignment(c.Context, machineID)
	if err != nil {
		return friendlyCommandError(err)
	}
	if err := manageConfigService(c.Context, machineID, false); err != nil {
		return fmt.Errorf("stop config sync service: %w", err)
	}
	if err := client.UnassignConfig(c.Context, machineID, assignment.Version); err != nil {
		repairErr := manageConfigService(c.Context, machineID, true)
		return errors.Join(friendlyCommandError(err), repairErr)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": map[string]string{"id": target.id, "kind": target.kind, "display_name": target.name}, "state": "unassigned", "outcome": "confirmed"})
	}
	fmt.Fprintf(c.Writer, "Removed config assignment from %s.\n", target.name)
	return nil
}

func manageConfigService(ctx context.Context, machineID string, install bool) error {
	stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
	var err error
	if stateRoot == "" {
		stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(stateRoot, "machine-registration.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		return err
	}
	registration, err := identityStore.Registration()
	if err != nil {
		return err
	}
	if registration.MachineID != machineID {
		return nil
	}
	if windowsConfig, windowsService, windowsErr := windowsConfigServiceDefinition(stateRoot); windowsService {
		if windowsErr != nil {
			return windowsErr
		}
		installer, installErr := service.New(windowsConfig)
		if installErr != nil {
			return installErr
		}
		if install {
			return installer.Install(ctx)
		}
		return installer.Uninstall(ctx)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	account, err := user.Current()
	if err != nil {
		return err
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return err
	}
	runner := service.ExecRunner{}
	var controller service.Controller
	switch runtime.GOOS {
	case "darwin":
		uid, parseErr := strconv.Atoi(account.Uid)
		if parseErr != nil {
			return parseErr
		}
		controller = service.LaunchdController{Runner: runner, UID: uid, Label: service.ConfigLabel, UserDomain: true}
	case "linux":
		controller = service.SystemdController{Runner: runner, Unit: "paperboat-runtime-config.service", User: true}
	default:
		return service.ErrUnsupportedPlatform
	}
	installer, err := service.New(service.Config{Platform: runtime.GOOS, Kind: service.ConfigKind, ConfigRoot: home, Executable: executable, User: account.Username, Group: group.Name, Arguments: []string{"__runtime-config", "--state-root", stateRoot}, Environment: map[string]string{"HOME": home}, Controller: controller})
	if err != nil {
		return err
	}
	if install {
		return installer.Install(ctx)
	}
	return installer.Uninstall(ctx)
}

func configStatus(c *command.Context) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	status, err := client.ConfigSyncStatus(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	items, err := selectConfigEnvironments(status.Environments, c.Args().First())
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "state": status.State, "environments": items})
	}
	if len(items) == 0 {
		fmt.Fprintln(c.Writer, "No configuration assignments are reporting status.")
		return nil
	}
	for _, item := range items {
		name := item.DisplayName
		if name == "" {
			name = item.EnvironmentID
		}
		fmt.Fprintf(c.Writer, "%s: %s, %s, manifest %s, %d managed, %d pending clean\n",
			name, item.State, strings.ReplaceAll(item.Mode, "_", "-"), item.ManifestHealth,
			item.ManagedPathCount, item.PendingCleanPathCount)
	}
	return nil
}

func configConflictCobraCommand() *cobra.Command {
	root := &cobra.Command{Use: "conflict", Short: "Inspect and resolve configuration conflicts"}
	list := &cobra.Command{Use: "list [environment]", Short: "List current path conflicts", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: actionRun(configConflictList)}
	list.Flags().Bool("json", false, "print JSON")
	show := &cobra.Command{Use: "show <environment> <path>", Short: "Show a current path conflict", Args: commandArgs(cobra.ExactArgs(2)), RunE: actionRun(configConflictShow)}
	show.Flags().Bool("json", false, "print JSON")
	resolve := &cobra.Command{Use: "resolve <environment> <path>", Short: "Choose the machine or repository version", Args: commandArgs(cobra.ExactArgs(2)), RunE: actionRun(configConflictResolve)}
	resolve.Flags().String("keep", "", "version to keep: machine or repository")
	resolve.Flags().Bool("json", false, "print JSON")
	root.AddCommand(list, show, resolve)
	return root
}

func configForceCobraCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "force <pull|push> <environment> [path]", Short: "Force a scoped configuration direction",
		Args: commandArgs(cobra.RangeArgs(2, 3)), RunE: actionRun(configForce),
	}
	command.Flags().Bool("yes", false, "confirm the force operation")
	command.Flags().Bool("json", false, "print JSON")
	return command
}

func configConflictList(c *command.Context) error {
	status, items, err := loadSelectedConfigStatus(c, c.Args().First())
	if err != nil {
		return err
	}
	type listedConflict struct {
		EnvironmentID   string                    `json:"environment_id"`
		EnvironmentName string                    `json:"environment_name"`
		Conflict        api.ConfigSyncPathSummary `json:"conflict"`
	}
	conflicts := make([]listedConflict, 0)
	for _, item := range items {
		for _, conflict := range item.Conflicts {
			conflicts = append(conflicts, listedConflict{item.EnvironmentID, item.DisplayName, conflict})
		}
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "state": status.State, "conflicts": conflicts})
	}
	if len(conflicts) == 0 {
		fmt.Fprintln(c.Writer, "No configuration conflicts.")
		return nil
	}
	for _, item := range conflicts {
		name := item.EnvironmentName
		if name == "" {
			name = item.EnvironmentID
		}
		fmt.Fprintf(c.Writer, "%s\t%s\t%s\n", name, item.Conflict.Path, strings.ReplaceAll(item.Conflict.Reason, "_", " "))
	}
	return nil
}

func configConflictShow(c *command.Context) error {
	_, items, err := loadSelectedConfigStatus(c, c.Args().First())
	if err != nil {
		return err
	}
	conflict, err := findConfigConflict(items[0], c.Args().Get(1))
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "environment": items[0], "conflict": conflict})
	}
	fmt.Fprintf(c.Writer, "%s on %s\nReason: %s\nChoices: keep this machine's version or use repository version.\n",
		conflict.Path, items[0].DisplayName, strings.ReplaceAll(conflict.Reason, "_", " "))
	return nil
}

func configConflictResolve(c *command.Context) error {
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	status, err := client.ConfigSyncStatus(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	items, err := selectConfigEnvironments(status.Environments, c.Args().First())
	if err != nil {
		return err
	}
	conflict, err := findConfigConflict(items[0], c.Args().Get(1))
	if err != nil {
		return err
	}
	action := ""
	switch strings.ToLower(strings.TrimSpace(c.String("keep"))) {
	case "machine", "local":
		action = "keep_local"
	case "repository", "remote":
		action = "keep_remote"
	default:
		return errors.New("config conflict resolve --keep must be machine or repository")
	}
	operation, err := client.ResolveConfigConflict(c.Context, items[0].EnvironmentID, api.ConfigConflictRequest{
		Path: conflict.Path, ConflictRevision: conflict.Revision, ExpectedRemoteRevision: items[0].RemoteRevision,
		ExpectedAssignmentVersion: items[0].AssignmentVersion, Action: action,
	})
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "operation": operation, "outcome": "queued"})
	}
	fmt.Fprintf(c.Writer, "Queued %s for %s on %s.\n", strings.ReplaceAll(action, "_", " "), conflict.Path, items[0].DisplayName)
	return nil
}

func configForce(c *command.Context) error {
	direction := strings.ToLower(strings.TrimSpace(c.Args().First()))
	if direction != "pull" && direction != "push" {
		return errors.New("config force direction must be pull or push")
	}
	client, err := backendClient(c)
	if err != nil {
		return err
	}
	status, err := client.ConfigSyncStatus(c.Context)
	if err != nil {
		return friendlyCommandError(err)
	}
	items, err := selectConfigEnvironments(status.Environments, c.Args().Get(1))
	if err != nil {
		return err
	}
	item := items[0]
	request := api.ConfigForceRequest{
		Scope: "config", ExpectedRemoteRevision: item.RemoteRevision, ExpectedAssignmentVersion: item.AssignmentVersion,
		Action: "force_" + direction, Confirmation: "FORCE " + strings.ToUpper(direction),
	}
	if c.Args().Len() == 3 {
		conflict, findErr := findConfigConflict(item, c.Args().Get(2))
		if findErr != nil {
			return findErr
		}
		request.Scope, request.Path, request.ConflictRevision = "path", conflict.Path, conflict.Revision
	}
	if !c.Bool("yes") {
		return fmt.Errorf("force preview: %s %s scope on %s; rerun with --yes to queue this recoverable operation", direction, request.Scope, item.DisplayName)
	}
	operation, err := client.ForceConfig(c.Context, item.EnvironmentID, request)
	if err != nil {
		return friendlyCommandError(err)
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Writer).Encode(map[string]any{"version": "1", "operation": operation, "outcome": "queued"})
	}
	fmt.Fprintf(c.Writer, "Queued force %s for %s on %s.\n", direction, request.Scope, item.DisplayName)
	return nil
}

func loadSelectedConfigStatus(c *command.Context, requested string) (api.ConfigSyncStatus, []api.ConfigSyncEnvironmentState, error) {
	client, err := backendClient(c)
	if err != nil {
		return api.ConfigSyncStatus{}, nil, err
	}
	status, err := client.ConfigSyncStatus(c.Context)
	if err != nil {
		return api.ConfigSyncStatus{}, nil, friendlyCommandError(err)
	}
	items, err := selectConfigEnvironments(status.Environments, requested)
	return status, items, err
}

func selectConfigEnvironments(items []api.ConfigSyncEnvironmentState, requested string) ([]api.ConfigSyncEnvironmentState, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return items, nil
	}
	matches := make([]api.ConfigSyncEnvironmentState, 0, 1)
	for _, item := range items {
		if item.EnvironmentID == requested || strings.EqualFold(item.DisplayName, requested) {
			matches = append(matches, item)
		}
	}
	if len(matches) == 1 {
		return matches, nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("configuration environment %q is ambiguous; use its stable ID", requested)
	}
	return nil, fmt.Errorf("configuration environment %q was not found", requested)
}

func findConfigConflict(item api.ConfigSyncEnvironmentState, requested string) (api.ConfigSyncPathSummary, error) {
	for _, conflict := range item.Conflicts {
		if conflict.Path == requested {
			return conflict, nil
		}
	}
	return api.ConfigSyncPathSummary{}, fmt.Errorf("configuration conflict %q was not found on %s", requested, item.DisplayName)
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

type proxyDoctorDiagnosis struct {
	State    string `json:"state"`
	Recovery string `json:"recovery"`
}

func doctorProxyDiagnosis(err error) (proxyDoctorDiagnosis, bool) {
	var proxyErr *httptransport.ProxyError
	if !errors.As(err, &proxyErr) {
		return proxyDoctorDiagnosis{}, false
	}
	switch proxyErr.Failure {
	case httptransport.ProxyAutomaticConfigurationUnsupported:
		return proxyDoctorDiagnosis{
			State:    "pac_unsupported",
			Recovery: "This network requires PAC/WPAD, which Paperboat does not execute. Configure a credential-free explicit HTTPS proxy with HTTPS_PROXY (or PAPERBOAT_HTTPS_PROXY for a managed service), then retry `pb doctor`.",
		}, true
	case httptransport.ProxyAuthenticationRequired:
		return proxyDoctorDiagnosis{
			State:    "authentication_required",
			Recovery: "The configured proxy requires authentication, which Paperboat does not accept in proxy URLs. Configure a credential-free explicit proxy, then retry `pb doctor`.",
		}, true
	case httptransport.ProxyInvalid:
		return proxyDoctorDiagnosis{
			State:    "invalid_configuration",
			Recovery: "Configure a credential-free http:// or https:// proxy URL with no path, query, or fragment, then retry `pb doctor`.",
		}, true
	default:
		return proxyDoctorDiagnosis{}, false
	}
}

type localDoctorReport struct {
	StateRoot               string   `json:"state_root,omitempty"`
	SetupState              string   `json:"setup_state"`
	MachineID               string   `json:"machine_id,omitempty"`
	EnvironmentID           string   `json:"environment_id,omitempty"`
	InstallationGeneration  int64    `json:"installation_generation,omitempty"`
	SetupRoles              []string `json:"setup_roles,omitempty"`
	SetupMode               string   `json:"setup_mode,omitempty"`
	IdentityState           string   `json:"identity_state"`
	CredentialState         string   `json:"machine_control_credential"`
	InboxPath               string   `json:"inbox_path,omitempty"`
	InboxState              string   `json:"inbox_state"`
	ConfigService           string   `json:"config_service"`
	HostRuntime             string   `json:"host_runtime"`
	ActivePreviews          int      `json:"active_previews"`
	ExpiredPreviews         int      `json:"expired_previews"`
	InvalidPreviews         int      `json:"invalid_previews"`
	ServedPreviews          int      `json:"served_previews"`
	ActiveServedPreviews    int      `json:"active_served_previews"`
	InvalidServeSources     int      `json:"invalid_serve_sources"`
	ActiveServeListeners    int      `json:"active_serve_listeners"`
	MissingServeListeners   int      `json:"missing_serve_listeners"`
	ServeLeaseAuthority     string   `json:"serve_lease_authority"`
	RuntimeForegroundServes uint64   `json:"runtime_foreground_serves"`
	RuntimeDetachedServes   uint64   `json:"runtime_detached_serves"`
	RemoteServedPreviews    int      `json:"remote_served_previews"`
	RouteReadiness          string   `json:"route_readiness"`
	ActiveSessions          uint64   `json:"active_sessions"`
	ActiveProcesses         uint64   `json:"active_processes"`
	ActiveAttachments       uint64   `json:"active_attachments"`
	ActiveTransfers         uint64   `json:"active_transfers"`
	WorkloadCounts          string   `json:"workload_counts_state"`
	RecoveryActions         []string `json:"recovery_actions,omitempty"`
}

func collectLocalDoctor() localDoctorReport {
	report := localDoctorReport{SetupState: "not_set_up", IdentityState: "missing", CredentialState: "missing", InboxState: "unconfigured", ConfigService: "not_installed", HostRuntime: "not_paired", WorkloadCounts: "unavailable", ServeLeaseAuthority: "unavailable", RouteReadiness: "unavailable"}
	stateRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT"))
	if stateRoot == "" {
		root, err := helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			report.SetupState = "error"
			report.RecoveryActions = append(report.RecoveryActions, "set PAPERBOAT_RUNTIME_STATE_ROOT to an absolute private directory")
			return report
		}
		stateRoot = root
	}
	report.StateRoot = stateRoot
	identityPath := filepath.Join(stateRoot, "machine-identity.json")
	registrationPath := filepath.Join(stateRoot, "machine-registration.json")
	if _, err := os.Lstat(registrationPath); errors.Is(err, os.ErrNotExist) {
		report.RecoveryActions = append(report.RecoveryActions, "run pb setup")
		return report
	}
	if info, err := os.Lstat(identityPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		report.SetupState, report.IdentityState = "invalid", "invalid"
		report.RecoveryActions = append(report.RecoveryActions, "restore the original machine identity or revoke and set up this installation again")
		return report
	}
	store, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		report.SetupState, report.IdentityState = "invalid", "invalid"
		report.RecoveryActions = append(report.RecoveryActions, "repair ownership and permissions of the Paperboat state directory")
		return report
	}
	registration, err := store.Registration()
	if err != nil {
		report.SetupState, report.IdentityState = "invalid", "invalid"
		report.RecoveryActions = append(report.RecoveryActions, "revoke the invalid machine registration and run pb setup")
		return report
	}
	report.SetupState, report.IdentityState = "configured", "valid"
	report.MachineID, report.EnvironmentID = registration.MachineID, registration.EnvironmentID
	report.InstallationGeneration = registration.InstallationGeneration
	report.SetupRoles = append([]string(nil), registration.SetupRoles...)
	report.SetupMode = registration.SetupMode
	report.InboxPath = registration.InboxPath
	if err := inbox.ValidatePath(registration.InboxPath); err != nil {
		report.InboxState = "unsafe_or_unavailable"
		report.RecoveryActions = append(report.RecoveryActions, "run pb inbox set <absolute-path> with a private writable directory")
	} else {
		report.InboxState = "ready"
	}
	if control, err := store.MachineControl(time.Now().UTC(), time.Hour); err == nil {
		if control.ExpiresAt.Before(time.Now().UTC()) {
			report.CredentialState = "grace"
		} else {
			report.CredentialState = "valid"
		}
	} else if registration.SetupMode == "host" || registration.SetupMode == "client" {
		report.CredentialState = "invalid_or_expired"
		report.RecoveryActions = append(report.RecoveryActions, "run pb pair to renew host authority")
	}
	if runtime.GOOS == "windows" {
		report.ConfigService = windowsConfigServiceStatus()
		if report.ConfigService == "invalid" {
			report.RecoveryActions = append(report.RecoveryActions, "repair the Windows config-sync service")
		}
	} else if home, homeErr := os.UserHomeDir(); homeErr == nil {
		definition := filepath.Join(home, ".config", "systemd", "user", "paperboat-runtime-config.service")
		if runtime.GOOS == "darwin" {
			definition = filepath.Join(home, "Library", "LaunchAgents", service.ConfigLabel+".plist")
		}
		if info, err := os.Lstat(definition); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			report.ConfigService = localConfigServiceState()
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			report.ConfigService = "invalid"
			report.RecoveryActions = append(report.RecoveryActions, "repair the config-sync service definition")
		}
	}
	inspectLocalRuntimeHealth(&report, stateRoot)
	inspectLocalPreviewDescriptors(&report, filepath.Join(stateRoot, "previews", "active"), time.Now().UTC())
	if report.RuntimeDetachedServes != uint64(report.ActiveServedPreviews) {
		report.RecoveryActions = append(report.RecoveryActions, "restart the local runtime to reconcile detached serve workload inventory")
	}
	return report
}

func localConfigServiceState() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if runtime.GOOS == "linux" {
		if err := exec.CommandContext(ctx, "systemctl", "--user", "is-active", "--quiet", "paperboat-runtime-config.service").Run(); err == nil {
			return "active"
		}
		return "installed_inactive"
	}
	if runtime.GOOS == "windows" {
		return windowsConfigServiceStatus()
	}
	account, err := user.Current()
	if err != nil {
		return "installed_unknown"
	}
	if err := exec.CommandContext(ctx, "launchctl", "print", "gui/"+account.Uid+"/"+service.ConfigLabel).Run(); err == nil {
		return "active"
	}
	return "installed_inactive"
}

func inspectLocalRuntimeHealth(report *localDoctorReport, stateRoot string) {
	var local struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}
	file, err := os.Open(filepath.Join(stateRoot, "runtime", "worker-local.json"))
	if err != nil {
		return
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&local)
	var extra any
	extraErr := decoder.Decode(&extra)
	file.Close()
	host, port, splitErr := net.SplitHostPort(local.ListenAddress)
	ip := net.ParseIP(host)
	if decodeErr != nil || extraErr != io.EOF || local.Schema != "paperboat.worker-local/v1" || splitErr != nil || ip == nil || !ip.IsLoopback() || port == "" {
		report.HostRuntime = "invalid_local_endpoint"
		report.RecoveryActions = append(report.RecoveryActions, "run pb pair to repair the local host-runtime endpoint")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+local.ListenAddress+"/healthz", nil)
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("local health endpoint redirected") }}
	response, err := client.Do(request)
	if err != nil {
		report.HostRuntime = "unavailable"
		return
	}
	defer response.Body.Close()
	var health struct {
		Live      bool              `json:"live"`
		Workloads map[string]uint64 `json:"workloads"`
	}
	decoder = json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK || decoder.Decode(&health) != nil || !health.Live {
		report.HostRuntime = "unhealthy"
		return
	}
	report.HostRuntime, report.WorkloadCounts = "ready", "available"
	report.ActiveSessions = health.Workloads["sessions"]
	report.ActiveProcesses = health.Workloads["processes"]
	report.ActiveAttachments = health.Workloads["attachments"]
	report.ActiveTransfers = health.Workloads["transfers"]
	report.RuntimeForegroundServes = health.Workloads["serves_foreground"]
	report.RuntimeDetachedServes = health.Workloads["serves_detached"]
	inspectServeLeaseAuthority(report, stateRoot, local.ListenAddress, client)
}

func inspectServeLeaseAuthority(report *localDoctorReport, stateRoot, listenAddress string, client *http.Client) {
	token, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "local-control-token"), 1024)
	if err != nil {
		report.ServeLeaseAuthority = "invalid_or_missing"
		report.RecoveryActions = append(report.RecoveryActions, "restart the local runtime to restore foreground serve lease authority")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listenAddress+"/v1/serve-leases", nil)
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	response, err := client.Do(request)
	if err != nil {
		report.ServeLeaseAuthority = "unavailable"
		return
	}
	defer response.Body.Close()
	var status struct {
		Schema string `json:"schema_version"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status) != nil || status.Schema != servelease.ProtocolVersion {
		report.ServeLeaseAuthority = "protocol_incompatible"
		report.RecoveryActions = append(report.RecoveryActions, "upgrade and restart the local runtime before using foreground serve")
		return
	}
	report.ServeLeaseAuthority = "ready"
}

func inspectLocalPreviewDescriptors(report *localDoctorReport, directory string, now time.Time) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		report.InvalidPreviews++
		report.RecoveryActions = append(report.RecoveryActions, "repair ownership of the active preview directory")
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		file, err := os.Open(filepath.Join(directory, entry.Name()))
		if err != nil {
			report.InvalidPreviews++
			continue
		}
		var descriptor struct {
			Schema            string          `json:"schema"`
			Name              string          `json:"name"`
			BindAddress       string          `json:"bind_address"`
			Port              uint16          `json:"port"`
			ServiceGeneration uint64          `json:"service_generation"`
			Indefinite        bool            `json:"indefinite"`
			ExpiresAt         *time.Time      `json:"expires_at"`
			ServiceDefinition string          `json:"service_definition"`
			Record            json.RawMessage `json:"record"`
			PrivateRemote     *struct {
				MachineID         string `json:"machine_id"`
				MachineName       string `json:"machine_name"`
				EnvironmentID     string `json:"environment_id"`
				MachineGeneration uint64 `json:"machine_generation"`
				TargetPort        uint16 `json:"target_port"`
				ListenPort        uint16 `json:"listen_port,omitempty"`
			} `json:"private_remote"`
			Serve *struct {
				SourcePath     string              `json:"source_path"`
				SourceKind     servepkg.SourceKind `json:"source_kind"`
				SourceIdentity string              `json:"source_identity"`
				SPA            bool                `json:"spa"`
				OwnerMode      string              `json:"owner_mode"`
				Visibility     string              `json:"visibility"`
			} `json:"serve"`
		}
		decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&descriptor)
		var extra any
		extraErr := decoder.Decode(&extra)
		file.Close()
		validPreview := descriptor.Serve == nil && descriptor.PrivateRemote == nil && descriptor.Port != 0
		validRemote := descriptor.Serve == nil && descriptor.PrivateRemote != nil && descriptor.BindAddress == "127.0.0.1" && descriptor.ServiceGeneration > 0 && descriptor.PrivateRemote.MachineID != "" && descriptor.PrivateRemote.MachineName != "" && descriptor.PrivateRemote.EnvironmentID != "" && descriptor.PrivateRemote.MachineGeneration > 0 && descriptor.PrivateRemote.TargetPort != 0
		validServe := descriptor.BindAddress == "127.0.0.1" && descriptor.ServiceGeneration > 0 && descriptor.Serve != nil && filepath.IsAbs(descriptor.Serve.SourcePath) && descriptor.Serve.SourceIdentity != "" && descriptor.Serve.OwnerMode == "detached" && (descriptor.Serve.Visibility == "private" || descriptor.Serve.Visibility == "public") &&
			(descriptor.Serve.SourceKind == servepkg.SourceFile || descriptor.Serve.SourceKind == servepkg.SourceDirectory) && (!descriptor.Serve.SPA || descriptor.Serve.SourceKind == servepkg.SourceDirectory)
		if decodeErr != nil || extraErr != io.EOF || descriptor.Schema != "paperboat.preview-runtime/v1" || !validPreview && !validServe && !validRemote || descriptor.Name == "" || descriptor.Indefinite == (descriptor.ExpiresAt != nil) {
			report.InvalidPreviews++
			continue
		}
		if validServe {
			report.ServedPreviews++
			if _, sourceErr := servepkg.ResolvePinnedSource(descriptor.Serve.SourcePath, descriptor.Serve.SourceKind, descriptor.Serve.SourceIdentity); sourceErr != nil {
				report.InvalidServeSources++
			}
			if descriptor.Port != 0 && (descriptor.ExpiresAt == nil || descriptor.ExpiresAt.After(now)) {
				connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(descriptor.Port))), 200*time.Millisecond)
				if connection != nil {
					connection.Close()
				}
				if dialErr == nil {
					report.ActiveServeListeners++
				} else {
					report.MissingServeListeners++
				}
			}
		}
		if descriptor.ExpiresAt != nil && !descriptor.ExpiresAt.After(now) {
			report.ExpiredPreviews++
		} else {
			report.ActivePreviews++
			if validServe {
				report.ActiveServedPreviews++
			}
		}
	}
	if report.ExpiredPreviews > 0 || report.InvalidPreviews > 0 || report.InvalidServeSources > 0 || report.MissingServeListeners > 0 {
		report.RecoveryActions = append(report.RecoveryActions, "restart the paired host runtime or recreate affected previews to reconcile descriptors")
	}
}

func compareLocalServedPreviewRoutes(report *localDoctorReport, previews []api.Preview) {
	ready := 0
	for _, item := range previews {
		served := item.SourceKind == "file" || item.SourceKind == "directory"
		if item.ResourceID != report.MachineID || !served || item.State == "removed" || item.State == "expired" {
			continue
		}
		report.RemoteServedPreviews++
		if item.State == "ready" {
			ready++
		}
	}
	local := report.ActiveServedPreviews + int(report.RuntimeForegroundServes)
	switch {
	case report.RemoteServedPreviews != local:
		report.RouteReadiness = "workload_route_drift"
		report.RecoveryActions = append(report.RecoveryActions, "revoke orphan served previews and restart the local runtime to reconcile workload and route state")
	case ready != report.RemoteServedPreviews:
		report.RouteReadiness = "not_ready"
		report.RecoveryActions = append(report.RecoveryActions, "inspect served preview readiness and connector health before retrying")
	default:
		report.RouteReadiness = "ready"
	}
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
	return api.UserMachine{}, errors.New("resolved machine is missing from the account")
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
