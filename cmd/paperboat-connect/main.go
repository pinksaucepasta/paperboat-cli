package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/buildinfo"
	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/connect"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: paperboat-connect <enroll|install|serve> [flags]")
		return 2
	}
	switch args[0] {
	case "enroll":
		return enroll(ctx, args[1:], stdout, stderr)
	case "install":
		return install(ctx, args[1:], stdout, stderr)
	case "serve":
		return serve(ctx, args[1:], stderr)
	default:
		fmt.Fprintln(stderr, "usage: paperboat-connect <enroll|install|serve> [flags]")
		return 2
	}
}

func install(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "Connector state directory")
	manifestURL := flags.String("manifest-url", "", "Signed release manifest URL")
	publicKey := flags.String("release-public-key", "", "Base64 Ed25519 release verification key")
	installDir := flags.String("install-dir", "", "Absolute component installation directory")
	fileFallback := flags.Bool("file-secret-fallback", false, "Use explicit 0600 file-backed enrollment secrets")
	var papercodeArgs, agentunnelArgs stringList
	flags.Var(&papercodeArgs, "papercode-arg", "Papercode argument (repeatable)")
	flags.Var(&agentunnelArgs, "agentunnel-arg", "Agentunnel argument (repeatable)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	dir, err := stateDirectory(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	secrets := config.SecretStore(config.KeyringStore{})
	if *fileFallback {
		secrets = config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}
	}
	if _, err := (connect.EnrollmentStore{Dir: dir, Secrets: secrets}).Load(); err != nil {
		fmt.Fprintln(stderr, "paperboat-connect: enrollment is unavailable; run enroll first")
		return 1
	}
	key, err := connect.ParseManifestPublicKey(*publicKey)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect: release public key is invalid")
		return 2
	}
	if *installDir == "" {
		*installDir = filepath.Join(dir, "bin")
	}
	if !filepath.IsAbs(*installDir) {
		fmt.Fprintln(stderr, "paperboat-connect: --install-dir must be absolute")
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	connectorPath := filepath.Join(*installDir, "paperboat-connect")
	serviceArgs := []string{"serve", "--state-dir", dir, "--papercode", filepath.Join(*installDir, "papercode", "papercode"), "--agentunnel", filepath.Join(*installDir, "agentunnel")}
	if *fileFallback {
		serviceArgs = append(serviceArgs, "--file-secret-fallback")
	}
	serviceSpec := connect.ServiceSpec{Label: "com.paperboat.connect", Executable: connectorPath, WorkingDirectory: dir, LogDirectory: logs, Arguments: append(serviceArgs, append(flagArguments("--papercode-arg", papercodeArgs), flagArguments("--agentunnel-arg", agentunnelArgs)...)...)}
	installer := connect.Installer{PublicKey: key}
	manifest, err := installer.Install(ctx, connect.InstallRequest{ManifestURL: *manifestURL, InstallDir: *installDir, Components: []string{"paperboat-connect", "papercode", "agentunnel"}, Activate: func() error {
		path, err := connect.InstallUserService(serviceSpec, home, runtime.GOOS)
		if err != nil {
			return err
		}
		return connect.ActivateUserService(path, runtime.GOOS, nil)
	}})
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	fmt.Fprintln(stdout, manifest.Version)
	return 0
}

func flagArguments(name string, values []string) []string {
	arguments := make([]string, 0, len(values)*2)
	for _, value := range values {
		arguments = append(arguments, name, value)
	}
	return arguments
}

func stateDirectory(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "paperboat", "connect"), nil
}

func enroll(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", buildinfo.DefaultServerURL, "Paperboat server URL")
	name := flags.String("name", "", "Connected-machine display name")
	workspace := flags.String("workspace", "", "Absolute workspace root")
	stateDir := flags.String("state-dir", "", "Connector state directory")
	fileFallback := flags.Bool("file-secret-fallback", false, "Allow 0600 file-backed enrollment secrets")
	resume := flags.Bool("resume", false, "Resume a pending enrollment approval")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	resolvedStateDir, err := stateDirectory(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	*stateDir = resolvedStateDir
	secrets := config.SecretStore(config.KeyringStore{})
	if *fileFallback {
		secrets = config.FileSecretStore{Dir: filepath.Join(*stateDir, "secrets")}
		fmt.Fprintln(stderr, "paperboat-connect: using explicit 0600 file secret fallback")
	}
	pendingStore := connect.PendingEnrollmentStore{Dir: *stateDir, Secrets: secrets}
	var pending connect.PendingEnrollment
	var verifier string
	if *resume {
		pending, verifier, err = pendingStore.Load()
		if err != nil {
			fmt.Fprintln(stderr, "paperboat-connect: pending enrollment is unavailable; run enroll again")
			return 1
		}
	} else {
		verifier, err = connect.NewVerifier()
		if err != nil {
			fmt.Fprintln(stderr, "paperboat-connect:", err)
			return 1
		}
		client := connect.EnrollmentClient{ServerURL: *server}
		pairing, createErr := client.CreatePairing(ctx, connect.PairingRequest{Verifier: verifier, DisplayName: *name, Platform: runtime.GOOS, Architecture: runtime.GOARCH, WorkspaceRoot: *workspace, RuntimeVersions: map[string]string{"connector": buildinfo.Version, "protocol": buildinfo.ProtocolVersion}})
		if createErr != nil {
			fmt.Fprintln(stderr, "paperboat-connect:", createErr)
			return 1
		}
		pending = connect.PendingEnrollment{ServerURL: *server, UserCode: pairing.UserCode, ExpiresAt: pairing.ExpiresAt}
		if err := pendingStore.Save(pending, verifier); err != nil {
			fmt.Fprintln(stderr, "paperboat-connect:", err)
			return 1
		}
		fmt.Fprintln(stdout, pending.UserCode)
	}
	client := connect.EnrollmentClient{ServerURL: pending.ServerURL}
	deadline := pending.ExpiresAt
	for time.Now().UTC().Before(deadline) {
		material, consumeErr := client.ConsumeInstallation(ctx, verifier)
		if consumeErr == nil {
			if err := (connect.EnrollmentStore{Dir: *stateDir, Secrets: secrets}).Save(material); err != nil {
				fmt.Fprintln(stderr, "paperboat-connect:", err)
				return 1
			}
			pendingStore.Delete()
			fmt.Fprintln(stdout, material.MachineID)
			return 0
		}
		select {
		case <-ctx.Done():
			return 1
		case <-time.After(2 * time.Second):
		}
	}
	fmt.Fprintln(stderr, "paperboat-connect: pairing expired before approval")
	return 1
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "Connector state directory")
	papercode := flags.String("papercode", "", "Absolute papercode server executable")
	agentunnel := flags.String("agentunnel", "", "Absolute agentunnel executable")
	fileFallback := flags.Bool("file-secret-fallback", false, "Use explicit 0600 file-backed enrollment secrets")
	var papercodeArgs, agentunnelArgs stringList
	flags.Var(&papercodeArgs, "papercode-arg", "Papercode argument (repeatable)")
	flags.Var(&agentunnelArgs, "agentunnel-arg", "Agentunnel argument (repeatable)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *papercode == "" || *agentunnel == "" {
		fmt.Fprintln(stderr, "paperboat-connect: --papercode and --agentunnel are required")
		return 2
	}
	dir, err := stateDirectory(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	secrets := config.SecretStore(config.KeyringStore{})
	if *fileFallback {
		secrets = config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}
	}
	enrollment, err := (connect.EnrollmentStore{Dir: dir, Secrets: secrets}).Load()
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect: enrollment is unavailable; run enroll first")
		return 1
	}
	agentunnelConfig, err := connect.WriteAgentunnelMachineConfig(dir, enrollment)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect: enrollment is invalid")
		return 1
	}
	papercodeState, err := connect.PreparePapercodeState(dir, enrollment)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-connect: enrollment is invalid")
		return 1
	}
	if len(papercodeArgs) == 0 {
		papercodeArgs, err = connect.PapercodeServeArgs(enrollment.PapercodeLocalURL)
		if err != nil {
			fmt.Fprintln(stderr, "paperboat-connect: enrollment is invalid")
			return 1
		}
	}
	papercodeArgs = append(papercodeArgs, "--base-dir", papercodeState)
	supervisor := connect.Supervisor{
		Processes: []connect.RuntimeProcess{
			{Name: "papercode", Executable: *papercode, Arguments: papercodeArgs, Ready: func(ctx context.Context) error {
				return connect.BootstrapPapercode(ctx, *papercode, papercodeState, enrollment)
			}},
			{Name: "agentunnel", Executable: *agentunnel, Arguments: append([]string{"client", "run", "--config", agentunnelConfig}, agentunnelArgs...)},
		},
		Runner: connect.ExecRunner{},
	}
	if err := supervisor.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "paperboat-connect:", err)
		return 1
	}
	return 0
}

type stringList []string

func (s *stringList) String() string         { return "" }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }
