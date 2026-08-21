//go:build windows

package hostruntimecmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	helperconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/machinename"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"golang.org/x/sys/windows"
)

func runBootstrap(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", "", "Paperboat server URL")
	legacyToken := flags.String("enrollment-token", "", "dashboard enrollment token (deprecated; use --enrollment-token-file)")
	tokenFile := flags.String("enrollment-token-file", "", "absolute dashboard enrollment token file")
	name := flags.String("name", "", "User machine name")
	stateRoot := flags.String("state-root", "", "Paperboat runtime state directory")
	acceptBetaPlatform := flags.Bool("accept-beta-platform", false, "accept enrollment on a beta platform")
	setupMode := flags.String("setup-mode", "host", "enrollment role: host or client")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("bootstrap accepts flags only")
	}
	if *setupMode != "host" && *setupMode != "client" && *setupMode != "receive" {
		return errors.New("setup-mode must be host or client")
	}
	if *setupMode == "client" {
		*setupMode = "receive"
	}
	if *legacyToken != "" && *tokenFile != "" {
		return errors.New("use only one enrollment token source")
	}
	token := strings.TrimSpace(*legacyToken)
	if *tokenFile != "" {
		var tokenErr error
		token, tokenErr = bootstrap.ReadEnrollmentTokenFile(*tokenFile)
		if tokenErr != nil {
			return errors.New("enrollment token file must be an absolute regular non-reparse file")
		}
	}
	if strings.TrimSpace(*name) == "" {
		// One-shot installers must never pause for input. Windows' computer
		// name is the default display name when the dashboard leaves it blank.
		if detected, detectErr := os.Hostname(); detectErr == nil {
			*name = strings.TrimSpace(detected)
		}
	}
	*name = strings.TrimSpace(*name)
	if err := machinename.Validate(*name); err != nil {
		return fmt.Errorf("invalid machine name: %w", err)
	}
	if *stateRoot == "" {
		var err error
		*stateRoot, err = helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
	}
	if !filepath.IsAbs(*stateRoot) || filepath.Clean(*stateRoot) != *stateRoot {
		return errors.New("Windows runtime state root is invalid")
	}
	account, err := user.Current()
	if err != nil || account.Username == "" {
		return errors.New("could not resolve enrolled Windows user")
	}
	sid, err := currentBootstrapSID()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return errors.New("could not resolve enrolled Windows home")
	}
	identityStore, err := identity.Open(identity.Config{StateRoot: *stateRoot})
	if err != nil {
		return err
	}
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return err
	}
	_, reusableIdentityErr := enrollment.LoadRuntimeIdentityForRenewal(*stateRoot, time.Now().UTC())
	sshConfig := windowsopenssh.DefaultConfig(nil)
	config := bootstrap.Config{ServerURL: *serverURL, EnrollmentToken: token, DisplayName: *name, WorkspaceRoot: home, Verifier: base64.RawURLEncoding.EncodeToString(verifier), PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityStore.Current().Public()), RuntimeVersions: map[string]string{"pb": buildinfo.Version}, AcceptBetaPlatform: *acceptBetaPlatform, SSHUser: windowsAccountName(account.Username), SSHPort: sshConfig.Port, CanReuseRuntimeIdentity: reusableIdentityErr == nil}
	pairing, err := bootstrap.CreatePairing(ctx, config)
	if err != nil {
		return err
	}
	if *tokenFile != "" {
		if err := bootstrap.ConsumeEnrollmentTokenFile(*tokenFile); err != nil {
			return fmt.Errorf("consume enrollment token file: %w", err)
		}
	}
	fmt.Fprintln(stderr, "Completing one-shot machine enrollment...")
	material, err := bootstrap.WaitForMaterial(ctx, config, pairing.ExpiresAt, 2*time.Second)
	if err != nil {
		return err
	}
	if err := saveBootstrapRegistration(identityStore, *serverURL, material, windowsAccountName(account.Username), sshConfig.Port); err != nil {
		return fmt.Errorf("save machine registration: %w", err)
	}
	// Host-only enrollment does not promise a local CLI profile. Keep the
	// machine enrollment one-shot even when the account already has an E2E
	// root; CLI identity bootstrap is required only for client setup.
	if material.ClientSession != nil && material.SetupMode != "host" {
		if err := installBootstrapCLI(ctx, material.ClientSession, *serverURL); err != nil {
			return fmt.Errorf("initialize Paperboat CLI session: %w", err)
		}
	}
	artifactPath, err := bootstrap.FetchVerifiedArtifact(ctx, *material.Artifact, filepath.Join(*stateRoot, "tuf"), windowsArtifactHTTPClient())
	if err != nil {
		return err
	}
	if material.ReuseIdentity {
		runtimeIdentity, loadErr := enrollment.LoadRuntimeIdentityForRenewal(*stateRoot, time.Now().UTC())
		if loadErr != nil || runtimeIdentity.HelperID != material.HelperID || runtimeIdentity.EnvironmentID != material.EnvironmentID {
			return errors.New("server attempted to reuse an unavailable Windows runtime identity")
		}
	} else {
		client, clientErr := enrollment.NewClient(nil, 15*time.Second)
		if clientErr != nil {
			return clientErr
		}
		if _, err := client.Enroll(ctx, enrollment.Config{ControlURL: material.ControlURL, StateRoot: *stateRoot, EnrollmentCredential: material.EnrollmentCredential}); err != nil {
			return err
		}
	}
	request := hostinstall.Request{Schema: hostinstall.SchemaV1, Platform: runtime.GOOS, User: windowsAccountName(account.Username), Group: "Paperboat", OwnerSID: sid, Executable: artifactPath, Artifact: *material.Artifact, Home: home, Path: os.Getenv("PATH"), StateRoot: *stateRoot, WorkspaceRoot: home, ControlURL: material.ControlURL, UserMachineID: material.UserMachineID, Shell: filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), HelperListenAddress: material.HelperListenAddress, SetupMode: *setupMode}
	if err := hostinstall.Validate(request, 0); err != nil {
		return fmt.Errorf("validate Windows host installation request: %w", err)
	}
	fmt.Fprintln(stderr, "Requesting administrator approval to install Paperboat Windows services...")
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve Paperboat executable for administrator approval: %w", err)
	}
	if err := elevation.RunRuntimeService(ctx, executable, elevation.ActionInstallCommit, request); err != nil {
		return fmt.Errorf("install Paperboat Windows host runtime: %w", err)
	}
	fmt.Fprintln(stdout, "Paperboat Windows host runtime is installed. It will resume after reboot.")
	return nil
}

func currentBootstrapSID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errors.New("could not resolve enrolled Windows SID")
	}
	return user.User.Sid.String(), nil
}
func windowsAccountName(value string) string {
	value = filepath.Base(value)
	if value == "." || value == string(filepath.Separator) || value == "" {
		return "Paperboat"
	}
	return value
}
func windowsArtifactHTTPClient() *http.Client {
	return &http.Client{Transport: httptransport.Default(), Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
