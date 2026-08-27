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
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
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
	setupMode := flags.String("setup-mode", "host", "enrollment role: host or client")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("bootstrap accepts flags only")
	}
	if *setupMode != "host" && *setupMode != "client" {
		return errors.New("setup-mode must be host or client")
	}
	if *legacyToken != "" && *tokenFile != "" {
		return errors.New("use only one enrollment token source")
	}
	token := strings.TrimSpace(*legacyToken)
	var tokenFileErr error
	if *tokenFile != "" {
		token, tokenFileErr = bootstrap.ReadEnrollmentTokenFile(*tokenFile)
		if tokenFileErr != nil {
			// A token file is consumed as soon as the server accepts pairing.
			// Defer this error until after the local resume journal is checked;
			// otherwise a failed first install could never resume.
			token = ""
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
	publicIdentityKey := base64.RawURLEncoding.EncodeToString(identityStore.Current().Public())
	resume, resumeErr := bootstrap.LoadResume(*stateRoot, *serverURL, publicIdentityKey, token, *name, *setupMode, time.Now().UTC())
	resumeExpired := errors.Is(resumeErr, bootstrap.ErrResumeExpired)
	if errors.Is(resumeErr, bootstrap.ErrResumeExpired) {
		if !resume.PairingStarted {
			if resume.AuthenticatedSetup {
				return bootstrap.ErrResumeExpired
			}
			if err := bootstrap.ClearResume(*stateRoot); err != nil {
				return fmt.Errorf("clear expired unpaired machine enrollment state: %w", err)
			}
			resumeErr = bootstrap.ErrResumeNotFound
		} else {
			// A paired verifier remains the only safe recovery binding after a
			// one-shot token is consumed. Keep the journal and ask the server to
			// renew/replay material for that verifier, even after local expiry.
			resumeErr = nil
		}
	}
	if errors.Is(resumeErr, bootstrap.ErrResumeTokenRequired) {
		return errors.New("the previous Windows enrollment has not reached server pairing; provide the original enrollment token file to resume it")
	}
	if resumeErr != nil && !errors.Is(resumeErr, bootstrap.ErrResumeNotFound) {
		return resumeErr
	}
	if errors.Is(resumeErr, bootstrap.ErrResumeNotFound) && tokenFileErr != nil {
		return errors.New("enrollment token file must be an absolute regular non-reparse file")
	}
	// Reusable means the bound identity can prove a renewal, including after
	// expiry. Reuse material is always passed through the renewing token source
	// below before it is treated as ready for machine-control bootstrap.
	_, reusableIdentityErr := enrollment.LoadRuntimeIdentityForRenewal(*stateRoot, time.Now().UTC())
	sshConfig := windowsopenssh.DefaultConfig(nil)
	if errors.Is(resumeErr, bootstrap.ErrResumeNotFound) {
		verifier := make([]byte, 32)
		if _, err := rand.Read(verifier); err != nil {
			return err
		}
		config := bootstrap.Config{ServerURL: *serverURL, EnrollmentToken: token, DisplayName: *name, WorkspaceRoot: home, Verifier: base64.RawURLEncoding.EncodeToString(verifier), PublicIdentityKey: publicIdentityKey, RuntimeVersions: map[string]string{"pb": buildinfo.Version}, SSHUser: windowsAccountName(account.Username), SSHPort: sshConfig.Port, CanReuseRuntimeIdentity: reusableIdentityErr == nil}
		resume = bootstrap.NewResumeRecord(*serverURL, publicIdentityKey, token, *name, *setupMode, config.Verifier, time.Now().UTC().Add(15*time.Minute))
		if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
			return fmt.Errorf("persist machine enrollment resume state: %w", err)
		}
	}
	var material bootstrap.Material
	if resume.Material != nil && !resumeExpired {
		material = *resume.Material
	} else {
		config := bootstrap.Config{ServerURL: resume.ServerURL, EnrollmentToken: token, DisplayName: resume.DisplayName, WorkspaceRoot: home, Verifier: resume.Verifier, PublicIdentityKey: publicIdentityKey, RuntimeVersions: map[string]string{"pb": buildinfo.Version}, SSHUser: windowsAccountName(account.Username), SSHPort: sshConfig.Port, CanReuseRuntimeIdentity: reusableIdentityErr == nil}
		if resume.PairingStarted {
			fmt.Fprintln(stderr, "Resuming one-shot machine enrollment...")
		}
		// Poll before creating a pairing whenever a journal exists. This closes
		// the crash window where CreatePairing committed on the server but the
		// client lost its response or could not persist the returned Pairing.
		if resume.AuthenticatedSetup {
			material, err = recoverAuthenticatedSetupMaterial(ctx, config, resume, resumeExpired, defaultOneShotResumeOperations())
		} else if resumeExpired {
			material, err = bootstrap.RecoverMaterial(ctx, config, resume.RuntimeEnrolled)
		} else {
			material, err = bootstrap.WaitForMaterial(ctx, config, resume.PairingExpiresAt, 2*time.Second)
		}
		if !resume.AuthenticatedSetup && errors.Is(err, bootstrap.ErrInstallationUnavailable) {
			if resumeExpired && resume.PairingStarted {
				// Never replace an expired paired journal with a new enrollment.
				// Its verifier is the durable recovery binding for the server-issued
				// machine and account.
				return bootstrap.ErrResumeExpired
			}
			if resume.RequiresEnrollmentTokenForRetry(token) {
				return bootstrap.ErrResumeTokenRequired
			}
			resume.PairingStarted = true
			if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
				return fmt.Errorf("persist machine pairing state: %w", err)
			}
			pairing, pairErr := bootstrap.CreatePairing(ctx, config)
			if pairErr != nil {
				// Keep the journal on every pairing error. A network or malformed
				// response can occur after the server has committed the one-shot
				// pairing, and the next run must poll the same verifier first.
				return pairErr
			}
			resume.PairingExpiresAt = pairing.ExpiresAt
			if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
				return fmt.Errorf("persist machine pairing state: %w", err)
			}
			if *tokenFile != "" && tokenFileErr == nil {
				if err := bootstrap.ConsumeEnrollmentTokenFile(*tokenFile); err != nil {
					return fmt.Errorf("consume enrollment token file: %w", err)
				}
			}
			fmt.Fprintln(stderr, "Completing one-shot machine enrollment...")
			material, err = bootstrap.WaitForMaterial(ctx, config, pairing.ExpiresAt, 2*time.Second)
		}
		if err != nil {
			return err
		}
		if resume.Material != nil {
			if err := bootstrap.ValidateRecoveredMaterial(*resume.Material, material, resume.RuntimeEnrolled); err != nil {
				return err
			}
		}
		if resume.AuthenticatedSetup {
			if err := bootstrap.ValidateAuthenticatedSetupMaterial(resume, material); err != nil {
				return err
			}
		}
		resume.PairingStarted = true
		resume.Material = &material
		if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
			return fmt.Errorf("persist machine enrollment material: %w", err)
		}
	}
	if *tokenFile != "" && tokenFileErr == nil {
		if err := bootstrap.ConsumeEnrollmentTokenFile(*tokenFile); err != nil {
			return fmt.Errorf("consume enrollment token file: %w", err)
		}
	}
	if resume.AuthenticatedSetup {
		if err := bootstrap.ValidateAuthenticatedSetupMaterial(resume, material); err != nil {
			return err
		}
	}
	if err := saveBootstrapRegistration(identityStore, *serverURL, material, windowsAccountName(account.Username), sshConfig.Port); err != nil {
		return fmt.Errorf("save machine registration: %w", err)
	}
	// Both modes receive the local CLI profile and daemon. Host mode then adds
	// the managed runtime below; the server-issued CLI session is bound to this
	// enrollment's independent endpoint identity.
	if shouldInstallBootstrapCLI(material) && !resume.ClientInstalled {
		if err := installBootstrapCLI(ctx, material.ClientSession, *serverURL); err != nil {
			return fmt.Errorf("initialize Paperboat CLI session: %w", err)
		}
		resume.ClientInstalled = true
		if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
			return fmt.Errorf("persist CLI enrollment progress: %w", err)
		}
	}
	artifactPath, err := prepareWindowsBootstrapRuntime(ctx, material.ReuseIdentity, resume.RuntimeEnrolled, func(ctx context.Context) error {
		return ensureWindowsRuntimeEnrollment(ctx, material, *stateRoot)
	}, func() error {
		resume.RuntimeEnrolled = true
		if err := bootstrap.SaveResume(*stateRoot, resume); err != nil {
			return fmt.Errorf("persist runtime enrollment progress: %w", err)
		}
		return nil
	}, func(ctx context.Context) error {
		if err := ensureWindowsMachineControl(ctx, material, *stateRoot); err != nil {
			return fmt.Errorf("persist machine control credential: %w", err)
		}
		return nil
	}, func(ctx context.Context) (string, error) {
		return bootstrap.FetchVerifiedArtifact(ctx, *material.Artifact, filepath.Join(*stateRoot, "tuf"), windowsArtifactHTTPClient())
	})
	if err != nil {
		return err
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
	// The one-shot installer invokes pb from the active installed slot. Windows
	// keeps that image open, so the elevated commit process must run from a
	// separate copy before it rotates the active slot.
	// The runtime state root is protected for credential custody and may be
	// unreadable to an elevated administrator token. Stage the elevation copy
	// in the user's temporary directory instead; it is still removed before
	// bootstrap returns and never becomes an installed runtime artifact.
	elevated, err := os.CreateTemp("", ".pb-elevated-*.exe")
	if err != nil {
		return fmt.Errorf("stage executable for administrator approval: %w", err)
	}
	elevatedPath := elevated.Name()
	defer os.Remove(elevatedPath)
	source, err := os.Open(executable)
	if err != nil {
		elevated.Close()
		return fmt.Errorf("open executable for administrator approval: %w", err)
	}
	_, copyErr := io.Copy(elevated, source)
	closeSourceErr := source.Close()
	closeElevatedErr := elevated.Close()
	if copyErr != nil || closeSourceErr != nil || closeElevatedErr != nil {
		return fmt.Errorf("copy executable for administrator approval: %w", errors.Join(copyErr, closeSourceErr, closeElevatedErr))
	}
	if err := elevation.RunRuntimeService(ctx, elevatedPath, elevation.ActionInstallCommit, request); err != nil {
		return fmt.Errorf("install Paperboat Windows host runtime: %w", err)
	}
	if err := bootstrap.ClearResume(*stateRoot); err != nil {
		return fmt.Errorf("clear completed machine enrollment resume state: %w", err)
	}
	fmt.Fprintln(stdout, "Paperboat Windows host runtime is installed. It will resume after reboot.")
	return nil
}

func ensureWindowsRuntimeEnrollment(ctx context.Context, material bootstrap.Material, stateRoot string) error {
	now := time.Now().UTC()
	runtimeIdentity, loadErr := enrollment.LoadRuntimeIdentity(stateRoot, now)
	renewableIdentity := runtimeIdentity
	renewalLoadErr := loadErr
	if loadErr != nil {
		renewableIdentity, renewalLoadErr = enrollment.LoadRuntimeIdentityForRenewal(stateRoot, now)
	}
	action, err := planRuntimeEnrollment(runtimeIdentity, loadErr, renewableIdentity, renewalLoadErr, material)
	if err != nil {
		return err
	}
	switch action {
	case runtimeEnrollmentReuse:
		return nil
	case runtimeEnrollmentRenew:
		source, sourceErr := enrollment.NewRenewingTokenSource(enrollment.RenewingTokenConfig{
			ControlURL: material.ControlURL,
			StateRoot:  stateRoot,
			Transport:  httptransport.Default(),
			Timeout:    15 * time.Second,
			OperationID: func() (string, error) {
				var value [16]byte
				if _, err := rand.Read(value[:]); err != nil {
					return "", err
				}
				return "bootstrap-runtime-renew-" + base64.RawURLEncoding.EncodeToString(value[:]), nil
			},
		})
		if sourceErr != nil {
			return sourceErr
		}
		if _, err = source.Token(ctx); err != nil {
			return err
		}
		readyIdentity, readyErr := enrollment.LoadRuntimeIdentity(stateRoot, time.Now().UTC())
		if readyErr != nil || !runtimeIdentityMatches(readyIdentity, material) {
			return errors.New("renewed runtime identity is unavailable or mismatched")
		}
		return nil
	case runtimeEnrollmentEnroll:
		client, clientErr := enrollment.NewClient(nil, 15*time.Second)
		if clientErr != nil {
			return clientErr
		}
		_, err = client.Enroll(ctx, enrollment.Config{ControlURL: material.ControlURL, StateRoot: stateRoot, EnrollmentCredential: material.EnrollmentCredential})
		return err
	default:
		return errors.New("runtime enrollment action is invalid")
	}
}

func ensureWindowsMachineControl(ctx context.Context, material bootstrap.Material, stateRoot string) error {
	// Machine-control credentials are host-only. Client enrollments must not
	// mint one, while Windows hosts need the same initial credential bootstrap
	// as Unix hosts before their managed service starts.
	if material.SetupMode != "host" {
		return nil
	}
	source, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: material.ControlURL, StateRoot: stateRoot, Timeout: 15 * time.Second})
	if err != nil {
		return err
	}
	_, err = source.EnsureInitial(ctx)
	return err
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
