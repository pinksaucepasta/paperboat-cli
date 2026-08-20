//go:build darwin || linux

package hostruntimecmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	helperconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/machinename"
)

var fetchBootstrapArtifact = bootstrap.FetchVerifiedArtifact

func runBootstrap(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", "", "Paperboat server URL")
	legacyToken := flags.String("enrollment-token", "", "dashboard enrollment token (deprecated; use --enrollment-token-file)")
	tokenFile := flags.String("enrollment-token-file", "", "absolute owner-only dashboard enrollment token file")
	name := flags.String("name", "", "User machine name")
	shell := flags.String("shell", "", "Absolute login shell (default: auto-detect)")
	stateRoot := flags.String("state-root", "", "Paperboat runtime state directory")
	acceptBetaPlatform := flags.Bool("accept-beta-platform", false, "accept enrollment on a beta platform")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("bootstrap accepts flags only")
	}
	if *legacyToken != "" && *tokenFile != "" {
		return errors.New("use only one enrollment token source")
	}
	token := strings.TrimSpace(*legacyToken)
	if *tokenFile != "" {
		var tokenErr error
		token, tokenErr = bootstrap.ReadEnrollmentTokenFile(*tokenFile)
		if tokenErr != nil {
			return errors.New("enrollment token file must be an absolute regular owner-only file")
		}
	}
	reader := bufio.NewReader(stdin)
	if err := promptBootstrapValue(reader, stderr, "User machine name", name); err != nil {
		return err
	}
	if err := machinename.Validate(strings.TrimSpace(*name)); err != nil {
		return fmt.Errorf("invalid machine name: %w", err)
	}
	account, err := user.Current()
	if err != nil || account.Username == "" {
		return errors.New("could not resolve enrolled user")
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil || group.Name == "" {
		return errors.New("could not resolve enrolled group")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 0 {
		return errors.New("could not resolve enrolled uid")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid < 0 {
		return errors.New("could not resolve enrolled gid")
	}
	if uid == 0 {
		if err := confirmRootBootstrap(reader, stderr); err != nil {
			return err
		}
	}
	resolvedShell, err := resolveUserShell(*shell, os.Getenv)
	if err != nil {
		return err
	}
	workspace, err := canonicalUserHome()
	if err != nil {
		return err
	}
	if *stateRoot == "" {
		root, err := helperconfig.DefaultStateRoot(os.Getenv)
		if err != nil {
			return err
		}
		*stateRoot = root
	}
	identityStore, err := identity.Open(identity.Config{StateRoot: *stateRoot})
	if err != nil {
		return err
	}
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return err
	}
	config := bootstrap.Config{ServerURL: *serverURL, EnrollmentToken: token, DisplayName: *name, WorkspaceRoot: workspace, Verifier: base64.RawURLEncoding.EncodeToString(verifierBytes), PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityStore.Current().Public()), RuntimeVersions: map[string]string{"pb": buildinfo.Version}, AcceptBetaPlatform: *acceptBetaPlatform}
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
	if err := saveBootstrapRegistration(identityStore, *serverURL, material, "", 0); err != nil {
		return fmt.Errorf("save machine registration: %w", err)
	}
	fmt.Fprintln(stderr, "Enrollment accepted. Setting up the managed host service...")
	client, err := enrollment.NewClient(nil, 15*time.Second)
	if err != nil {
		return errors.Join(err, reportInstallationFailureWithEnrollmentCredential(ctx, material, "artifact_verification"))
	}
	artifactHTTP := artifactHTTPClient()
	artifactPath, err := prepareInstallation(ctx, &material, *stateRoot, artifactHTTP, client)
	if err != nil {
		if !material.ReuseIdentity {
			return errors.Join(err, reportInstallationFailureWithEnrollmentCredential(ctx, material, "artifact_verification"))
		}
		return failBootstrapInstallation(ctx, err, material, *stateRoot, "artifact_verification")
	}
	executable := artifactPath
	home, err := os.UserHomeDir()
	if err != nil {
		return failBootstrapInstallation(ctx, err, material, *stateRoot, "service_install")
	}
	commandDirectory := filepath.Join(home, ".local", "bin")
	servicePath := os.Getenv("PATH")
	if !pathListContains(servicePath, commandDirectory) {
		servicePath = commandDirectory + string(os.PathListSeparator) + servicePath
	}
	installRequest := hostinstall.Request{
		Schema: hostinstall.SchemaV1, Platform: runtime.GOOS, User: account.Username, UID: uid, Group: group.Name, GID: gid,
		Executable: executable, Artifact: *material.Artifact,
		Home: home, Path: servicePath, StateRoot: *stateRoot, WorkspaceRoot: workspace, ControlURL: material.ControlURL,
		UserMachineID: material.UserMachineID, Shell: resolvedShell, HelperListenAddress: material.HelperListenAddress,
		SetupMode: "host",
	}
	previousGeneration := workerGeneration(*stateRoot)
	fmt.Fprintln(stderr, "Paperboat must run before login and while this account is logged out.")
	fmt.Fprintln(stderr, "Paperboat will keep this machine awake by default, including on battery and with the lid closed; this can increase battery use and heat.")
	fmt.Fprintln(stderr, "Administrator approval is required to install its durable system service.")
	installCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := authorizeServiceInstall(installCtx, executable, installRequest, stdin, stdout, stderr); err != nil {
		return failBootstrapInstallation(ctx, err, material, *stateRoot, "service_install")
	}
	workerCommand, err := installWorkerCommand(commandDirectory, systemWorkerExecutable())
	if err != nil {
		failureErr := errors.Join(err, authorizeServiceOperation(ctx, executable, "uninstall", installRequest, stdout, stderr))
		return failBootstrapInstallation(ctx, failureErr, material, *stateRoot, "service_install")
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 45*time.Second)
	defer readyCancel()
	healthClient := &http.Client{Timeout: 2 * time.Second}
	for {
		request, _ := http.NewRequestWithContext(readyCtx, http.MethodGet, "http://"+material.HelperListenAddress+"/healthz", nil)
		response, requestErr := healthClient.Do(request)
		if requestErr == nil && bootstrapWorkerReady(readyCtx, response, *stateRoot, material.Artifact.Version, previousGeneration) {
			if err := authorizeServiceOperation(ctx, executable, "commit", installRequest, stdout, stderr); err != nil {
				failureErr := errors.Join(err, authorizeServiceOperation(ctx, executable, "uninstall", installRequest, stdout, stderr), workerCommand.Rollback())
				return failBootstrapInstallation(ctx, failureErr, material, *stateRoot, "service_readiness")
			}
			if err := workerCommand.Commit(); err != nil {
				return &installationStageError{Stage: "service_install", Cause: fmt.Errorf("remove previous pb command backup: %w", err)}
			}
			fmt.Fprintln(stdout, "Paperboat host runtime is ready.")
			return nil
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		select {
		case <-readyCtx.Done():
			failureErr := errors.Join(errors.New("host service did not become ready"), authorizeServiceOperation(ctx, executable, "uninstall", installRequest, stdout, stderr), workerCommand.Rollback())
			return failBootstrapInstallation(ctx, failureErr, material, *stateRoot, "service_readiness")
		case <-time.After(time.Second):
		}
	}
}

func bootstrapWorkerReady(ctx context.Context, response *http.Response, stateRoot, expectedVersion string, previousGeneration uint64) bool {
	if response == nil || response.Body == nil {
		return false
	}
	defer response.Body.Close()
	if !bootstrapHealthMatches(response, expectedVersion) || workerGeneration(stateRoot) <= previousGeneration || !serverHeartbeatReady(stateRoot, expectedVersion, previousGeneration) {
		return false
	}
	_, err := systemServiceScope(ctx)
	return err == nil
}

func serverHeartbeatReady(stateRoot, expectedVersion string, previousGeneration uint64) bool {
	var receipt struct {
		Schema           string    `json:"schema"`
		WorkerGeneration uint64    `json:"worker_generation"`
		ReporterVersion  string    `json:"reporter_version"`
		AcceptedAt       time.Time `json:"accepted_at"`
	}
	if decodeStrictFile(filepath.Join(stateRoot, "runtime", "server-heartbeat.json"), 4096, &receipt) != nil {
		return false
	}
	return receipt.Schema == "paperboat.server-heartbeat/v1" && receipt.WorkerGeneration > previousGeneration && receipt.ReporterVersion == expectedVersion && !receipt.AcceptedAt.IsZero()
}

func bootstrapHealthMatches(response *http.Response, expectedVersion string) bool {
	var snapshot health.Snapshot
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	var extra any
	if response.StatusCode != http.StatusOK || decoder.Decode(&snapshot) != nil || decoder.Decode(&extra) != io.EOF || !snapshot.Live || snapshot.Version != expectedVersion {
		return false
	}
	return true
}

func workerGeneration(stateRoot string) uint64 {
	var state struct {
		Schema     string    `json:"schema"`
		OSBootID   string    `json:"os_boot_id"`
		Generation uint64    `json:"generation"`
		StartedAt  time.Time `json:"started_at"`
	}
	if decodeStrictFile(filepath.Join(stateRoot, "runtime", "worker-boot.json"), 4096, &state) != nil || state.Schema != "paperboat.worker-boot/v1" || state.OSBootID == "" || state.Generation < 1 || state.StartedAt.IsZero() {
		return 0
	}
	return state.Generation
}

type installationStageError struct {
	Stage string
	Cause error
}

func (e *installationStageError) Error() string {
	return "installation stage " + e.Stage + ": " + e.Cause.Error()
}
func (e *installationStageError) Unwrap() error { return e.Cause }

func failBootstrapInstallation(ctx context.Context, cause error, material bootstrap.Material, stateRoot, stage string) error {
	reportErr := reportInstallationFailure(ctx, material, stateRoot, stage)
	var cleanupErr error
	if !material.ReuseIdentity {
		cleanupErr = removeNewEnrollmentCredentials(stateRoot)
	}
	return &installationStageError{Stage: stage, Cause: errors.Join(cause, reportErr, cleanupErr)}
}

func removeNewEnrollmentCredentials(stateRoot string) error {
	if !filepath.IsAbs(stateRoot) {
		return bootstrap.ErrInvalid
	}
	info, err := os.Lstat(stateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return bootstrap.ErrInvalid
	}
	var result error
	for _, name := range []string{"runtime-identity.json"} {
		path := filepath.Join(stateRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			result = errors.Join(result, bootstrap.ErrInvalid)
			continue
		}
		result = errors.Join(result, os.Remove(path))
	}
	return result
}

func authorizeServiceInstall(ctx context.Context, executable string, request hostinstall.Request, stdin io.Reader, stdout, stderr io.Writer) error {
	return authorizeServiceOperation(ctx, executable, "install", request, stdout, stderr)
}

func authorizeServiceOperation(ctx context.Context, executable, operation string, request hostinstall.Request, stdout, stderr io.Writer) error {
	if !filepath.IsAbs(executable) {
		return hostinstall.ErrInvalidRequest
	}
	if operation != "install" && operation != "commit" && operation != "uninstall" {
		return hostinstall.ErrInvalidRequest
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", executable, "__runtime-service", operation)
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("administrator approval or service installation failed: %w", err)
	}
	return nil
}

func artifactHTTPClient() *http.Client {
	return &http.Client{Transport: httptransport.Default(), Timeout: 2 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) != 1 || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.User != nil ||
			!strings.EqualFold(via[0].URL.Hostname(), "github.com") ||
			!strings.EqualFold(request.URL.Hostname(), "release-assets.githubusercontent.com") {
			return bootstrap.ErrArtifactTarget
		}
		return nil
	}}
}

func canonicalUserHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("could not resolve an absolute user home directory")
	}
	home = filepath.Clean(home)
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil || resolved != home {
		return "", errors.New("user home directory must be canonical and non-symlinked")
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		return "", errors.New("user home directory must exist")
	}
	return home, nil
}

func resolveUserShell(explicit string, getenv func(string) string) (string, error) {
	candidates := []string{strings.TrimSpace(explicit)}
	if candidates[0] == "" && getenv != nil {
		candidates = append(candidates, strings.TrimSpace(getenv("SHELL")))
	}
	if candidates[0] == "" {
		candidates = append(candidates, accountLoginShell())
	}
	if candidates[0] == "" {
		candidates = append(candidates, "/bin/sh")
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		resolved, err := validateUserShell(candidate)
		if err == nil {
			return resolved, nil
		}
		if explicit != "" {
			return "", err
		}
	}
	return "", errors.New("could not detect an executable login shell; use --shell")
}

func validateUserShell(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("shell must be an absolute canonical path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("shell must be an executable regular file")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("shell must be an executable regular file")
	}
	return resolved, nil
}

func accountLoginShell() string {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return ""
	}
	if runtime.GOOS == "darwin" {
		output, err := exec.Command("dscl", ".", "-read", "/Users/"+current.Username, "UserShell").Output()
		if err == nil {
			return strings.TrimSpace(strings.TrimPrefix(string(output), "UserShell:"))
		}
	}
	output, err := exec.Command("getent", "passwd", current.Username).Output()
	if err != nil {
		return ""
	}
	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) != 7 {
		return ""
	}
	return fields[6]
}

type workerCommandInstallation struct {
	commandPath string
	backupPath  string
}

func installWorkerCommand(directory, artifact string) (*workerCommandInstallation, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(artifact) {
		return nil, bootstrap.ErrInvalid
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, bootstrap.ErrInvalid
	}
	commandPath := filepath.Join(directory, "pb")
	backupPath := filepath.Join(directory, fmt.Sprintf(".pb-backup-%d", time.Now().UnixNano()))
	previousExists := false
	if info, err = os.Lstat(commandPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0) {
			return nil, bootstrap.ErrInvalid
		}
		//paperboat:allow-source-policy atomic-replacement owner=runtime-bootstrap reason=command-backup-transition
		if err := os.Rename(commandPath, backupPath); err != nil {
			return nil, err
		}
		previousExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	temporary := filepath.Join(directory, fmt.Sprintf(".pb-%d", time.Now().UnixNano()))
	if err := os.Symlink(artifact, temporary); err != nil {
		if previousExists {
			//paperboat:allow-source-policy atomic-replacement owner=runtime-bootstrap reason=failed-symlink-rollback
			_ = os.Rename(backupPath, commandPath)
		}
		return nil, err
	}
	defer os.Remove(temporary)
	//paperboat:allow-source-policy atomic-replacement owner=runtime-bootstrap reason=command-symlink-activation
	if err := os.Rename(temporary, commandPath); err != nil {
		if previousExists {
			//paperboat:allow-source-policy atomic-replacement owner=runtime-bootstrap reason=activation-failure-rollback
			_ = os.Rename(backupPath, commandPath)
		}
		return nil, err
	}
	if !previousExists {
		backupPath = ""
	}
	return &workerCommandInstallation{commandPath: commandPath, backupPath: backupPath}, nil
}

func (i *workerCommandInstallation) Commit() error {
	if i.backupPath == "" {
		return nil
	}
	return os.Remove(i.backupPath)
}

func (i *workerCommandInstallation) Rollback() error {
	removeErr := os.Remove(i.commandPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if i.backupPath == "" {
		return removeErr
	}
	//paperboat:allow-source-policy atomic-replacement owner=runtime-bootstrap reason=explicit-command-rollback
	return errors.Join(removeErr, os.Rename(i.backupPath, i.commandPath))
}

func pathListContains(value, want string) bool {
	for _, entry := range filepath.SplitList(value) {
		if entry == want {
			return true
		}
	}
	return false
}

func reportInstallationFailure(ctx context.Context, material bootstrap.Material, stateRoot, stage string) error {
	return reportInstallationFailureWithClient(ctx, material, stateRoot, stage, &http.Client{Transport: httptransport.Default(), Timeout: 5 * time.Second})
}

func reportInstallationFailureWithClient(ctx context.Context, material bootstrap.Material, stateRoot, stage string, client *http.Client) error {
	identity, err := enrollment.LoadRuntimeIdentity(stateRoot, time.Now().UTC())
	if err != nil {
		return err
	}
	if identity.HelperID != material.HelperID || identity.EnvironmentID != material.EnvironmentID {
		return bootstrap.ErrInvalid
	}
	body, err := json.Marshal(struct {
		EnrollmentID       string `json:"enrollment_id"`
		HelperID           string `json:"helper_id"`
		HelperEnrollmentID string `json:"helper_enrollment_id"`
		Stage              string `json:"stage"`
	}{material.UserMachineEnrollmentID, material.HelperID, material.EnrollmentID, stage})
	if err != nil {
		return err
	}
	operationID := "install-failure-" + material.UserMachineEnrollmentID + "-" + stage
	proof, err := (enrollment.ProofSource{StateRoot: stateRoot}).Proof(ctx, operationID, http.MethodPost, "/v1/machine-installation-failures", body)
	if err != nil {
		return err
	}
	base := strings.TrimRight(material.ControlURL, "/") + "/v1/machine-installation-failures"
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, base, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+identity.Credential)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("installation failure report returned HTTP %d", response.StatusCode)
	}
	return nil
}

func reportInstallationFailureWithEnrollmentCredential(ctx context.Context, material bootstrap.Material, stage string) error {
	return reportInstallationFailureWithEnrollmentCredentialClient(ctx, material, stage, &http.Client{Transport: httptransport.Default(), Timeout: 5 * time.Second})
}

func reportInstallationFailureWithEnrollmentCredentialClient(ctx context.Context, material bootstrap.Material, stage string, client *http.Client) error {
	body, err := json.Marshal(struct {
		EnrollmentID       string `json:"enrollment_id"`
		HelperID           string `json:"helper_id"`
		HelperEnrollmentID string `json:"helper_enrollment_id"`
		Stage              string `json:"stage"`
	}{material.UserMachineEnrollmentID, material.HelperID, material.EnrollmentID, stage})
	if err != nil {
		return err
	}
	base := strings.TrimRight(material.ControlURL, "/") + "/v1/machine-installation-failures"
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, base, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+material.EnrollmentCredential)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("installation failure report returned HTTP %d", response.StatusCode)
	}
	return nil
}

type enrollmentClient interface {
	Enroll(context.Context, enrollment.Config) (enrollment.RuntimeIdentity, error)
}

type serviceInstaller interface {
	Install(context.Context) error
}

func installService(ctx context.Context, installer serviceInstaller, attempts int, delay time.Duration) error {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if lastErr = installer.Install(ctx); lastErr == nil {
			return nil
		}
		if attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func prepareInstallation(ctx context.Context, material *bootstrap.Material, stateRoot string, artifactHTTP *http.Client, client enrollmentClient) (string, error) {
	if material.ReuseIdentity {
		identity, err := enrollment.LoadRuntimeIdentityForRenewal(stateRoot, time.Now().UTC())
		if err != nil || identity.HelperID != material.HelperID || identity.EnvironmentID != material.EnvironmentID {
			return "", bootstrap.ErrInvalid
		}
	}
	artifactPath, err := fetchBootstrapArtifact(ctx, *material.Artifact, filepath.Join(stateRoot, "tuf"), artifactHTTP)
	if err != nil {
		return "", err
	}
	if material.ReuseIdentity {
		return artifactPath, nil
	}
	if _, err := client.Enroll(ctx, enrollment.Config{ControlURL: material.ControlURL, StateRoot: stateRoot, EnrollmentCredential: material.EnrollmentCredential}); err != nil {
		_ = os.Remove(artifactPath)
		return "", err
	}
	material.EnrollmentCredential = ""
	return artifactPath, nil
}

func confirmRootBootstrap(reader *bufio.Reader, output io.Writer) error {
	fmt.Fprintln(output, "Warning: installing Paperboat for root gives remote terminal sessions, processes, and configuration full control of this machine.")
	fmt.Fprint(output, "Type \"yes\" to install and run Paperboat as root: ")
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(line) != "yes" {
		return errors.New("root installation was not confirmed")
	}
	return nil
}
