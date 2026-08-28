//go:build windows

package hostruntimecmd

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	gort "runtime"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntimeentry"
	"github.com/pinksaucepasta/paperboat/internal/processlaunch"
	"github.com/pinksaucepasta/paperboat/internal/windows/previewbroker"
	"golang.org/x/sys/windows"
)

const windowsOwnerWorkloadEnvironment = "PAPERBOAT_WINDOWS_OWNER_WORKLOAD"

// runHostd owns Windows workloads for the service lifetime and starts the
// replaceable worker only through the authenticated named-pipe fence.
func runHostd(ctx context.Context, output io.Writer) (err error) {
	defer func() {
		if err != nil {
			recordWindowsServiceLaunchFailure("PaperboatHostd-worker", err)
		}
	}()
	return runHostdInner(ctx, output)
}

func runHostdInner(ctx context.Context, output io.Writer) error {
	install, err := windowsRuntimeInstallConfig()
	if err != nil {
		return err
	}
	// The SCM parent launches the owner workload with CreateProcessAsUser.
	// That child is deliberately not an SCM service process. Relying solely on
	// an inherited environment marker is fragile on Windows because token
	// environment construction can omit overrides under S4U. Use the process
	// context as the authoritative boundary, while retaining the marker for
	// explicit diagnostics and older service environments.
	if os.Getenv(windowsOwnerWorkloadEnvironment) != "1" {
		// CreateProcessAsUser intentionally launches the owner workload without
		// the SCM dispatcher. On Windows, svc.IsWindowsService can still report
		// true for that detached process because it has no console, so the SID is
		// the authoritative boundary. LocalSystem, which owns the SCM parent,
		// cannot match the enrolled owner SID and continues into the dispatcher.
		if sid, sidErr := currentWindowsSID(); sidErr == nil && sid == install.OwnerSID {
			return runOwnerHostd(ctx, output, install)
		}
		return runWindowsHostdService(install)
	}
	if sid, sidErr := currentWindowsSID(); sidErr != nil || sid != install.OwnerSID {
		return errors.New("Paperboat Windows hostd workload is not running as the enrolled owner")
	}
	return runOwnerHostd(ctx, output, install)
}

func windowsHostdWorkerEnvironment(install hostinstall.WindowsRuntimeConfig, layout service.Layout, runtimeExecutable string) (map[string]string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	shell := filepath.Join(systemDirectory, "cmd.exe")
	if err := validateWindowsWorkerExecutable(shell); err != nil {
		return nil, errors.Join(errors.New("Paperboat Windows command shell is unavailable"), err)
	}
	return map[string]string{
		windowsOwnerWorkloadEnvironment:    "1",
		"PAPERBOAT_WINDOWS_OWNER_SID":      install.OwnerSID,
		"PAPERBOAT_HOSTD_SOCKET":           layout.HostdSocket,
		"PAPERBOAT_HOSTD_TOKEN_FILE":       install.TokenFile,
		"PAPERBOAT_RUNTIME_CURRENT":        runtimeExecutable,
		"PAPERBOAT_RUNTIME_STATE_ROOT":     install.StateRoot,
		"PAPERBOAT_WORKSPACE_ROOT":         install.Workspace,
		"PAPERBOAT_CONTROL_URL":            install.ControlURL,
		"PAPERBOAT_RUNTIME_LISTEN_ADDRESS": install.ListenAddress,
		"PAPERBOAT_MACHINE_ID":             install.MachineID,
		"PAPERBOAT_SETUP_MODE":             install.SetupMode,
		"PAPERBOAT_RUNTIME_SERVICE_SCOPE":  "user",
		// CreateEnvironmentBlock does not guarantee ComSpec for S4U and
		// service-created owner tokens. Pin the native system shell explicitly;
		// the production host validates this value before starting any session.
		"PAPERBOAT_SHELL": shell,
	}, nil
}

// runWindowsHostdService is the only SCM-facing hostd path. The child marker
// is generated here, not accepted from the installed service definition, so a
// LocalSystem process cannot accidentally run the workload itself.
func runWindowsHostdService(install hostinstall.WindowsRuntimeConfig) error {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	hostdExecutable, runtimeExecutable := layout.Binary, layout.Binary
	environment, err := windowsHostdWorkerEnvironment(install, layout, runtimeExecutable)
	if err != nil {
		return err
	}
	token, err := readWindowsHostdTokenForSID(install.TokenFile, install.OwnerSID)
	if err != nil {
		return err
	}
	brokerToken := previewbroker.DeriveToken(token)
	return service.RunWindowsService(service.ServiceEntryConfig{
		Name:        "PaperboatHostd",
		Executable:  hostdExecutable,
		Arguments:   []string{"__runtime-hostd"},
		EnrolledSID: install.OwnerSID,
		Environment: environment,
		LaunchFailure: func(err error) {
			recordWindowsServiceLaunchFailure("PaperboatHostd", err)
		},
		StartPrivilegedSidecar: func(ctx context.Context) (service.PrivilegedSidecar, error) {
			sidecarCtx, cancelSidecars := context.WithCancel(ctx)
			results := make(chan error, 2)
			previewReady := make(chan struct{})
			availabilityReady := make(chan struct{})
			updateDiagnostics, err := hostservice.NewWindowsUpdateDiagnostics(layout.UpdateStateRoot, install.MachineID)
			if err != nil {
				cancelSidecars()
				return service.PrivilegedSidecar{}, err
			}
			authorizedKeys, err := hostservice.NewWindowsAuthorizedKeys()
			if err != nil {
				cancelSidecars()
				return service.PrivilegedSidecar{}, err
			}
			availability, err := hostservice.New(hostservice.Config{
				SocketPath:        hostservice.DefaultSocketPath(),
				StatePath:         filepath.Join(hostinstall.WindowsProgramDataRoot(), "availability-policy.json"),
				SID:               install.OwnerSID,
				Applier:           hostservice.NewPlatformApplier(filepath.Join(hostinstall.WindowsProgramDataRoot(), "power-baseline.json")),
				Version:           buildinfo.Version,
				UpdateDiagnostics: updateDiagnostics,
				AuthorizedKeys:    authorizedKeys,
				Ready: func() error {
					close(availabilityReady)
					return nil
				},
			})
			if err != nil {
				cancelSidecars()
				return service.PrivilegedSidecar{}, err
			}
			go func() {
				results <- (previewbroker.Server{OwnerSID: install.OwnerSID, Token: brokerToken, Ready: previewReady, Handle: func(callCtx context.Context, payload []byte) error {
					return hostruntimeentry.ApplyEncodedWindowsPreviewMutation(callCtx, payload)
				}}).Run(sidecarCtx)
			}()
			go func() { results <- availability.Run(sidecarCtx) }()
			for previewReady != nil || availabilityReady != nil {
				select {
				case sidecarErr := <-results:
					cancelSidecars()
					return service.PrivilegedSidecar{}, sidecarErr
				case <-previewReady:
					previewReady = nil
				case <-availabilityReady:
					availabilityReady = nil
				case <-time.After(15 * time.Second):
					cancelSidecars()
					return service.PrivilegedSidecar{}, errors.New("Windows privileged host sidecars did not become ready")
				}
			}
			done := make(chan error, 1)
			go func() {
				first := <-results
				cancelSidecars()
				second := <-results
				done <- errors.Join(first, second)
			}()
			return service.PrivilegedSidecar{Done: done}, nil
		},
	})
}

func recordWindowsServiceLaunchFailure(name string, err error) {
	message := "unknown startup failure"
	if err != nil {
		message = err.Error()
	}
	message = strings.NewReplacer("\r", " ", "\n", " ").Replace(message)
	if len(message) > 2048 {
		message = message[:2048]
	}
	_ = os.WriteFile(filepath.Join(hostinstall.WindowsProgramDataRoot(), name+"-startup-error.log"), []byte(message+"\n"), 0o600)
}

func runOwnerHostd(ctx context.Context, output io.Writer, install hostinstall.WindowsRuntimeConfig) error {
	if handled, err := runWindowsHostdNativeE2E(ctx, install); handled {
		return err
	}
	socket, tokenPath, executable := os.Getenv("PAPERBOAT_HOSTD_SOCKET"), os.Getenv("PAPERBOAT_HOSTD_TOKEN_FILE"), os.Getenv("PAPERBOAT_RUNTIME_CURRENT")
	if socket == "" {
		socket = `\\.\pipe\PaperboatHostd`
	}
	if tokenPath == "" {
		tokenPath = install.TokenFile
	}
	if executable == "" {
		layout, layoutErr := service.DefaultLayout("windows")
		if layoutErr != nil {
			return layoutErr
		}
		executable = layout.Binary
	}
	if !validWindowsPipe(socket) {
		return fmt.Errorf("hostd worker named-pipe configuration is invalid: %q", socket)
	}
	if !filepath.IsAbs(tokenPath) || filepath.Clean(tokenPath) != tokenPath {
		return errors.New("hostd worker token-file configuration is invalid")
	}
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return errors.New("hostd worker executable configuration is invalid")
	}
	token, err := readWindowsHostdTokenForSID(tokenPath, install.OwnerSID)
	if err != nil {
		return err
	}
	if err := validateWindowsWorkerExecutable(executable); err != nil {
		return err
	}
	sid := install.OwnerSID
	if sid == "" {
		sid, err = currentWindowsSID()
		if err != nil {
			return err
		}
	}
	host, err := hostruntime.NewProductionHost(ctx, buildinfo.Version, os.Getenv)
	if err != nil {
		return err
	}
	if err := host.StartStable(ctx); err != nil {
		return err
	}
	statePath, err := windowsHostdFencePath()
	if err != nil {
		shutdownWindowsStableHost(host)
		return err
	}
	if err := ensureWindowsHostdStateDirectory(filepath.Dir(statePath), sid); err != nil {
		shutdownWindowsStableHost(host)
		return err
	}
	server, err := hostdproto.NewServer(hostdproto.SocketConfig{SocketPath: socket, StatePath: statePath, SID: sid, Token: token, APIMin: 1, APIMax: 1, Workloads: host.WorkloadStatus})
	if err != nil {
		shutdownWindowsStableHost(host)
		return err
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	if err := waitForWindowsHostdPipe(ctx, socket, token, serverDone); err != nil {
		stopServer()
		shutdownWindowsStableHost(host)
		return err
	}
	worker, err := startWindowsRuntimeWorker(ctx, executable, socket, tokenPath, "runtime-"+strings.ReplaceAll(buildinfo.Version, " ", "-"))
	if err == nil {
		_, err = worker.Ready(ctx)
	}
	if err == nil {
		_, err = worker.Activate(ctx)
	}
	if err != nil {
		if worker != nil {
			_ = worker.Stop(context.Background())
		}
		stopServer()
		shutdownWindowsStableHost(host)
		return err
	}
	fmt.Fprintln(output, "pb hostd ready")
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stopErr := worker.Stop(shutdownCtx)
	stopServer()
	serverErr := <-serverDone
	return errors.Join(stopErr, serverErr, host.ShutdownStable(shutdownCtx))
}

func ensureWindowsHostdStateDirectory(path, sidValue string) error {
	sid, err := windows.StringToSid(sidValue)
	if err != nil || sid == nil || !sid.IsValid() || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("hostd state directory configuration is invalid")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("hostd state directory is unsafe")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sidValue + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := setWindowsHostdStateSecurity(path, sid, dacl); err != nil {
		return err
	}
	// Older SYSTEM-owned hostd releases created the persisted fence with an
	// Administrators owner. Repair that exact owned state during upgrade before
	// the owner-scoped worker validates it.
	fencePath := filepath.Join(path, "fence.json")
	if info, statErr := os.Lstat(fencePath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("hostd fence state is unsafe")
		}
		if err := setWindowsHostdStateSecurity(fencePath, sid, dacl); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return nil
}

func setWindowsHostdStateSecurity(path string, owner *windows.SID, dacl *windows.ACL) error {
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

func runWorker(ctx context.Context, args []string, input io.Reader, output, stderr io.Writer) error {
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "", "hostd lifecycle named pipe")
	tokenPath := flags.String("token-file", "", "hostd capability token")
	workerID := flags.String("worker-id", "", "runtime worker identity")
	version := flags.String("version", buildinfo.Version, "runtime version")
	apiMin := flags.Uint("api-min", 1, "minimum hostd API")
	apiMax := flags.Uint("api-max", 1, "maximum hostd API")
	heartbeat := flags.Duration("heartbeat", 5*time.Second, "hostd heartbeat interval")
	waitActivation := flags.Bool("wait-activation", false, "wait for private supervisor activation")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validWindowsPipe(*socket) || !filepath.IsAbs(*tokenPath) || filepath.Clean(*tokenPath) != *tokenPath || *workerID == "" || *version == "" || *apiMin == 0 || *apiMin > 1024 || *apiMax < *apiMin || *apiMax > 1024 || *heartbeat < time.Second || *heartbeat > time.Minute {
		return errors.New("invalid worker invocation")
	}
	token, err := readWindowsHostdToken(*tokenPath)
	if err != nil {
		return err
	}
	client, err := hostdproto.NewClient(*socket, token, 5*time.Second)
	if err != nil {
		return err
	}
	candidate, err := hostdproto.NewCandidate(client, *workerID, *version, uint16(*apiMin), uint16(*apiMax))
	if err != nil {
		return err
	}
	ready, err := candidate.Ready(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "ready %d %d\n", ready.Epoch, ready.APIVersion)
	if *waitActivation {
		if err := awaitWindowsWorkerActivation(ctx, input); err != nil {
			return err
		}
	}
	active, err := candidate.Activate(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "active %d %d\n", active.Epoch, active.APIVersion)
	ticker := time.NewTicker(*heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := candidate.Heartbeat(ctx); err != nil {
				return fmt.Errorf("hostd worker heartbeat: %w", err)
			}
		}
	}
}

func awaitWindowsWorkerActivation(ctx context.Context, input io.Reader) error {
	activation := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 64)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			activation <- err
			return
		}
		if line != "activate\n" {
			activation <- errors.New("invalid worker activation")
			return
		}
		activation <- nil
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-activation:
		return err
	}
}

func currentWindowsSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errors.New("Windows hostd enrolled SID is unavailable")
	}
	return user.User.Sid.String(), nil
}

func windowsHostdFencePath() (string, error) {
	if value := os.Getenv("PAPERBOAT_HOSTD_FENCE_FILE"); value != "" {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return "", errors.New("Paperboat Windows hostd fence path is invalid")
		}
		return value, nil
	}
	root := os.Getenv("PAPERBOAT_RUNTIME_STATE_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("Paperboat Windows runtime state path is invalid")
	}
	return filepath.Join(root, "hostd", "fence.json"), nil
}

func validWindowsPipe(value string) bool {
	return strings.HasPrefix(strings.ToLower(value), `\\.\pipe\`) && len(value) > len(`\\.\pipe\`) && !strings.ContainsAny(value, "\x00\r\n")
}

func validateWindowsWorkerExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return errors.New("Paperboat Windows runtime executable is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Paperboat Windows runtime executable is unavailable")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("Paperboat Windows runtime executable is unsafe")
	}
	return nil
}

func waitForWindowsHostdPipe(ctx context.Context, socket string, token []byte, done <-chan error) error {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		client, err := hostdproto.NewClient(socket, token, time.Second)
		if err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			_, err = client.Active(probeCtx)
			cancel()
			if err == nil {
				return nil
			}
		}
		select {
		case serverErr := <-done:
			return serverErr
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("hostd lifecycle named pipe did not become ready")
		case <-tick.C:
		}
	}
}

func shutdownWindowsStableHost(host *hostruntime.Host) {
	if host == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = host.ShutdownStable(ctx)
}

type windowsRuntimeWorker struct {
	command  *exec.Cmd
	control  io.WriteCloser
	lines    *bufio.Reader
	workerID string
	mu       sync.Mutex
	ready    hostdproto.Status
}

func startWindowsRuntimeWorker(ctx context.Context, executable, socket, tokenPath, workerID string) (*windowsRuntimeWorker, error) {
	command := exec.CommandContext(ctx, executable, "__runtime-worker", "--socket", socket, "--token-file", tokenPath, "--worker-id", workerID, "--version", buildinfo.Version, "--api-min", "1", "--api-max", "1", "--wait-activation")
	processlaunch.ConfigureBackground(command)
	control, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = control.Close()
		return nil, err
	}
	return &windowsRuntimeWorker{command: command, control: control, lines: bufio.NewReader(io.LimitReader(stdout, 128)), workerID: workerID}, nil
}

func (w *windowsRuntimeWorker) Ready(ctx context.Context) (hostdproto.Status, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready.Epoch != 0 {
		return w.ready, nil
	}
	line, err := readWindowsWorkerLine(ctx, w.lines)
	if err != nil {
		return hostdproto.Status{}, err
	}
	status, err := parseWindowsWorkerStatus(line, "ready", w.workerID)
	if err == nil {
		w.ready = status
	}
	return status, err
}

func (w *windowsRuntimeWorker) Activate(ctx context.Context) (hostdproto.Status, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready.Epoch == 0 || w.control == nil {
		return hostdproto.Status{}, errors.New("worker is not ready")
	}
	if _, err := io.WriteString(w.control, "activate\n"); err != nil {
		return hostdproto.Status{}, err
	}
	if err := w.control.Close(); err != nil {
		return hostdproto.Status{}, err
	}
	w.control = nil
	line, err := readWindowsWorkerLine(ctx, w.lines)
	if err != nil {
		return hostdproto.Status{}, err
	}
	status, err := parseWindowsWorkerStatus(line, "active", w.workerID)
	if err != nil || status.Epoch != w.ready.Epoch || status.APIVersion != w.ready.APIVersion {
		return hostdproto.Status{}, errors.New("invalid Windows worker activation")
	}
	return status, nil
}

func (w *windowsRuntimeWorker) Stop(ctx context.Context) error {
	if w == nil || w.command == nil || w.command.Process == nil {
		return nil
	}
	_ = w.command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- w.command.Wait() }()
	select {
	case <-ctx.Done():
		_ = w.command.Process.Kill()
		return ctx.Err()
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		_ = w.command.Process.Kill()
		return <-done
	}
}

func readWindowsWorkerLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	resultCh := make(chan result, 1)
	go func() { line, err := reader.ReadString('\n'); resultCh <- result{line, err} }()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-resultCh:
		if result.err != nil || len(result.line) > 64 {
			if result.err != nil {
				return "", result.err
			}
			return "", errors.New("worker lifecycle response exceeds limit")
		}
		return result.line, nil
	}
}

func parseWindowsWorkerStatus(line, state, workerID string) (hostdproto.Status, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != state || workerID == "" {
		return hostdproto.Status{}, errors.New("invalid Windows worker lifecycle response")
	}
	var epoch uint64
	var api uint16
	if _, err := fmt.Sscanf(parts[1], "%d", &epoch); err != nil || epoch == 0 {
		return hostdproto.Status{}, errors.New("invalid Windows worker lifecycle response")
	}
	if _, err := fmt.Sscanf(parts[2], "%d", &api); err != nil || api == 0 {
		return hostdproto.Status{}, errors.New("invalid Windows worker lifecycle response")
	}
	hostState := hostdproto.StateCandidate
	if state == "active" {
		hostState = hostdproto.StateActive
	}
	return hostdproto.Status{State: hostState, WorkerID: workerID, Epoch: epoch, APIVersion: api}, nil
}

var _ = gort.GOARCH
