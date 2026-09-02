//go:build windows

// Package hostinstall owns the fixed, machine-wide Windows runtime layout.
// It deliberately accepts no caller-selected service executable or service
// name: installation material is verified before this package is called and
// every durable path below is part of Paperboat's native layout.
package hostinstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"github.com/pinksaucepasta/paperboat/internal/processlaunch"
	winenv "github.com/pinksaucepasta/paperboat/internal/windowsenvironment"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const SchemaV1 = "paperboat.host-install/v1"

var (
	ErrInvalidRequest = errors.New("invalid privileged installation request")
	ErrNotPrivileged  = errors.New("privileged installation requires administrator approval")
	ErrNotInstalled   = errors.New("Paperboat Windows host runtime is not installed")

	removePaperboatSSHService = windowsopenssh.RemoveServiceOwned
	removePaperboatSSHState   = windowsopenssh.RemovePaperboatState
	setupPaperboatSSH         = windowsopenssh.Setup
)

type Request struct {
	Schema              string                   `json:"schema"`
	Platform            string                   `json:"platform"`
	User                string                   `json:"user"`
	UID                 int                      `json:"uid"`
	Group               string                   `json:"group"`
	GID                 int                      `json:"gid"`
	OwnerSID            string                   `json:"owner_sid,omitempty"`
	Executable          string                   `json:"executable"`
	Artifact            bootstrap.ArtifactTarget `json:"artifact"`
	Home                string                   `json:"home"`
	Path                string                   `json:"path"`
	StateRoot           string                   `json:"state_root"`
	WorkspaceRoot       string                   `json:"workspace_root"`
	ControlURL          string                   `json:"control_url"`
	UserMachineID       string                   `json:"machine_id"`
	Shell               string                   `json:"shell"`
	HelperListenAddress string                   `json:"helper_listen_address"`
	SetupMode           string                   `json:"setup_mode"`
}

// WindowsRuntimeConfig is the protected input consumed by Paperboat SCM
// entries. It contains no command line and cannot redirect an SCM service.
type WindowsRuntimeConfig struct {
	Schema        string                   `json:"schema"`
	OwnerSID      string                   `json:"owner_sid"`
	User          string                   `json:"user"`
	StateRoot     string                   `json:"state_root"`
	Workspace     string                   `json:"workspace_root"`
	ControlURL    string                   `json:"control_url"`
	ListenAddress string                   `json:"listen_address"`
	MachineID     string                   `json:"machine_id"`
	SetupMode     string                   `json:"setup_mode"`
	TokenFile     string                   `json:"token_file"`
	InstalledAt   time.Time                `json:"installed_at"`
	Committed     bool                     `json:"committed"`
	Artifact      bootstrap.ArtifactTarget `json:"artifact"`
}

const windowsConfigSchema = "paperboat.windows-runtime-install/v1"

func Decode(reader io.Reader) (Request, error) {
	var request Request
	decoder := json.NewDecoder(io.LimitReader(reader, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("%w: decode request: %v", ErrInvalidRequest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Request{}, fmt.Errorf("%w: trailing request data: %v", ErrInvalidRequest, err)
	}
	return request, nil
}

var windowsProgramDataRoot = `C:\ProgramData\Paperboat`

func WindowsProgramDataRoot() string { return windowsProgramDataRoot }
func WindowsInstallConfigPath() string {
	return filepath.Join(WindowsProgramDataRoot(), "runtime-install.json")
}
func WindowsHostdTokenPath() string { return filepath.Join(WindowsProgramDataRoot(), "hostd.token") }

// InstallStandaloneBinary is the single Windows bootstrap elevation path.
// The downloaded pb.exe invokes this command itself, so no launcher or
// updater executable is fetched or installed separately.
func InstallStandaloneBinary(ctx context.Context, source, version string, fresh bool) error {
	if !isAdministrator() || ctx == nil || !safeAbsolute(source) || !standaloneVersionPattern.MatchString(version) {
		return ErrInvalidRequest
	}
	if fresh {
		// Dashboard enrollment is a replacement boundary. Remove the old
		// services, credentials, managed SSH host keys, and machine-wide state
		// before staging the verified runtime so a new machine identity cannot
		// inherit authority from an earlier enrollment.
		if err := Purge(ctx); err != nil {
			return fmt.Errorf("purge previous Paperboat enrollment: %w", err)
		}
		if err := os.RemoveAll(WindowsProgramDataRoot()); err != nil {
			return fmt.Errorf("remove previous Paperboat machine state: %w", err)
		}
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil || layout.Binary == "" {
		return ErrInvalidRequest
	}
	for _, directory := range []string{layout.InstallRoot, layout.ReleasesRoot, filepath.Dir(layout.Binary), filepath.Dir(filepath.Join(layout.ReleasesRoot, "pb.rollback"))} {
		if err := ensureWindowsDirectory(directory, ""); err != nil {
			return err
		}
	}
	if err := winenv.EnsureMachinePath(filepath.Dir(layout.Binary)); err != nil {
		return fmt.Errorf("register Paperboat command path: %w", err)
	}
	artifact := bootstrap.ArtifactTarget{
		Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: version,
		Platform: "windows", Architecture: runtime.GOARCH, RepositoryURL: "https://get.pprbt.dev/tuf",
		TargetPath: releaseindex.AssetName("windows", runtime.GOARCH),
	}
	rollback := filepath.Join(layout.ReleasesRoot, "pb.rollback")
	return stageWindowsBinary(ctx, source, layout.Binary, rollback, artifact, "")
}

func LoadWindowsRuntimeConfig() (WindowsRuntimeConfig, error) {
	config, err := readWindowsRuntimeConfig()
	if err != nil {
		return WindowsRuntimeConfig{}, err
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("resolve trusted Windows runtime owner: %w", err)
	}
	fileDACL := windowsRuntimeCurrentFileDACL(config.OwnerSID)
	rootDACL := windowsRuntimeCurrentRootDACL(config.OwnerSID)
	if err := validateWindowsRuntimeSecurity(WindowsProgramDataRoot(), trustedOwner, rootDACL, "root"); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	if err := validateWindowsRuntimeSecurity(WindowsInstallConfigPath(), trustedOwner, fileDACL, "config"); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	if err := secureWindowsFile(WindowsHostdTokenPath(), ""); err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime token file: %w", err)
	}
	tokenInfo, err := os.Stat(WindowsHostdTokenPath())
	if err != nil || tokenInfo.Size() != 32 {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime token size: %w", ErrInvalidRequest)
	}
	if err := validateWindowsRuntimeSecurity(WindowsHostdTokenPath(), trustedOwner, fileDACL, "token"); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	return config, nil
}

func readWindowsRuntimeConfig() (WindowsRuntimeConfig, error) {
	path := WindowsInstallConfigPath()
	if err := secureWindowsFile(path, ""); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || len(body) > 128<<10 {
		return WindowsRuntimeConfig{}, ErrInvalidRequest
	}
	return decodeWindowsRuntimeConfig(body)
}

func decodeWindowsRuntimeConfig(body []byte) (WindowsRuntimeConfig, error) {
	var config WindowsRuntimeConfig
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var extra any
	// Older installations predate setup_mode and always created PaperboatSshd,
	// so retain host semantics until their next verified enrollment writes an
	// explicit role.
	if decoder.Decode(&config) != nil || decoder.Decode(&extra) != io.EOF {
		return WindowsRuntimeConfig{}, ErrInvalidRequest
	}
	if config.SetupMode == "" {
		config.SetupMode = "host"
	}
	if config.ListenAddress == "" {
		// Older Windows installs used the runtime's fixed loopback default.
		config.ListenAddress = "127.0.0.1:8080"
	}
	if !validWindowsConfig(config) {
		return WindowsRuntimeConfig{}, ErrInvalidRequest
	}
	return config, nil
}

func migrateLegacyWindowsRuntimeSecurity() (WindowsRuntimeConfig, error) {
	if !isAdministrator() {
		return WindowsRuntimeConfig{}, ErrNotPrivileged
	}
	rootHandle, _, err := openWindowsRuntimeObject(WindowsProgramDataRoot(), true)
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("open legacy Windows runtime root: %w", err)
	}
	defer windows.CloseHandle(rootHandle)
	configHandle, configInfo, err := openWindowsRuntimeObject(WindowsInstallConfigPath(), false)
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("open legacy Windows runtime config: %w", err)
	}
	defer windows.CloseHandle(configHandle)
	tokenHandle, tokenInfo, err := openWindowsRuntimeObject(WindowsHostdTokenPath(), false)
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("open legacy Windows runtime token: %w", err)
	}
	defer windows.CloseHandle(tokenHandle)
	if uint64(configInfo.FileSizeHigh)<<32|uint64(configInfo.FileSizeLow) == 0 || uint64(configInfo.FileSizeHigh)<<32|uint64(configInfo.FileSizeLow) > 128<<10 {
		return WindowsRuntimeConfig{}, fmt.Errorf("read legacy Windows runtime config: %w", ErrInvalidRequest)
	}
	configBody := make([]byte, uint64(configInfo.FileSizeHigh)<<32|uint64(configInfo.FileSizeLow))
	for offset := 0; offset < len(configBody); {
		var configRead uint32
		if err := windows.ReadFile(configHandle, configBody[offset:], &configRead, nil); err != nil || configRead == 0 {
			return WindowsRuntimeConfig{}, fmt.Errorf("read legacy Windows runtime config: %w", ErrInvalidRequest)
		}
		offset += int(configRead)
	}
	config, err := decodeWindowsRuntimeConfig(configBody)
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("read legacy Windows runtime config: %w", err)
	}
	caller, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || caller == nil || caller.User.Sid == nil || !strings.EqualFold(caller.User.Sid.String(), config.OwnerSID) {
		// The legacy file granted its enrolled owner WRITE_DAC and WRITE_DATA.
		// Bind migration to the elevated identity that explicitly requested the
		// repair so rewritten legacy bytes cannot select another Windows account.
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime repair caller: %w", ErrInvalidRequest)
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("resolve trusted Windows runtime owner: %w", err)
	}
	legacyOwner := caller.User.Sid
	legacyFileDACL := windowsRuntimeLegacyFileDACL(config.OwnerSID)
	legacyRootDACL := windowsRuntimeLegacyRootDACL(config.OwnerSID)
	currentFileDACL := windowsRuntimeCurrentFileDACL(config.OwnerSID)
	currentRootDACL := windowsRuntimeCurrentRootDACL(config.OwnerSID)
	if !windowsRuntimeMigrationHandleSecurityMatches(rootHandle, legacyOwner, trustedOwner, legacyRootDACL, currentRootDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime root security: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeMigrationHandleSecurityMatches(configHandle, legacyOwner, trustedOwner, legacyFileDACL, currentFileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime config security: %w", ErrInvalidRequest)
	}
	if uint64(tokenInfo.FileSizeHigh)<<32|uint64(tokenInfo.FileSizeLow) != 32 {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime token file: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeMigrationHandleSecurityMatches(tokenHandle, legacyOwner, trustedOwner, legacyFileDACL, currentFileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime token security: %w", ErrInvalidRequest)
	}
	allCurrent := windowsRuntimeHandleSecurityMatches(rootHandle, trustedOwner, currentRootDACL) &&
		windowsRuntimeHandleSecurityMatches(configHandle, trustedOwner, currentFileDACL) &&
		windowsRuntimeHandleSecurityMatches(tokenHandle, trustedOwner, currentFileDACL)
	if allCurrent {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime transition: %w", ErrInvalidRequest)
	}
	// Validate every object before the first mutation. A foreign owner must fail
	// without allowing a partially trusted tree to be adopted. Each subsequent
	// owner+DACL replacement is idempotent, so an interrupted migration can
	// resume from any mixture of the two explicitly supported states.
	for _, item := range []struct {
		handle windows.Handle
		dacl   string
		stage  string
	}{
		{tokenHandle, currentFileDACL, "token"},
		{configHandle, currentFileDACL, "config"},
		{rootHandle, currentRootDACL, "root"},
	} {
		if err := applyWindowsHandleOwnedDACL(item.handle, trustedOwner, item.dacl); err != nil {
			return WindowsRuntimeConfig{}, fmt.Errorf("migrate Windows runtime %s security: %w", item.stage, err)
		}
	}
	return config, nil
}

func Install(ctx context.Context, request Request) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	if err := Validate(request, 0); err != nil {
		return err
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	lifecycle, err := newWindowsLifecycleManager(request, layout, true)
	if err != nil {
		return err
	}
	// Recover the durable hostd/updater transaction before touching SCM,
	// binaries, credentials, or machine state. A corrupt/stale journal is a
	// fail-closed startup condition.
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat machine state", func() error { return ensureWindowsMachineDirectory(WindowsProgramDataRoot(), request.OwnerSID) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "register Paperboat command path", func() error { return winenv.EnsureMachinePath(filepath.Dir(layout.Binary)) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat release slots", func() error { return ensureWindowsDirectory(layout.ReleasesRoot, request.OwnerSID) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat user state", func() error { return ensureWindowsDirectory(request.StateRoot, request.OwnerSID) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "repair Paperboat user-state permissions", func() error { return repairWindowsTreeACL(request.StateRoot, request.OwnerSID) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "stop Paperboat Windows services for activation", func() error { return stopWindowsRuntimeServices(ctx) }); err != nil {
		return err
	}
	// Service stop only waits for SCM-owned parents. A previous hostd worker
	// can outlive its parent after an interrupted activation and keep the
	// runtime listen port occupied, causing the fresh owner workload to exit.
	// The elevated activation process is staged under a temporary executable,
	// so terminating the fixed pb.exe image cannot terminate this installer.
	if err := runWindowsInstallPhase(ctx, "terminate stale Paperboat runtime processes", func() error { return terminateStaleWindowsRuntimeProcesses(ctx) }); err != nil {
		return err
	}
	// Client has no SSH capability, but PaperboatSshd can hold the current
	// runtime open. Release that service before slot rotation; defer its slower
	// firewall/state cleanup until the new runtime services are running.
	if err := runWindowsInstallPhase(ctx, "release Paperboat OpenSSH service for activation", func() error { return removeWindowsSSHBeforeActivation(ctx, request, layout) }); err != nil {
		return err
	}
	runtimeCurrent, runtimeRollback, _ := windowsRuntimePaths(layout)
	if err := runWindowsInstallPhase(ctx, "stage verified Paperboat runtime", func() error {
		return stageWindowsBinary(ctx, request.Executable, runtimeCurrent, runtimeRollback, request.Artifact, request.OwnerSID)
	}); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat host token", func() error { return ensureWindowsToken(request.OwnerSID) }); err != nil {
		return err
	}
	config := WindowsRuntimeConfig{Schema: windowsConfigSchema, OwnerSID: request.OwnerSID, User: request.User, StateRoot: request.StateRoot, Workspace: request.WorkspaceRoot, ControlURL: request.ControlURL, ListenAddress: request.HelperListenAddress, MachineID: request.UserMachineID, SetupMode: request.SetupMode, TokenFile: WindowsHostdTokenPath(), InstalledAt: time.Now().UTC(), Artifact: request.Artifact}
	if err := runWindowsInstallPhase(ctx, "write Paperboat runtime configuration", func() error { return writeWindowsConfig(config) }); err != nil {
		return err
	}
	// Activation deliberately stopped both services before rotating the runtime
	// slot. Re-apply their SCM definitions so the newly staged image is started;
	// UpgradeReload would treat existing declarations as stable and leave the
	// services stopped.
	if err := runWindowsInstallPhase(ctx, "install Paperboat Windows services", func() error {
		return installWindowsRoleServices(ctx, request, layout, "")
	}); err != nil {
		return err
	}
	return nil
}

// runWindowsInstallPhase turns an uninterruptible Windows filesystem or SCM
// call into a named, bounded bridge result. When invoked through the elevated
// bridge, the child exits after a timeout, so a still-blocked worker cannot
// remain alive after the installer has received its deterministic failure.
// Normal callers get the same phase identity for ordinary errors.
func runWindowsInstallPhase(ctx context.Context, phase string, operation func() error) error {
	if ctx == nil || operation == nil {
		return ErrInvalidRequest
	}
	result := make(chan error, 1)
	go func() { result <- operation() }()
	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("%s: %w", phase, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", phase, ctx.Err())
	}
}

func windowsOpenSSHConfig(layout service.Layout, ownerSID string) windowsopenssh.Config {
	config := windowsopenssh.DefaultConfig(nil)
	config.OwnerSID = ownerSID
	config.ServiceExecutable, _, _ = windowsRuntimePaths(layout)
	return config
}

func windowsLocalDaemonLockPath(stateRoot string) (string, error) {
	if !safeAbsolute(stateRoot) {
		return "", ErrInvalidRequest
	}
	return filepath.Join(filepath.Dir(stateRoot), "state", "daemon.lock"), nil
}

func waitWindowsLocalDaemonReady(ctx context.Context, ownerSID, stateRoot string) error {
	lockPath, err := windowsLocalDaemonLockPath(stateRoot)
	if err != nil {
		return err
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		running, probeErr := localdaemon.WindowsOwnerServiceRunning(lockPath, ownerSID)
		if probeErr == nil && running {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(probeErr, ctx.Err())
		case <-deadline.C:
			return errors.Join(probeErr, errors.New("Paperboat local daemon service did not become ready"))
		case <-tick.C:
		}
	}
}

// prepareWindowsLocalDaemonMigration stops the exact owner-scoped ONLOGON task
// and its process without deleting the task. The task remains the rollback
// point until the replacement SCM service has started successfully.
func prepareWindowsLocalDaemonMigration(ctx context.Context, ownerSID, stateRoot string) error {
	lockPath, err := windowsLocalDaemonLockPath(stateRoot)
	if err != nil {
		return err
	}
	if err := localdaemon.StopWindowsLegacyTask(ctx, ownerSID); err != nil {
		return err
	}
	installed, err := localdaemon.WindowsLocalDaemonServiceInstalled()
	if err != nil {
		return err
	}
	active, err := localdaemon.WindowsLocalDaemonServiceActive()
	if err != nil {
		return err
	}
	if installed && active {
		return nil
	}
	return localdaemon.StopWindowsLegacyService(ctx, lockPath, ownerSID)
}

func prepareWindowsLocalDaemonMigrationAndState(ctx context.Context, ownerSID, stateRoot string) error {
	migrationErr := prepareWindowsLocalDaemonMigration(ctx, ownerSID, stateRoot)
	stateErr := PrepareWindowsLocalDaemonState(stateRoot, ownerSID)
	// A stale lock DACL can make the first legacy-process probe fail after its
	// SCM parent is already stopped. Repair the exact owner state, then retry
	// the idempotent migration before any service is started.
	if migrationErr != nil && stateErr == nil {
		migrationErr = prepareWindowsLocalDaemonMigration(ctx, ownerSID, stateRoot)
	}
	return errors.Join(migrationErr, stateErr)
}

// EnsureWindowsLocalDaemonService upgrades an existing Windows installation
// from the owner-scoped scheduled task to the protected LocalDaemon SCM
// service. It is idempotent and is also called by the updater so an in-place
// upgrade from a pre-SCM release cannot leave the task behind.
func EnsureWindowsLocalDaemonService(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	// Recover hostd/updater before touching the legacy LocalDaemon service or
	// its state. The updater may invoke this migration during startup, so a
	// stale lifecycle journal must remain a fail-closed boundary here too.
	preflight, err := newWindowsLifecycleManager(Request{Platform: "windows"}, layout, true)
	if err != nil {
		return err
	}
	if err := preflight.Recover(ctx); err != nil {
		return err
	}
	config, err := LoadWindowsRuntimeConfig()
	if err != nil {
		return err
	}
	if err := prepareWindowsLocalDaemonMigrationAndState(ctx, config.OwnerSID, config.StateRoot); err != nil {
		return fmt.Errorf("migrate Paperboat local daemon task: %w", err)
	}
	installed, err := localdaemon.WindowsLocalDaemonServiceInstalled()
	if err != nil {
		return err
	}
	install := func(installCtx context.Context) error {
		installer, err := service.New(service.Config{
			Platform: "windows", Kind: service.DaemonKind, ConfigRoot: WindowsProgramDataRoot(),
			Executable: layout.Binary, User: "Paperboat", Group: "Paperboat",
			Arguments: []string{"__runtime-local-daemon"}, Controller: service.WindowsController{},
		})
		if err != nil {
			return err
		}
		return installer.Install(installCtx)
	}
	// The stable SCM definition already owns the canonical executable. An
	// idempotent readiness repair must start it, not run Installer.Install:
	// Windows upgrades deliberately stop an existing service before applying
	// its definition, which can kill the process another migration just made
	// ready.
	if err := activateLocalDaemon(ctx, localDaemonActivation{
		Installed: installed,
		Start: func(startCtx context.Context) error {
			return localdaemon.StartWindowsOwnerService(startCtx, config.OwnerSID)
		},
		Install: install,
		WaitReady: func(waitCtx context.Context) error {
			return waitWindowsLocalDaemonReady(waitCtx, config.OwnerSID, config.StateRoot)
		},
	}); err != nil {
		return err
	}
	return localdaemon.RemoveWindowsLegacyTask(ctx, config.OwnerSID)
}

// The activator and the newly restarted updater can both observe a committed
// activation journal. Serialize their idempotent service migration so one
// caller cannot stop an SCM service while the other is waiting for readiness.
func lockWindowsLocalDaemonMigration(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	name, err := windows.UTF16PtrFromString(`Global\PaperboatLocalDaemonMigration`)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(`O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)`)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateMutex(&attributes, false, name)
	runtime.KeepAlive(descriptor)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil, err
	}
	if handle == 0 {
		return nil, ErrInvalidRequest
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		state, waitErr := windows.WaitForSingleObject(handle, 100)
		if waitErr != nil {
			windows.CloseHandle(handle)
			return nil, waitErr
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			return func() {
				_ = windows.ReleaseMutex(handle)
				_ = windows.CloseHandle(handle)
			}, nil
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			windows.CloseHandle(handle)
			return nil, ErrInvalidRequest
		}
	}
}

// removeWindowsSSHBeforeActivation releases the old runtime image before any
// slot rotation. The service is removed only after its ownership check passes.
// Client completes its Paperboat-owned SSH state cleanup after its new runtime
// is online; Host recreates the owned service after the new runtime is active.
func removeWindowsSSHBeforeActivation(ctx context.Context, request Request, layout service.Layout) error {
	config := windowsOpenSSHConfig(layout, request.OwnerSID)
	return removePaperboatSSHService(ctx, config)
}

func installWindowsSSHAfterActivation(ctx context.Context, request Request, layout service.Layout) error {
	if request.SetupMode == "client" {
		// This can query firewall state. It runs after the new client runtime is
		// active so an interrupted cleanup cannot leave the machine offline.
		return removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, request.OwnerSID))
	}
	config := windowsOpenSSHConfig(layout, request.OwnerSID)
	runtimeCurrent, _, _ := windowsRuntimePaths(layout)
	config.ServiceExecutable = runtimeCurrent
	_, err := setupPaperboatSSH(ctx, config)
	return err
}

// cleanupWindowsSSHAfterRuntimeFailure rolls back only the service registration
// for a host installation. The host key inventory is the identity used by the
// managed-SSH operation and must survive a failed runtime activation so an
// exact retry can replay its immutable operation. Client installations have
// no managed-SSH authority and may remove their complete owned state.
func cleanupWindowsSSHAfterRuntimeFailure(ctx context.Context, request Request, layout service.Layout) error {
	config := windowsOpenSSHConfig(layout, request.OwnerSID)
	if request.SetupMode == "host" {
		return removePaperboatSSHService(ctx, config)
	}
	if request.SetupMode == "client" {
		return removePaperboatSSHState(ctx, config)
	}
	return ErrInvalidRequest
}

func Commit(request Request) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	if err := Validate(request, 0); err != nil {
		return err
	}
	config, err := LoadWindowsRuntimeConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !windowsRuntimeServiceExists() {
			return ErrNotInstalled
		}
		return err
	}
	if config.OwnerSID != request.OwnerSID || config.MachineID != request.UserMachineID {
		return ErrInvalidRequest
	}
	config.Committed = true
	return writeWindowsConfig(config)
}

func windowsRuntimeServiceExists() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return true
	}
	defer manager.Disconnect()
	for _, name := range []string{"PaperboatHostd", "PaperboatUpdated", "PaperboatLocalDaemon"} {
		current, err := manager.OpenService(name)
		if err == nil {
			current.Close()
			return true
		}
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return true
		}
	}
	return false
}

func stopWindowsRuntimeServices(ctx context.Context) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	for _, name := range []string{"PaperboatHostd", "PaperboatUpdated", "PaperboatLocalDaemon"} {
		current, openErr := manager.OpenService(name)
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		_, controlErr := current.Control(svc.Stop)
		if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
			current.Close()
			return controlErr
		}
		for {
			status, queryErr := current.Query()
			if queryErr != nil {
				current.Close()
				return queryErr
			}
			if status.State == svc.Stopped {
				break
			}
			select {
			case <-ctx.Done():
				current.Close()
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err := current.Close(); err != nil {
			return err
		}
	}
	return nil
}

func Uninstall(ctx context.Context, request Request) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	if err := Validate(request, 0); err != nil {
		return err
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	runtimeErr := uninstallWindows(ctx, false)
	if runtimeErr != nil {
		return runtimeErr
	}
	lockPath, lockErr := windowsLocalDaemonLockPath(request.StateRoot)
	legacyErr := lockErr
	if lockErr == nil {
		legacyErr = localdaemon.RemoveWindowsLegacyService(ctx, lockPath, request.OwnerSID)
	}
	if legacyErr != nil {
		return legacyErr
	}
	return removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, request.OwnerSID))
}

func UninstallPersisted(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	preflight, err := newWindowsLifecycleManager(Request{Platform: "windows"}, layout, true)
	if err != nil {
		return err
	}
	if err := preflight.Recover(ctx); err != nil {
		return err
	}
	config, err := LoadWindowsRuntimeConfig()
	if err != nil {
		return err
	}
	runtimeErr := uninstallWindows(ctx, false)
	if runtimeErr != nil {
		return runtimeErr
	}
	lockPath, lockErr := windowsLocalDaemonLockPath(config.StateRoot)
	legacyErr := lockErr
	if lockErr == nil {
		legacyErr = localdaemon.RemoveWindowsLegacyService(ctx, lockPath, config.OwnerSID)
	}
	if legacyErr != nil {
		return legacyErr
	}
	return removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, config.OwnerSID))
}

// Stop stops the persisted hostd and updater services without removing their
// declarations or binaries. It uses pending installers so a missing runtime
// image cannot prevent lifecycle recovery or a durable stop.
func Stop(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	lifecycle, err := newWindowsLifecycleManager(Request{Platform: "windows"}, layout, true)
	if err != nil {
		return err
	}
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	return lifecycle.Stop(ctx)
}

// Repair restores the persisted Windows runtime and its role-scoped OpenSSH
// service set. Client repair keeps Paperboat SSH absent.
func Repair(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	// Build the pending lifecycle boundary before reading or migrating the
	// persisted config. Missing binaries are valid at this recovery boundary;
	// host-mode SSH is restored below before this manager is allowed to recover
	// a journal that may restart Hostd.
	preflight, err := newWindowsLifecycleManager(Request{Platform: "windows"}, layout, true)
	if err != nil {
		return err
	}
	config, err := LoadWindowsRuntimeConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !windowsRuntimeServiceExists() {
			return ErrNotInstalled
		}
		config, err = migrateLegacyWindowsRuntimeSecurity()
		if err != nil {
			return err
		}
	}
	config, err = reconcileWindowsRepairVersion(ctx, config, layout)
	if err != nil {
		return err
	}
	// The persisted helper endpoint is required both for the authenticated
	// Hostd readiness probe and for deterministic recovery. Older repair code
	// passed only the user state and owner SID, allowing SCM rollback to restore
	// Hostd without an application probe or an SSH readiness boundary.
	request := windowsRepairRequest(config)
	// Keep one host-mode SSH service alive across the complete repair. The
	// previous flow prepared PaperboatSshd for preflight recovery, deleted it
	// immediately afterwards, then installed it again inside the role plan.
	// Windows SCM deletion is asynchronous, so that gap could leave the second
	// install marked-for-delete or let Hostd race an absent loopback target.
	return executeWindowsServiceRepairPlan(
		request.SetupMode,
		func() error {
			if err := installWindowsSSHAfterActivation(ctx, request, layout); err != nil {
				return fmt.Errorf("prepare Paperboat OpenSSH before lifecycle recovery: %w", err)
			}
			return nil
		},
		func() error {
			return preflight.Recover(ctx)
		},
		func() error {
			if err := repairWindowsRuntimeBinary(ctx, config, layout); err != nil {
				return err
			}
			if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), config.OwnerSID); err != nil {
				return err
			}
			if err := winenv.EnsureMachinePath(filepath.Dir(layout.Binary)); err != nil {
				return err
			}
			if err := ensureWindowsDirectory(config.StateRoot, config.OwnerSID); err != nil {
				return err
			}
			if err := repairWindowsTreeACL(config.StateRoot, config.OwnerSID); err != nil {
				return err
			}
			if err := ensureWindowsToken(config.OwnerSID); err != nil {
				return err
			}
			if err := writeWindowsConfig(config); err != nil {
				return err
			}
			return prepareWindowsLocalDaemonMigrationAndState(ctx, request.OwnerSID, request.StateRoot)
		},
		func() error {
			return repairWindowsRoleServices(ctx, request, layout)
		},
		func() error {
			return cleanupWindowsSSHAfterRuntimeFailure(ctx, request, layout)
		},
	)
}

// windowsRepairRequest carries the persisted values needed to reconstruct the
// native role boundary. In particular, HelperListenAddress enables the same
// authenticated Hostd readiness probe used during installation; repair must
// not silently fall back to SCM running state alone.
func windowsRepairRequest(config WindowsRuntimeConfig) Request {
	return Request{
		SetupMode:           config.SetupMode,
		OwnerSID:            config.OwnerSID,
		StateRoot:           config.StateRoot,
		HelperListenAddress: config.ListenAddress,
	}
}

func reconcileWindowsRepairVersion(ctx context.Context, config WindowsRuntimeConfig, layout service.Layout) (WindowsRuntimeConfig, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return config, err
	}
	defer manager.Disconnect()
	for _, item := range []struct{ name, argument string }{{"PaperboatHostd", "__runtime-hostd"}, {"PaperboatUpdated", "__runtime-updated"}, {"PaperboatLocalDaemon", "__runtime-local-daemon"}} {
		registered, err := manager.OpenService(item.name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return config, nil
		}
		if err != nil {
			return config, err
		}
		definition, configErr := registered.Config()
		closeErr := registered.Close()
		if configErr != nil || closeErr != nil {
			return config, errors.Join(configErr, closeErr)
		}
		arguments, err := windows.DecomposeCommandLine(definition.BinaryPathName)
		if err != nil || len(arguments) != 2 || arguments[1] != item.argument {
			return config, ErrInvalidRequest
		}
		if !strings.EqualFold(filepath.Clean(arguments[0]), filepath.Clean(layout.Binary)) {
			return config, ErrInvalidRequest
		}
		if err := verifyWindowsInstalledBinary(ctx, layout.Binary, config.Artifact.Architecture); err != nil {
			return config, err
		}
	}
	return config, nil
}

// Purge removes only Paperboat-owned service declarations, slots, tokens, and
// ProgramData state. It is intentionally idempotent so it can finish after a
// reboot or an interrupted uninstall.
func Purge(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	unlock, err := lockWindowsLocalDaemonMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	layout, layoutErr := service.DefaultLayout("windows")
	if layoutErr != nil {
		return layoutErr
	}
	preflight, err := newWindowsLifecycleManager(Request{Platform: "windows"}, layout, true)
	if err != nil {
		return err
	}
	if err := preflight.Recover(ctx); err != nil {
		return err
	}
	persisted, persistedErr := LoadWindowsRuntimeConfig()
	if errors.Is(persistedErr, os.ErrNotExist) {
		persistedErr = nil
	}
	if persistedErr != nil {
		return persistedErr
	}
	// Remove retired logon tasks even when an interrupted uninstall already
	// removed ProgramData and its owner SID record. The task names are strictly
	// limited to Paperboat's hashed legacy daemon namespace.
	if err := localdaemon.RemoveAllWindowsLegacyTasks(ctx); err != nil {
		return err
	}
	// The updater's one-shot activator can survive an interrupted activation
	// after its versioned executable has been removed. Delete its exact owned
	// SCM declaration before removing release slots.
	if err := removeWindowsActivatorService(ctx, layout); err != nil {
		return err
	}
	if _, err := os.Stat(WindowsProgramDataRoot()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	// Windows OpenSSH is a shared WinGet dependency. Purge only removes the
	// dedicated PaperboatSshd service, Paperboat SSH keys/configuration, and
	// firewall deltas that Paperboat recorded as its own. This must happen
	// before the Paperboat runtime slots are removed because their fixed path
	// is the ownership proof for PaperboatSshd.
	if err := removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, "")); err != nil {
		return err
	}
	// A service can have been removed already while its old pb.exe process is
	// still alive. Terminate only the fixed Paperboat executable before deleting
	// the release slots, otherwise pb.rollback.exe remains locked and a fresh
	// dashboard install fails halfway through cleanup.
	if err := terminatePaperboatProcesses(ctx); err != nil {
		return err
	}
	if err := uninstallWindows(ctx, true); err != nil {
		return err
	}
	if persisted.OwnerSID != "" {
		if lockPath, lockErr := windowsLocalDaemonLockPath(persisted.StateRoot); lockErr != nil {
			return lockErr
		} else {
			if err := localdaemon.RemoveWindowsLegacyService(ctx, lockPath, persisted.OwnerSID); err != nil {
				return err
			}
		}
	}
	return nil
}

func terminatePaperboatProcesses(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// The fresh installer is itself a pb.exe process. Never terminate that
	// process while it is performing the replacement purge, or the dashboard
	// command exits before the new enrollment can complete.
	script := fmt.Sprintf(`$self=%d; Get-CimInstance Win32_Process -Filter "Name = 'pb.exe'" | Where-Object { $_.ProcessId -ne $self } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }`, os.Getpid())
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	processlaunch.ConfigureBackground(command)
	if output, err := command.CombinedOutput(); err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return fmt.Errorf("terminate Paperboat processes: %w: %s", err, message)
		}
		return fmt.Errorf("terminate Paperboat processes: %w", err)
	}
	return nil
}

func terminateStaleWindowsRuntimeProcesses(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Match only durable runtime entry points. The dashboard installer itself
	// is a pb.exe bootstrap process and must remain alive while the elevated
	// commit rotates the installed slot.
	const script = staleWindowsRuntimeProcessScript
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	processlaunch.ConfigureBackground(command)
	if output, err := command.CombinedOutput(); err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 2048 {
			message = message[:2048]
		}
		if message != "" {
			return fmt.Errorf("terminate stale Paperboat runtime processes: %w: %s", err, message)
		}
		return fmt.Errorf("terminate stale Paperboat runtime processes: %w", err)
	}
	return nil
}

const staleWindowsRuntimeProcessPattern = `__(runtime-(hostd|worker|updated|local-daemon)|local-daemon|windows-sshd-service)`

const staleWindowsRuntimeProcessScript = `$ErrorActionPreference = 'Stop'; Get-CimInstance Win32_Process -Filter "Name = 'pb.exe'" | Where-Object { $_.CommandLine -match '` + staleWindowsRuntimeProcessPattern + `' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }`

func uninstallWindows(ctx context.Context, purge bool) error {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	hostd, updater, daemon, err := windowsRoleInstallers(layout, true)
	if err != nil {
		return err
	}
	lifecycle, err := newWindowsLifecycleManagerForInstallers(layout, hostd, updater, nil)
	if err != nil {
		return err
	}
	// Recovery must be a separate fail-closed step. Do not delete binaries or
	// machine configuration if the previous journal cannot be reconciled.
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	if err := lifecycle.Uninstall(ctx); err != nil {
		return err
	}
	if err := daemon.Uninstall(ctx); err != nil {
		return err
	}
	if err := winenv.RemoveMachinePath(filepath.Dir(layout.Binary)); err != nil {
		return err
	}
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if purge {
		for _, path := range []string{layout.ReleasesRoot, filepath.Join(WindowsProgramDataRoot(), "services"), filepath.Join(WindowsProgramDataRoot(), "service-lifecycle"), layout.UpdateStateRoot} {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func serviceNameForKind(kind string) string {
	switch kind {
	case service.UpdaterKind:
		return "PaperboatUpdated"
	case service.DaemonKind:
		return "PaperboatLocalDaemon"
	default:
		return "PaperboatHostd"
	}
}

func removeOrphanWindowsService(ctx context.Context, name, executable string, args []string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	current, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer current.Close()
	config, err := current.Config()
	if err != nil {
		return err
	}
	want := windows.ComposeCommandLine(append([]string{executable}, args...))
	if !strings.EqualFold(config.BinaryPathName, want) || !strings.EqualFold(strings.TrimSpace(config.ServiceStartName), "LocalSystem") {
		return service.ErrInvalidDefinition
	}
	status, err := current.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		if _, err := current.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		for status.State != svc.Stopped {
			if !time.Now().Before(deadline) {
				return context.DeadlineExceeded
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			status, err = current.Query()
			if err != nil {
				return err
			}
		}
	}
	if err := current.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return nil
}

func removeWindowsActivatorService(ctx context.Context, layout service.Layout) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	current, err := manager.OpenService("PaperboatUpdateActivator")
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_ = manager.Disconnect()
		return nil
	}
	if err != nil {
		_ = manager.Disconnect()
		return err
	}
	config, configErr := current.Config()
	closeErr := current.Close()
	disconnectErr := manager.Disconnect()
	if configErr != nil || closeErr != nil || disconnectErr != nil {
		return errors.Join(configErr, closeErr, disconnectErr)
	}
	arguments, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(arguments) != 2 || !windowsActivatorServiceOwned(layout, filepath.Clean(arguments[0]), arguments[1:], config.ServiceStartName) {
		return errors.Join(service.ErrInvalidDefinition, err)
	}
	return removeOrphanWindowsService(ctx, "PaperboatUpdateActivator", filepath.Clean(arguments[0]), []string{"__runtime-activate"})
}

func installWindowsRoleServices(ctx context.Context, request Request, layout service.Layout, upgradeMode string) error {
	hostd, updater, daemon, err := windowsRoleInstallers(layout, false)
	if err != nil {
		return err
	}
	lifecycle, err := newWindowsLifecycleManagerForInstallers(layout, hostd, updater, &request)
	if err != nil {
		return err
	}
	return executeWindowsServiceInstallPlan(request.SetupMode,
		func() error { return installWindowsSSHAfterActivation(ctx, request, layout) },
		func() error {
			if err := lifecycle.Recover(ctx); err != nil {
				return err
			}
			if err := prepareWindowsLocalDaemonMigrationAndState(ctx, request.OwnerSID, request.StateRoot); err != nil {
				return fmt.Errorf("migrate Paperboat local daemon task: %w", err)
			}
			return nil
		},
		func() error {
			var lifecycleErr error
			if upgradeMode == "" {
				lifecycleErr = lifecycle.Install(ctx)
			} else {
				lifecycleErr = lifecycle.Repair(ctx)
			}
			if lifecycleErr != nil {
				return lifecycleErr
			}
			if err := daemon.Install(ctx); err != nil {
				return errors.Join(err, lifecycle.Uninstall(ctx))
			}
			if err := waitWindowsLocalDaemonReady(ctx, request.OwnerSID, request.StateRoot); err != nil {
				return errors.Join(err, daemon.Uninstall(ctx), lifecycle.Uninstall(ctx))
			}
			if err := localdaemon.RemoveWindowsLegacyTask(ctx, request.OwnerSID); err != nil {
				return errors.Join(err, daemon.Uninstall(ctx), lifecycle.Uninstall(ctx))
			}
			return nil
		},
		func() error { return cleanupWindowsSSHAfterRuntimeFailure(ctx, request, layout) },
	)
}

// repairWindowsRoleServices repairs the native role declarations after the
// persisted config and runtime binary have been restored. PaperboatSshd is
// intentionally not installed here: host-mode repair establishes it before
// lifecycle recovery and keeps it in place until this final phase succeeds.
func repairWindowsRoleServices(ctx context.Context, request Request, layout service.Layout) error {
	hostd, updater, daemon, err := windowsRoleInstallers(layout, false)
	if err != nil {
		return err
	}
	lifecycle, err := newWindowsLifecycleManagerForInstallers(layout, hostd, updater, &request)
	if err != nil {
		return err
	}
	if err := lifecycle.Repair(ctx); err != nil {
		return err
	}
	if err := daemon.Install(ctx); err != nil {
		return errors.Join(err, lifecycle.Uninstall(ctx))
	}
	if err := waitWindowsLocalDaemonReady(ctx, request.OwnerSID, request.StateRoot); err != nil {
		return errors.Join(err, daemon.Uninstall(ctx), lifecycle.Uninstall(ctx))
	}
	if err := localdaemon.RemoveWindowsLegacyTask(ctx, request.OwnerSID); err != nil {
		return errors.Join(err, daemon.Uninstall(ctx), lifecycle.Uninstall(ctx))
	}
	return nil
}

func windowsRoleInstallers(layout service.Layout, allowMissingExecutable bool) (*service.Installer, *service.Installer, *service.Installer, error) {
	runtimeCurrent, _, _ := windowsRuntimePaths(layout)
	newInstaller := func(kind string, arguments []string) (*service.Installer, error) {
		config := service.Config{Platform: "windows", Kind: kind, ConfigRoot: WindowsProgramDataRoot(), Executable: runtimeCurrent, User: "Paperboat", Group: "Paperboat", Arguments: arguments, Controller: service.WindowsController{}}
		if allowMissingExecutable {
			return service.NewPending(config)
		}
		return service.New(config)
	}
	hostd, err := newInstaller(service.HostdKind, []string{"__runtime-hostd"})
	if err != nil {
		return nil, nil, nil, err
	}
	updater, err := newInstaller(service.UpdaterKind, []string{"__runtime-updated"})
	if err != nil {
		return nil, nil, nil, err
	}
	daemon, err := newInstaller(service.DaemonKind, []string{"__runtime-local-daemon"})
	if err != nil {
		return nil, nil, nil, err
	}
	return hostd, updater, daemon, nil
}

func newWindowsLifecycleManager(request Request, layout service.Layout, allowMissingExecutable bool) (*service.LifecycleManager, error) {
	hostd, updater, _, err := windowsRoleInstallers(layout, allowMissingExecutable)
	if err != nil {
		return nil, err
	}
	return newWindowsLifecycleManagerForInstallers(layout, hostd, updater, &request)
}

func newWindowsLifecycleManagerForInstallers(_ service.Layout, hostd, updater *service.Installer, request *Request) (*service.LifecycleManager, error) {
	var probe func(context.Context) error
	if request != nil && request.HelperListenAddress != "" {
		var err error
		probe, err = service.NewHTTPReadinessProbe("http://" + request.HelperListenAddress + "/healthz")
		if err != nil {
			return nil, err
		}
	}
	return service.NewHostLifecycleManager(service.HostLifecycleConfig{StateRoot: filepath.Join(WindowsProgramDataRoot(), "service-lifecycle"), Hostd: hostd, Updater: updater, HostdProbe: probe})
}

func Validate(request Request, _ int) error {
	if request.Schema != SchemaV1 {
		return fmt.Errorf("%w: schema", ErrInvalidRequest)
	}
	if request.Platform != runtime.GOOS {
		return fmt.Errorf("%w: platform", ErrInvalidRequest)
	}
	if request.User == "" {
		return fmt.Errorf("%w: user", ErrInvalidRequest)
	}
	if request.OwnerSID == "" || !validSID(request.OwnerSID) {
		return fmt.Errorf("%w: owner SID", ErrInvalidRequest)
	}
	if request.UserMachineID == "" {
		return fmt.Errorf("%w: machine ID", ErrInvalidRequest)
	}
	if request.SetupMode != "host" && request.SetupMode != "client" {
		return fmt.Errorf("%w: setup mode", ErrInvalidRequest)
	}
	listenHost, listenPort, listenErr := net.SplitHostPort(request.HelperListenAddress)
	if listenErr != nil || listenPort == "" || net.ParseIP(listenHost) == nil || !net.ParseIP(listenHost).IsLoopback() {
		return fmt.Errorf("%w: helper listen address", ErrInvalidRequest)
	}
	if err := bootstrap.VerifyArtifactTarget(request.Artifact); err != nil || request.Artifact.Platform != "windows" {
		return fmt.Errorf("%w: artifact descriptor", ErrInvalidRequest)
	}
	for _, item := range []struct{ name, path string }{{"executable", request.Executable}, {"home", request.Home}, {"state root", request.StateRoot}, {"workspace root", request.WorkspaceRoot}} {
		if !safeAbsolute(item.path) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, item.name)
		}
	}
	if err := binarytarget.Validate(request.Executable, request.Platform, request.Artifact.Architecture); err != nil {
		return fmt.Errorf("%w: executable format", ErrInvalidRequest)
	}
	return nil
}

func writeWindowsConfig(config WindowsRuntimeConfig) error {
	if !validWindowsConfig(config) {
		return ErrInvalidRequest
	}
	body, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), config.OwnerSID); err != nil {
		return err
	}
	fileDACL := windowsRuntimeCurrentFileDACL(config.OwnerSID)
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(WindowsInstallConfigPath(), body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SY" + fileDACL})
	}); err != nil {
		return err
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return err
	}
	return applyWindowsOwnedDACL(WindowsInstallConfigPath(), trustedOwner, fileDACL)
}

func validWindowsConfig(config WindowsRuntimeConfig) bool {
	host, port, listenErr := net.SplitHostPort(config.ListenAddress)
	return config.Schema == windowsConfigSchema && validSID(config.OwnerSID) && config.User != "" && safeAbsolute(config.StateRoot) && safeAbsolute(config.Workspace) && config.TokenFile == WindowsHostdTokenPath() && config.MachineID != "" && (config.SetupMode == "host" || config.SetupMode == "client") && bootstrap.VerifyArtifactTarget(config.Artifact) == nil && config.Artifact.Platform == "windows" && config.Artifact.Architecture == runtime.GOARCH && listenErr == nil && port != "" && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}
func safeAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func validSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.IsValid()
}

func ensureWindowsToken(ownerSID string) error {
	path := WindowsHostdTokenPath()
	if err := secureWindowsFile(path, ""); err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() != 32 {
			return ErrInvalidRequest
		}
		trustedOwner, ownerErr := windowsRuntimeTrustedOwner()
		if ownerErr != nil {
			return ownerErr
		}
		if !windowsRuntimeSecurityMatches(path, trustedOwner, windowsRuntimeCurrentFileDACL(ownerSID)) {
			return fmt.Errorf("validate existing Windows runtime token security: %w", ErrInvalidRequest)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(path, token, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SY" + windowsRuntimeCurrentFileDACL(ownerSID)})
	}); err != nil {
		return err
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return err
	}
	return applyWindowsOwnedDACL(path, trustedOwner, windowsRuntimeCurrentFileDACL(ownerSID))
}

func ensureWindowsMachineDirectory(path, ownerSID string) error {
	if !safeAbsolute(path) || !validSID(ownerSID) {
		return ErrInvalidRequest
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return err
	}
	_, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := createWindowsRuntimeRoot(path, trustedOwner, windowsRuntimeCurrentRootDACL(ownerSID)); err == nil {
			// Creation and the BA-to-SYSTEM owner transition were verified through
			// one nonshared, non-reparse handle. Do not weaken that proof by
			// resolving the path again after the trusted handle is closed.
			return nil
		} else if err != windows.ERROR_ALREADY_EXISTS {
			return err
		}
	} else if statErr != nil {
		return statErr
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidRequest
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidRequest
	}
	handle, _, err := openWindowsRuntimeObject(path, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	// A pre-existing machine root may be created by MSI under SYSTEM. A process
	// cut between protected creation and the owner transfer may leave the exact
	// Administrators-owned current-DACL transition. WiX also creates DATAROOT
	// with an Administrators owner and a protected SYSTEM/Administrators-only
	// DACL before the enrolled SID is known. Both states exclude the enrolled
	// user's filtered token and are safe to complete through this held handle.
	// Reject every other owner or DACL without rewriting it.
	if !windowssecurity.HandleOwnerMatchesSID(handle, trustedOwner) {
		administrators, ownerErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		trustedTransition := windowssecurity.ProtectedHandleDACLMatches(handle, windowsRuntimeCurrentRootDACL(ownerSID)) ||
			windowssecurity.ProtectedHandleDACLMatches(handle, windowsRuntimeMSIBootstrapRootDACL()) ||
			windowssecurity.ProtectedHandleDACLMatches(handle, windowsRuntimeStandaloneBootstrapRootDACL())
		if ownerErr != nil || !windowssecurity.HandleOwnerMatchesSID(handle, administrators) || !trustedTransition {
			return fmt.Errorf("validate existing Windows runtime root owner: %w", ErrInvalidRequest)
		}
	}
	return applyWindowsHandleOwnedDACL(handle, trustedOwner, windowsRuntimeCurrentRootDACL(ownerSID))
}

func windowsRuntimeTrustedOwner() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinLocalSystemSid)
}

func windowsRuntimeLegacyFileDACL(ownerSID string) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ownerSID + ")"
}

func windowsRuntimeLegacyRootDACL(ownerSID string) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ownerSID + ")"
}

func windowsRuntimeCurrentFileDACL(ownerSID string) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + ownerSID + ")"
}

func windowsRuntimeCurrentRootDACL(ownerSID string) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + ownerSID + ")"
}

func windowsRuntimeMSIBootstrapRootDACL() string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
}

// The standalone dashboard installer creates ProgramData through the normal
// inherited Windows directory ACL before a machine owner SID exists. Accept
// only that exact protected inherited bootstrap state, then atomically replace
// it with the final SYSTEM-owned, enrolled-user-readable runtime ACL. Any
// additional or changed ACE remains fail-closed.
func windowsRuntimeStandaloneBootstrapRootDACL() string {
	return "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
}

func windowsRuntimeSecurityMatches(path string, owner *windows.SID, dacl string) bool {
	handle, err := openWindowsRuntimeSecurityObject(path)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	return windowsRuntimeHandleSecurityMatches(handle, owner, dacl)
}

func validateWindowsRuntimeSecurity(path string, owner *windows.SID, dacl, stage string) error {
	handle, err := openWindowsRuntimeSecurityObject(path)
	if err != nil {
		return fmt.Errorf("open Windows runtime %s security: %w", stage, err)
	}
	defer windows.CloseHandle(handle)
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
		return fmt.Errorf("validate Windows runtime %s filesystem owner: %w", stage, ErrInvalidRequest)
	}
	if !windowssecurity.ProtectedHandleDACLMatches(handle, dacl) {
		actual := "unavailable"
		if current, queryErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); queryErr == nil && current != nil {
			actual = current.String()
		}
		return fmt.Errorf("validate Windows runtime %s protected DACL (got %s want %s): %w", stage, actual, dacl, ErrInvalidRequest)
	}
	return nil
}

func openWindowsRuntimeSecurityObject(path string) (windows.Handle, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		if err == nil {
			err = ErrInvalidRequest
		}
		return 0, err
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if info.IsDir() {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != info.IsDir() {
		windows.CloseHandle(handle)
		return 0, ErrInvalidRequest
	}
	return handle, nil
}

func windowsRuntimeMigrationSecurityMatches(path string, legacyOwner, trustedOwner *windows.SID, legacyDACL, currentDACL string) bool {
	return windowsRuntimeSecurityMatches(path, legacyOwner, legacyDACL) || windowsRuntimeSecurityMatches(path, trustedOwner, currentDACL)
}

func windowsRuntimeHandleSecurityMatches(handle windows.Handle, owner *windows.SID, dacl string) bool {
	return windowssecurity.HandleOwnerMatchesSID(handle, owner) && windowssecurity.ProtectedHandleDACLMatches(handle, dacl)
}

func windowsRuntimeMigrationHandleSecurityMatches(handle windows.Handle, legacyOwner, trustedOwner *windows.SID, legacyDACL, currentDACL string) bool {
	return windowsRuntimeHandleSecurityMatches(handle, legacyOwner, legacyDACL) || windowsRuntimeHandleSecurityMatches(handle, trustedOwner, currentDACL)
}

func openWindowsRuntimeObject(path string, directory bool) (windows.Handle, windows.ByHandleFileInformation, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, 0, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, ErrInvalidRequest
	}
	return handle, information, nil
}

func applyWindowsHandleOwnedDACL(handle windows.Handle, owner *windows.SID, access string) error {
	if owner == nil || !owner.IsValid() {
		return ErrInvalidRequest
	}
	descriptor, err := windows.SecurityDescriptorFromString(access)
	if err != nil {
		return err
	}
	absoluteDescriptor, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absoluteDescriptor.DACL()
	if err != nil {
		return err
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		if setErr := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); setErr != nil {
			return setErr
		}
		runtime.KeepAlive(absoluteDescriptor)
		if !windowssecurity.ProtectedHandleDACLMatches(handle, access) {
			return fmt.Errorf("validate rewritten object protected DACL: %w", ErrInvalidRequest)
		}
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}); err != nil {
		return err
	}
	runtime.KeepAlive(absoluteDescriptor)
	if !windowsRuntimeHandleSecurityMatches(handle, owner, access) {
		return ErrInvalidRequest
	}
	return nil
}

func applyWindowsOwnedDACL(path string, owner *windows.SID, access string) error {
	if owner == nil || !owner.IsValid() {
		return ErrInvalidRequest
	}
	descriptor, err := windows.SecurityDescriptorFromString(access)
	if err != nil {
		return err
	}
	absoluteDescriptor, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absoluteDescriptor.DACL()
	if err != nil {
		return err
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		if setErr := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); setErr != nil {
			return setErr
		}
		runtime.KeepAlive(absoluteDescriptor)
		if !windowssecurity.ProtectedDACLMatches(path, access) {
			return fmt.Errorf("validate rewritten object protected DACL: %w", ErrInvalidRequest)
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}); err != nil {
		return err
	}
	runtime.KeepAlive(absoluteDescriptor)
	if err := validateWindowsRuntimeSecurity(path, owner, access, "rewritten object"); err != nil {
		return err
	}
	return nil
}

func createWindowsRuntimeRoot(path string, owner *windows.SID, dacl string) error {
	// Administrators is a trusted creation owner in an elevated token. The
	// final protected DACL gives the enrolled user read/execute only, so the
	// object is safe while its owner is transferred to SYSTEM.
	descriptor, err := windows.SecurityDescriptorFromString(dacl)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	created := false
	err = windowssecurity.WithRestorePrivilegeAndOwner(administrators, func() error {
		if err := windows.CreateDirectory(pathUTF16, &attributes); err != nil {
			return err
		}
		created = true
		handle, openErr := windows.CreateFile(pathUTF16, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if openErr != nil {
			return openErr
		}
		defer windows.CloseHandle(handle)
		var information windows.ByHandleFileInformation
		if infoErr := windows.GetFileInformationByHandle(handle, &information); infoErr != nil {
			return infoErr
		}
		if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalidRequest
		}
		if !windowssecurity.HandleOwnerMatchesSID(handle, administrators) || !windowssecurity.ProtectedHandleDACLMatches(handle, dacl) {
			return windows.ERROR_INVALID_SECURITY_DESCR
		}
		finalDescriptor, descriptorErr := windows.SecurityDescriptorFromString(dacl)
		if descriptorErr != nil {
			return descriptorErr
		}
		absoluteDescriptor, descriptorErr := finalDescriptor.ToAbsolute()
		if descriptorErr != nil {
			return descriptorErr
		}
		finalDACL, _, descriptorErr := absoluteDescriptor.DACL()
		if descriptorErr != nil {
			return descriptorErr
		}
		descriptorErr = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, finalDACL, nil)
		runtime.KeepAlive(absoluteDescriptor)
		if descriptorErr != nil {
			return descriptorErr
		}
		if !windowssecurity.ProtectedHandleDACLMatches(handle, dacl) {
			return fmt.Errorf("validate created Windows runtime root protected DACL: %w", ErrInvalidRequest)
		}
		if descriptorErr = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); descriptorErr != nil {
			return descriptorErr
		}
		if !windowssecurity.HandleOwnerMatchesSID(handle, owner) || !windowssecurity.ProtectedHandleDACLMatches(handle, dacl) {
			return windows.ERROR_INVALID_SECURITY_DESCR
		}
		return nil
	})
	runtime.KeepAlive(descriptor)
	if err != nil {
		removeErr := error(nil)
		if created {
			removeErr = os.Remove(path)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
		}
		if removeErr != nil {
			return errors.Join(err, removeErr)
		}
		return err
	}
	return nil
}

// windowsRuntimePaths returns the only active executable and its two protected
// transaction slots.
func windowsRuntimePaths(layout service.Layout) (current, rollback, staged string) {
	return layout.Binary, layout.BinaryRollback, layout.BinaryStaged
}

func stageWindowsBinary(ctx context.Context, source, current, rollback string, artifact bootstrap.ArtifactTarget, ownerSID string) error {
	if err := ensureWindowsExecutableDirectory(filepath.Dir(current), ownerSID); err != nil {
		return fmt.Errorf("prepare runtime slot: %w", err)
	}
	if err := ensureWindowsExecutableDirectory(filepath.Dir(rollback), ownerSID); err != nil {
		return fmt.Errorf("prepare runtime rollback slot: %w", err)
	}
	if err := secureWindowsFile(source, ""); err != nil {
		return fmt.Errorf("validate downloaded runtime file: %w", err)
	}
	sourceVerifyCtx, cancelSourceVerify := context.WithTimeout(ctx, 30*time.Second)
	defer cancelSourceVerify()
	if err := nativesignature.New(nil).Verify(sourceVerifyCtx, source, "windows", artifact.Architecture); err != nil {
		return fmt.Errorf("%w: downloaded runtime Authenticode: %v", ErrInvalidRequest, err)
	}
	// The dashboard bootstrap may execute the verified binary directly from the
	// installed active slot. That process necessarily keeps the image open on
	// Windows, so rotating the slot would fail with a sharing violation. The
	// image has already passed every integrity and signature check above; leave
	// it in place and let service installation bind to the same executable.
	if filepath.Clean(source) == filepath.Clean(current) {
		return nil
	}
	body, err := os.ReadFile(source)
	if err != nil || len(body) < 1 || len(body) > 256<<20 {
		return fmt.Errorf("%w: read staged runtime", ErrInvalidRequest)
	}
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-host-install reason=same-directory-verified-runtime-staging
	temporaryPath := filepath.Join(filepath.Dir(current), ".paperboat-runtime-"+hex.EncodeToString(suffix[:])+".exe")
	defer os.Remove(temporaryPath)
	publicDACL := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	if ownerSID != "" {
		publicDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + ownerSID + ")"
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(temporaryPath, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SY" + publicDACL})
	}); err != nil {
		return err
	}
	if err := binarytarget.Validate(temporaryPath, "windows", artifact.Architecture); err != nil {
		return fmt.Errorf("%w: staged runtime executable format", ErrInvalidRequest)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, temporaryPath, "windows", artifact.Architecture); err != nil {
		return fmt.Errorf("%w: staged runtime Authenticode: %v", ErrInvalidRequest, err)
	}
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return err
	}
	if err := validateWindowsRuntimeSecurity(temporaryPath, trustedOwner, publicDACL, "staged executable"); err != nil {
		return err
	}
	if err := removeWindowsFileWithRetry(ctx, rollback); err != nil {
		return err
	}
	if _, err := os.Stat(current); err == nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-install reason=current-to-rollback-slot-transition
		if err := os.Rename(current, rollback); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-host-install reason=verified-staged-runtime-activation
	if err := os.Rename(temporaryPath, current); err != nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-install reason=restore-rollback-after-activation-failure
		_ = os.Rename(rollback, current)
		return err
	}
	return nil
}

func removeWindowsFileWithRetry(ctx context.Context, path string) error {
	var last error
	for attempt := 0; attempt < 10; attempt++ {
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return last
}

func ensureWindowsExecutableDirectory(path, readerSID string) error {
	if !safeAbsolute(path) {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidRequest
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidRequest
	}
	if readerSID == "" {
		readerSID = "BU"
	} else if !validSID(readerSID) {
		return ErrInvalidRequest
	}
	dacl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + readerSID + ")"
	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		return err
	}
	return applyWindowsOwnedDACL(path, trustedOwner, dacl)
}

func repairWindowsRuntimeBinary(ctx context.Context, config WindowsRuntimeConfig, layout service.Layout) error {
	current, rollback, _ := windowsRuntimePaths(layout)
	quarantine := current + ".repair-quarantine"
	if verifyWindowsInstalledBinary(ctx, current, config.Artifact.Architecture) == nil {
		_ = os.Remove(quarantine)
		return applyWindowsACL(current, config.OwnerSID, false)
	}
	if _, err := os.Stat(current); errors.Is(err, os.ErrNotExist) && verifyWindowsInstalledBinary(ctx, quarantine, config.Artifact.Architecture) == nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=verified-quarantine-runtime-restoration
		if err := os.Rename(quarantine, current); err != nil {
			return err
		}
		return applyWindowsACL(current, config.OwnerSID, false)
	}
	_ = os.Remove(quarantine)
	currentExists := false
	if _, err := os.Stat(current); err == nil {
		currentExists = true
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=current-runtime-quarantine-before-verification
		if err := os.Rename(current, quarantine); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	restoreCurrent := func() {
		if currentExists {
			//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=restore-quarantined-current-runtime
			_ = os.Rename(quarantine, current)
		}
	}
	if verifyWindowsInstalledBinary(ctx, rollback, config.Artifact.Architecture) == nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=verified-rollback-runtime-activation
		if err := os.Rename(rollback, current); err != nil {
			restoreCurrent()
			return err
		}
		_ = os.Remove(quarantine)
		return applyWindowsACL(current, config.OwnerSID, false)
	}
	repairState := filepath.Join(layout.UpdateStateRoot, "repair-tuf")
	artifactPath, err := bootstrap.FetchVerifiedArtifact(ctx, config.Artifact, repairState, nil)
	if err != nil {
		restoreCurrent()
		return err
	}
	if err := stageWindowsBinary(ctx, artifactPath, current, rollback, config.Artifact, config.OwnerSID); err != nil {
		restoreCurrent()
		return err
	}
	_ = os.Remove(quarantine)
	return nil
}

func verifyWindowsInstalledBinary(ctx context.Context, path, architecture string) error {
	if err := secureWindowsFile(path, ""); err != nil {
		return err
	}
	if err := binarytarget.Validate(path, "windows", architecture); err != nil {
		return err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return nativesignature.New(nil).Verify(verifyCtx, path, "windows", architecture)
}

func ensureWindowsDirectory(path, ownerSID string) error {
	if !safeAbsolute(path) {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidRequest
	}
	return applyWindowsACL(path, ownerSID, true)
}

// PrepareWindowsLocalDaemonState repairs the enrolled user's LocalDaemon
// state before an SCM service starts. Windows S4U logon SIDs are temporary;
// state inherited from one service session must therefore be rebound to the
// permanent enrolled SID by the elevated installer or updater.
func PrepareWindowsLocalDaemonState(runtimeStateRoot, ownerSID string) error {
	lockPath, err := windowsLocalDaemonLockPath(runtimeStateRoot)
	if err != nil || !validSID(ownerSID) {
		return ErrInvalidRequest
	}
	root := filepath.Dir(lockPath)
	if err := rejectWindowsReparseAncestors(root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := rejectWindowsReparseAncestors(root); err != nil {
		return err
	}
	owner, err := windows.StringToSid(ownerSID)
	if err != nil || owner == nil || !owner.IsValid() {
		return ErrInvalidRequest
	}
	handle, err := openWindowsLocalDaemonStateRoot(root)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	rootFinal, err := windowsFinalPath(handle)
	if err != nil || !strings.EqualFold(rootFinal, windowsExpectedFinalPath(root)) {
		return errors.Join(err, ErrInvalidRequest)
	}
	access := windowsLocalDaemonStateRootDACL(ownerSID)
	if err := applyWindowsHandleOwnedDACL(handle, owner, access); err != nil {
		return err
	}
	// Existing lock, owner, and diagnostic files can retain a protected DACL
	// from an earlier S4U session. Repair the bounded Paperboat-owned subtree
	// while the root remains pinned against replacement.
	if err := repairWindowsLocalDaemonTreeChildren(root, handle, owner); err != nil {
		return err
	}
	if !windowsRuntimeHandleSecurityMatches(handle, owner, access) {
		return ErrInvalidRequest
	}
	return nil
}

func rejectWindowsReparseAncestors(path string) error {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		return ErrInvalidRequest
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalidRequest
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidRequest
		}
		attributes, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func openWindowsLocalDaemonStateRoot(path string) (windows.Handle, error) {
	return openWindowsLocalDaemonStateObject(path, true)
}

func openWindowsLocalDaemonStateObject(path string, directory bool) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory {
		windows.CloseHandle(handle)
		return 0, ErrInvalidRequest
	}
	return handle, nil
}

func repairWindowsLocalDaemonTreeChildren(root string, rootHandle windows.Handle, owner *windows.SID) error {
	if !safeAbsolute(root) || owner == nil || !owner.IsValid() {
		return ErrInvalidRequest
	}
	rootFinal, err := windowsFinalPath(rootHandle)
	if err != nil {
		return err
	}
	rootPrefix := strings.TrimRight(rootFinal, `\/`) + string(filepath.Separator)
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		handle, err := openWindowsLocalDaemonStateObject(path, entry.IsDir())
		if err != nil {
			return err
		}
		finalPath, finalErr := windowsFinalPath(handle)
		var information windows.ByHandleFileInformation
		infoErr := windows.GetFileInformationByHandle(handle, &information)
		if finalErr != nil || infoErr != nil || !strings.HasPrefix(strings.ToLower(finalPath), strings.ToLower(rootPrefix)) || !entry.IsDir() && information.NumberOfLinks != 1 {
			return errors.Join(finalErr, infoErr, windows.CloseHandle(handle), ErrInvalidRequest)
		}
		access := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + owner.String() + ")"
		if entry.IsDir() {
			access = windowssecurity.OwnerFullControlDirectoryDACL(owner.String())
		}
		applyErr := applyWindowsHandleOwnedDACL(handle, owner, access)
		return errors.Join(applyErr, windows.CloseHandle(handle))
	})
}

func windowsFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length == 0 {
			return "", ErrInvalidRequest
		}
		if int(length) < len(buffer) {
			return filepath.Clean(windows.UTF16ToString(buffer[:length])), nil
		}
		if length > 32<<10 {
			return "", ErrInvalidRequest
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func windowsExpectedFinalPath(path string) string {
	path = filepath.Clean(path)
	if strings.HasPrefix(path, `\\`) {
		return filepath.Clean(`\\?\UNC\` + strings.TrimPrefix(path, `\\`))
	}
	return filepath.Clean(`\\?\` + path)
}

func windowsLocalDaemonStateRootDACL(ownerSID string) string {
	return windowssecurity.OwnerFullControlDirectoryDACL(ownerSID)
}

func secureWindowsFile(path, ownerSID string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidRequest
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidRequest
	}
	if ownerSID != "" {
		return applyWindowsACL(path, ownerSID, false)
	}
	return nil
}
func applyWindowsACL(path, ownerSID string, directory bool) error {
	flags := ""
	if directory {
		flags = "OICI"
	}
	access := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)"
	if ownerSID != "" {
		access += "(A;" + flags + ";FA;;;" + ownerSID + ")"
	}
	return applyWindowsDACL(path, access)
}

func applyWindowsDACL(path, access string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		if err == nil {
			err = ErrInvalidRequest
		}
		return err
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if info.IsDir() {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pathUTF16, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != info.IsDir() {
		return ErrInvalidRequest
	}
	descriptor, err := windows.SecurityDescriptorFromString(access)
	if err != nil {
		return err
	}
	absoluteDescriptor, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absoluteDescriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	runtime.KeepAlive(absoluteDescriptor)
	if !windowssecurity.ProtectedHandleDACLMatches(handle, access) {
		return fmt.Errorf("validate rewritten Windows object protected DACL: %w", ErrInvalidRequest)
	}
	return nil
}

func repairWindowsTreeACL(root, ownerSID string) error {
	if !safeAbsolute(root) || !validSID(ownerSID) {
		return ErrInvalidRequest
	}
	owner, err := windows.StringToSid(ownerSID)
	if err != nil {
		return ErrInvalidRequest
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalidRequest
		}
		if err := applyWindowsACL(path, ownerSID, entry.IsDir()); err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	})
}
func isAdministrator() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
