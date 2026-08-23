//go:build windows

// Package hostinstall owns the fixed, machine-wide Windows runtime layout.
// It deliberately accepts no caller-selected service executable or service
// name: installation material is verified before this package is called and
// every durable path below is part of Paperboat's native layout.
package hostinstall

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
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
	installPaperboatSSH       = windowsopenssh.InstallService
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
	if !windowsRuntimeSecurityMatches(WindowsProgramDataRoot(), trustedOwner, rootDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime root security: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeSecurityMatches(WindowsInstallConfigPath(), trustedOwner, fileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime config security: %w", ErrInvalidRequest)
	}
	if err := secureWindowsFile(WindowsHostdTokenPath(), ""); err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime token file: %w", err)
	}
	tokenInfo, err := os.Stat(WindowsHostdTokenPath())
	if err != nil || tokenInfo.Size() != 32 {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime token size: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeSecurityMatches(WindowsHostdTokenPath(), trustedOwner, fileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate Windows runtime token security: %w", ErrInvalidRequest)
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
	config, err := readWindowsRuntimeConfig()
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
	if !windowsRuntimeMigrationSecurityMatches(WindowsProgramDataRoot(), legacyOwner, trustedOwner, legacyRootDACL, currentRootDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime root security: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeMigrationSecurityMatches(WindowsInstallConfigPath(), legacyOwner, trustedOwner, legacyFileDACL, currentFileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime config security: %w", ErrInvalidRequest)
	}
	tokenErr := secureWindowsFile(WindowsHostdTokenPath(), "")
	tokenInfo, tokenStatErr := os.Stat(WindowsHostdTokenPath())
	if tokenErr != nil || tokenStatErr != nil || tokenInfo.Size() != 32 {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime token file: %w", ErrInvalidRequest)
	}
	if !windowsRuntimeMigrationSecurityMatches(WindowsHostdTokenPath(), legacyOwner, trustedOwner, legacyFileDACL, currentFileDACL) {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime token security: %w", ErrInvalidRequest)
	}
	allCurrent := windowsRuntimeSecurityMatches(WindowsProgramDataRoot(), trustedOwner, currentRootDACL) &&
		windowsRuntimeSecurityMatches(WindowsInstallConfigPath(), trustedOwner, currentFileDACL) &&
		windowsRuntimeSecurityMatches(WindowsHostdTokenPath(), trustedOwner, currentFileDACL)
	if allCurrent {
		return WindowsRuntimeConfig{}, fmt.Errorf("validate legacy Windows runtime transition: %w", ErrInvalidRequest)
	}
	// Validate every object before the first mutation. A foreign owner must fail
	// without allowing a partially trusted tree to be adopted. Each subsequent
	// owner+DACL replacement is idempotent, so an interrupted migration can
	// resume from any mixture of the two explicitly supported states.
	for _, item := range []struct{ path, dacl, stage string }{
		{WindowsHostdTokenPath(), currentFileDACL, "token"},
		{WindowsInstallConfigPath(), currentFileDACL, "config"},
		{WindowsProgramDataRoot(), currentRootDACL, "root"},
	} {
		if err := applyWindowsOwnedDACL(item.path, trustedOwner, item.dacl); err != nil {
			return WindowsRuntimeConfig{}, fmt.Errorf("migrate Windows runtime %s security: %w", item.stage, err)
		}
	}
	migrated, err := LoadWindowsRuntimeConfig()
	if err != nil {
		return WindowsRuntimeConfig{}, fmt.Errorf("verify migrated Windows runtime security: %w", err)
	}
	return migrated, nil
}

func Install(ctx context.Context, request Request) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	if err := Validate(request, 0); err != nil {
		return err
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat machine state", func() error { return ensureWindowsMachineDirectory(WindowsProgramDataRoot(), request.OwnerSID) }); err != nil {
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
	// Client has no SSH capability, but PaperboatSshd can hold the current
	// runtime open. Release that service before slot rotation; defer its slower
	// firewall/state cleanup until the new runtime services are running.
	if err := runWindowsInstallPhase(ctx, "release Paperboat OpenSSH service for activation", func() error { return removeWindowsSSHBeforeActivation(ctx, request, layout) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "stage verified Paperboat runtime", func() error {
		return stageWindowsBinary(ctx, request.Executable, layout.RuntimeCurrent, layout.RuntimeRollback, request.Artifact, request.OwnerSID)
	}); err != nil {
		return err
	}
	// The bootstrap artifact is also the signed CLI target. Seed the stable
	// CLI slot during every install/renewal instead of leaving the MSI's old
	// pb.exe as the command users execute.
	if err := runWindowsInstallPhase(ctx, "stage verified Paperboat CLI", func() error {
		return stageWindowsBinary(ctx, request.Executable, layout.CLICurrent, layout.CLIRollback, request.Artifact, "")
	}); err != nil {
		return err
	}
	immutableRelease, err := layout.WindowsRelease(request.Artifact.Version)
	if err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "seed immutable Paperboat Windows release", func() error {
		return seedWindowsImmutableRelease(ctx, request, layout, immutableRelease)
	}); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "protect Paperboat CLI release slots", func() error { return protectWindowsCLISlots(layout) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "activate stable Paperboat CLI launcher", func() error { return installWindowsCLIEntrypoint(ctx, layout, request.Artifact.Architecture) }); err != nil {
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
		return installWindowsServices(ctx, layout, "", immutableRelease.Hostd, immutableRelease.Updater)
	}); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "finalize Paperboat OpenSSH role", func() error { return installWindowsSSHAfterActivation(ctx, request, layout) }); err != nil {
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
	config.ServiceExecutable = layout.RuntimeCurrent
	if installed, err := LoadWindowsRuntimeConfig(); err == nil {
		if release, releaseErr := layout.WindowsRelease(installed.Artifact.Version); releaseErr == nil {
			if _, statErr := os.Lstat(release.Runtime); statErr == nil {
				config.ServiceExecutable = release.Runtime
			}
		}
	}
	return config
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
	return installPaperboatSSH(ctx, layout.RuntimeCurrent, filepath.Join(config.InstallRoot, "sshd.exe"), filepath.Join(config.StateRoot, "sshd_config"))
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
	for _, name := range []string{"PaperboatHostd", "PaperboatUpdated"} {
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
	for _, name := range []string{"PaperboatHostd", "PaperboatUpdated"} {
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
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	return errors.Join(uninstallWindows(ctx, false), removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, request.OwnerSID)))
}

func UninstallPersisted(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	config, err := LoadWindowsRuntimeConfig()
	if err != nil {
		return err
	}
	layout, layoutErr := service.DefaultLayout("windows")
	if layoutErr != nil {
		return layoutErr
	}
	return errors.Join(uninstallWindows(ctx, false), removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, config.OwnerSID)))
}

// Repair restores the persisted Windows runtime and its role-scoped OpenSSH
// service set. Client repair keeps Paperboat SSH absent.
func Repair(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
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
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	config, err = reconcileWindowsRepairVersion(ctx, config, layout)
	if err != nil {
		return err
	}
	request := Request{SetupMode: config.SetupMode, OwnerSID: config.OwnerSID}
	if err := removeWindowsSSHBeforeActivation(ctx, request, layout); err != nil {
		return err
	}
	if err := repairWindowsRuntimeBinary(ctx, config, layout); err != nil {
		return err
	}
	if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), config.OwnerSID); err != nil {
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
	immutableRelease, err := layout.WindowsRelease(config.Artifact.Version)
	if err != nil {
		return err
	}
	seedRequest := Request{Executable: layout.RuntimeCurrent, OwnerSID: config.OwnerSID, Artifact: config.Artifact}
	if err := seedWindowsImmutableRelease(ctx, seedRequest, layout, immutableRelease); err != nil {
		return err
	}
	if err := installWindowsServices(ctx, layout, "", immutableRelease.Hostd, immutableRelease.Updater); err != nil {
		return err
	}
	return installWindowsSSHAfterActivation(ctx, request, layout)
}

func reconcileWindowsRepairVersion(ctx context.Context, config WindowsRuntimeConfig, layout service.Layout) (WindowsRuntimeConfig, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return config, err
	}
	defer manager.Disconnect()
	versions := make([]string, 0, 2)
	for _, item := range []struct{ name, argument string }{{"PaperboatHostd", "__runtime-hostd"}, {"PaperboatUpdated", "__runtime-updated"}} {
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
		version, err := layout.WindowsVersionForExecutable(arguments[0])
		if err != nil {
			return config, nil
		}
		if err := verifyWindowsInstalledBinary(ctx, arguments[0], config.Artifact.Architecture); err != nil {
			return config, err
		}
		versions = append(versions, version)
	}
	if len(versions) != 2 || versions[0] != versions[1] {
		return config, ErrInvalidRequest
	}
	if versions[0] != config.Artifact.Version {
		config.Artifact.Version = versions[0]
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
	// Windows OpenSSH is a shared WinGet dependency. Purge only removes the
	// dedicated PaperboatSshd service, Paperboat SSH keys/configuration, and
	// firewall deltas that Paperboat recorded as its own. This must happen
	// before the Paperboat runtime slots are removed because their fixed path
	// is the ownership proof for PaperboatSshd.
	var result error
	if layout, err := service.DefaultLayout("windows"); err != nil {
		result = errors.Join(result, err)
	} else {
		result = errors.Join(result, removePaperboatSSHState(ctx, windowsOpenSSHConfig(layout, "")))
	}
	return errors.Join(result, uninstallWindows(ctx, true))
}

func uninstallWindows(ctx context.Context, purge bool) error {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	var result error
	for _, item := range []struct {
		kind       string
		executable string
		args       []string
	}{
		{service.HostdKind, layout.RuntimeCurrent, []string{"__runtime-hostd"}},
		{service.UpdaterKind, layout.RuntimeCurrent, []string{"__runtime-updated"}},
	} {
		installer, makeErr := service.New(service.Config{Platform: "windows", Kind: item.kind, ConfigRoot: WindowsProgramDataRoot(), Executable: item.executable, User: "Paperboat", Group: "Paperboat", Arguments: item.args, Controller: service.WindowsController{}})
		if makeErr == nil {
			result = errors.Join(result, installer.Uninstall(ctx))
		}
	}
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	if purge {
		for _, path := range []string{layout.ReleasesRoot, filepath.Join(WindowsProgramDataRoot(), "services"), layout.UpdateStateRoot} {
			if err := os.RemoveAll(path); err != nil {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func installWindowsServices(ctx context.Context, layout service.Layout, upgradeMode string, immutableTargets ...string) error {
	hostdExecutable, updaterExecutable := layout.RuntimeCurrent, layout.RuntimeCurrent
	if len(immutableTargets) == 2 {
		hostdExecutable, updaterExecutable = immutableTargets[0], immutableTargets[1]
	}
	for _, item := range []struct {
		kind, executable string
		args             []string
	}{{service.HostdKind, hostdExecutable, []string{"__runtime-hostd"}}, {service.UpdaterKind, updaterExecutable, []string{"__runtime-updated"}}} {
		installer, err := service.New(service.Config{Platform: "windows", Kind: item.kind, ConfigRoot: WindowsProgramDataRoot(), Executable: item.executable, User: "Paperboat", Group: "Paperboat", Arguments: item.args, Controller: service.WindowsController{}, UpgradeMode: upgradeMode})
		if err != nil {
			return err
		}
		if err := installer.Install(ctx); err != nil {
			return err
		}
	}
	return nil
}

func seedWindowsImmutableRelease(ctx context.Context, request Request, layout service.Layout, release service.WindowsReleasePaths) error {
	if err := ensureWindowsImmutableDirectory(filepath.Dir(release.Root)); err != nil {
		return err
	}
	if err := ensureWindowsImmutableDirectory(release.Root); err != nil {
		return err
	}
	// MSI owns the stable launcher and the initial role-stamped artifacts.
	// Never manufacture a missing hostd/updater by copying the general CLI or
	// runtime binary: that would erase the build-time command allowlist.
	for _, destination := range []string{release.Runtime, release.Hostd, release.Updater} {
		if err := verifyWindowsInstalledBinary(ctx, destination, request.Artifact.Architecture); err != nil {
			return err
		}
		if err := applyWindowsDACL(destination, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)"); err != nil {
			return err
		}
	}
	return nil
}

func ensureWindowsImmutableDirectory(path string) error {
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
	return applyWindowsDACL(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
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
	if err := withWindowsRestorePrivilege(func() error {
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
	if err := withWindowsRestorePrivilege(func() error {
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
	created := false
	if errors.Is(statErr, os.ErrNotExist) {
		if err := createWindowsRuntimeRoot(path, trustedOwner, windowsRuntimeCurrentRootDACL(ownerSID)); err == nil {
			created = true
		} else if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
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
	// A pre-existing machine root may be created by MSI under SYSTEM.
	// Never rewrite an enrolled-user or foreign-owned root outside the explicit
	// legacy migration path.
	if !created && !windowssecurity.OwnerMatchesSID(path, trustedOwner) {
		return fmt.Errorf("validate existing Windows runtime root owner: %w", ErrInvalidRequest)
	}
	return applyWindowsOwnedDACL(path, trustedOwner, windowsRuntimeCurrentRootDACL(ownerSID))
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
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;" + ownerSID + ")"
}

func windowsRuntimeCurrentRootDACL(ownerSID string) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + ownerSID + ")"
}

func windowsRuntimeSecurityMatches(path string, owner *windows.SID, dacl string) bool {
	return windowssecurity.OwnerMatchesSID(path, owner) && windowssecurity.ProtectedDACLMatches(path, dacl)
}

func windowsRuntimeMigrationSecurityMatches(path string, legacyOwner, trustedOwner *windows.SID, legacyDACL, currentDACL string) bool {
	return windowsRuntimeSecurityMatches(path, legacyOwner, legacyDACL) || windowsRuntimeSecurityMatches(path, trustedOwner, currentDACL)
}

func applyWindowsOwnedDACL(path string, owner *windows.SID, access string) error {
	if owner == nil || !owner.IsValid() {
		return ErrInvalidRequest
	}
	descriptor, err := windows.SecurityDescriptorFromString(access)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := withWindowsRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
	}); err != nil {
		return err
	}
	if !windowsRuntimeSecurityMatches(path, owner, access) {
		return ErrInvalidRequest
	}
	return nil
}

func createWindowsRuntimeRoot(path string, owner *windows.SID, dacl string) error {
	descriptor, err := windows.SecurityDescriptorFromString("O:SY" + dacl)
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
	err = withWindowsRestorePrivilege(func() error { return windows.CreateDirectory(pathUTF16, &attributes) })
	runtime.KeepAlive(descriptor)
	if err != nil {
		return err
	}
	if !windowsRuntimeSecurityMatches(path, owner, dacl) {
		return ErrInvalidRequest
	}
	return nil
}

func withWindowsRestorePrivilege(operation func() error) (result error) {
	if operation == nil {
		return ErrInvalidRequest
	}
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer func() {
		revertErr := windows.RevertToSelf()
		result = errors.Join(result, revertErr)
		if revertErr == nil {
			runtime.UnlockOSThread()
		}
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &token); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, token.Close()) }()
	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	desired := windows.Tokenprivileges{PrivilegeCount: 1}
	desired.AllPrivileges()[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var previous windows.Tokenprivileges
	var previousLength uint32
	if err := windows.AdjustTokenPrivileges(token, false, &desired, uint32(unsafe.Sizeof(previous)), &previous, &previousLength); err != nil {
		return err
	}
	if lastErr := windows.GetLastError(); lastErr != windows.ERROR_SUCCESS {
		return lastErr
	}
	defer func() {
		if previousLength == 0 {
			return
		}
		restoreErr := windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
		if restoreErr == nil {
			if lastErr := windows.GetLastError(); lastErr != windows.ERROR_SUCCESS {
				restoreErr = lastErr
			}
		}
		result = errors.Join(result, restoreErr)
	}()
	return operation()
}

func stageWindowsBinary(ctx context.Context, source, current, rollback string, artifact bootstrap.ArtifactTarget, ownerSID string) error {
	if err := ensureWindowsDirectory(filepath.Dir(current), ownerSID); err != nil {
		return fmt.Errorf("prepare runtime slot: %w", err)
	}
	if err := ensureWindowsDirectory(filepath.Dir(rollback), ownerSID); err != nil {
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
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	//paperboat:allow-source-policy atomic-replacement owner=windows-host-install reason=same-directory-verified-runtime-staging
	temporary, err := os.CreateTemp(filepath.Dir(current), ".paperboat-runtime-*.exe")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, copyErr := io.Copy(temporary, io.LimitReader(input, 256<<20+1))
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written < 1 || written > 256<<20 {
		return fmt.Errorf("%w: copy staged runtime", ErrInvalidRequest)
	}
	if err := binarytarget.Validate(temporaryPath, "windows", artifact.Architecture); err != nil {
		return fmt.Errorf("%w: staged runtime executable format", ErrInvalidRequest)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, temporaryPath, "windows", artifact.Architecture); err != nil {
		return fmt.Errorf("%w: staged runtime Authenticode: %v", ErrInvalidRequest, err)
	}
	if err := applyWindowsACL(temporaryPath, ownerSID, false); err != nil {
		return err
	}
	if err := os.Remove(rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
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

// Built-in Users may read and execute the public CLI, but only SYSTEM and
// Administrators may replace its launcher or its active release slot.
const windowsCLIEntrypointDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

// windowsCLIEntrypointPaths returns the stable launcher installed by the MSI
// and the public command path. The latter must always be a launcher: the CLI
// bytes themselves live in the protected, rollback-capable release slot.
func windowsCLIEntrypointPaths(layout service.Layout) (launcher, entrypoint string) {
	binaryRoot := filepath.Join(layout.InstallRoot, "bin")
	return filepath.Join(binaryRoot, "pb-launcher.exe"), filepath.Join(binaryRoot, "pb.exe")
}

func installWindowsCLIEntrypoint(ctx context.Context, layout service.Layout, architecture string) error {
	launcher, entrypoint := windowsCLIEntrypointPaths(layout)
	if err := verifyWindowsInstalledBinary(ctx, launcher, architecture); err != nil {
		return fmt.Errorf("verify installed stable launcher: %w", err)
	}
	return replaceWindowsCLIEntrypoint(entrypoint, launcher)
}

func protectWindowsCLISlots(layout service.Layout) error {
	for _, path := range []string{layout.CLICurrent, layout.CLIRollback} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := applyWindowsDACL(path, windowsCLIEntrypointDACL); err != nil {
			return err
		}
	}
	return nil
}

// replaceWindowsCLIEntrypoint publishes the already validated launcher with a
// same-directory atomic replacement. A Client renewal therefore replaces a
// stale full CLI in bin\\pb.exe without modifying either CLI release slot or
// its rollback sibling.
func replaceWindowsCLIEntrypoint(entrypoint, launcher string) error {
	if !safeAbsolute(entrypoint) || !safeAbsolute(launcher) || filepath.Dir(entrypoint) != filepath.Dir(launcher) || strings.EqualFold(entrypoint, launcher) {
		return ErrInvalidRequest
	}
	body, err := os.ReadFile(launcher)
	if err != nil || len(body) == 0 || len(body) > 256<<20 {
		return ErrInvalidRequest
	}
	return atomicfile.Write(entrypoint, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: windowsCLIEntrypointDACL})
}

func repairWindowsRuntimeBinary(ctx context.Context, config WindowsRuntimeConfig, layout service.Layout) error {
	quarantine := layout.RuntimeCurrent + ".repair-quarantine"
	if verifyWindowsInstalledBinary(ctx, layout.RuntimeCurrent, config.Artifact.Architecture) == nil {
		_ = os.Remove(quarantine)
		return applyWindowsACL(layout.RuntimeCurrent, config.OwnerSID, false)
	}
	if _, err := os.Stat(layout.RuntimeCurrent); errors.Is(err, os.ErrNotExist) && verifyWindowsInstalledBinary(ctx, quarantine, config.Artifact.Architecture) == nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=verified-quarantine-runtime-restoration
		if err := os.Rename(quarantine, layout.RuntimeCurrent); err != nil {
			return err
		}
		return applyWindowsACL(layout.RuntimeCurrent, config.OwnerSID, false)
	}
	_ = os.Remove(quarantine)
	currentExists := false
	if _, err := os.Stat(layout.RuntimeCurrent); err == nil {
		currentExists = true
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=current-runtime-quarantine-before-verification
		if err := os.Rename(layout.RuntimeCurrent, quarantine); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	restoreCurrent := func() {
		if currentExists {
			//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=restore-quarantined-current-runtime
			_ = os.Rename(quarantine, layout.RuntimeCurrent)
		}
	}
	if verifyWindowsInstalledBinary(ctx, layout.RuntimeRollback, config.Artifact.Architecture) == nil {
		//paperboat:allow-source-policy atomic-replacement owner=windows-host-repair reason=verified-rollback-runtime-activation
		if err := os.Rename(layout.RuntimeRollback, layout.RuntimeCurrent); err != nil {
			restoreCurrent()
			return err
		}
		_ = os.Remove(quarantine)
		return applyWindowsACL(layout.RuntimeCurrent, config.OwnerSID, false)
	}
	repairState := filepath.Join(layout.UpdateStateRoot, "repair-tuf")
	artifactPath, err := bootstrap.FetchVerifiedArtifact(ctx, config.Artifact, repairState, nil)
	if err != nil {
		restoreCurrent()
		return err
	}
	if err := stageWindowsBinary(ctx, artifactPath, layout.RuntimeCurrent, layout.RuntimeRollback, config.Artifact, config.OwnerSID); err != nil {
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
	descriptor, err := windows.SecurityDescriptorFromString(access)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
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
