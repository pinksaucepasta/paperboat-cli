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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
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
	Schema      string                   `json:"schema"`
	OwnerSID    string                   `json:"owner_sid"`
	User        string                   `json:"user"`
	StateRoot   string                   `json:"state_root"`
	Workspace   string                   `json:"workspace_root"`
	ControlURL  string                   `json:"control_url"`
	MachineID   string                   `json:"machine_id"`
	SetupMode   string                   `json:"setup_mode"`
	TokenFile   string                   `json:"token_file"`
	InstalledAt time.Time                `json:"installed_at"`
	Committed   bool                     `json:"committed"`
	Artifact    bootstrap.ArtifactTarget `json:"artifact"`
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

func WindowsProgramDataRoot() string { return `C:\ProgramData\Paperboat` }
func WindowsInstallConfigPath() string {
	return filepath.Join(WindowsProgramDataRoot(), "runtime-install.json")
}
func WindowsHostdTokenPath() string { return filepath.Join(WindowsProgramDataRoot(), "hostd.token") }

func LoadWindowsRuntimeConfig() (WindowsRuntimeConfig, error) {
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
	if !validWindowsConfig(config) {
		return WindowsRuntimeConfig{}, ErrInvalidRequest
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
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat machine state", func() error { return ensureWindowsDirectory(WindowsProgramDataRoot(), request.OwnerSID) }); err != nil {
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
	if err := runWindowsInstallPhase(ctx, "protect Paperboat CLI release slots", func() error { return protectWindowsCLISlots(layout) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "activate stable Paperboat CLI launcher", func() error { return installWindowsCLIEntrypoint(ctx, layout, request.Artifact.Architecture) }); err != nil {
		return err
	}
	if err := runWindowsInstallPhase(ctx, "prepare Paperboat host token", func() error { return ensureWindowsToken(request.OwnerSID) }); err != nil {
		return err
	}
	config := WindowsRuntimeConfig{Schema: windowsConfigSchema, OwnerSID: request.OwnerSID, User: request.User, StateRoot: request.StateRoot, Workspace: request.WorkspaceRoot, ControlURL: request.ControlURL, MachineID: request.UserMachineID, SetupMode: request.SetupMode, TokenFile: WindowsHostdTokenPath(), InstalledAt: time.Now().UTC(), Artifact: request.Artifact}
	if err := runWindowsInstallPhase(ctx, "write Paperboat runtime configuration", func() error { return writeWindowsConfig(config) }); err != nil {
		return err
	}
	// Activation deliberately stopped both services before rotating the runtime
	// slot. Re-apply their SCM definitions so the newly staged image is started;
	// UpgradeReload would treat existing declarations as stable and leave the
	// services stopped.
	if err := runWindowsInstallPhase(ctx, "install Paperboat Windows services", func() error { return installWindowsServices(ctx, layout, "") }); err != nil {
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
		return err
	}
	layout, err := service.DefaultLayout("windows")
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
	if err := ensureWindowsDirectory(WindowsProgramDataRoot(), config.OwnerSID); err != nil {
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
	if err := applyWindowsACL(WindowsInstallConfigPath(), config.OwnerSID, false); err != nil {
		return err
	}
	if err := installWindowsServices(ctx, layout, ""); err != nil {
		return err
	}
	return installWindowsSSHAfterActivation(ctx, request, layout)
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

func installWindowsServices(ctx context.Context, layout service.Layout, upgradeMode string) error {
	for _, item := range []struct {
		kind string
		args []string
	}{{service.HostdKind, []string{"__runtime-hostd"}}, {service.UpdaterKind, []string{"__runtime-updated"}}} {
		installer, err := service.New(service.Config{Platform: "windows", Kind: item.kind, ConfigRoot: WindowsProgramDataRoot(), Executable: layout.RuntimeCurrent, User: "Paperboat", Group: "Paperboat", Arguments: item.args, Controller: service.WindowsController{}, UpgradeMode: upgradeMode})
		if err != nil {
			return err
		}
		if err := installer.Install(ctx); err != nil {
			return err
		}
	}
	return nil
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
	if err := ensureWindowsDirectory(WindowsProgramDataRoot(), config.OwnerSID); err != nil {
		return err
	}
	if err := atomicfile.Write(WindowsInstallConfigPath(), body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return err
	}
	return applyWindowsACL(WindowsInstallConfigPath(), config.OwnerSID, false)
}

func validWindowsConfig(config WindowsRuntimeConfig) bool {
	return config.Schema == windowsConfigSchema && validSID(config.OwnerSID) && config.User != "" && safeAbsolute(config.StateRoot) && safeAbsolute(config.Workspace) && safeAbsolute(config.TokenFile) && config.MachineID != "" && (config.SetupMode == "host" || config.SetupMode == "client") && config.Artifact.Platform == "windows"
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
	if err := secureWindowsFile(path, ownerSID); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	if err := os.WriteFile(path, token, 0o600); err != nil {
		return err
	}
	return applyWindowsACL(path, ownerSID, false)
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
