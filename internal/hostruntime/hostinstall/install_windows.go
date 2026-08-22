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
	if decoder.Decode(&config) != nil || decoder.Decode(&extra) != io.EOF || !validWindowsConfig(config) {
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
	if err := ensureWindowsDirectory(WindowsProgramDataRoot(), request.OwnerSID); err != nil {
		return fmt.Errorf("prepare Paperboat machine state: %w", err)
	}
	if err := ensureWindowsDirectory(layout.ReleasesRoot, request.OwnerSID); err != nil {
		return fmt.Errorf("prepare Paperboat release slots: %w", err)
	}
	if err := ensureWindowsDirectory(request.StateRoot, request.OwnerSID); err != nil {
		return fmt.Errorf("prepare Paperboat user state: %w", err)
	}
	if err := repairWindowsTreeACL(request.StateRoot, request.OwnerSID); err != nil {
		return fmt.Errorf("repair Paperboat user-state permissions: %w", err)
	}
	if err := stopWindowsRuntimeServices(ctx); err != nil {
		return fmt.Errorf("stop Paperboat Windows services for activation: %w", err)
	}
	if err := stageWindowsBinary(ctx, request.Executable, layout.RuntimeCurrent, layout.RuntimeRollback, request.Artifact, request.OwnerSID); err != nil {
		return fmt.Errorf("stage verified Paperboat runtime: %w", err)
	}
	if err := ensureWindowsToken(request.OwnerSID); err != nil {
		return fmt.Errorf("prepare Paperboat host token: %w", err)
	}
	config := WindowsRuntimeConfig{Schema: windowsConfigSchema, OwnerSID: request.OwnerSID, User: request.User, StateRoot: request.StateRoot, Workspace: request.WorkspaceRoot, ControlURL: request.ControlURL, MachineID: request.UserMachineID, TokenFile: WindowsHostdTokenPath(), InstalledAt: time.Now().UTC(), Artifact: request.Artifact}
	if err := writeWindowsConfig(config); err != nil {
		return fmt.Errorf("write Paperboat runtime configuration: %w", err)
	}
	// Activation deliberately stopped both services before rotating the runtime
	// slot. Re-apply their SCM definitions so the newly staged image is started;
	// UpgradeReload would treat existing declarations as stable and leave the
	// services stopped.
	if err := installWindowsServices(ctx, layout, ""); err != nil {
		return fmt.Errorf("install Paperboat Windows services: %w", err)
	}
	sshConfig := windowsopenssh.DefaultConfig(nil)
	sshConfig.OwnerSID = request.OwnerSID
	if err := windowsopenssh.InstallService(ctx, layout.RuntimeCurrent, filepath.Join(sshConfig.InstallRoot, "sshd.exe"), filepath.Join(sshConfig.StateRoot, "sshd_config")); err != nil {
		return fmt.Errorf("bind Paperboat OpenSSH service to protected runtime: %w", err)
	}
	return nil
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
	return errors.Join(uninstallWindows(ctx, false), windowsopenssh.RemovePaperboatState(ctx, windowsopenssh.DefaultConfig(nil)))
}

func UninstallPersisted(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	if _, err := LoadWindowsRuntimeConfig(); err != nil {
		return err
	}
	return errors.Join(uninstallWindows(ctx, false), windowsopenssh.RemovePaperboatState(ctx, windowsopenssh.DefaultConfig(nil)))
}

// Repair restores only the persisted Windows host runtime. It never changes
// Paperboat-managed OpenSSH state; the caller composes both repairs explicitly.
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
	return installWindowsServices(ctx, layout, "")
}

// Purge removes only Paperboat-owned service declarations, slots, tokens, and
// ProgramData state. It is intentionally idempotent so it can finish after a
// reboot or an interrupted uninstall.
func Purge(ctx context.Context) error {
	if !isAdministrator() {
		return ErrNotPrivileged
	}
	result := uninstallWindows(ctx, true)
	// Windows OpenSSH is a shared WinGet dependency. Purge only removes the
	// dedicated PaperboatSshd service, Paperboat SSH keys/configuration, and
	// firewall deltas that Paperboat recorded as its own.
	result = errors.Join(result, windowsopenssh.RemovePaperboatState(ctx, windowsopenssh.DefaultConfig(nil)))
	return result
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
	return config.Schema == windowsConfigSchema && validSID(config.OwnerSID) && config.User != "" && safeAbsolute(config.StateRoot) && safeAbsolute(config.Workspace) && safeAbsolute(config.TokenFile) && config.MachineID != "" && config.Artifact.Platform == "windows"
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
