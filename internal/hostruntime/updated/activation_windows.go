//go:build windows

package updated

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsActivatorService = "PaperboatUpdateActivator"
	windowsHostdService     = "PaperboatHostd"
	windowsUpdaterService   = "PaperboatUpdated"
	windowsSSHService       = "PaperboatSshd"
)

// windowsReleasePaths is retained only as an internal transaction view while
// the Windows service controller is being collapsed onto the canonical pb
// slot. It is never exposed by service.Layout or written into service
// definitions.
type windowsReleasePaths struct {
	Root, Runtime, CLI, Hostd, Updater string
}

func canonicalWindowsRelease(layout service.Layout, version string) (windowsReleasePaths, error) {
	if !exactReleasePattern.MatchString(version) {
		return windowsReleasePaths{}, errInvalidWindowsActivation
	}
	root := filepath.Join(layout.ReleasesRoot, "versions", version)
	return windowsReleasePaths{
		Root: root, Runtime: filepath.Join(root, "pb.exe"), CLI: filepath.Join(root, "pb.exe"),
		Hostd: filepath.Join(root, "pb.exe"), Updater: filepath.Join(root, "pb.exe"),
	}, nil
}

func windowsActivationJournalPath(stateRoot string) string {
	return filepath.Join(stateRoot, "activation", "journal.json")
}

func stageWindowsActivation(ctx context.Context, config WindowsConfig, release workerupdate.Release) (windowsActivationJournal, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !exactReleasePattern.MatchString(release.Version) || release.Platform != "windows" || release.Architecture != config.Architecture {
		return windowsActivationJournal{}, workerupdate.ErrInvalidRelease
	}
	// The signed deployment policy is part of the crash journal. Validate it
	// before creating any immutable release files so a malformed canary/drain
	// policy cannot strand a partially staged transaction.
	if err := workerupdate.ValidateActivationRelease(release); err != nil {
		return windowsActivationJournal{}, err
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return windowsActivationJournal{}, err
	}
	paths, err := canonicalWindowsRelease(layout, release.Version)
	if err != nil {
		return windowsActivationJournal{}, err
	}
	if _, err := os.Lstat(filepath.Join(paths.Root, ".quarantined")); err == nil {
		return windowsActivationJournal{}, workerupdate.ErrQuarantined
	} else if !errors.Is(err, os.ErrNotExist) {
		return windowsActivationJournal{}, err
	}
	// Resolve and validate every mutable SCM dependency before downloading any
	// release bytes. An inconsistent installation fails cheaply and unchanged.
	oldHostd, err := queryWindowsServiceTarget(windowsHostdService, "__runtime-hostd")
	if err != nil {
		return windowsActivationJournal{}, err
	}
	oldUpdater, err := queryWindowsServiceTarget(windowsUpdaterService, "__runtime-updated")
	if err != nil {
		return windowsActivationJournal{}, err
	}
	oldSSH := windowsServiceTarget{}
	if config.SetupMode == "host" {
		oldSSH, err = queryOptionalWindowsServiceTarget(windowsSSHService)
		if err != nil {
			return windowsActivationJournal{}, err
		}
		if !validWindowsSSHRoleTarget(config.SetupMode, oldSSH) {
			return windowsActivationJournal{}, errInvalidWindowsActivation
		}
		if !validWindowsSSHArguments(oldSSH.Arguments) {
			return windowsActivationJournal{}, errInvalidWindowsActivation
		}
	} else {
		unexpectedSSH, queryErr := queryOptionalWindowsServiceTarget(windowsSSHService)
		if queryErr != nil {
			return windowsActivationJournal{}, queryErr
		}
		if !validWindowsSSHRoleTarget(config.SetupMode, unexpectedSSH) {
			return windowsActivationJournal{}, errInvalidWindowsActivation
		}
	}
	if !activeWindowsServiceTargetsMatch(layout, config.ActiveVersion, oldHostd, oldUpdater, oldSSH) {
		return windowsActivationJournal{}, errInvalidWindowsActivation
	}
	localDaemonLock, err := windowsLocalDaemonLockPath(config.RuntimeStateRoot)
	if err != nil {
		return windowsActivationJournal{}, err
	}
	localDaemonWasRunning, err := localdaemon.WindowsOwnerServiceRunning(localDaemonLock, config.OwnerSID)
	if err != nil {
		return windowsActivationJournal{}, err
	}
	localDaemonServiceRunning, err := localdaemon.WindowsLocalDaemonServiceRunning()
	if err != nil {
		return windowsActivationJournal{}, err
	}
	localDaemonWasRunning = localDaemonWasRunning || localDaemonServiceRunning
	previousBinary, err := describeWindowsActivationComponent(layout.Binary, config.Architecture)
	if err != nil {
		return windowsActivationJournal{}, err
	}
	verifyCtx, cancelVerify := context.WithTimeout(ctx, 30*time.Second)
	if err := nativesignature.New(nil).Verify(verifyCtx, layout.Binary, "windows", config.Architecture); err != nil {
		cancelVerify()
		return windowsActivationJournal{}, err
	}
	cancelVerify()
	if err := secureWindowsTransactionDirectory(filepath.Dir(windowsActivationJournalPath(config.StateRoot))); err != nil {
		return windowsActivationJournal{}, err
	}
	if err := secureWindowsReleaseDirectory(filepath.Dir(paths.Root)); err != nil {
		return windowsActivationJournal{}, err
	}
	if err := secureWindowsReleaseDirectory(paths.Root); err != nil {
		return windowsActivationJournal{}, err
	}
	source, err := newWindowsTUFSource(config)
	if err != nil {
		return windowsActivationJournal{}, err
	}
	components := []struct {
		name, path string
		target     workerupdate.ComponentTarget
	}{
		{"runtime", paths.Runtime, workerupdate.ComponentTarget{SHA256: release.SHA256, Length: release.Length, Platform: release.Platform, Architecture: release.Architecture}},
		{"cli", paths.CLI, workerupdate.ComponentTarget{SHA256: release.CLISHA256, Length: release.CLILength, Platform: release.CLIPlatform, Architecture: release.CLIArchitecture}},
		{"hostd", paths.Hostd, release.Hostd}, {"updater", paths.Updater, release.Updater},
	}
	staged := make(map[string]windowsActivationComponent, len(components))
	for _, component := range components {
		if component.target.Platform != "windows" || component.target.Architecture != config.Architecture || component.target.Length <= 0 || component.target.Length > maxWindowsComponentSize || len(component.target.SHA256) != 64 || !lowerHex(component.target.SHA256) {
			return windowsActivationJournal{}, workerupdate.ErrInvalidRelease
		}
		if err := stageWindowsComponent(ctx, source, release, component.name, component.path, component.target, config.OwnerSID); err != nil {
			return windowsActivationJournal{}, err
		}
		staged[component.name] = windowsActivationComponent{Path: component.path, SHA256: component.target.SHA256, Length: component.target.Length}
	}
	newSSH := windowsServiceTarget{}
	if oldSSH.Executable != "" {
		newSSH = windowsServiceTarget{Executable: layout.Binary, Arguments: append([]string(nil), oldSSH.Arguments...), WasRunning: oldSSH.WasRunning}
	}
	var transaction [16]byte
	if _, err := rand.Read(transaction[:]); err != nil {
		return windowsActivationJournal{}, err
	}
	journal := windowsActivationJournal{
		Schema: windowsActivationJournalSchema, TransactionID: hex.EncodeToString(transaction[:]), PreviousVersion: config.ActiveVersion, Version: release.Version, Architecture: config.Architecture, Stage: windowsActivationStaged,
		Runtime: staged["runtime"], CLI: staged["cli"], Hostd: staged["hostd"], Updater: staged["updater"], PreviousBinary: previousBinary,
		OldHostd: oldHostd, OldUpdater: oldUpdater, OldSSH: oldSSH, NewSSH: newSSH,
		LocalDaemonWasRunning: localDaemonWasRunning,
		ManifestSHA256:        release.ManifestSHA256, CanaryPath: release.CanaryPath, CanaryStatus: release.CanaryStatus, CanarySamples: release.CanarySamples,
		CanaryTimeout: release.CanaryTimeout, DrainTimeout: release.DrainTimeout, StabilityWindow: release.StabilityWindow, StabilityInterval: release.StabilityInterval, RollbackTimeout: release.RollbackTimeout,
		HostdAPIMin: release.HostdAPIMin, HostdAPIMax: release.HostdAPIMax, RuntimeAPIMin: release.RuntimeAPIMin, RuntimeAPIMax: release.RuntimeAPIMax,
		NewHostd:   windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-hostd"}, WasRunning: oldHostd.WasRunning},
		NewUpdater: windowsServiceTarget{Executable: layout.Binary, Arguments: []string{"__runtime-updated"}, WasRunning: oldUpdater.WasRunning},
	}
	backend := newWindowsSCMActivationBackend(config)
	if err := backend.WriteJournal(journal); err != nil {
		return windowsActivationJournal{}, err
	}
	if err := installWindowsActivatorService(paths.Updater); err != nil {
		return windowsActivationJournal{}, err
	}
	return journal, nil
}

func activeWindowsServiceTargetsMatch(layout service.Layout, version string, hostd, updater, ssh windowsServiceTarget) bool {
	if !exactReleasePattern.MatchString(version) || !strings.EqualFold(hostd.Executable, layout.Binary) || !windowsUpdaterExecutableMatches(layout, updater.Executable) {
		return false
	}
	return ssh.Executable == "" || strings.EqualFold(ssh.Executable, layout.Binary)
}

func windowsUpdaterExecutableMatches(layout service.Layout, executable string) bool {
	return strings.EqualFold(executable, layout.Binary) || strings.EqualFold(executable, layout.BinaryRollback)
}

func describeWindowsActivationComponent(path, architecture string) (windowsActivationComponent, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxWindowsComponentSize {
		if err == nil {
			err = errInvalidWindowsActivation
		}
		return windowsActivationComponent{}, err
	}
	if err := binarytarget.Validate(path, "windows", architecture); err != nil {
		return windowsActivationComponent{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return windowsActivationComponent{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxWindowsComponentSize+1)); err != nil {
		return windowsActivationComponent{}, err
	}
	return windowsActivationComponent{Path: filepath.Clean(path), SHA256: hex.EncodeToString(hash.Sum(nil)), Length: info.Size()}, nil
}

func windowsActivationComponentTarget(component windowsActivationComponent, architecture string) workerupdate.ComponentTarget {
	return workerupdate.ComponentTarget{SHA256: component.SHA256, Length: component.Length, Platform: "windows", Architecture: architecture}
}

func stageWindowsComponent(ctx context.Context, source workerupdate.TUFSource, release workerupdate.Release, name, destination string, target workerupdate.ComponentTarget, ownerSID string) error {
	if matchesWindowsComponent(destination, target) {
		if err := secureWindowsReleaseFile(destination); err != nil {
			return err
		}
		verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return nativesignature.New(nil).Verify(verifyCtx, destination, "windows", target.Architecture)
	}
	if _, err := os.Lstat(destination); err == nil {
		return errInvalidWindowsActivation
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stream, err := source.FetchComponent(ctx, release, name)
	if err != nil {
		return err
	}
	defer stream.Close()
	temporary := destination + ".staged"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(stream, target.Length+1))
	syncErr, closeErr := file.Sync(), file.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if written != target.Length || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), target.SHA256) {
		_ = os.Remove(temporary)
		return workerupdate.ErrInvalidRelease
	}
	if err := binarytarget.Validate(temporary, "windows", target.Architecture); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, temporary, "windows", target.Architecture); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := secureWindowsReleaseFile(temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// Destination cannot exist: immutable version paths are never overwritten.
	//paperboat:allow-source-policy atomic-replacement owner=windows-updater reason=verified-immutable-component-publication
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func secureWindowsReleaseDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errInvalidWindowsActivation
	}
	return applyWindowsReleaseACL(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
}

func secureWindowsTransactionDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errInvalidWindowsActivation
	}
	return applyWindowsReleaseACL(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

func secureWindowsReleaseFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errInvalidWindowsActivation
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errInvalidWindowsActivation
	}
	return applyWindowsReleaseACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)")
}

func applyWindowsReleaseACL(path, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, system, nil, dacl, nil)
	}); err != nil {
		return err
	}
	if !windowssecurity.OwnerMatchesSID(path, system) || !windowssecurity.ProtectedDACLMatches(path, sddl) {
		return errInvalidWindowsActivation
	}
	return nil
}

func matchesWindowsComponent(path string, target workerupdate.ComponentTarget) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != target.Length {
		return false
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), target.SHA256) && binarytarget.Validate(path, "windows", target.Architecture) == nil
}

func readOptionalWindowsCLIRecord(path string) (string, error) {
	if _, err := os.Lstat(path); err == nil {
		if !windowsMachineFileSecurityMatches(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)") {
			return "", errInvalidWindowsActivation
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || len(body) > 256 || strings.Count(string(body), "\n") != 1 {
		return "", errInvalidWindowsActivation
	}
	return string(body), nil
}

func windowsMachineFileSecurityMatches(path, dacl string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return err == nil && windowssecurity.OwnerMatchesSID(path, system) && windowssecurity.ProtectedDACLMatches(path, dacl)
}

func queryWindowsServiceTarget(name, expectedArgument string) (windowsServiceTarget, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(name)
	if err != nil {
		return windowsServiceTarget{}, err
	}
	defer item.Close()
	config, err := item.Config()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) != 2 || args[1] != expectedArgument || !filepath.IsAbs(args[0]) || !validPrivilegedWindowsServiceConfig(config, mgr.StartAutomatic, mgr.ErrorNormal) {
		return windowsServiceTarget{}, errInvalidWindowsActivation
	}
	if err := validateWindowsRecovery(item); err != nil {
		return windowsServiceTarget{}, err
	}
	status, err := item.Query()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	return windowsServiceTarget{Executable: filepath.Clean(args[0]), Arguments: []string{expectedArgument}, WasRunning: status.State != svc.Stopped}, nil
}

func queryOptionalWindowsServiceTarget(name string) (windowsServiceTarget, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return windowsServiceTarget{}, nil
	}
	if err != nil {
		return windowsServiceTarget{}, err
	}
	defer item.Close()
	config, err := item.Config()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) < 2 || !filepath.IsAbs(args[0]) || !validPrivilegedWindowsServiceConfig(config, mgr.StartAutomatic, mgr.ErrorNormal) {
		return windowsServiceTarget{}, errInvalidWindowsActivation
	}
	status, err := item.Query()
	if err != nil {
		return windowsServiceTarget{}, err
	}
	return windowsServiceTarget{Executable: filepath.Clean(args[0]), Arguments: append([]string(nil), args[1:]...), WasRunning: status.State != svc.Stopped}, nil
}

func validPrivilegedWindowsServiceConfig(config mgr.Config, startType, errorControl uint32) bool {
	return strings.EqualFold(config.ServiceStartName, "LocalSystem") && config.StartType == startType && config.ErrorControl == errorControl && config.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED && !config.DelayedAutoStart
}

func installWindowsActivatorService(executable string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if current, openErr := manager.OpenService(windowsActivatorService); openErr == nil {
		defer current.Close()
		config, e := current.Config()
		if e != nil {
			return e
		}
		config.BinaryPathName = windows.ComposeCommandLine([]string{executable, "__runtime-activate"})
		config.StartType = mgr.StartAutomatic
		config.ErrorControl = mgr.ErrorSevere
		config.ServiceStartName = "LocalSystem"
		config.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
		config.DelayedAutoStart = false
		if err := current.UpdateConfig(config); err != nil {
			return err
		}
		if err := configureWindowsRecovery(current); err != nil {
			return err
		}
		updated, err := current.Config()
		if err != nil || !strings.EqualFold(updated.BinaryPathName, config.BinaryPathName) || !validPrivilegedWindowsServiceConfig(updated, mgr.StartAutomatic, mgr.ErrorSevere) {
			return errors.Join(errInvalidWindowsActivation, err)
		}
		return validateWindowsRecovery(current)
	} else if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return openErr
	}
	item, err := manager.CreateService(windowsActivatorService, executable, mgr.Config{DisplayName: "Paperboat Update Activator", Description: "Paperboat one-shot verified update activation", StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorSevere, ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "__runtime-activate")
	if err != nil {
		return err
	}
	defer item.Close()
	if err := configureWindowsRecovery(item); err != nil {
		return err
	}
	return validateWindowsRecovery(item)
}

func configureWindowsRecovery(item *mgr.Service) error {
	if err := item.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}, 24*60*60); err != nil {
		return err
	}
	return item.SetRecoveryActionsOnNonCrashFailures(true)
}

func validateWindowsRecovery(item *mgr.Service) error {
	return validateWindowsRecoveryActions(item, standardWindowsRecoveryActions())
}

func standardWindowsRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}
}

func windowsRecoveryActionsForService(name string) []mgr.RecoveryAction {
	if name == windowsSSHService {
		return windowsopenssh.ServiceRecoveryActions()
	}
	return standardWindowsRecoveryActions()
}

func validateWindowsRecoveryActions(item *mgr.Service, expected []mgr.RecoveryAction) error {
	actions, err := item.RecoveryActions()
	if err != nil || !windowsRecoveryActionsMatch(actions, expected) {
		return errors.Join(errInvalidWindowsActivation, err)
	}
	nonCrash, err := item.RecoveryActionsOnNonCrashFailures()
	if err != nil || !nonCrash {
		return errors.Join(errInvalidWindowsActivation, err)
	}
	return nil
}

func windowsRecoveryActionsMatch(actual, expected []mgr.RecoveryAction) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func startWindowsActivatorService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsActivatorService)
	if err != nil {
		return err
	}
	defer item.Close()
	return item.Start()
}

type windowsSCMActivationBackend struct {
	config         WindowsConfig
	candidate      workerupdate.Worker
	candidateReady hostdproto.Status
}

func newWindowsSCMActivationBackend(config WindowsConfig) *windowsSCMActivationBackend {
	return &windowsSCMActivationBackend{config: config}
}

func (b *windowsSCMActivationBackend) WriteJournal(j windowsActivationJournal) error {
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	path := windowsActivationJournalPath(b.config.StateRoot)
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return err
	}
	return applyWindowsReleaseACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
}

// ProbeCandidate starts the signed staged executable as a hostd candidate and
// runs the complete edge/connector/route/origin canary while the old active
// route is still serving. The candidate remains mutation-disabled and waits
// for the activator's later cutover signal.
func (b *windowsSCMActivationBackend) ProbeCandidate(ctx context.Context, journal windowsActivationJournal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if b == nil || b.config.CandidateStarter == nil || b.config.ActivationGate == nil || b.candidate != nil || journal.Stage != windowsActivationCandidateValidating {
		return errInvalidWindowsActivation
	}
	release := windowsCandidateRelease(journal)
	request := workerupdate.StartRequest{
		Executable:        journal.Runtime.Path,
		Release:           release,
		WorkerID:          windowsCandidateWorkerID(journal.Version),
		HostdEndpoint:     b.config.HostdSocket,
		MutationsDisabled: true,
	}
	candidate, err := b.config.CandidateStarter(ctx, request)
	if err != nil {
		return err
	}
	if candidate == nil {
		return errInvalidWindowsActivation
	}
	// Publish the process handle before any readiness call. If readiness or
	// canary verification fails, the caller can retry cleanup even when the
	// first Stop is interrupted.
	b.candidate = candidate
	stopCandidate := func() error {
		return b.StopCandidate(context.Background(), journal)
	}
	ready, err := candidate.Ready(ctx)
	if err != nil {
		return errors.Join(err, stopCandidate())
	}
	gateRequest, err := windowsCandidateGateRequest(journal, ready)
	if err != nil {
		return errors.Join(err, stopCandidate())
	}
	canaryCtx, cancel := context.WithTimeout(ctx, journal.CanaryTimeout)
	canaryErr := b.config.ActivationGate.Candidate(canaryCtx, gateRequest)
	cancel()
	if canaryErr != nil {
		return errors.Join(canaryErr, stopCandidate())
	}
	b.candidateReady = ready
	return nil
}

func (b *windowsSCMActivationBackend) StopCandidate(ctx context.Context, _ windowsActivationJournal) error {
	if b == nil || b.candidate == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background()
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := b.candidate.Stop(stopCtx)
	if err == nil {
		b.candidate, b.candidateReady = nil, hostdproto.Status{}
	}
	return err
}

func windowsLocalDaemonLockPath(runtimeStateRoot string) (string, error) {
	if !filepath.IsAbs(runtimeStateRoot) || filepath.Clean(runtimeStateRoot) != runtimeStateRoot {
		return "", errInvalidWindowsActivation
	}
	return filepath.Join(filepath.Dir(runtimeStateRoot), "state", "daemon.lock"), nil
}

func (b *windowsSCMActivationBackend) StopServices(ctx context.Context, localDaemonWasRunning bool) error {
	// A staged candidate is attached to the current hostd lease. Stop it before
	// stopping SCM services so it cannot race the old route or survive an
	// owner-service teardown with an ambiguous lease.
	candidateErr := b.StopCandidate(ctx, windowsActivationJournal{})
	serviceErr := stopNamedWindowsServices(ctx, windowsActivationServiceNames(b.config.SetupMode)...)
	lockPath, err := windowsLocalDaemonLockPath(b.config.RuntimeStateRoot)
	if err != nil {
		return errors.Join(candidateErr, serviceErr, err)
	}
	stopErr := localdaemon.StopWindowsOwnerService(ctx, lockPath, b.config.OwnerSID)
	stateErr := hostinstall.PrepareWindowsLocalDaemonState(b.config.RuntimeStateRoot, b.config.OwnerSID)
	// A stale session-scoped lock DACL can prevent the first owner-process
	// cleanup after SCM has stopped the service. Once the privileged state
	// repair succeeds, retry that exact idempotent stop before slot rotation.
	if stopErr != nil && stateErr == nil {
		stopErr = localdaemon.StopWindowsOwnerService(ctx, lockPath, b.config.OwnerSID)
	}
	if !localDaemonWasRunning && errors.Is(stopErr, os.ErrNotExist) {
		stopErr = nil
	}
	return errors.Join(candidateErr, serviceErr, stopErr, stateErr)
}

func windowsStableBinaryDACL(ownerSID string) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + ownerSID + ")"
}

func windowsStableBinarySecurityDescriptor(ownerSID string) string {
	return "O:SY" + windowsStableBinaryDACL(ownerSID)
}

func (b *windowsSCMActivationBackend) ActivateBinary(ctx context.Context, journal windowsActivationJournal) error {
	layout, err := service.DefaultLayout("windows")
	if err != nil || b.config.Binary != layout.Binary || b.config.BinaryRollback != layout.BinaryRollback || b.config.BinaryStaged != layout.BinaryStaged {
		return errInvalidWindowsActivation
	}
	candidateTarget := windowsActivationComponentTarget(journal.Runtime, journal.Architecture)
	if err := verifyWindowsActivationComponent(ctx, journal.Runtime.Path, candidateTarget); err != nil {
		return err
	}
	previousTarget := windowsActivationComponentTarget(journal.PreviousBinary, journal.Architecture)
	if !matchesWindowsComponent(b.config.Binary, previousTarget) {
		return errInvalidWindowsActivation
	}
	body, err := readWindowsActivationBinary(journal.Runtime.Path)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(b.config.BinaryStaged, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: windowsStableBinarySecurityDescriptor(b.config.OwnerSID)}); err != nil {
		return err
	}
	if err := verifyWindowsStableBinary(ctx, b.config.BinaryStaged, candidateTarget, b.config.OwnerSID); err != nil {
		_ = removeWindowsActivationFile(b.config.BinaryStaged)
		return err
	}
	if err := removeWindowsActivationFile(b.config.BinaryRollback); err != nil {
		_ = removeWindowsActivationFile(b.config.BinaryStaged)
		return err
	}
	if err := moveWindowsActivationFile(ctx, b.config.Binary, b.config.BinaryRollback); err != nil {
		_ = removeWindowsActivationFile(b.config.BinaryStaged)
		return err
	}
	if err := moveWindowsActivationFile(ctx, b.config.BinaryStaged, b.config.Binary); err != nil {
		_ = moveWindowsActivationFile(ctx, b.config.BinaryRollback, b.config.Binary)
		return err
	}
	if err := verifyWindowsStableBinary(ctx, b.config.Binary, candidateTarget, b.config.OwnerSID); err != nil {
		_ = removeWindowsActivationFile(b.config.Binary)
		_ = moveWindowsActivationFile(ctx, b.config.BinaryRollback, b.config.Binary)
		return err
	}
	return nil
}

func (b *windowsSCMActivationBackend) RestoreBinary(ctx context.Context, journal windowsActivationJournal) error {
	layout, err := service.DefaultLayout("windows")
	if err != nil || b.config.Binary != layout.Binary || b.config.BinaryRollback != layout.BinaryRollback || b.config.BinaryStaged != layout.BinaryStaged {
		return errInvalidWindowsActivation
	}
	candidateTarget := windowsActivationComponentTarget(journal.Runtime, journal.Architecture)
	previousTarget := windowsActivationComponentTarget(journal.PreviousBinary, journal.Architecture)
	if _, err := os.Lstat(b.config.BinaryStaged); err == nil {
		if !matchesWindowsComponent(b.config.BinaryStaged, candidateTarget) {
			return errInvalidWindowsActivation
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	currentExists := false
	if _, err := os.Lstat(b.config.Binary); err == nil {
		currentExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rollbackExists := false
	if _, err := os.Lstat(b.config.BinaryRollback); err == nil {
		rollbackExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if currentExists && matchesWindowsComponent(b.config.Binary, previousTarget) {
		return removeWindowsActivationFile(b.config.BinaryStaged)
	}
	if !rollbackExists || !matchesWindowsComponent(b.config.BinaryRollback, previousTarget) {
		return errInvalidWindowsActivation
	}
	if currentExists {
		if !matchesWindowsComponent(b.config.Binary, candidateTarget) {
			return errInvalidWindowsActivation
		}
		if err := removeWindowsActivationFile(b.config.Binary); err != nil {
			return err
		}
	}
	if err := removeWindowsActivationFile(b.config.BinaryStaged); err != nil {
		return err
	}
	if err := moveWindowsActivationFile(ctx, b.config.BinaryRollback, b.config.Binary); err != nil {
		return err
	}
	return verifyWindowsStableBinary(ctx, b.config.Binary, previousTarget, b.config.OwnerSID)
}

func readWindowsActivationBinary(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxWindowsComponentSize+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maxWindowsComponentSize {
		return nil, errInvalidWindowsActivation
	}
	return body, nil
}

func verifyWindowsActivationComponent(ctx context.Context, path string, target workerupdate.ComponentTarget) error {
	if !matchesWindowsComponent(path, target) {
		return errInvalidWindowsActivation
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return nativesignature.New(nil).Verify(verifyCtx, path, "windows", target.Architecture)
}

func verifyWindowsStableBinary(ctx context.Context, path string, target workerupdate.ComponentTarget, ownerSID string) error {
	if err := verifyWindowsActivationComponent(ctx, path, target); err != nil {
		return err
	}
	if !windowsMachineFileSecurityMatches(path, windowsStableBinaryDACL(ownerSID)) {
		return errInvalidWindowsActivation
	}
	return nil
}

func moveWindowsActivationFile(ctx context.Context, from, to string) error {
	fromPointer, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPointer, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return retryWindowsFileOperation(ctx, func() error {
		return windows.MoveFileEx(fromPointer, toPointer, windows.MOVEFILE_WRITE_THROUGH)
	})
}

func removeWindowsActivationFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errInvalidWindowsActivation
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errInvalidWindowsActivation
	}
	return os.Remove(path)
}

func retryWindowsFileOperation(ctx context.Context, operation func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	var lastErr error
	for {
		if err := operation(); err == nil {
			return nil
		} else {
			lastErr = err
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(lastErr, ctx.Err())
		case <-deadline.C:
			return lastErr
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (b *windowsSCMActivationBackend) SetServiceTargets(_ context.Context, hostd, updater, ssh windowsServiceTarget) error {
	if err := setWindowsServiceTarget(windowsHostdService, hostd); err != nil {
		return err
	}
	if err := setWindowsServiceTarget(windowsUpdaterService, updater); err != nil {
		return err
	}
	if b.config.SetupMode == "host" && ssh.Executable != "" {
		return setWindowsServiceTarget(windowsSSHService, ssh)
	}
	return nil
}

// normalizeWindowsRollbackTargets returns service targets that are valid after
// the rollback slot has been moved back into the canonical binary location.
// A previous interrupted activation may have recorded PaperboatUpdated on the
// rollback path. Once RestoreBinary succeeds that path no longer exists, so
// restarting it verbatim leaves every service stopped and strands recovery.
func normalizeWindowsRollbackTargets(hostd, updater, ssh windowsServiceTarget) (windowsServiceTarget, windowsServiceTarget, windowsServiceTarget, error) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return windowsServiceTarget{}, windowsServiceTarget{}, windowsServiceTarget{}, err
	}
	if strings.EqualFold(updater.Executable, layout.BinaryRollback) {
		updater.Executable = layout.Binary
	}
	return hostd, updater, ssh, nil
}
func (b *windowsSCMActivationBackend) StartServices(ctx context.Context, hostd, updater, ssh, localDaemon bool) error {
	if localDaemon {
		if err := hostinstall.PrepareWindowsLocalDaemonState(b.config.RuntimeStateRoot, b.config.OwnerSID); err != nil {
			return err
		}
	}
	// Hostd validates its managed SSH loopback target during startup. Start SSH
	// first so both activation and rollback can bring a host runtime up from a
	// fully stopped service set without a dependency deadlock.
	for _, name := range windowsActivationServiceStartNames(b.config.SetupMode, hostd, updater, ssh) {
		if err := startNamedWindowsService(ctx, name); err != nil {
			return err
		}
	}
	if localDaemon {
		return localdaemon.StartWindowsOwnerService(ctx, b.config.OwnerSID)
	}
	return nil
}

func (b *windowsSCMActivationBackend) FinalizeServices(ctx context.Context, journal windowsActivationJournal) error {
	if journal.Stage != windowsActivationCommitted {
		return errInvalidWindowsActivation
	}
	return hostinstall.EnsureWindowsLocalDaemonService(ctx)
}

func (b *windowsSCMActivationBackend) Drain(ctx context.Context, journal windowsActivationJournal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := windowsDrainGateRequest(journal, b.candidateReady)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, journal.DrainTimeout)
	defer cancel()
	return b.config.ActivationGate.Drain(bounded, request)
}

func (b *windowsSCMActivationBackend) VerifyRollback(ctx context.Context, journal windowsActivationJournal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	status, err := b.activeHostdStatus(ctx)
	if err != nil {
		return err
	}
	request, err := windowsRollbackGateRequest(journal, status)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, journal.RollbackTimeout)
	defer cancel()
	return b.config.ActivationGate.Rollback(bounded, request)
}

func (b *windowsSCMActivationBackend) activeHostdStatus(ctx context.Context) (hostdproto.Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	token, err := os.ReadFile(b.config.TokenFile)
	if err != nil {
		return hostdproto.Status{}, err
	}
	defer clear(token)
	hostd, err := hostdproto.NewClient(b.config.HostdSocket, token, 5*time.Second)
	if err != nil {
		return hostdproto.Status{}, err
	}
	return hostd.Active(ctx)
}

func (b *windowsSCMActivationBackend) VerifyHealth(ctx context.Context, journal windowsActivationJournal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if b == nil || b.config.ActivationGate == nil {
		return errInvalidWindowsActivation
	}
	if err := requireNamedWindowsServicesRunning(windowsHostdService, windowsUpdaterService); err != nil {
		return fmt.Errorf("verify Windows runtime services: %w", err)
	}
	token, err := os.ReadFile(b.config.TokenFile)
	if err != nil {
		return err
	}
	defer clear(token)
	hostd, err := hostdproto.NewClient(b.config.HostdSocket, token, 5*time.Second)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	var status hostdproto.Status
	var activeErr error
	for {
		status, activeErr = hostd.Active(ctx)
		if activeErr == nil && status.State == hostdproto.StateActive && status.WorkerID != "" && status.Epoch != 0 && status.LastHeartbeatUnixMilli > 0 && time.Since(time.UnixMilli(status.LastHeartbeatUnixMilli)) <= 15*time.Second {
			break
		}
		if time.Now().After(deadline) {
			return errors.Join(errors.New("verify PaperboatHostd active heartbeat"), errInvalidWindowsActivation, activeErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if b.config.HealthURL == "" {
		return errors.Join(errors.New("verify runtime health URL"), errInvalidWindowsActivation)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.config.HealthURL, nil)
	response, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var health struct {
		Live bool `json:"live"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&health) != nil || !health.Live {
		return fmt.Errorf("runtime health returned HTTP %d", response.StatusCode)
	}
	client, err := NewClient(b.config.ControlSocket, 2*time.Second)
	if err != nil {
		return fmt.Errorf("verify PaperboatUpdated control: %w", err)
	}
	if err := waitForWindowsUpdaterVersion(ctx, journal.Version, 30*time.Second, 250*time.Millisecond, client.Status); err != nil {
		return err
	}
	if !matchesWindowsComponent(journal.CLI.Path, workerupdate.ComponentTarget{SHA256: journal.CLI.SHA256, Length: journal.CLI.Length, Platform: "windows", Architecture: journal.Architecture}) {
		return errors.Join(errors.New("verify staged Windows CLI component"), errInvalidWindowsActivation)
	}
	if journal.NewSSH.WasRunning {
		if err := requireNamedWindowsServicesRunning(windowsSSHService); err != nil {
			return err
		}
	}
	// Candidate was already canaried while the old route was authoritative.
	// The post-cutover gate is exclusively a signed stability observation over
	// the exact new active worker. Calling Candidate here would be invalid: the
	// worker is StateActive, not StateCandidate, and would also blur the journal
	// boundary between canary and stability.
	activeRequest, err := windowsActiveGateRequest(journal, status)
	if err != nil {
		return err
	}
	// Hostd owns and observes the complete signed stability window. Give the
	// local RPC enough time to return its terminal result after that window;
	// using the window itself as the transport deadline races a successful
	// final observation with deadline expiry.
	stabilityCtx, stabilityCancel := context.WithTimeout(ctx, windowsStabilityCallTimeout(journal.StabilityWindow, journal.StabilityInterval))
	stabilityErr := b.config.ActivationGate.Active(stabilityCtx, activeRequest)
	stabilityCancel()
	if stabilityErr != nil {
		return stabilityErr
	}
	return nil
}

func windowsStabilityCallTimeout(window, interval time.Duration) time.Duration {
	const maximumCompletionMargin = 30 * time.Second
	margin := interval
	if margin < time.Second {
		margin = time.Second
	}
	if margin > maximumCompletionMargin {
		margin = maximumCompletionMargin
	}
	return window + margin
}

func waitForWindowsUpdaterVersion(ctx context.Context, want string, timeout, retryDelay time.Duration, status func(context.Context) (ControlResponse, error)) error {
	if ctx == nil || !exactReleasePattern.MatchString(want) || timeout <= 0 || retryDelay <= 0 || status == nil {
		return errors.Join(errors.New("verify PaperboatUpdated control version"), errInvalidWindowsActivation)
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastVersion string
	var lastErr error
	for {
		response, err := status(bounded)
		if err == nil && response.Version == want {
			return nil
		}
		lastVersion, lastErr = response.Version, err
		timer := time.NewTimer(retryDelay)
		select {
		case <-bounded.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			message := fmt.Errorf("verify PaperboatUpdated control version: got %q, want %q", lastVersion, want)
			return errors.Join(message, errInvalidWindowsActivation, lastErr, bounded.Err())
		case <-timer.C:
		}
	}
}

func requireNamedWindowsServicesRunning(names ...string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	for _, name := range names {
		item, err := manager.OpenService(name)
		if err != nil {
			return fmt.Errorf("open Windows service %s: %w", name, err)
		}
		status, queryErr := item.Query()
		closeErr := item.Close()
		if queryErr != nil || closeErr != nil {
			return errors.Join(fmt.Errorf("query Windows service %s", name), errInvalidWindowsActivation, queryErr, closeErr)
		}
		if status.State != svc.Running {
			return errors.Join(fmt.Errorf("Windows service %s state is %d, want %d", name, status.State, svc.Running), errInvalidWindowsActivation)
		}
	}
	return nil
}
func (b *windowsSCMActivationBackend) CommitCLI(ctx context.Context, journal windowsActivationJournal) error {
	if exactReleasePattern.MatchString(journal.Version) {
		if err := commitWindowsInstallVersion(b.config, journal.Version); err != nil {
			return err
		}
	}
	recordPath := filepath.Join(filepath.Dir(b.config.Binary), "pb.active")
	if journal.NewCLIRecord == "" {
		if err := os.Remove(recordPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	name := strings.TrimSuffix(journal.NewCLIRecord, "\n")
	if strings.ContainsAny(name, `/\:*?"<>|`) || !strings.HasPrefix(name, "pb.slot-") || !strings.HasSuffix(name, ".exe") {
		return errInvalidWindowsActivation
	}
	destination := filepath.Join(filepath.Dir(b.config.Binary), name)
	if journal.CLI.Path != "" && !matchesWindowsComponent(destination, workerupdate.ComponentTarget{SHA256: journal.CLI.SHA256, Length: journal.CLI.Length, Platform: "windows", Architecture: journal.Architecture}) {
		body, err := os.ReadFile(journal.CLI.Path)
		if err != nil {
			return err
		}
		if err := windowssecurity.WithRestorePrivilege(func() error {
			return atomicfile.Write(destination, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"})
		}); err != nil {
			return err
		}
	}
	if !windowsMachineFileSecurityMatches(destination, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)") {
		return errInvalidWindowsActivation
	}
	if journal.CLI.Path != "" {
		target := workerupdate.ComponentTarget{SHA256: journal.CLI.SHA256, Length: journal.CLI.Length, Platform: "windows", Architecture: journal.Architecture}
		if !matchesWindowsComponent(destination, target) {
			return errInvalidWindowsActivation
		}
		verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := nativesignature.New(nil).Verify(verifyCtx, destination, "windows", journal.Architecture); err != nil {
			return err
		}
	} else if journal.NewCLIRecord != "" {
		if err := binarytarget.Validate(destination, "windows", b.config.Architecture); err != nil {
			return err
		}
		verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := nativesignature.New(nil).Verify(verifyCtx, destination, "windows", b.config.Architecture); err != nil {
			return err
		}
	}
	return windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(recordPath, []byte(journal.NewCLIRecord), atomicfile.Options{Mode: 0o644, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"})
	})
}

func commitWindowsInstallVersion(config WindowsConfig, version string) error {
	body, err := os.ReadFile(config.InstallState)
	if err != nil || len(body) == 0 || len(body) > 128<<10 {
		return errInvalidWindowsActivation
	}
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	artifact, ok := document["artifact"].(map[string]any)
	if !ok {
		return errInvalidWindowsActivation
	}
	artifact["version"] = version
	updated, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(config.InstallState, updated, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + config.OwnerSID + ")"})
	}); err != nil {
		return err
	}
	return applyWindowsReleaseACL(config.InstallState, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;"+config.OwnerSID+")")
}

func reconcileWindowsInstallVersion(ctx context.Context, config WindowsConfig) error {
	body, err := os.ReadFile(config.InstallState)
	if err != nil || len(body) == 0 || len(body) > 128<<10 {
		return errInvalidWindowsActivation
	}
	var document struct {
		Artifact struct {
			Version string `json:"version"`
		} `json:"artifact"`
	}
	if json.Unmarshal(body, &document) != nil || !exactReleasePattern.MatchString(document.Artifact.Version) {
		return errInvalidWindowsActivation
	}
	if document.Artifact.Version == config.ActiveVersion {
		return nil
	}
	if journal, journalErr := loadWindowsActivationJournal(config); journalErr == nil && journal.Stage != windowsActivationCommitted && journal.Stage != windowsActivationRolledBack {
		if document.Artifact.Version != journal.PreviousVersion && document.Artifact.Version != journal.Version || config.ActiveVersion != journal.PreviousVersion && config.ActiveVersion != journal.Version {
			return errInvalidWindowsActivation
		}
		return nil
	} else if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return journalErr
	}
	source, err := newWindowsTUFSource(config)
	if err != nil {
		return err
	}
	release, err := source.Active(ctx, config.ActiveVersion)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	target := workerupdate.ComponentTarget{SHA256: release.Updater.SHA256, Length: release.Updater.Length, Platform: release.Updater.Platform, Architecture: release.Updater.Architecture}
	if !matchesWindowsComponent(executable, target) {
		return errInvalidWindowsActivation
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, executable, "windows", config.Architecture); err != nil {
		return err
	}
	return commitWindowsInstallVersion(config, config.ActiveVersion)
}
func (b *windowsSCMActivationBackend) Quarantine(_ context.Context, journal windowsActivationJournal) error {
	path := filepath.Join(filepath.Dir(journal.Runtime.Path), ".quarantined")
	if err := atomicfile.Write(path, []byte(boundedWindowsActivationFailure(errors.New(journal.Failure))+"\n"), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return err
	}
	return applyWindowsReleaseACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
}

func setWindowsServiceTarget(name string, target windowsServiceTarget) error {
	if !filepath.IsAbs(target.Executable) || len(target.Arguments) == 0 || len(target.Arguments) > 16 {
		return errInvalidWindowsActivation
	}
	if name == windowsHostdService && (len(target.Arguments) != 1 || target.Arguments[0] != "__runtime-hostd") || name == windowsUpdaterService && (len(target.Arguments) != 1 || target.Arguments[0] != "__runtime-updated") {
		return errInvalidWindowsActivation
	}
	if name == windowsSSHService && !validWindowsSSHArguments(target.Arguments) {
		return errInvalidWindowsActivation
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(name)
	if err != nil {
		return err
	}
	defer item.Close()
	config, err := item.Config()
	if err != nil {
		return err
	}
	config.BinaryPathName = windows.ComposeCommandLine(append([]string{target.Executable}, target.Arguments...))
	config.StartType = mgr.StartAutomatic
	config.ErrorControl = mgr.ErrorNormal
	config.ServiceStartName = "LocalSystem"
	config.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	config.DelayedAutoStart = false
	if err := item.UpdateConfig(config); err != nil {
		return err
	}
	updated, err := item.Config()
	if err != nil || !strings.EqualFold(updated.BinaryPathName, config.BinaryPathName) || !validPrivilegedWindowsServiceConfig(updated, mgr.StartAutomatic, mgr.ErrorNormal) {
		return errors.Join(errInvalidWindowsActivation, err)
	}
	return validateWindowsRecoveryActions(item, windowsRecoveryActionsForService(name))
}
func stopNamedWindowsServices(ctx context.Context, names ...string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	for _, name := range names {
		item, err := manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			return err
		}
		_, controlErr := item.Control(svc.Stop)
		if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
			item.Close()
			return controlErr
		}
		for {
			status, queryErr := item.Query()
			if queryErr != nil {
				item.Close()
				return queryErr
			}
			if status.State == svc.Stopped {
				break
			}
			select {
			case <-ctx.Done():
				item.Close()
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		item.Close()
	}
	return nil
}
func startNamedWindowsService(ctx context.Context, name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(name)
	if err != nil {
		return err
	}
	defer item.Close()
	if err := item.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	for {
		status, err := item.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Running {
			return nil
		}
		if status.State == svc.Stopped {
			return errInvalidWindowsActivation
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func loadWindowsActivationJournal(config WindowsConfig) (windowsActivationJournal, error) {
	file, err := os.Open(windowsActivationJournalPath(config.StateRoot))
	if err != nil {
		return windowsActivationJournal{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(file, 128<<10)))
	decoder.DisallowUnknownFields()
	var journal windowsActivationJournal
	var extra any
	if decoder.Decode(&journal) != nil || decoder.Decode(&extra) != io.EOF || !validWindowsActivationJournal(journal) || !validWindowsActivationPaths(config, journal) {
		return windowsActivationJournal{}, errInvalidWindowsActivation
	}
	return journal, nil
}

func resumeWindowsActivation(ctx context.Context, config WindowsConfig) (bool, error) {
	journal, err := loadWindowsActivationJournal(config)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !windowsActivationNeedsResume(journal, config.ActiveVersion, false) {
		return false, nil
	}
	activatorOwnsTransaction, err := windowsActivatorOwnsTransaction()
	if err != nil {
		return false, err
	}
	if !windowsActivationNeedsResume(journal, config.ActiveVersion, activatorOwnsTransaction) {
		return false, nil
	}
	target := workerupdate.ComponentTarget{SHA256: journal.Updater.SHA256, Length: journal.Updater.Length, Platform: "windows", Architecture: journal.Architecture}
	if !matchesWindowsComponent(journal.Updater.Path, target) {
		return false, errInvalidWindowsActivation
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, journal.Updater.Path, "windows", journal.Architecture); err != nil {
		return false, err
	}
	if err := installWindowsActivatorService(journal.Updater.Path); err != nil {
		return false, err
	}
	if err := startWindowsActivatorService(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return false, err
	}
	return true, nil
}

func windowsActivatorOwnsTransaction() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsActivatorService)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer item.Close()
	status, err := item.Query()
	if err != nil {
		return false, err
	}
	return status.State != svc.Stopped, nil
}

func validWindowsActivationPaths(config WindowsConfig, journal windowsActivationJournal) bool {
	if config.SetupMode == "client" && (journal.OldSSH.Executable != "" || journal.NewSSH.Executable != "") {
		return false
	}
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		return false
	}
	paths, err := canonicalWindowsRelease(layout, journal.Version)
	if err != nil || !strings.EqualFold(journal.Runtime.Path, paths.Runtime) || !strings.EqualFold(journal.CLI.Path, paths.CLI) || !strings.EqualFold(journal.Hostd.Path, paths.Hostd) || !strings.EqualFold(journal.Updater.Path, paths.Updater) {
		return false
	}
	if !strings.EqualFold(journal.PreviousBinary.Path, layout.Binary) || !strings.EqualFold(journal.NewHostd.Executable, layout.Binary) || !strings.EqualFold(journal.NewUpdater.Executable, layout.Binary) || journal.NewSSH.Executable != "" && !strings.EqualFold(journal.NewSSH.Executable, layout.Binary) {
		return false
	}
	// The updater may deliberately be fenced on the rollback slot while a
	// previous activation is being recovered.  Hostd and SSH always remain on
	// the canonical binary, but accepting only layout.Binary here rejects a
	// valid staged journal before the activator can run, leaving the updater
	// service stopped and the transaction permanently staged.
	if !exactReleasePattern.MatchString(journal.PreviousVersion) || !strings.EqualFold(journal.OldHostd.Executable, layout.Binary) || !windowsUpdaterExecutableMatches(layout, journal.OldUpdater.Executable) || journal.OldSSH.Executable != "" && !strings.EqualFold(journal.OldSSH.Executable, layout.Binary) {
		return false
	}
	for _, target := range []windowsServiceTarget{journal.OldHostd, journal.OldUpdater, journal.OldSSH} {
		if target.Executable == "" {
			continue
		}
		if !filepath.IsAbs(target.Executable) || filepath.Clean(target.Executable) != target.Executable || len(target.Arguments) == 0 || len(target.Arguments) > 16 {
			return false
		}
		for _, argument := range target.Arguments {
			if strings.ContainsAny(argument, "\x00\r\n") || len(argument) > 4096 {
				return false
			}
		}
	}
	return true
}

// RunWindowsActivator is the fixed one-shot SCM entry. Its only input is the
// protected journal created by the signed updater.
func RunWindowsActivator(ctx context.Context, config WindowsConfig) error {
	journal, err := loadWindowsActivationJournal(config)
	if err != nil {
		return err
	}
	result, activationErr := executeWindowsActivation(ctx, newWindowsSCMActivationBackend(config), journal)
	var connectErr error
	if result.Stage == windowsActivationCommitted || result.Stage == windowsActivationRolledBack {
		var manager *mgr.Mgr
		manager, connectErr = mgr.Connect()
		if connectErr == nil {
			if item, openErr := manager.OpenService(windowsActivatorService); openErr == nil {
				_ = item.Delete()
				_ = item.Close()
			}
			_ = manager.Disconnect()
		}
	}
	if result.Stage == windowsActivationRolledBack {
		activationErr = nil
	}
	return errors.Join(activationErr, connectErr)
}
