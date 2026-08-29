//go:build windows

package localdaemon

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	hostruntimeservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/processlaunch"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var runWindowsTaskCommand = defaultWindowsTaskCommand
var listWindowsTaskNames = defaultListWindowsTaskNames
var readWindowsDaemonPIDLock = defaultReadWindowsDaemonPIDLock
var openWindowsDaemonProcess = defaultOpenWindowsDaemonProcess
var windowsDaemonLayout = hostruntimeservice.DefaultLayout
var probeWindowsLocalDaemonService = defaultProbeWindowsLocalDaemonService
var stopWindowsLocalDaemonService = defaultStopWindowsLocalDaemonService
var startWindowsLocalDaemonService = defaultStartWindowsLocalDaemonService

var errUnsafeWindowsDaemonProcess = errors.New("unsafe Windows local daemon process identity")

type windowsDaemonPIDLock struct {
	Record windowsDaemonOwnerRecord
}

const windowsDaemonOwnerSchema = "paperboat.windows-local-daemon-owner/v1"
const windowsLocalDaemonServiceName = "PaperboatLocalDaemon"
const windowsLocalDaemonServiceStopTimeout = 30 * time.Second

type windowsDaemonOwnerRecord struct {
	Schema               string `json:"schema"`
	PID                  uint32 `json:"pid"`
	CreationTimeUnixNano int64  `json:"creation_time_unix_nano"`
	Executable           string `json:"executable"`
	ArgumentsSHA256      string `json:"arguments_sha256"`
}

type windowsDaemonProcessIdentity struct {
	PID          uint32
	OwnerSID     string
	Executable   string
	Arguments    []string
	CreationTime time.Time
}

type windowsDaemonProcess interface {
	Identity() (windowsDaemonProcessIdentity, error)
	TerminateAndWait(context.Context) error
	Close() error
}

func installWindowsCurrentUserService(ctx context.Context, executable, configPath, serverURL string) error {
	executable = resolveWindowsDaemonExecutable(executable)
	if ctx == nil || !validWindowsExecutable(executable) || configPath != "" && !validWindowsConfigPath(configPath) || !validTaskText(serverURL) {
		return ErrInvalidInventoryConfig
	}
	installed, err := probeWindowsLocalDaemonService()
	if err != nil {
		return err
	}
	if installed {
		// Managed installations own one silent SCM service. Never recreate the
		// old interactive ONLOGON task after migration merely because a CLI
		// command observed a cold local pipe.
		return startWindowsLocalDaemonService(ctx)
	}
	return windows.ERROR_SERVICE_DOES_NOT_EXIST
}

// RemoveWindowsLegacyTask removes the pre-SCM ONLOGON task for exactly one
// enrolled owner. The task name is derived from the SID, so callers never
// accept a task name supplied by an untrusted request.
func RemoveWindowsLegacyTask(ctx context.Context, ownerSID string) error {
	if ctx == nil || !validWindowsOwnerSID(ownerSID) {
		return ErrInvalidInventoryConfig
	}
	err := runWindowsTaskCommand(ctx, "/Delete", "/TN", windowsDaemonTaskName(ownerSID), "/F")
	if isMissingWindowsTaskError(err) {
		return nil
	}
	return err
}

// RemoveAllWindowsLegacyTasks removes only the retired owner-scoped daemon
// tasks in Paperboat's dedicated folder. Fresh cleanup cannot depend on a
// surviving runtime-install.json: an interrupted uninstall may remove
// ProgramData first while leaving a task that would reopen a console at the
// next logon.
func RemoveAllWindowsLegacyTasks(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInventoryConfig
	}
	names, err := listWindowsTaskNames(ctx)
	if err != nil {
		// A disabled or unavailable Task Scheduler cannot launch the retired
		// task. Do not strand a fresh installation when there is no safe task
		// identity to delete; the exact owner-derived cleanup still runs when
		// runtime-install.json survives.
		return nil
	}
	var result error
	for _, name := range names {
		if !isWindowsLegacyDaemonTaskName(name) {
			continue
		}
		endErr := runWindowsTaskCommand(ctx, "/End", "/TN", name)
		if isMissingWindowsTaskError(endErr) || isWindowsTaskNotRunningError(endErr) {
			endErr = nil
		}
		deleteErr := runWindowsTaskCommand(ctx, "/Delete", "/TN", name, "/F")
		if isMissingWindowsTaskError(deleteErr) {
			deleteErr = nil
		}
		result = errors.Join(result, endErr, deleteErr)
	}
	return result
}

func isWindowsLegacyDaemonTaskName(name string) bool {
	const prefix = `\Paperboat\LocalDaemon-`
	if len(name) != len(prefix)+16 || !strings.EqualFold(name[:len(prefix)], prefix) {
		return false
	}
	for _, character := range name[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F') {
			return false
		}
	}
	return true
}

// StopWindowsLegacyTask ends the exact pre-SCM task without deleting its
// rollback registration.
func StopWindowsLegacyTask(ctx context.Context, ownerSID string) error {
	if ctx == nil || !validWindowsOwnerSID(ownerSID) {
		return ErrInvalidInventoryConfig
	}
	err := runWindowsTaskCommand(ctx, "/End", "/TN", windowsDaemonTaskName(ownerSID))
	if isMissingWindowsTaskError(err) || isWindowsTaskNotRunningError(err) {
		return nil
	}
	return err
}

// RemoveWindowsLegacyService removes the legacy task and terminates its
// owner-scoped process, if one is still present. It is used while migrating to
// the LocalDaemon SCM service and deliberately does not touch the new service.
func RemoveWindowsLegacyService(ctx context.Context, lockPath, ownerSID string) error {
	if ctx == nil || !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath || !validWindowsOwnerSID(ownerSID) {
		return ErrInvalidInventoryConfig
	}
	taskErr := RemoveWindowsLegacyTask(ctx, ownerSID)
	stopErr := stopOwnedWindowsDaemon(ctx, lockPath, ownerSID, "")
	return errors.Join(taskErr, stopErr)
}

// StopWindowsLegacyService stops the pre-SCM task and its exact owner process
// without deleting the task. Install and update migrations retain that
// rollback point until the replacement SCM service is running.
func StopWindowsLegacyService(ctx context.Context, lockPath, ownerSID string) error {
	if ctx == nil || !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath || !validWindowsOwnerSID(ownerSID) {
		return ErrInvalidInventoryConfig
	}
	taskErr := StopWindowsLegacyTask(ctx, ownerSID)
	return errors.Join(taskErr, stopOwnedWindowsDaemon(ctx, lockPath, ownerSID, ""))
}

// WindowsLocalDaemonServiceInstalled reports whether the dedicated SCM
// service exists. It is used by migration to avoid terminating a process that
// is already owned by the new service when a stale legacy task remains.
func WindowsLocalDaemonServiceInstalled() (bool, error) {
	return probeWindowsLocalDaemonService()
}

// WindowsLocalDaemonServiceRunning reports the authoritative SCM state. It is
// independent of the child lock so an updater can stop a service that is still
// starting and has not published its owner record yet.
func WindowsLocalDaemonServiceRunning() (bool, error) {
	state, installed, err := windowsLocalDaemonServiceState()
	return err == nil && installed && state == svc.Running, err
}

// WindowsLocalDaemonServiceActive reports whether SCM still owns a live or
// transitioning service process. Migration must not terminate the SID-bound
// owner lock while SCM is in StartPending or StopPending: that lock can
// already belong to the managed service rather than the retired task.
func WindowsLocalDaemonServiceActive() (bool, error) {
	state, installed, err := windowsLocalDaemonServiceState()
	return err == nil && installed && state != svc.Stopped, err
}

func windowsLocalDaemonServiceState() (svc.State, bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return svc.Stopped, false, err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsLocalDaemonServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return svc.Stopped, false, nil
	}
	if err != nil {
		return svc.Stopped, false, err
	}
	defer item.Close()
	status, err := item.Query()
	return status.State, err == nil, err
}

// resolveWindowsDaemonExecutable binds the persistent task to the stable MSI
// launcher instead of the mutable cli-current payload. Major upgrades and
// updater slot rotation may replace the payload, but the launcher path remains
// the public command contract. Development and test binaries outside the
// managed CLI slot are left unchanged.
func resolveWindowsDaemonExecutable(executable string) string {
	layout, err := hostruntimeservice.DefaultLayout("windows")
	if err != nil {
		return executable
	}
	return resolveManagedWindowsDaemonExecutable(executable, layout, validWindowsExecutable)
}

func resolveManagedWindowsDaemonExecutable(executable string, layout hostruntimeservice.Layout, valid func(string) bool) string {
	if valid == nil || !strings.EqualFold(filepath.Dir(filepath.Clean(executable)), filepath.Dir(layout.Binary)) {
		return executable
	}
	launcher := filepath.Join(layout.InstallRoot, "bin", "pb.exe")
	if valid(launcher) {
		return launcher
	}
	return executable
}

func removeWindowsCurrentUserService(ctx context.Context, executable string) error {
	if ctx == nil || !validWindowsExecutable(executable) {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	serviceErr := stopWindowsLocalDaemonService(ctx)
	taskErr := RemoveWindowsLegacyTask(ctx, ownerSID)
	paths, pathsErr := CurrentUserPaths()
	if pathsErr != nil {
		return errors.Join(serviceErr, taskErr, pathsErr)
	}
	stopErr := stopOwnedWindowsDaemon(ctx, paths.LockPath, ownerSID, executable)
	return errors.Join(serviceErr, taskErr, stopErr)
}

func stopOwnedWindowsDaemon(ctx context.Context, lockPath, ownerSID, _ string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	record, err := readWindowsDaemonPIDLock(lockPath, ownerSID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	process, err := openWindowsDaemonProcess(record.Record.PID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer process.Close()
	identity, err := process.Identity()
	if err != nil {
		return err
	}
	if err := validateOwnedWindowsDaemon(identity, record, ownerSID); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return process.TerminateAndWait(bounded)
}

func windowsOwnerServiceRunning(lockPath, ownerSID string) (bool, error) {
	record, err := readWindowsDaemonPIDLock(lockPath, ownerSID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	process, err := openWindowsDaemonProcess(record.Record.PID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer process.Close()
	identity, err := process.Identity()
	if err != nil {
		return false, err
	}
	if err := validateOwnedWindowsDaemon(identity, record, ownerSID); err != nil {
		return false, err
	}
	return true, nil
}

func stopWindowsOwnerService(ctx context.Context, lockPath, ownerSID string) error {
	if ctx == nil || !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath || ownerSID == "" {
		return ErrInvalidInventoryConfig
	}
	installed, probeErr := probeWindowsLocalDaemonService()
	serviceErr := stopWindowsLocalDaemonService(ctx)
	var taskErr error
	if !installed && probeErr == nil {
		taskErr = StopWindowsLegacyTask(ctx, ownerSID)
	}
	return errors.Join(probeErr, serviceErr, taskErr, stopOwnedWindowsDaemon(ctx, lockPath, ownerSID, ""))
}

func startWindowsOwnerService(ctx context.Context, ownerSID string) error {
	if ctx == nil || !validWindowsOwnerSID(ownerSID) {
		return ErrInvalidInventoryConfig
	}
	return startWindowsLocalDaemonService(ctx)
}

func validWindowsOwnerSID(ownerSID string) bool {
	sid, err := windows.StringToSid(ownerSID)
	return err == nil && sid != nil && sid.IsValid()
}

func defaultProbeWindowsLocalDaemonService() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsLocalDaemonServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, item.Close()
}

func defaultStartWindowsLocalDaemonService(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInventoryConfig
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsLocalDaemonServiceName)
	if err != nil {
		return err
	}
	defer item.Close()
	err = item.Start()
	if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) || errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		return nil
	}
	return err
}

func defaultStopWindowsLocalDaemonService(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInventoryConfig
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	item, err := manager.OpenService(windowsLocalDaemonServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer item.Close()
	if _, err := item.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	deadline := time.NewTimer(windowsLocalDaemonServiceStopTimeout)
	defer deadline.Stop()
	for {
		status, err := item.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return context.DeadlineExceeded
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func defaultReadWindowsDaemonPIDLock(path, ownerSID string) (windowsDaemonPIDLock, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return windowsDaemonPIDLock{}, os.ErrNotExist
	}
	if err != nil {
		return windowsDaemonPIDLock{}, err
	}
	if err := validateWindowsLockFile(path); err != nil {
		return windowsDaemonPIDLock{}, err
	}
	if err := verifyWindowsLockACL(path, ownerSID); err != nil {
		return windowsDaemonPIDLock{}, errUnsafeWindowsDaemonProcess
	}
	held, err := windowsDaemonLockHeld(path)
	if err != nil {
		return windowsDaemonPIDLock{}, err
	}
	if !held {
		return windowsDaemonPIDLock{}, os.ErrNotExist
	}
	record, err := readWindowsDaemonOwnerRecord(path+".owner.json", ownerSID)
	if err != nil {
		return windowsDaemonPIDLock{}, errors.Join(errUnsafeWindowsDaemonProcess, err)
	}
	return windowsDaemonPIDLock{Record: record}, nil
}

func windowsDaemonLockHeld(path string) (bool, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var region windows.Overlapped
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &region)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &region)
}

func validateOwnedWindowsDaemon(identity windowsDaemonProcessIdentity, lock windowsDaemonPIDLock, ownerSID string) error {
	record := lock.Record
	executable := identity.Executable
	if !strings.EqualFold(filepath.Clean(executable), record.Executable) {
		layout, layoutErr := windowsDaemonLayout("windows")
		if layoutErr != nil || !strings.EqualFold(record.Executable, layout.Binary) || !strings.EqualFold(filepath.Clean(executable), layout.BinaryRollback) {
			return errUnsafeWindowsDaemonProcess
		}
		// Windows keeps the image path of a running process attached to the
		// file after an atomic stable-to-rollback rename. The command line and
		// owner record still name the stable launcher, so validate that exact
		// recorded identity while accepting only the canonical rollback slot.
		executable = record.Executable
	}
	executable, digest, err := normalizedWindowsDaemonIdentity(executable, identity.Arguments)
	if err != nil || identity.PID == 0 || identity.PID != record.PID || !strings.EqualFold(identity.OwnerSID, ownerSID) || identity.CreationTime.IsZero() || identity.CreationTime.UnixNano() != record.CreationTimeUnixNano || executable != record.Executable || digest != record.ArgumentsSHA256 {
		return errUnsafeWindowsDaemonProcess
	}
	if len(identity.Arguments) < 2 || identity.Arguments[1] != "__local-daemon" {
		return errUnsafeWindowsDaemonProcess
	}
	remaining := identity.Arguments[2:]
	seen := make(map[string]bool)
	for len(remaining) > 0 {
		if len(remaining) < 2 || seen[remaining[0]] {
			return errUnsafeWindowsDaemonProcess
		}
		seen[remaining[0]] = true
		switch remaining[0] {
		case "--config":
			if !validWindowsConfigPath(remaining[1]) {
				return errUnsafeWindowsDaemonProcess
			}
		case "--server":
			if !validTaskText(remaining[1]) {
				return errUnsafeWindowsDaemonProcess
			}
		default:
			return errUnsafeWindowsDaemonProcess
		}
		remaining = remaining[2:]
	}
	return nil
}

func normalizedWindowsDaemonIdentity(executable string, arguments []string) (string, string, error) {
	executable = filepath.Clean(executable)
	if !validWindowsExecutable(executable) || len(arguments) < 2 {
		return "", "", errUnsafeWindowsDaemonProcess
	}
	normalized := append([]string(nil), arguments...)
	normalized[0] = strings.ToLower(executable)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(encoded)
	return strings.ToLower(executable), hex.EncodeToString(digest[:]), nil
}

func currentWindowsDaemonOwnerRecord() (windowsDaemonOwnerRecord, error) {
	executable, err := os.Executable()
	if err != nil {
		return windowsDaemonOwnerRecord{}, err
	}
	var created, exited, kernel, userTime windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &userTime); err != nil {
		return windowsDaemonOwnerRecord{}, err
	}
	normalizedExecutable, digest, err := normalizedWindowsDaemonIdentity(executable, os.Args)
	if err != nil {
		return windowsDaemonOwnerRecord{}, err
	}
	return windowsDaemonOwnerRecord{Schema: windowsDaemonOwnerSchema, PID: uint32(os.Getpid()), CreationTimeUnixNano: created.Nanoseconds(), Executable: normalizedExecutable, ArgumentsSHA256: digest}, nil
}

func writeWindowsDaemonOwnerRecord(path, ownerSID string, record windowsDaemonOwnerRecord) error {
	if err := validateWindowsDaemonOwnerRecord(record); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary := path + ".new"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := setWindowsLockACL(temporary, ownerSID); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	from, fromErr := windows.UTF16PtrFromString(temporary)
	to, toErr := windows.UTF16PtrFromString(path)
	if fromErr != nil || toErr != nil {
		_ = os.Remove(temporary)
		return errors.Join(fromErr, toErr)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return verifyWindowsLockACL(path, ownerSID)
}

func readWindowsDaemonOwnerRecord(path, ownerSID string) (windowsDaemonOwnerRecord, error) {
	var record windowsDaemonOwnerRecord
	if err := validateWindowsLockFile(path); err != nil {
		return record, err
	}
	if err := verifyWindowsLockACL(path, ownerSID); err != nil {
		return record, err
	}
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 || len(encoded) > 4096 {
		return record, errors.Join(errUnsafeWindowsDaemonProcess, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&record) != nil || !errors.Is(decoder.Decode(&extra), io.EOF) {
		return windowsDaemonOwnerRecord{}, errUnsafeWindowsDaemonProcess
	}
	if err := validateWindowsDaemonOwnerRecord(record); err != nil {
		return windowsDaemonOwnerRecord{}, err
	}
	return record, nil
}

func validateWindowsDaemonOwnerRecord(record windowsDaemonOwnerRecord) error {
	if record.Schema != windowsDaemonOwnerSchema || record.PID == 0 || record.CreationTimeUnixNano <= 0 || !filepath.IsAbs(record.Executable) || filepath.Clean(record.Executable) != record.Executable || record.Executable != strings.ToLower(record.Executable) || len(record.ArgumentsSHA256) != sha256.Size*2 {
		return errUnsafeWindowsDaemonProcess
	}
	if _, err := hex.DecodeString(record.ArgumentsSHA256); err != nil {
		return errUnsafeWindowsDaemonProcess
	}
	return nil
}

type nativeWindowsDaemonProcess struct {
	pid    uint32
	handle windows.Handle
}

func defaultOpenWindowsDaemonProcess(pid uint32) (windowsDaemonProcess, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return &nativeWindowsDaemonProcess{pid: pid, handle: handle}, nil
}

func (p *nativeWindowsDaemonProcess) Identity() (windowsDaemonProcessIdentity, error) {
	if p == nil || p.handle == 0 {
		return windowsDaemonProcessIdentity{}, errUnsafeWindowsDaemonProcess
	}
	executableBuffer := make([]uint16, 32768)
	size := uint32(len(executableBuffer))
	if err := windows.QueryFullProcessImageName(p.handle, 0, &executableBuffer[0], &size); err != nil || size == 0 {
		return windowsDaemonProcessIdentity{}, errors.Join(errUnsafeWindowsDaemonProcess, err)
	}
	executable := windows.UTF16ToString(executableBuffer[:size])
	var token windows.Token
	if err := windows.OpenProcessToken(p.handle, windows.TOKEN_QUERY, &token); err != nil {
		return windowsDaemonProcessIdentity{}, err
	}
	user, userErr := token.GetTokenUser()
	closeErr := token.Close()
	if userErr != nil || closeErr != nil || user == nil || user.User.Sid == nil {
		return windowsDaemonProcessIdentity{}, errors.Join(errUnsafeWindowsDaemonProcess, userErr, closeErr)
	}
	arguments, err := queryWindowsProcessArguments(p.handle)
	if err != nil {
		return windowsDaemonProcessIdentity{}, err
	}
	var created, exited, kernel, userTime windows.Filetime
	if err := windows.GetProcessTimes(p.handle, &created, &exited, &kernel, &userTime); err != nil {
		return windowsDaemonProcessIdentity{}, err
	}
	return windowsDaemonProcessIdentity{PID: p.pid, OwnerSID: user.User.Sid.String(), Executable: filepath.Clean(executable), Arguments: arguments, CreationTime: time.Unix(0, created.Nanoseconds())}, nil
}

type windowsUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func queryWindowsProcessArguments(handle windows.Handle) ([]string, error) {
	var required uint32
	_ = windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation, nil, 0, &required)
	if required == 0 || required > 64<<10 {
		return nil, errUnsafeWindowsDaemonProcess
	}
	buffer := make([]byte, required)
	if err := windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation, unsafe.Pointer(&buffer[0]), uint32(len(buffer)), &required); err != nil {
		return nil, err
	}
	value := (*windowsUnicodeString)(unsafe.Pointer(&buffer[0]))
	if value.Buffer == nil || value.Length == 0 || value.Length%2 != 0 || int(value.Length) > len(buffer) {
		return nil, errUnsafeWindowsDaemonProcess
	}
	commandLine := windows.UTF16ToString(unsafe.Slice(value.Buffer, int(value.Length/2)))
	arguments, err := windows.DecomposeCommandLine(commandLine)
	if err != nil || len(arguments) == 0 {
		return nil, errors.Join(errUnsafeWindowsDaemonProcess, err)
	}
	return arguments, nil
}

func (p *nativeWindowsDaemonProcess) TerminateAndWait(ctx context.Context) error {
	if p == nil || p.handle == 0 || ctx == nil {
		return ErrInvalidInventoryConfig
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case <-bounded.Done():
		return bounded.Err()
	default:
	}
	// Re-read identity through the pinned process handle immediately before
	// termination. A PID reuse cannot substitute a different process here.
	if _, err := p.Identity(); err != nil {
		return err
	}
	select {
	case <-bounded.Done():
		return bounded.Err()
	default:
	}
	if err := windows.TerminateProcess(p.handle, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	for {
		result, err := windows.WaitForSingleObject(p.handle, 100)
		if err != nil {
			return err
		}
		if result == windows.WAIT_OBJECT_0 {
			return nil
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wait for Paperboat local daemon returned %d", result)
		}
		select {
		case <-bounded.Done():
			return bounded.Err()
		default:
		}
	}
}

func (p *nativeWindowsDaemonProcess) Close() error {
	if p == nil || p.handle == 0 {
		return nil
	}
	handle := p.handle
	p.handle = 0
	return windows.CloseHandle(handle)
}

func validWindowsExecutable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func validWindowsConfigPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	return !strings.ContainsAny(path, "\x00\r\n")
}

func validTaskText(value string) bool {
	return len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func windowsDaemonTaskName(ownerSID string) string {
	sum := sha256.Sum256([]byte(ownerSID))
	return "\\Paperboat\\LocalDaemon-" + hex.EncodeToString(sum[:8])
}

func quoteWindowsTaskArg(value string) string {
	if value == "" {
		return "\"\""
	}
	if !strings.ContainsAny(value, " \t\"") {
		return value
	}
	return "\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""
}

func defaultWindowsTaskCommand(ctx context.Context, arguments ...string) error {
	if ctx == nil {
		return ErrInvalidInventoryConfig
	}
	executable := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	if !validWindowsSystemExecutable(executable) {
		var err error
		executable, err = exec.LookPath("schtasks.exe")
		if err != nil {
			return err
		}
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	processlaunch.ConfigureBackground(command)
	output, err := command.CombinedOutput()
	if err != nil {
		return &windowsTaskCommandError{err: err, output: redactTaskOutput(output)}
	}
	return nil
}

func defaultListWindowsTaskNames(ctx context.Context) ([]string, error) {
	if ctx == nil {
		return nil, ErrInvalidInventoryConfig
	}
	executable := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	if !validWindowsSystemExecutable(executable) {
		var err error
		executable, err = exec.LookPath("schtasks.exe")
		if err != nil {
			return nil, err
		}
	}
	command := exec.CommandContext(ctx, executable, "/Query", "/FO", "CSV", "/NH")
	processlaunch.ConfigureBackground(command)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, &windowsTaskCommandError{err: err, output: redactTaskOutput(output)}
	}
	reader := csv.NewReader(strings.NewReader(string(output)))
	reader.FieldsPerRecord = -1
	var names []string
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			return names, nil
		}
		if readErr != nil {
			return nil, readErr
		}
		if len(record) > 0 && isWindowsLegacyDaemonTaskName(record[0]) {
			names = append(names, record[0])
		}
	}
}

func validWindowsSystemExecutable(path string) bool {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

type windowsTaskCommandError struct {
	err    error
	output string
}

func (e *windowsTaskCommandError) Error() string {
	if e == nil {
		return ""
	}
	if e.output == "" {
		return e.err.Error()
	}
	return e.err.Error() + ": " + e.output
}

func (e *windowsTaskCommandError) Unwrap() error { return e.err }

func redactTaskOutput(value []byte) string {
	const maximum = 4096
	if len(value) > maximum {
		value = value[:maximum]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, string(value)))
}

func isMissingWindowsTaskError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "does not exist") || strings.Contains(value, "cannot find") || strings.Contains(value, "not found")
}

func isWindowsTaskNotRunningError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "not currently running") || strings.Contains(value, "is not running")
}
