//go:build windows

package localdaemon

import (
	"context"
	"crypto/sha256"
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

	"golang.org/x/sys/windows"
)

var runWindowsTaskCommand = defaultWindowsTaskCommand
var startWindowsDetachedDaemon = defaultStartWindowsDetachedDaemon
var readWindowsDaemonPIDLock = defaultReadWindowsDaemonPIDLock
var openWindowsDaemonProcess = defaultOpenWindowsDaemonProcess

var errUnsafeWindowsDaemonProcess = errors.New("unsafe Windows local daemon process identity")

type windowsDaemonPIDLock struct {
	Record windowsDaemonOwnerRecord
}

const windowsDaemonOwnerSchema = "paperboat.windows-local-daemon-owner/v1"

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
	if ctx == nil || !validWindowsExecutable(executable) || configPath != "" && !validWindowsConfigPath(configPath) || !validTaskText(serverURL) {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	taskName := windowsDaemonTaskName(ownerSID)
	arguments := []string{"__local-daemon"}
	commandLine := quoteWindowsTaskArg(filepath.Clean(executable)) + " __local-daemon"
	if configPath != "" {
		arguments = append(arguments, "--config", filepath.Clean(configPath))
		commandLine += " --config " + quoteWindowsTaskArg(filepath.Clean(configPath))
	}
	if serverURL != "" {
		arguments = append(arguments, "--server", strings.TrimSpace(serverURL))
		commandLine += " --server " + quoteWindowsTaskArg(strings.TrimSpace(serverURL))
	}
	if err := runWindowsTaskCommand(ctx, "/Create", "/TN", taskName, "/TR", commandLine, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"); err != nil {
		return fmt.Errorf("install Paperboat local daemon task: %w", err)
	}
	// Start immediately in the caller's authenticated user context. An ONLOGON
	// task cannot run in a non-interactive OpenSSH session, while an S4U task
	// cannot use the network credentials required by the client daemon. The
	// detached process covers the current session and the task restores it on
	// future interactive logons. The daemon's SID-bound process lock makes a
	// concurrent task launch harmless.
	if err := startWindowsDetachedDaemon(filepath.Clean(executable), arguments); err != nil {
		return fmt.Errorf("start Paperboat local daemon: %w", err)
	}
	return nil
}

func defaultStartWindowsDetachedDaemon(executable string, arguments []string) error {
	command := exec.Command(executable, arguments...)
	command.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB,
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func removeWindowsCurrentUserService(ctx context.Context, executable string) error {
	if ctx == nil || !validWindowsExecutable(executable) {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	taskErr := runWindowsTaskCommand(ctx, "/Delete", "/TN", windowsDaemonTaskName(ownerSID), "/F")
	if isMissingWindowsTaskError(taskErr) {
		taskErr = nil
	}
	paths, pathsErr := CurrentUserPaths()
	if pathsErr != nil {
		return errors.Join(taskErr, pathsErr)
	}
	stopErr := stopOwnedWindowsDaemon(ctx, paths.LockPath, ownerSID, executable)
	return errors.Join(taskErr, stopErr)
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
	executable, digest, err := normalizedWindowsDaemonIdentity(identity.Executable, identity.Arguments)
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
	output, err := command.CombinedOutput()
	if err != nil {
		return &windowsTaskCommandError{err: err, output: redactTaskOutput(output)}
	}
	return nil
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
