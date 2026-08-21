//go:build windows

package elevation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	bridgeCancelGrace     = 2 * time.Second
	bridgeLaunchGrace     = 1 * time.Second
	bridgePollInterval    = 100 * time.Millisecond
	bridgeShutdownCode    = 0xC000013A
)

var (
	shell32                        = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW            = shell32.NewProc("ShellExecuteExW")
	shellExecuteExForRun           = shellExecuteEx
	isCurrentProcessElevatedForRun = IsCurrentProcessElevated
	waitForProcess                 = waitForProcessExit
	terminateProcess               = windows.TerminateProcess
	closeProcessHandle             = windows.CloseHandle
)

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

type bridgePaths struct {
	directory string
	request   string
	result    string
	cancel    string
}

// bridgeHandles is the privileged side of the elevation protocol. All
// privileged reads and writes happen through these handles. The directory
// chain and file handles deliberately omit FILE_SHARE_DELETE: once the
// elevated child has validated the request, the caller cannot rename or
// replace the objects behind the handles while the operation is running.
type bridgeHandles struct {
	directories   []windows.Handle
	directory     windows.Handle
	directoryPath string
	request       windows.Handle
	result        windows.Handle
	cancel        windows.Handle
}

const bridgeFileShareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE

func (h *bridgeHandles) close() error {
	if h == nil {
		return nil
	}
	var closeErr error
	for _, handle := range []windows.Handle{h.request, h.result, h.cancel} {
		if handle != 0 {
			closeErr = errors.Join(closeErr, windows.CloseHandle(handle))
		}
	}
	for index := len(h.directories) - 1; index >= 0; index-- {
		if h.directories[index] != 0 {
			closeErr = errors.Join(closeErr, windows.CloseHandle(h.directories[index]))
		}
	}
	h.request, h.result, h.cancel, h.directory = 0, 0, 0, 0
	h.directories = nil
	return closeErr
}

type launchResult struct {
	handle windows.Handle
	err    error
}

// RunRuntimeService requests one of the existing privileged __runtime-service
// operations. The payload is serialized to a protected file and is never put
// in the elevated process command line or environment.
func RunRuntimeService(ctx context.Context, executable, action string, payload any) error {
	return runOperation(ctx, executable, OperationRuntimeService, action, payload)
}

// RunOpenSSH requests a Paperboat-owned OpenSSH operation in the existing
// __runtime-service elevated target. OpenSSH credentials and host keys are
// never part of this request.
func RunOpenSSH(ctx context.Context, executable, action string) error {
	return runOperation(ctx, executable, OperationOpenSSH, action, nil)
}

// IsCurrentProcessElevated reports whether the current process has a full UAC
// administrator token. It is used to avoid re-elevating the hidden child.
func IsCurrentProcessElevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func runOperation(ctx context.Context, executable, operation, action string, payload any) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrElevationProtocol)
	}
	if !validOperationAction(operation, action) {
		return fmt.Errorf("%w: unsupported operation %q/%q", ErrElevationProtocol, operation, action)
	}
	if actionNeedsPayload(operation, action) && payload == nil {
		return fmt.Errorf("%w: %s requires a payload", ErrElevationProtocol, action)
	}
	if !actionNeedsPayload(operation, action) && payload != nil {
		return fmt.Errorf("%w: %s does not accept a payload", ErrElevationProtocol, action)
	}

	var encoded []byte
	var err error
	if payload != nil {
		encoded, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("%w: encode request payload: %v", ErrElevationProtocol, err)
		}
		if len(encoded) == 0 || len(encoded) > MaxRequestBytes || !json.Valid(encoded) {
			return fmt.Errorf("%w: request payload is too large or invalid", ErrElevationProtocol)
		}
	}

	ownerSID, err := currentOwnerSID()
	if err != nil {
		return fmt.Errorf("%w: resolve current Windows user: %v", ErrElevationProtocol, err)
	}
	validatedExecutable, executableHandle, err := pinExecutable(executable)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrElevationUnavailable, err)
	}
	defer windows.CloseHandle(executableHandle)

	operationCtx, cancel := context.WithTimeout(ctx, MaxOperationDuration)
	defer cancel()
	select {
	case <-operationCtx.Done():
		return contextError(ctx, operationCtx)
	default:
	}

	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		return fmt.Errorf("%w: create protected request files: %v", ErrElevationProtocol, err)
	}
	cleanupNow := true
	defer func() {
		if cleanupNow {
			_ = os.RemoveAll(paths.directory)
		}
	}()

	now := time.Now().UTC()
	request := Request{
		Schema:     SchemaV1,
		RequestID:  filepath.Base(paths.directory),
		OwnerSID:   ownerSID,
		Operation:  operation,
		Action:     action,
		Payload:    encoded,
		CancelPath: paths.cancel,
		CreatedAt:  now,
		ExpiresAt:  now.Add(MaxOperationDuration),
	}
	if err := validateRequest(request); err != nil {
		cleanup()
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		cleanup()
		return fmt.Errorf("%w: write protected request: %v", ErrElevationProtocol, err)
	}

	parameters := bridgeParameters(paths)
	launchCh := make(chan launchResult, 1)
	go func() {
		launcher := shellExecuteExForRun
		if isCurrentProcessElevatedForRun() {
			launcher = createProcessForRun
		}
		handle, launchErr := launcher(validatedExecutable, parameters, filepath.Dir(validatedExecutable))
		launchCh <- launchResult{handle: handle, err: launchErr}
	}()

	var launched launchResult
	select {
	case launched = <-launchCh:
	case <-operationCtx.Done():
		_ = writeCancellation(paths, ownerSID)
		select {
		case launched = <-launchCh:
			stopProcess(launched.handle)
		case <-time.After(bridgeLaunchGrace):
			cleanupNow = false
			go func() {
				launched := <-launchCh
				stopProcess(launched.handle)
				cleanup()
			}()
		}
		return contextError(ctx, operationCtx)
	}
	if launched.err != nil {
		cleanup()
		return classifyLaunchError(launched.err)
	}
	if launched.handle == 0 {
		cleanup()
		return fmt.Errorf("%w: ShellExecuteEx did not return a process handle", ErrElevationProtocol)
	}
	defer closeProcessHandle(launched.handle)

	waitErr := waitForProcess(operationCtx, launched.handle)
	if waitErr != nil {
		if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) || operationCtx.Err() != nil {
			_ = writeCancellation(paths, ownerSID)
			stopProcessAndWait(launched.handle)
			return contextError(ctx, operationCtx)
		}
		stopProcessAndWait(launched.handle)
		return fmt.Errorf("%w: wait for elevated helper: %v", ErrElevationProtocol, waitErr)
	}

	result, err := readProtectedResult(paths, ownerSID, request.RequestID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	switch result.Status {
	case statusOK:
		return nil
	case statusCanceled:
		return ErrElevationCanceled
	case statusTimedOut:
		return ErrElevationTimedOut
	case statusError:
		return &RemoteError{Code: result.ErrorCode, Message: result.ErrorMessage}
	default:
		return fmt.Errorf("%w: unknown helper result status %q", ErrElevationProtocol, result.Status)
	}
}

// Execute validates and executes a request inside the elevated
// __runtime-service child. The handler is intentionally supplied by the
// hostruntimecmd package so this package does not own SCM or OpenSSH policy.
func Execute(ctx context.Context, requestPath, resultPath, cancelPath string, handler func(context.Context, Request) error) error {
	if ctx == nil || handler == nil {
		return fmt.Errorf("%w: invalid elevated helper arguments", ErrElevationProtocol)
	}
	paths, err := validateBridgePaths(requestPath, resultPath, cancelPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	handles, err := openBridgeHandles(paths)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	defer handles.close()
	var request Request
	err = readBoundedJSONHandle(handles.request, MaxRequestBytes, &request)
	if err != nil {
		return fmt.Errorf("%w: read protected request: %v", ErrElevationProtocol, err)
	}
	if err := validateRequest(request); err != nil {
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	requestCancelPath, requestPathErr := expectedBridgePath(request.CancelPath)
	pathsCancelPath, pathsCancelErr := expectedBridgePath(paths.cancel)
	if requestPathErr != nil || pathsCancelErr != nil || requestCancelPath != pathsCancelPath {
		return fmt.Errorf("%w: cancellation path does not match request", ErrElevationProtocol)
	}
	if err := validateSID(request.OwnerSID); err != nil {
		return fmt.Errorf("%w: invalid owner SID: %v", ErrElevationProtocol, err)
	}
	if err := handles.verify(request.OwnerSID); err != nil {
		return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
	}
	if !IsCurrentProcessElevated() {
		writeErr := writeResultHandle(handles.result, request, Result{Schema: SchemaV1, RequestID: request.RequestID, Status: statusError, ErrorCode: "not_elevated", ErrorMessage: ErrNotElevated.Error()})
		return errors.Join(ErrNotElevated, writeErr)
	}
	if time.Now().UTC().After(request.ExpiresAt) {
		writeErr := writeResultHandle(handles.result, request, Result{Schema: SchemaV1, RequestID: request.RequestID, Status: statusTimedOut, ErrorCode: "deadline_exceeded", ErrorMessage: ErrElevationTimedOut.Error()})
		return errors.Join(ErrElevationTimedOut, writeErr)
	}

	operationCtx, cancel := context.WithTimeout(ctx, MaxOperationDuration)
	defer cancel()
	watchDone := make(chan struct{})
	go watchCancellation(operationCtx, cancel, handles.cancel, watchDone)
	operationErr := handler(operationCtx, request)
	operationContextErr := operationCtx.Err()
	cancel()
	<-watchDone

	result := Result{Schema: SchemaV1, RequestID: request.RequestID, Status: statusOK}
	switch {
	case operationErr == nil:
	case errors.Is(operationErr, context.Canceled) || errors.Is(operationContextErr, context.Canceled):
		result.Status, result.ErrorCode, result.ErrorMessage = statusCanceled, "canceled", ErrElevationCanceled.Error()
	case errors.Is(operationErr, context.DeadlineExceeded) || errors.Is(operationContextErr, context.DeadlineExceeded):
		result.Status, result.ErrorCode, result.ErrorMessage = statusTimedOut, "deadline_exceeded", ErrElevationTimedOut.Error()
	default:
		result.Status, result.ErrorCode, result.ErrorMessage = statusError, operationFailed, sanitizeMessage(operationErr.Error(), 2048)
	}
	writeErr := writeResultHandle(handles.result, request, result)
	if operationErr != nil {
		return errors.Join(operationErr, writeErr)
	}
	return writeErr
}

func contextError(parent, bounded context.Context) error {
	if errors.Is(parent.Err(), context.Canceled) {
		return ErrElevationCanceled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return ErrElevationTimedOut
	}
	return ErrElevationCanceled
}

func classifyLaunchError(err error) error {
	if errors.Is(err, windows.ERROR_CANCELLED) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_ELEVATION_REQUIRED) {
		return fmt.Errorf("%w: %v", ErrElevationDenied, err)
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_BAD_EXE_FORMAT) {
		return fmt.Errorf("%w: %v", ErrElevationUnavailable, err)
	}
	return fmt.Errorf("%w: %v", ErrElevationProtocol, err)
}

func currentOwnerSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		if err == nil {
			err = errors.New("current token has no valid user SID")
		}
		return "", err
	}
	return user.User.Sid.String(), nil
}

func validateSID(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("SID is empty")
	}
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() {
		return errors.New("SID is invalid")
	}
	return nil
}

func openBridgeObject(path string, access, creation uint32, directory bool) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_WRITE_THROUGH)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pathPtr, access, bridgeFileShareMode, nil, creation, flags, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func inspectBridgeHandle(handle windows.Handle, directory bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, errors.New("elevation path is a reparse point")
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		return info, errors.New("elevation path is not the expected file type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return info, errors.New("elevation file has multiple hard links")
	}
	return info, nil
}

func finalBridgePath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 256)
	for {
		// The zero flag requests the normalized DOS/UNC volume form.
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		if n == 0 || n >= 32768 {
			return "", errors.New("elevation final path is too long")
		}
		buffer = make([]uint16, n+1)
	}
}

func normalizeBridgePath(path string) string {
	path = filepath.Clean(path)
	if strings.HasPrefix(path, `\\?\UNC\`) {
		path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	} else if strings.HasPrefix(path, `\\?\`) {
		path = strings.TrimPrefix(path, `\\?\`)
	}
	path = strings.TrimRight(path, `\`)
	if len(path) == 2 && path[1] == ':' {
		path += `\`
	}
	return strings.ToLower(path)
}

func expectedBridgePath(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return "", errors.New("elevation path is not absolute")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	input, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetLongPathName(input, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return "", errors.New("elevation canonical path is too long")
	}
	return normalizeBridgePath(windows.UTF16ToString(buffer[:n])), nil
}

func verifyHandleFinalPath(handle windows.Handle, expected string) error {
	actual, err := finalBridgePath(handle)
	if err != nil {
		return err
	}
	want, err := expectedBridgePath(expected)
	if err != nil {
		return err
	}
	if normalizeBridgePath(actual) != want {
		return fmt.Errorf("elevation final path mismatch: got %q want %q", actual, expected)
	}
	return nil
}

func bridgeDirectoryComponents(path string) ([]string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || filepath.VolumeName(clean) == "" {
		return nil, errors.New("elevation directory path is not an absolute Windows path")
	}
	var components []string
	for current := clean; ; current = filepath.Dir(current) {
		components = append(components, current)
		parent := filepath.Dir(current)
		if strings.EqualFold(parent, current) {
			break
		}
	}
	for left, right := 0, len(components)-1; left < right; left, right = left+1, right-1 {
		components[left], components[right] = components[right], components[left]
	}
	return components, nil
}

func openBridgeDirectoryChain(path string, finalAccess uint32) ([]windows.Handle, string, error) {
	components, err := bridgeDirectoryComponents(path)
	if err != nil {
		return nil, "", err
	}
	handles := make([]windows.Handle, 0, len(components))
	closeAll := func() {
		for index := len(handles) - 1; index >= 0; index-- {
			_ = windows.CloseHandle(handles[index])
		}
	}
	for index, component := range components {
		access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE)
		if index == len(components)-1 {
			access = finalAccess
		}
		handle, openErr := openBridgeObject(component, access, windows.OPEN_EXISTING, true)
		if openErr != nil {
			closeAll()
			return nil, "", fmt.Errorf("open protected directory %q: %w", component, openErr)
		}
		if _, inspectErr := inspectBridgeHandle(handle, true); inspectErr != nil {
			_ = windows.CloseHandle(handle)
			closeAll()
			return nil, "", fmt.Errorf("validate protected directory %q: %w", component, inspectErr)
		}
		if pathErr := verifyHandleFinalPath(handle, component); pathErr != nil {
			_ = windows.CloseHandle(handle)
			closeAll()
			return nil, "", fmt.Errorf("validate protected directory %q: %w", component, pathErr)
		}
		handles = append(handles, handle)
	}
	final, err := finalBridgePath(handles[len(handles)-1])
	if err != nil {
		closeAll()
		return nil, "", err
	}
	return handles, normalizeBridgePath(final), nil
}

func openBridgeFile(path string, access uint32) (windows.Handle, error) {
	handle, err := openBridgeObject(path, access, windows.OPEN_EXISTING, false)
	if err != nil {
		return 0, err
	}
	if _, inspectErr := inspectBridgeHandle(handle, false); inspectErr != nil {
		_ = windows.CloseHandle(handle)
		return 0, inspectErr
	}
	if pathErr := verifyHandleFinalPath(handle, path); pathErr != nil {
		_ = windows.CloseHandle(handle)
		return 0, pathErr
	}
	return handle, nil
}

func openBridgeHandles(paths bridgePaths) (*bridgeHandles, error) {
	directories, directoryPath, err := openBridgeDirectoryChain(paths.directory, windows.FILE_GENERIC_READ)
	if err != nil {
		return nil, err
	}
	handles := &bridgeHandles{directories: directories, directory: directories[len(directories)-1], directoryPath: directoryPath}
	closeOnError := func() {
		_ = handles.close()
	}
	for _, item := range []struct {
		path   string
		access uint32
		dest   *windows.Handle
		name   string
	}{{paths.request, windows.FILE_GENERIC_READ, &handles.request, "request.json"}, {paths.result, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE, &handles.result, "result.json"}, {paths.cancel, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE, &handles.cancel, "cancel"}} {
		file, openErr := openBridgeFile(item.path, item.access)
		if openErr != nil {
			closeOnError()
			return nil, fmt.Errorf("open protected %s: %w", item.name, openErr)
		}
		want := directoryPath + `\` + item.name
		if finalErr := verifyHandleFinalPath(file, want); finalErr != nil {
			_ = windows.CloseHandle(file)
			closeOnError()
			return nil, fmt.Errorf("validate protected %s: %w", item.name, finalErr)
		}
		*item.dest = file
	}
	return handles, nil
}

func (h *bridgeHandles) verify(ownerSID string) error {
	if h == nil || h.directory == 0 || h.request == 0 || h.result == 0 || h.cancel == 0 {
		return errors.New("elevation bridge handles are incomplete")
	}
	if err := verifyProtectedACLHandle(h.directory, ownerSID, true); err != nil {
		return fmt.Errorf("protected request directory: %w", err)
	}
	for handle, name := range map[windows.Handle]string{h.request: "request", h.result: "result", h.cancel: "cancel"} {
		if err := verifyProtectedACLHandle(handle, ownerSID, false); err != nil {
			return fmt.Errorf("protected %s file: %w", name, err)
		}
	}
	return nil
}

func validateExecutable(path string) (string, error) {
	validated, handle, err := pinExecutable(path)
	if handle != 0 {
		_ = windows.CloseHandle(handle)
	}
	return validated, err
}

// pinExecutable prevents an unelevated caller from replacing or modifying the
// portable or installed executable between validation and ShellExecuteEx.
// FILE_SHARE_READ still lets Windows map the image, while omission of write
// and delete sharing keeps the validated file identity stable through launch.
func pinExecutable(path string) (string, windows.Handle, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, '\x00') {
		return "", 0, errors.New("elevation executable path is empty or contains NUL")
	}
	abs, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(abs) || filepath.Clean(abs) != abs || !strings.EqualFold(filepath.Ext(abs), ".exe") {
		return "", 0, errors.New("elevation executable path is not a clean absolute .exe path")
	}
	pointer, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", 0, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return "", 0, err
	}
	if _, err := inspectBridgeHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return "", 0, fmt.Errorf("validate elevation executable: %w", err)
	}
	if err := verifyHandleFinalPath(handle, abs); err != nil {
		_ = windows.CloseHandle(handle)
		return "", 0, fmt.Errorf("validate elevation executable identity: %w", err)
	}
	return abs, handle, nil
}

func newBridgeFiles(ownerSID string) (bridgePaths, func(), error) {
	if err := validateSID(ownerSID); err != nil {
		return bridgePaths{}, func() {}, err
	}
	localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if localAppData == "" {
		return bridgePaths{}, func() {}, errors.New("LOCALAPPDATA is unavailable")
	}
	localAppData, err := filepath.Abs(localAppData)
	if err != nil || !filepath.IsAbs(localAppData) || filepath.Clean(localAppData) != localAppData {
		return bridgePaths{}, func() {}, errors.New("LOCALAPPDATA is not a clean absolute path")
	}
	base := filepath.Join(localAppData, "Paperboat", "elevation")
	if err := ensureProtectedDirectory(base, ownerSID); err != nil {
		return bridgePaths{}, func() {}, err
	}
	for attempt := 0; attempt < 8; attempt++ {
		var randomID [16]byte
		if _, err := rand.Read(randomID[:]); err != nil {
			return bridgePaths{}, func() {}, err
		}
		name := "request-" + hex.EncodeToString(randomID[:])
		directory := filepath.Join(base, name)
		if err := os.Mkdir(directory, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return bridgePaths{}, func() {}, err
		}
		cleanup := func() { _ = os.RemoveAll(directory) }
		if err := applyProtectedACL(directory, ownerSID, true); err != nil {
			cleanup()
			return bridgePaths{}, func() {}, err
		}
		paths := bridgePaths{directory: directory, request: filepath.Join(directory, "request.json"), result: filepath.Join(directory, "result.json"), cancel: filepath.Join(directory, "cancel")}
		directories, directoryPath, chainErr := openBridgeDirectoryChain(directory, windows.FILE_GENERIC_READ)
		if chainErr != nil {
			cleanup()
			return bridgePaths{}, func() {}, chainErr
		}
		for _, item := range []struct {
			path string
			name string
		}{{paths.result, "result"}, {paths.cancel, "cancel"}} {
			if placeholderErr := createProtectedPlaceholder(item.path, ownerSID, directoryPath); placeholderErr != nil {
				for index := len(directories) - 1; index >= 0; index-- {
					_ = windows.CloseHandle(directories[index])
				}
				cleanup()
				return bridgePaths{}, func() {}, fmt.Errorf("create protected %s placeholder: %w", item.name, placeholderErr)
			}
		}
		for index := len(directories) - 1; index >= 0; index-- {
			_ = windows.CloseHandle(directories[index])
		}
		return paths, cleanup, nil
	}
	return bridgePaths{}, func() {}, errors.New("could not allocate a unique elevation request directory")
}

func validateBridgePaths(requestPath, resultPath, cancelPath string) (bridgePaths, error) {
	paths := bridgePaths{directory: filepath.Dir(requestPath), request: requestPath, result: resultPath, cancel: cancelPath}
	for _, item := range []struct {
		path string
		name string
	}{{requestPath, "request.json"}, {resultPath, "result.json"}, {cancelPath, "cancel"}} {
		if item.path == "" || strings.ContainsRune(item.path, '\x00') || !filepath.IsAbs(item.path) || filepath.Clean(item.path) != item.path || !strings.EqualFold(filepath.Base(item.path), item.name) {
			return bridgePaths{}, errors.New("elevation file path is invalid")
		}
	}
	if !strings.EqualFold(filepath.Dir(requestPath), filepath.Dir(resultPath)) || !strings.EqualFold(filepath.Dir(requestPath), filepath.Dir(cancelPath)) {
		return bridgePaths{}, errors.New("elevation files must share one directory")
	}
	return paths, nil
}

func ensureProtectedDirectory(path, ownerSID string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == string(os.PathSeparator) || strings.ContainsRune(path, '\x00') {
		return errors.New("elevation directory path is unsafe")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	directories, _, err := openBridgeDirectoryChain(path, windows.FILE_GENERIC_READ|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer func() {
		for index := len(directories) - 1; index >= 0; index-- {
			_ = windows.CloseHandle(directories[index])
		}
	}()
	return applyProtectedACLHandle(directories[len(directories)-1], ownerSID, true)
}

func protectedSDDL(ownerSID string, directory bool) string {
	if ownerSID == "S-1-5-18" {
		if directory {
			return "D:P(A;OICI;FA;;;SY)"
		}
		return "D:P(A;;FA;;;SY)"
	}
	if directory {
		return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ownerSID + ")"
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ownerSID + ")"
}

func applyProtectedACL(path, ownerSID string, directory bool) error {
	if err := validateSID(ownerSID); err != nil {
		return err
	}
	if directory {
		directories, _, err := openBridgeDirectoryChain(path, windows.FILE_GENERIC_READ|windows.WRITE_DAC)
		if err != nil {
			return err
		}
		defer func() {
			for index := len(directories) - 1; index >= 0; index-- {
				_ = windows.CloseHandle(directories[index])
			}
		}()
		return applyProtectedACLHandle(directories[len(directories)-1], ownerSID, true)
	}
	handle, err := openBridgeObject(path, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.WRITE_DAC, windows.OPEN_EXISTING, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if _, err := inspectBridgeHandle(handle, false); err != nil {
		return err
	}
	if err := verifyHandleFinalPath(handle, path); err != nil {
		return err
	}
	return applyProtectedACLHandle(handle, ownerSID, false)
}

func protectedACL(ownerSID string, directory bool) (*windows.ACL, error) {
	if err := validateSID(ownerSID); err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(protectedSDDL(ownerSID, directory))
	if err != nil {
		return nil, err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return nil, err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return nil, err
	}
	return dacl, nil
}

func applyProtectedACLHandle(handle windows.Handle, ownerSID string, directory bool) error {
	dacl, err := protectedACL(ownerSID, directory)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func verifyProtectedDirectory(path, ownerSID string) error {
	return verifyProtectedACL(path, ownerSID, true)
}

func verifyProtectedFile(path, ownerSID string, mustExist bool) error {
	if !mustExist {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	return verifyProtectedACL(path, ownerSID, false)
}

func verifyProtectedACL(path, ownerSID string, directory bool) error {
	var handle windows.Handle
	var err error
	var directories []windows.Handle
	if directory {
		directories, _, err = openBridgeDirectoryChain(path, windows.FILE_GENERIC_READ)
		if err == nil {
			handle = directories[len(directories)-1]
		}
	} else {
		handle, err = openBridgeFile(path, windows.FILE_GENERIC_READ)
	}
	if err != nil {
		return err
	}
	if len(directories) > 0 {
		defer func() {
			for index := len(directories) - 1; index >= 0; index-- {
				_ = windows.CloseHandle(directories[index])
			}
		}()
	} else {
		defer windows.CloseHandle(handle)
	}
	return verifyProtectedACLHandle(handle, ownerSID, directory)
}

func verifyProtectedACLHandle(handle windows.Handle, ownerSID string, directory bool) error {
	if _, err := inspectBridgeHandle(handle, directory); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	wantDescriptor, err := windows.SecurityDescriptorFromString(protectedSDDL(ownerSID, directory))
	if err != nil {
		return err
	}
	want := wantDescriptor.String()
	got := descriptor.String()
	// Windows can mark a DACL as auto-inherited when it is applied. That flag
	// does not grant any access; normalize it before comparing the protected
	// descriptor.
	if strings.HasPrefix(strings.ToUpper(got), "D:PAI(") {
		got = "D:P" + got[len("D:PAI"):]
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("unexpected elevation ACL: got %q want %q", descriptor.String(), want)
	}
	return nil
}

func createProtectedPlaceholder(path, ownerSID, directoryPath string) error {
	handle, err := openBridgeObject(path, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.WRITE_DAC, windows.CREATE_NEW, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if _, err := inspectBridgeHandle(handle, false); err != nil {
		return err
	}
	if err := verifyHandleFinalPath(handle, directoryPath+`\`+filepath.Base(path)); err != nil {
		return err
	}
	if err := applyProtectedACLHandle(handle, ownerSID, false); err != nil {
		return err
	}
	if err := verifyProtectedACLHandle(handle, ownerSID, false); err != nil {
		return err
	}
	return windows.FlushFileBuffers(handle)
}

func writeProtectedJSON(path string, value any, ownerSID string) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > MaxRequestBytes {
		if err == nil {
			err = errors.New("JSON value exceeds elevation request limit")
		}
		return err
	}
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: protectedSDDL(ownerSID, false)}); err != nil {
		return err
	}
	return verifyProtectedFile(path, ownerSID, true)
}

func writeProtectedJSONHandle(handle windows.Handle, value any, limit int64) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("JSON value exceeds elevation size limit")
	}
	return writeHandleBytes(handle, body)
}

func writeResult(path string, request Request, ownerSID string, result Result) error {
	if result.Schema == "" {
		result.Schema = SchemaV1
	}
	if result.RequestID == "" {
		result.RequestID = request.RequestID
	}
	result.ErrorMessage = sanitizeMessage(result.ErrorMessage, 2048)
	if len(result.ErrorCode) > 64 {
		result.ErrorCode = result.ErrorCode[:64]
	}
	handle, err := openBridgeFile(path, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := verifyProtectedACLHandle(handle, ownerSID, false); err != nil {
		return err
	}
	if err := writeResultHandle(handle, request, result); err != nil {
		return err
	}
	return nil
}

func writeResultHandle(handle windows.Handle, request Request, result Result) error {
	if result.Schema == "" {
		result.Schema = SchemaV1
	}
	if result.RequestID == "" {
		result.RequestID = request.RequestID
	}
	result.ErrorMessage = sanitizeMessage(result.ErrorMessage, 2048)
	if len(result.ErrorCode) > 64 {
		result.ErrorCode = result.ErrorCode[:64]
	}
	return writeProtectedJSONHandle(handle, result, MaxResultBytes)
}

func writeCancellation(paths bridgePaths, ownerSID string) error {
	handles, err := openBridgeHandles(paths)
	if err != nil {
		return err
	}
	defer handles.close()
	if err := handles.verify(ownerSID); err != nil {
		return err
	}
	return writeHandleBytes(handles.cancel, []byte("cancelled\n"))
}

func readProtectedRequest(path string) (Request, error) {
	var request Request
	if err := readBoundedJSON(path, MaxRequestBytes, &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func readProtectedResult(paths bridgePaths, ownerSID, requestID string) (Result, error) {
	handles, err := openBridgeHandles(paths)
	if err != nil {
		return Result{}, err
	}
	defer handles.close()
	if err := handles.verify(ownerSID); err != nil {
		return Result{}, err
	}
	var result Result
	if err := readBoundedJSONHandle(handles.result, MaxResultBytes, &result); err != nil {
		return Result{}, err
	}
	if result.Schema != SchemaV1 || result.RequestID != requestID || result.Status == "" || result.Status == statusPending {
		return Result{}, errors.New("elevation result does not match request")
	}
	return result, nil
}

func readBoundedJSON(path string, limit int64, target any) error {
	file, err := openBridgeFile(path, windows.FILE_GENERIC_READ)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(file)
	return readBoundedJSONHandle(file, limit, target)
}

func bridgeHandleSize(handle windows.Handle) (uint64, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, err
	}
	return uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow), nil
}

func readBoundedJSONHandle(handle windows.Handle, limit int64, target any) error {
	if limit < 0 {
		return errors.New("invalid JSON size limit")
	}
	size, err := bridgeHandleSize(handle)
	if err != nil {
		return err
	}
	if size > uint64(limit) {
		return errors.New("JSON file exceeds elevation size limit")
	}
	data := make([]byte, int(size))
	for offset := 0; offset < len(data); {
		var read uint32
		if err := windows.ReadFile(handle, data[offset:], &read, nil); err != nil {
			return err
		}
		if read == 0 {
			return errors.New("short read from protected JSON file")
		}
		offset += int(read)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON file has trailing data")
		}
		return err
	}
	return nil
}

func writeHandleBytes(handle windows.Handle, data []byte) error {
	var high int32
	if _, err := windows.SetFilePointer(handle, 0, &high, windows.FILE_BEGIN); err != nil {
		return err
	}
	if err := windows.SetEndOfFile(handle); err != nil {
		return err
	}
	for len(data) > 0 {
		var written uint32
		if err := windows.WriteFile(handle, data, &written, nil); err != nil {
			return err
		}
		if written == 0 {
			return errors.New("short write to protected elevation file")
		}
		data = data[written:]
	}
	return windows.FlushFileBuffers(handle)
}

func bridgeParameters(paths bridgePaths) string {
	args := []string{"__runtime-service", BridgeCommand, RequestFlagName, paths.request, ResultFlagName, paths.result, CancelFlagName, paths.cancel}
	var builder strings.Builder
	for index, arg := range args {
		if index > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteString(quoteWindowsArgument(arg))
	}
	return builder.String()
}

func quoteWindowsArgument(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\"") {
		return value
	}
	var builder strings.Builder
	builder.WriteByte('"')
	backslashes := 0
	for _, r := range value {
		switch r {
		case '\\':
			backslashes++
		case '"':
			builder.WriteString(strings.Repeat("\\", backslashes*2+1))
			builder.WriteRune(r)
			backslashes = 0
		default:
			if backslashes > 0 {
				builder.WriteString(strings.Repeat("\\", backslashes))
				backslashes = 0
			}
			builder.WriteRune(r)
		}
	}
	if backslashes > 0 {
		builder.WriteString(strings.Repeat("\\", backslashes*2))
	}
	builder.WriteByte('"')
	return builder.String()
}

// createProcessForRun avoids an unnecessary interactive UAC round-trip when
// the caller already owns a full administrator token. This is required for
// elevated SSH, enterprise deployment, repair, and other unattended flows.
func createProcessForRun(executable, parameters, directory string) (windows.Handle, error) {
	commandLine, err := windows.UTF16PtrFromString(quoteWindowsArgument(executable) + " " + parameters)
	if err != nil {
		return 0, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, err
	}
	var startup windows.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var process windows.ProcessInformation
	if err := windows.CreateProcess(nil, commandLine, nil, nil, false, 0, nil, workingDirectory, &startup, &process); err != nil {
		return 0, err
	}
	_ = windows.CloseHandle(process.Thread)
	return process.Process, nil
}

func shellExecuteEx(executable, parameters, directory string) (windows.Handle, error) {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(parameters)
	if err != nil {
		return 0, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: args,
		lpDirectory:  workingDirectory,
		nShow:        windows.SW_HIDE,
	}
	result, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(args)
	runtime.KeepAlive(workingDirectory)
	if result == 0 {
		if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
			callErr = windows.GetLastError()
		}
		if callErr == nil {
			callErr = errors.New("ShellExecuteExW failed")
		}
		return 0, callErr
	}
	if info.hProcess == 0 {
		return 0, errors.New("ShellExecuteExW returned no process handle")
	}
	return info.hProcess, nil
}

func waitForProcessExit(ctx context.Context, handle windows.Handle) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		event, err := windows.WaitForSingleObject(handle, uint32(bridgePollInterval/time.Millisecond))
		if err != nil {
			return err
		}
		switch event {
		case windows.WAIT_OBJECT_0:
			return nil
		case uint32(windows.WAIT_TIMEOUT):
			continue
		default:
			return fmt.Errorf("unexpected process wait result %#x", event)
		}
	}
}

func stopProcess(handle windows.Handle) {
	if handle == 0 {
		return
	}
	_ = terminateProcess(handle, bridgeShutdownCode)
}

func stopProcessAndWait(handle windows.Handle) {
	stopProcess(handle)
	stopCtx, cancel := context.WithTimeout(context.Background(), bridgeCancelGrace)
	defer cancel()
	_ = waitForProcess(stopCtx, handle)
}

func watchCancellation(ctx context.Context, cancel context.CancelFunc, cancelHandle windows.Handle, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(bridgePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			size, err := bridgeHandleSize(cancelHandle)
			if err == nil && size > 0 {
				cancel()
				return
			}
		}
	}
}

func sanitizeMessage(value string, limit int) string {
	if limit < 1 {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		if builder.Len() >= limit {
			break
		}
		if r == '\r' || r == '\n' || unicode.IsControl(r) {
			r = ' '
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

// Keep the package's test seams scoped to Windows. They are reset by tests and
// are deliberately not exposed to production callers.
var bridgeTestMutex sync.Mutex
