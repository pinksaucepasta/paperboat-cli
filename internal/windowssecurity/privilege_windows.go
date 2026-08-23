//go:build windows

package windowssecurity

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WithRestorePrivilege enables SeRestorePrivilege only on a pinned
// self-impersonation thread, restores its exact prior state, and surfaces every
// cleanup failure. A thread that cannot revert is never returned to Go's pool.
func WithRestorePrivilege(operation func() error) (result error) {
	if operation == nil {
		return windows.ERROR_INVALID_PARAMETER
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
