//go:build windows

package windowssecurity

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	restoreImpersonateSelf = windows.ImpersonateSelf
	restoreOpenThreadToken = windows.OpenThreadToken
	restoreRevertToSelf    = windows.RevertToSelf
)

// WithRestorePrivilege enables SeRestorePrivilege only on a pinned thread. It
// reuses an existing thread token so nested security operations cannot destroy
// their caller's impersonation, or creates and later reverts a self-token when
// none exists. It restores the exact prior privilege state and surfaces every
// cleanup failure. A thread that cannot revert is never returned to Go's pool.
func WithRestorePrivilege(operation func() error) (result error) {
	if operation == nil {
		return windows.ERROR_INVALID_PARAMETER
	}
	runtime.LockOSThread()
	createdSelfToken := false
	privilegeRestoreFailed := false
	var token windows.Token
	err := restoreOpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &token)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		if err = restoreImpersonateSelf(windows.SecurityImpersonation); err == nil {
			createdSelfToken = true
			err = restoreOpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &token)
		}
	}
	if err != nil {
		if !createdSelfToken {
			runtime.UnlockOSThread()
			return err
		}
		revertErr := restoreRevertToSelf()
		if revertErr == nil {
			runtime.UnlockOSThread()
		}
		return errors.Join(err, revertErr)
	}
	defer func() {
		revertErr := error(nil)
		if createdSelfToken {
			revertErr = restoreRevertToSelf()
		}
		result = errors.Join(result, revertErr)
		if revertErr == nil && (createdSelfToken || !privilegeRestoreFailed) {
			runtime.UnlockOSThread()
		}
	}()
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
		privilegeRestoreFailed = restoreErr != nil
		result = errors.Join(result, restoreErr)
	}()
	return operation()
}
