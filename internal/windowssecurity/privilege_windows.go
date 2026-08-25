//go:build windows

package windowssecurity

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	terminateTokenLeak = func(error) {
		if windows.TerminateProcess(windows.CurrentProcess(), 127) != nil {
			os.Exit(127)
		}
		os.Exit(127)
	}
)

// WithRestorePrivilege enables SeRestorePrivilege only on an isolated duplicate
// of the pinned thread's effective token. The source token is never modified.
// Nested calls restore their caller's exact impersonation, and a thread that
// cannot be restored is never returned to Go's pool.
func WithRestorePrivilege(operation func() error) (result error) {
	return withIsolatedRestorePrivilege(nil, operation)
}

// WithRestorePrivilegeAndOwner runs operation with SeRestorePrivilege enabled
// and an exact default owner on a pinned thread token. Windows can otherwise
// ignore an explicit owner in SECURITY_ATTRIBUTES and substitute the token's
// default owner during filesystem object creation.
func WithRestorePrivilegeAndOwner(owner *windows.SID, operation func() error) (result error) {
	if owner == nil || !owner.IsValid() || operation == nil {
		return windows.ERROR_INVALID_SID
	}
	return withIsolatedRestorePrivilege(owner, operation)
}

func withIsolatedRestorePrivilege(owner *windows.SID, operation func() error) (result error) {
	if operation == nil {
		return windows.ERROR_INVALID_PARAMETER
	}
	runtime.LockOSThread()
	var source windows.Token
	hadThreadToken := true
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, false, &source)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		hadThreadToken = false
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &source)
	}
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	var isolated windows.Token
	err = windows.DuplicateTokenEx(source, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &isolated)
	if err != nil {
		closeErr := source.Close()
		runtime.UnlockOSThread()
		return errors.Join(err, closeErr)
	}
	if err = windows.SetThreadToken(nil, isolated); err != nil {
		closeErr := errors.Join(isolated.Close(), source.Close())
		runtime.UnlockOSThread()
		return errors.Join(err, closeErr)
	}
	defer func() {
		restoreErr := error(nil)
		if hadThreadToken {
			restoreErr = windows.SetThreadToken(nil, source)
			if restoreErr != nil {
				// Reverting would silently replace the caller's exact restricted or
				// impersonated identity with the process token. Never return this OS
				// thread to Go unless the original token was restored exactly.
				terminateTokenLeak(restoreErr)
				return
			}
		} else {
			restoreErr = windows.RevertToSelf()
			if restoreErr != nil {
				terminateTokenLeak(restoreErr)
				return
			}
		}
		cleanupErr := errors.Join(restoreErr, isolated.Close(), source.Close())
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
		runtime.UnlockOSThread()
	}()
	if err := enableRestorePrivilege(isolated); err != nil {
		return err
	}
	if owner != nil {
		requested := tokenOwner{Owner: owner}
		if err := windows.SetTokenInformation(isolated, windows.TokenOwner, (*byte)(unsafe.Pointer(&requested)), uint32(unsafe.Sizeof(requested))); err != nil {
			runtime.KeepAlive(owner)
			return err
		}
		runtime.KeepAlive(owner)
		actualBuffer, actualOwner, err := tokenOwnerInformation(isolated)
		if err != nil || actualOwner == nil || !actualOwner.Equals(owner) {
			if err == nil {
				err = windows.ERROR_INVALID_OWNER
			}
			return err
		}
		runtime.KeepAlive(actualBuffer)
	}
	result = operation()
	return result
}

type tokenOwner struct {
	Owner *windows.SID
}

func enableRestorePrivilege(token windows.Token) error {
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
	if err := windows.AdjustTokenPrivileges(token, false, &desired, 0, nil, nil); err != nil {
		return err
	}
	if lastErr := windows.GetLastError(); lastErr != windows.ERROR_SUCCESS {
		return lastErr
	}
	return nil
}

func tokenOwnerInformation(token windows.Token) ([]byte, *windows.SID, error) {
	var length uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &length)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || length < uint32(unsafe.Sizeof(tokenOwner{})) {
		if err == nil {
			err = windows.ERROR_INVALID_OWNER
		}
		return nil, nil, err
	}
	buffer := make([]byte, length)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], uint32(len(buffer)), &length); err != nil {
		return nil, nil, err
	}
	owner := (*tokenOwner)(unsafe.Pointer(&buffer[0])).Owner
	if owner == nil || !owner.IsValid() {
		return nil, nil, windows.ERROR_INVALID_OWNER
	}
	return buffer, owner, nil
}
