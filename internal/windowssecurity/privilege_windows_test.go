//go:build windows

package windowssecurity

import (
	"errors"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWithRestorePrivilegeNestedPreservesOuterToken(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var existing windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &existing); err == nil {
		existing.Close()
		t.Skip("test requires a thread without pre-existing impersonation")
	} else if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		t.Fatal(err)
	}
	if err := WithRestorePrivilege(func() error {
		return WithRestorePrivilege(func() error {
			var token windows.Token
			if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token); err != nil {
				return err
			}
			return token.Close()
		})
	}); err != nil {
		t.Fatal(err)
	}
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token); !errors.Is(err, windows.ERROR_NO_TOKEN) {
		if err == nil {
			token.Close()
		}
		t.Fatalf("nested restore-privilege scope leaked its self-token: %v", err)
	}
}

func TestWithRestorePrivilegePreservesExistingTokenAndPrivilegeState(t *testing.T) {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Errorf("revert test impersonation: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	beforeToken, beforeEnabled := restorePrivilegeState(t)
	beforeToken.Close()
	if err := WithRestorePrivilege(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	afterToken, afterEnabled := restorePrivilegeState(t)
	afterToken.Close()
	if beforeEnabled != afterEnabled {
		t.Fatalf("SeRestorePrivilege state changed across scope: before=%t after=%t", beforeEnabled, afterEnabled)
	}
}

func TestWithRestorePrivilegeAndOwnerRestoresExistingTokenOwner(t *testing.T) {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Errorf("revert test impersonation: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	beforeBuffer, beforeOwner, err := tokenOwnerInformation(token)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if !tokenHasOwnerGroup(token, administrators) {
		t.Skip("test token cannot use Administrators as its default owner")
	}
	if err := WithRestorePrivilegeAndOwner(administrators, func() error {
		currentBuffer, currentOwner, err := tokenOwnerInformation(windows.GetCurrentThreadEffectiveToken())
		defer runtime.KeepAlive(currentBuffer)
		if err != nil {
			return err
		}
		if !currentOwner.Equals(administrators) {
			return windows.ERROR_INVALID_OWNER
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	afterBuffer, afterOwner, err := tokenOwnerInformation(token)
	if err != nil {
		t.Fatal(err)
	}
	if !afterOwner.Equals(beforeOwner) {
		t.Fatal("default token owner was not restored")
	}
	runtime.KeepAlive(beforeBuffer)
	runtime.KeepAlive(afterBuffer)
}

func tokenHasOwnerGroup(token windows.Token, wanted *windows.SID) bool {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Sid.Equals(wanted) && group.Attributes&windows.SE_GROUP_OWNER != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}

func restorePrivilegeState(t *testing.T) (windows.Token, bool) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		t.Fatal(err)
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		t.Fatal(err)
	}
	var length uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &length)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || length == 0 {
		t.Fatal(err)
	}
	buffer := make([]byte, length)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], uint32(len(buffer)), &length); err != nil {
		t.Fatal(err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid == luid {
			return token, privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0
		}
	}
	token.Close()
	t.Fatal("thread token has no SeRestorePrivilege")
	return 0, false
}
