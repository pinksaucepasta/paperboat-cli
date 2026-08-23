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

func TestWithRestorePrivilegeRevertsWhenOpeningSelfTokenFails(t *testing.T) {
	previousImpersonate := restoreImpersonateSelf
	previousOpen := restoreOpenThreadToken
	previousRevert := restoreRevertToSelf
	t.Cleanup(func() {
		restoreImpersonateSelf = previousImpersonate
		restoreOpenThreadToken = previousOpen
		restoreRevertToSelf = previousRevert
	})
	openCalls := 0
	reverted := false
	restoreImpersonateSelf = func(uint32) error { return nil }
	restoreOpenThreadToken = func(windows.Handle, uint32, bool, *windows.Token) error {
		openCalls++
		if openCalls == 1 {
			return windows.ERROR_NO_TOKEN
		}
		return windows.ERROR_ACCESS_DENIED
	}
	restoreRevertToSelf = func() error {
		reverted = true
		return nil
	}
	if err := WithRestorePrivilege(func() error { return nil }); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reverted {
		t.Fatal("failed self-token open did not revert impersonation")
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
