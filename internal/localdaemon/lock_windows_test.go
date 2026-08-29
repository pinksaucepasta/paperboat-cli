//go:build windows

package localdaemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestVerifyWindowsLockACLAcceptsProtectedDACLSerialization(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current SID: %v", err)
	}
	path := filepath.Join(t.TempDir(), "daemon.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsLockACL(path, user.User.Sid.String()); err != nil {
		t.Fatalf("set protected lock DACL: %v", err)
	}
	if err := verifyWindowsLockACL(path, user.User.Sid.String()); err != nil {
		t.Fatalf("verify semantically identical protected lock DACL: %v", err)
	}
}

func TestPrepareWindowsOwnerStateRebindsExistingTreeToPermanentOwner(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current SID: %v", err)
	}
	ownerSID := user.User.Sid.String()
	root := filepath.Join(t.TempDir(), "state")
	if err := PrepareWindowsOwnerState(root, ownerSID); err != nil {
		if errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("repairing another Windows service owner requires LocalSystem restore privilege: %v", err)
		}
		t.Fatalf("prepare owner state: %v", err)
	}
	if !windowssecurity.OwnerMatchesSID(root, user.User.Sid) || !windowssecurity.ProtectedDACLMatches(root, windowsOwnerStateDirectorySDDL(ownerSID)) {
		t.Fatal("state directory was not rebound to the permanent owner")
	}
}
