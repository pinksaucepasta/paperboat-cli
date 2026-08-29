//go:build windows

package localdaemon

import (
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

func TestEnsureWindowsLockParentReplacesSessionScopedDirectoryDACL(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current SID: %v", err)
	}
	ownerSID := user.User.Sid.String()
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsLockACL(root, ownerSID); err != nil {
		t.Fatalf("set non-inheritable session-style DACL: %v", err)
	}
	if err := ensureWindowsLockParent(root, ownerSID); err != nil {
		t.Fatalf("repair lock parent: %v", err)
	}
	if !windowssecurity.ProtectedDACLMatches(root, windowsOwnerStateDirectorySDDL(ownerSID)) {
		t.Fatal("lock parent was not rebound to the permanent inheritable DACL")
	}
	child := filepath.Join(root, "daemon.lock.owner.json.new")
	if err := os.WriteFile(child, []byte("owner"), 0o600); err != nil {
		t.Fatalf("create owner record after DACL repair: %v", err)
	}
}
