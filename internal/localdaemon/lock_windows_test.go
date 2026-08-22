//go:build windows

package localdaemon

import (
	"os"
	"path/filepath"
	"testing"

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
