//go:build windows

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestWriteDefaultDescriptorAllowsOwnerAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, body := range []string{"first\n", "second\n"} {
		if err := Write(path, []byte(body), Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != body {
			t.Fatalf("contents=%q err=%v", contents, err)
		}
	}
}

func TestWriteAppliesExplicitOwnerBeforeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-state.json")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal(err)
	}
	descriptor := "O:" + user.User.Sid.String() + "D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")"
	if err := Write(path, []byte("protected\n"), Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: descriptor}); err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.OwnerMatchesSID(path, user.User.Sid) {
		t.Fatal("atomic replacement did not retain the explicit trusted owner")
	}
	if !windowssecurity.ProtectedDACLMatches(path, descriptor) {
		t.Fatal("atomic replacement did not retain the explicit protected DACL")
	}
}

func TestWriteTransfersTrustedCreationOwnerToSystemBeforeReplacement(t *testing.T) {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	member, err := windows.GetCurrentProcessToken().IsMember(administrators)
	if err != nil || !member {
		t.Skip("SYSTEM-owner atomic replacement requires an elevated administrator")
	}
	path := filepath.Join(t.TempDir(), "machine-state.json")
	descriptor := "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if err := Write(path, []byte("protected\n"), Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: descriptor}); err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.OwnerMatchesSID(path, system) {
		t.Fatal("atomic replacement did not transfer its trusted creation owner to SYSTEM")
	}
	if !windowssecurity.ProtectedDACLMatches(path, descriptor) {
		t.Fatal("atomic replacement did not retain the explicit protected DACL")
	}
}
