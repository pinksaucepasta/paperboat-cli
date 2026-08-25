//go:build windows

package launcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestWindowsLauncherRejectsForeignOwnedExecutableWithExactDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pb.slot-hostile.exe")
	if err := os.WriteFile(path, []byte("MZ hostile fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLauncherTestForeignOwnerDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePlatformTarget(path, info); err == nil {
		t.Fatal("foreign-owned executable with an exact DACL was trusted")
	}
}

func TestWindowsLauncherRejectsForeignOwnedActivePointerWithExactDACL(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "pb.exe")
	active := filepath.Join(directory, "pb.active")
	if err := os.WriteFile(active, []byte("pb.slot-hostile.exe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLauncherTestForeignOwnerDACL(t, active, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	if _, err := resolveTargetPath(path); err == nil {
		t.Fatal("foreign-owned active pointer with an exact DACL was trusted")
	}
}

func setLauncherTestForeignOwnerDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, foreignOwner, nil, dacl, nil)
	}); err != nil {
		t.Fatal(err)
	}
}
