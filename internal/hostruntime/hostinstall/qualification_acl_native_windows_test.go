//go:build windows && paperboat_native_e2e

package hostinstall

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestNativeApplyQualificationRuntimeCurrentACL is a narrow helper invoked by
// the Windows qualification harness. It deliberately uses the same native
// restore-privilege and SetNamedSecurityInfo path as production installation,
// rather than relying on PowerShell's ambient token privileges.
func TestNativeApplyQualificationRuntimeCurrentACL(t *testing.T) {
	path := os.Getenv("PAPERBOAT_WINDOWS_E2E_ACL_PATH")
	if path == "" {
		t.Skip("qualification ACL helper path is not configured")
	}
	if !isAdministrator() {
		t.Fatal("runtime-current ACL qualification requires an elevated Windows runner")
	}
	qualificationSID := os.Getenv("PAPERBOAT_WINDOWS_E2E_ACL_SID")
	qualification, err := windows.StringToSid(qualificationSID)
	if err != nil || qualification == nil || !qualification.IsValid() {
		t.Fatalf("invalid qualification SID %q: %v", qualificationSID, err)
	}
	owner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		t.Fatalf("resolve LocalSystem owner: %v", err)
	}
	directory := os.Getenv("PAPERBOAT_WINDOWS_E2E_ACL_DIRECTORY") == "1"
	access := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + qualificationSID + ")"
	if directory {
		access = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + qualificationSID + ")"
	}
	if err := applyWindowsOwnedDACL(path, owner, access); err != nil {
		t.Fatalf("apply production runtime-current ACL: %v", err)
	}
	if !windowsRuntimeSecurityMatches(path, owner, access) {
		t.Fatalf("production runtime-current ACL did not match expected owner and protected DACL: %s", path)
	}
}
