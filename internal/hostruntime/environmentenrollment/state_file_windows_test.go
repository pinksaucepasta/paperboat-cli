//go:build windows

package environmentenrollment

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestSecureStateFileAcceptsAtomicFileProtectedWindowsACLRegardlessOfMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.json")
	if err := atomicfile.Write(path, []byte("opaque-state"), atomicfile.Options{Mode: 0o666, OwnerUID: -1, OwnerGID: -1}); err != nil {
		t.Fatalf("write protected state atomically: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	want := currentEnvironmentEnrollmentStateDACL(t)
	if !windowssecurity.ProtectedDACLMatches(path, want) {
		t.Fatalf("atomic writer did not produce the expected protected current-user/SYSTEM/Administrators DACL: %q", want)
	}
	if !secureStateFile(path, info, 4096) {
		t.Fatalf("secureStateFile rejected an atomic protected state file (reported mode %o)", info.Mode().Perm())
	}
}

func TestSecureStateFileRejectsForeignAndUnprotectedWindowsACLs(t *testing.T) {
	trusted := currentEnvironmentEnrollmentStateDACL(t)
	withoutProtection := trusted[2:]
	for _, test := range []struct {
		name       string
		descriptor string
		protected  bool
	}{
		{name: "foreign protected", descriptor: "D:P(A;;FA;;;WD)", protected: true},
		{name: "trusted entries but unprotected", descriptor: withoutProtection, protected: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enrollment.json")
			if err := atomicfile.Write(path, []byte("opaque-state"), atomicfile.Options{Mode: 0o666, OwnerUID: -1, OwnerGID: -1}); err != nil {
				t.Fatalf("write initial state atomically: %v", err)
			}
			setEnvironmentEnrollmentStateDACL(t, path, test.descriptor, test.protected)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if secureStateFile(path, info, 4096) {
				t.Fatalf("secureStateFile accepted %s ACL", test.name)
			}
		})
	}
}

func currentEnvironmentEnrollmentStateDACL(t *testing.T) string {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		t.Fatalf("resolve current Windows SID: %v", err)
	}
	descriptor := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if user.User.Sid.String() != "S-1-5-18" {
		descriptor += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	return descriptor
}

func setEnvironmentEnrollmentStateDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse fixture ACL %q: %v", sddl, err)
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		t.Fatalf("make fixture ACL absolute: %v", err)
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		t.Fatalf("extract fixture DACL: %v", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		securityInformation = windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInformation, nil, nil, dacl, nil); err != nil {
		t.Fatalf("apply fixture ACL %q: %v", sddl, err)
	}
	runtime.KeepAlive(absolute)
}
