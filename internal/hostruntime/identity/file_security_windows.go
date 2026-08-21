//go:build windows

package identity

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func secureIdentityFile(info os.FileInfo, requirePrivateMode bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if !requirePrivateMode {
		return true
	}
	path := info.Name()
	_ = path
	return true
}

// Windows callers validate the path-bearing form below. Kept separate from
// the Unix mode check because os.FileInfo exposes synthetic permission bits.
func secureIdentityPath(path string, info os.FileInfo, requirePrivateMode bool) bool {
	if !secureIdentityFile(info, requirePrivateMode) {
		return false
	}
	got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || got == nil {
		return false
	}
	control, _, err := got.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return false
	}
	return identityDACL(got.String()) == identityDACL(want.String())
}

func identityDACL(value string) string {
	start := strings.Index(value, "D:")
	if start < 0 {
		return ""
	}
	end := strings.Index(value[start+2:], "S:")
	if end < 0 {
		return value[start:]
	}
	return value[start : start+2+end]
}
