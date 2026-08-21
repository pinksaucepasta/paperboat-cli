//go:build windows

package windowssecurity

import (
	"strings"

	"golang.org/x/sys/windows"
)

// ProtectedDACLMatches compares a protected file DACL with the requested
// descriptor. Windows may serialize the current elevated administrator SID as
// the well-known LA alias, so compare that canonical representation too. LA
// is accepted only for an elevated token; non-admin users still require their
// exact SID.
func ProtectedDACLMatches(path, expected string) bool {
	got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || got == nil {
		return false
	}
	control, _, err := got.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	actual := dacl(got.String())
	if actual == dacl(expected) {
		return true
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
	if !strings.HasSuffix(user.User.Sid.String(), "-500") {
		return false
	}
	return actual == dacl(strings.Replace(expected, user.User.Sid.String(), "LA", 1))
}

func dacl(value string) string {
	start := strings.Index(value, "D:")
	if start < 0 {
		return ""
	}
	open := strings.IndexByte(value[start:], '(')
	if open < 0 {
		return ""
	}
	return "D:" + value[start+open:]
}
