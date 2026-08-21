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
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := token.IsMember(adminSID)
	if err != nil || !member {
		return false
	}
	return actual == dacl(strings.Replace(expected, user.User.Sid.String(), "LA", 1))
}

func dacl(value string) string {
	start := strings.Index(value, "D:")
	if start < 0 {
		return ""
	}
	end := strings.Index(value[start+2:], "S:")
	if end < 0 {
		return value[start:]
	}
	value = value[start : start+2+end]
	return strings.Replace(value, "D:P", "D:", 1)
}
