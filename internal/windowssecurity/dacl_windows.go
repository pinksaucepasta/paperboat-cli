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

// OwnerMatchesSID rejects attacker-owned filesystem objects even when their
// current DACL text matches the expected protected ACL. A Windows owner can
// restore WRITE_DAC and replace a machine-scope DPAPI credential later.
func OwnerMatchesSID(path string, expected *windows.SID) bool {
	if expected == nil || !expected.IsValid() {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	return err == nil && owner != nil && owner.Equals(expected)
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
	body := value[start+open:]
	var result strings.Builder
	seen := make(map[string]struct{})
	for len(body) > 0 {
		begin := strings.IndexByte(body, '(')
		if begin < 0 {
			break
		}
		end := strings.IndexByte(body[begin:], ')')
		if end < 0 {
			return ""
		}
		ace := body[begin : begin+end+1]
		ace = strings.ReplaceAll(ace, "S-1-5-18", "SY")
		if _, ok := seen[ace]; !ok {
			seen[ace] = struct{}{}
			result.WriteString(ace)
		}
		body = body[begin+end+1:]
	}
	return "D:" + result.String()
}
