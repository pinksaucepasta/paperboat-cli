//go:build windows

package bootstrap

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func secureEnrollmentTokenFile(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 512 || !windowsHasSingleLink(path) {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	sddl := "D:P(A;;FA;;;SY)"
	if user.User.Sid.String() != "S-1-5-18" {
		sddl += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	want, err := windows.SecurityDescriptorFromString(sddl)
	return err == nil && tokenFileDACL(descriptor.String()) == tokenFileDACL(want.String())
}

func tokenFileDACL(value string) string {
	index := strings.Index(value, "D:")
	if index < 0 {
		return ""
	}
	open := strings.IndexByte(value[index:], '(')
	if open < 0 {
		return ""
	}
	return "D:" + value[index+open:]
}
