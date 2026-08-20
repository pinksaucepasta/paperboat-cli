//go:build windows

package inbox

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, errors.New("cannot resolve current Windows user SID")
	}
	return user.User.Sid, nil
}

func inboxSDDL(sid *windows.SID) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid.String() + ")"
}

func secureInboxPath(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(inboxSDDL(sid))
	if err != nil {
		return err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sid, nil, dacl, nil)
}

func validateInboxPath(path string, _ os.FileInfo) error {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("inbox path must not be a reparse point")
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("inbox path has an invalid Windows security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		return errors.New("inbox path must be owned by the current user")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("inbox path must have a protected Windows ACL")
	}
	want, err := windows.SecurityDescriptorFromString(inboxSDDL(sid))
	if err != nil || inboxDACL(descriptor.String()) != inboxDACL(want.String()) {
		return errors.New("inbox path ACL grants access outside the current user and SYSTEM")
	}
	return nil
}

func inboxDACL(value string) string {
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
