//go:build windows

package bootstrap

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrArtifactTarget
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrArtifactTarget
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return ErrArtifactTarget
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	abs, err := want.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := abs.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		return err
	}
	got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || got == nil || !got.IsValid() {
		return ErrArtifactTarget
	}
	owner, _, err := got.Owner()
	control, _, controlErr := got.Control()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) || controlErr != nil || control&windows.SE_DACL_PROTECTED == 0 || directoryDACL(got.String()) != directoryDACL(want.String()) {
		return ErrArtifactTarget
	}
	return nil
}

func directoryDACL(value string) string {
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
