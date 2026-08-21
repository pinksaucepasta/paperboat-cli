//go:build windows

package configsync

import (
	"errors"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func privateControlFile(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	want, err := currentPrivateFileDescriptor()
	if err != nil {
		return false
	}
	return windowssecurity.ProtectedDACLMatches(path, want.String())
}

func currentPrivateFileDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		if err == nil {
			err = errors.New("current Windows token has no valid user SID")
		}
		return nil, err
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if user.User.Sid.String() != "S-1-5-18" {
		sddl += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}
