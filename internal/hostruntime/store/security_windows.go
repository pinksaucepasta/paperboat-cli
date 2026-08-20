//go:build windows

package store

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func secureStoreDirectory(path string) error { return secureStoreObject(path, true) }
func secureStoreFile(path string) error      { return secureStoreObject(path, false) }

func secureStoreObject(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || directory != info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrCorrupt
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrCorrupt
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return errors.New("Windows store owner SID is unavailable")
	}
	aceFlags := ""
	if directory {
		aceFlags = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;" + aceFlags + ";FA;;;SY)(A;" + aceFlags + ";FA;;;BA)(A;" + aceFlags + ";FA;;;" + user.User.Sid.String() + ")")
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
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
