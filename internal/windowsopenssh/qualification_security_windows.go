//go:build windows

package windowsopenssh

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

type qualificationSecurity string

func validateQualificationFile(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("qualification file is not a regular file")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("qualification file is a reparse point")
	}
	return nil
}

func captureQualificationSecurity(path string, exists bool) (qualificationSecurity, error) {
	if !exists {
		return "", nil
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	sddl := descriptor.String()
	if sddl == "" {
		return "", errors.New("empty qualification security descriptor")
	}
	return qualificationSecurity(sddl), nil
}

func restoreQualificationSecurity(path string, security qualificationSecurity) error {
	if security == "" {
		return nil
	}
	descriptor, err := windows.SecurityDescriptorFromString(string(security))
	if err != nil {
		return err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	owner, _, err := absolute.Owner()
	if err != nil {
		return err
	}
	group, _, err := absolute.Group()
	if err != nil {
		return err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, owner, group, dacl, nil)
}

func lstatQualificationFile(path string) (os.FileInfo, error) { return os.Lstat(path) }
func isQualificationNotExist(err error) bool                  { return errors.Is(err, os.ErrNotExist) }
