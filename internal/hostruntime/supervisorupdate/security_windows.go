//go:build windows

package supervisorupdate

import (
	"errors"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func supervisorFileIsSecure(path string, info os.FileInfo) bool {
	if !supervisorFileIsUsable(path, info) || !windowsPathIsNotReparse(path) {
		return false
	}
	want, err := currentSupervisorFileDescriptor()
	return err == nil && windowssecurity.ProtectedDACLMatches(path, want.String())
}

func supervisorFileIsUsable(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && windowsPathIsNotReparse(path)
}

func supervisorDirectoryIsSecure(path string, info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !windowsPathIsNotReparse(path) {
		return false
	}
	want, err := currentSupervisorDirectoryDescriptor()
	return err == nil && windowssecurity.ProtectedDACLMatches(path, want.String())
}

func setSupervisorDirectoryOwner(_ string, _, _ int) error { return nil }

func prepareSupervisorArtifact(path string, _ *os.File, _, _ int) error {
	return applySupervisorDescriptor(path, false)
}

func windowsPathIsNotReparse(path string) bool {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func currentSupervisorFileDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentSupervisorSID()
	if err != nil {
		return nil, err
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if sid != "S-1-5-18" {
		sddl += "(A;;FA;;;" + sid + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

func currentSupervisorDirectoryDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentSupervisorSID()
	if err != nil {
		return nil, err
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if sid != "S-1-5-18" {
		sddl += "(A;OICI;FA;;;" + sid + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

func currentSupervisorSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		if err == nil {
			err = errors.New("current Windows token has no valid user SID")
		}
		return "", err
	}
	return user.User.Sid.String(), nil
}

func applySupervisorDescriptor(path string, directory bool) error {
	var descriptor *windows.SECURITY_DESCRIPTOR
	var err error
	if directory {
		descriptor, err = currentSupervisorDirectoryDescriptor()
	} else {
		descriptor, err = currentSupervisorFileDescriptor()
	}
	if err != nil {
		return err
	}
	abs, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := abs.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
