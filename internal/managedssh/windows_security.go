//go:build windows

package managedssh

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const windowsSystemSID = "S-1-5-18"

func currentManagedSSHSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", ErrAgentDenied
	}
	return user.User.Sid.String(), nil
}

func managedSSHSDDL(sid string) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")"
}

func managedSSHPipeSDDL(sid string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
}

func rejectWindowsReparseAncestors(path string) error {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		return errors.New("managed SSH path must be an absolute Windows path")
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("managed SSH path escapes its volume")
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || windowsReparsePoint(current) {
			return errors.New("managed SSH path contains a reparse point")
		}
	}
	return nil
}

func windowsReparsePoint(path string) bool {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func verifyManagedSSHACL(path, sid string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return ErrAuthorizedKeysConflict
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrAuthorizedKeysConflict
	}
	expected, err := windows.SecurityDescriptorFromString(managedSSHSDDL(sid))
	if err != nil || managedSSHDACL(descriptor.String()) != managedSSHDACL(expected.String()) {
		return ErrAuthorizedKeysConflict
	}
	return nil
}

func managedSSHDACL(value string) string {
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

func applyManagedSSHACL(path, sid string) error {
	descriptor, err := windows.SecurityDescriptorFromString(managedSSHSDDL(sid))
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

func ensureManagedSSHDirectory(path, sid string) error {
	if err := rejectWindowsReparseAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := rejectWindowsReparseAncestors(path); err != nil {
		return err
	}
	if err := applyManagedSSHACL(path, sid); err != nil {
		return fmt.Errorf("protect managed SSH directory: %w", err)
	}
	return verifyManagedSSHACL(path, sid)
}

func verifyCurrentUserOwnedPath(path, sid string, requireDirectory bool) error {
	if err := rejectWindowsReparseAncestors(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (requireDirectory && !info.IsDir()) || (!requireDirectory && !info.Mode().IsRegular()) || windowsReparsePoint(path) {
		return ErrOpenSSHConfigConflict
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ErrOpenSSHConfigConflict
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || owner.String() != sid {
		return ErrOpenSSHConfigConflict
	}
	return nil
}
