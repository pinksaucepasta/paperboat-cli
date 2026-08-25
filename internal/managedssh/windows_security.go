//go:build windows

package managedssh

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
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
	return "O:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")"
}

func managedSSHPipeSDDL(sid string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
}

// withManagedSSHOwner keeps same-directory staging files from inheriting an
// elevated token's Administrators default owner. A normal user token already
// has the enrolled user as its default owner and needs no privilege change.
func withManagedSSHOwner(sid string, operation func() error) error {
	owner, err := windows.StringToSid(sid)
	if err != nil || owner == nil || !owner.IsValid() || operation == nil {
		return ErrOpenSSHConfigConflict
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	effectiveOwner, err := currentEffectiveTokenOwnerSID()
	if err != nil {
		return err
	}
	if effectiveOwner == sid {
		return operation()
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || effectiveOwner != administrators.String() {
		return ErrOpenSSHConfigConflict
	}
	return windowssecurity.WithRestorePrivilegeAndOwner(owner, operation)
}

func currentEffectiveTokenOwnerSID() (string, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	}
	if err != nil {
		return "", err
	}
	defer token.Close()
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < uint32(unsafe.Sizeof(uintptr(0))) {
		if err == nil {
			err = windows.ERROR_INVALID_OWNER
		}
		return "", err
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], uint32(len(buffer)), &size); err != nil {
		return "", err
	}
	owner := (*struct{ Owner *windows.SID })(unsafe.Pointer(&buffer[0])).Owner
	if owner == nil || !owner.IsValid() {
		return "", ErrOpenSSHConfigConflict
	}
	value := owner.String()
	runtime.KeepAlive(buffer)
	return value, nil
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
	owner, err := windows.StringToSid(sid)
	if err != nil || owner == nil || !windowssecurity.OwnerMatchesSID(path, owner) || !windowssecurity.ProtectedDACLMatches(path, managedSSHSDDL(sid)) {
		return ErrAuthorizedKeysConflict
	}
	return nil
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
	owner, _, err := absolute.Owner()
	if err != nil || owner == nil {
		return ErrAuthorizedKeysConflict
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

func ensureManagedSSHDirectory(path, sid string) error {
	if err := rejectWindowsReparseAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := withManagedSSHOwner(sid, func() error { return os.MkdirAll(path, 0o700) }); err != nil {
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

// verifyCurrentUserProfileRoot accepts SYSTEM ownership only for the existing
// Windows profile root. Provisioning and profile migration commonly leave
// C:\Users\<name> owned by SYSTEM even though the enrolled user owns .ssh.
// Writable descendants continue through verifyCurrentUserOwnedPath and must be
// owned by the exact current-user SID.
func verifyCurrentUserProfileRoot(path, sid string) error {
	if err := rejectWindowsReparseAncestors(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrOpenSSHConfigConflict
	}
	reparse := windowsReparsePoint(path)
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ErrOpenSSHConfigConflict
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !validWindowsProfileRootState(info.Mode(), reparse, owner.String(), sid) {
		return ErrOpenSSHConfigConflict
	}
	return nil
}

func validWindowsProfileRootState(mode os.FileMode, reparse bool, owner, sid string) bool {
	return mode.IsDir() && mode&os.ModeSymlink == 0 && !reparse && (owner == sid || owner == windowsSystemSID)
}
