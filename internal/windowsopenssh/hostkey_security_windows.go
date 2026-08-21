//go:build windows

package windowsopenssh

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const hostKeySDDL = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"

func protectHostPublicKeyFile(path, ownerSID, serviceSID string) error {
	if ownerSID == "" || serviceSID == "" {
		return errors.New("Windows OpenSSH owner and service SIDs are required")
	}
	if _, err := windows.StringToSid(ownerSID); err != nil {
		return err
	}
	if _, err := windows.StringToSid(serviceSID); err != nil {
		return err
	}
	// The SYSTEM service context can also be the enrolled owner during
	// unattended qualification. Avoid emitting a duplicate SYSTEM read ACE
	// beside the existing SYSTEM full-control ACE; Windows canonicalizes the
	// duplicate differently and exact ACL verification would become unstable.
	ownerACE := "(A;;FR;;;" + ownerSID + ")"
	if systemSID, err := windows.StringToSid("S-1-5-18"); err == nil {
		if owner, err := windows.StringToSid(ownerSID); err == nil && owner.Equals(systemSID) {
			ownerACE = ""
		}
	}
	return protectHostKeyFileWithSDDL(path, hostKeySDDL+"(A;;FR;;;"+serviceSID+")"+ownerACE)
}

func protectHostKeyFiles(paths ...string) error {
	for _, path := range paths {
		if err := protectHostKeyFileWithSDDL(path, hostKeySDDL); err != nil {
			return err
		}
	}
	return verifyHostKeyFiles(paths...)
}

func protectHostKeyFileWithSDDL(path, expectedSDDL string) error {
	descriptor, err := windows.SecurityDescriptorFromString(expectedSDDL)
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
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrUntrustedBinary, statErr)
	}
	attributes, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrUntrustedBinary, attrErr)
	}
	if verifyHostKeyFile(path, expectedSDDL) == nil {
		return nil
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var setOwner, setGroup *windows.SID
	current, currentErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if currentErr != nil {
		return currentErr
	}
	currentOwner, _, ownerErr := current.Owner()
	currentGroup, _, groupErr := current.Group()
	if ownerErr != nil || groupErr != nil {
		return errors.Join(ownerErr, groupErr)
	}
	if !currentOwner.Equals(owner) {
		information |= windows.OWNER_SECURITY_INFORMATION
		setOwner = owner
	}
	if !currentGroup.Equals(group) {
		information |= windows.GROUP_SECURITY_INFORMATION
		setGroup = group
	}
	// Assigning the protected SYSTEM owner is a machine-security operation.
	// Administrator tokens on GitHub-hosted Windows runners have the privilege
	// present but disabled, unlike the LocalSystem service context used on a
	// normal unattended host.
	if err := enableHostKeyPrivileges(); err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, setOwner, setGroup, dacl, nil); err != nil {
		return err
	}
	return verifyHostKeyFile(path, expectedSDDL)
}

func enableHostKeyPrivileges() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token); err != nil {
		return err
	}
	defer token.Close()
	for _, privilegeName := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
		name, err := windows.UTF16PtrFromString(privilegeName)
		if err != nil {
			return err
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
			return err
		}
		privileges := windows.Tokenprivileges{PrivilegeCount: 1}
		privileges.AllPrivileges()[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil); err != nil {
			return err
		}
		if err := windows.GetLastError(); err != windows.ERROR_SUCCESS {
			return err
		}
	}
	return nil
}

func verifyHostKeyFiles(paths ...string) error {
	for _, path := range paths {
		if err := verifyHostKeyFile(path, hostKeySDDL); err != nil {
			return err
		}
	}
	return nil
}

func verifyHostKeyFile(path, expectedSDDL string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrUntrustedBinary, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrUntrustedBinary, err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Windows may retain the informational auto-inherited (AI) control bit
	// after replacing and protecting the DACL. With DACL_PROTECTED set and
	// the exact ACEs below, AI does not permit inherited access.
	actual := strings.Replace(descriptor.String(), "D:PAI", "D:P", 1)
	if actual != expectedSDDL {
		// Include only the path and canonical descriptor. This is safe diagnostic
		// metadata (the descriptor contains SIDs, never key material) and makes
		// native qualification failures actionable instead of opaque.
		return fmt.Errorf("%w: host key ACL for %s (got %s, want %s)", ErrUntrustedBinary, path, actual, expectedSDDL)
	}
	return nil
}
