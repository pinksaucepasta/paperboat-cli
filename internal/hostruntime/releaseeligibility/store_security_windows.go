//go:build windows

package releaseeligibility

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

// The deferral record is updater-owned state. It is deliberately machine
// scoped: LocalSystem owns it and only LocalSystem and Administrators receive
// full control. Both directory and record ACLs are protected from inheritance
// so an untrusted parent cannot grant access after validation.
const (
	windowsEligibilityDirectoryDACL = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	windowsEligibilityRecordDACL    = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// createTemporaryFile creates the staging object with the final protected
// security descriptor in CreateFileW. Using os.CreateTemp here would leave a
// race in which a different local principal could read or replace the record
// before a subsequent ACL call.
func createTemporaryFile(directory, base string) (*os.File, string, error) {
	descriptor, err := windows.SecurityDescriptorFromString(windowsEligibilityRecordDACL)
	if err != nil {
		return nil, "", err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for attempt := 0; attempt < 16; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", err
		}
		path := filepath.Join(directory, "."+base+".tmp-"+hex.EncodeToString(random))
		pathUTF16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, "", err
		}
		handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		runtime.KeepAlive(descriptor)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			_ = windows.CloseHandle(handle)
			_ = os.Remove(path)
			return nil, "", ErrUnsafePath
		}
		return file, path, nil
	}
	return nil, "", windows.ERROR_FILE_EXISTS
}

func validateParentSecurity(path string, _ os.FileInfo) error {
	if !windowsRealDirectory(path) {
		return ErrUnsafePath
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || !windowssecurity.OwnerMatchesSID(path, system) || !windowssecurity.ProtectedDACLMatches(path, windowsEligibilityDirectoryDACL) {
		return ErrUnsafePath
	}
	return nil
}

func validateRecordSecurity(path string, info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	return validateRecordPath(path)
}

// secureRecordFile applies the protected owner and DACL to both staging and
// final names. It is called before bytes are written and after replacement, so
// os.CreateTemp never exposes an unprotected deferral payload.
func secureRecordFile(path string) error {
	if !windowsRealFile(path) {
		return ErrUnsafePath
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsEligibilityRecordDACL)
	if err != nil {
		return ErrUnsafePath
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return ErrUnsafePath
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return ErrUnsafePath
	}
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, system, nil, dacl, nil)
	}); err != nil {
		return ErrUnsafePath
	}
	if !windowssecurity.OwnerMatchesSID(path, system) || !windowssecurity.ProtectedDACLMatches(path, windowsEligibilityRecordDACL) {
		return ErrUnsafePath
	}
	return nil
}

func windowsRealDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func windowsRealFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// validateRecordPath performs the path-dependent Windows owner/DACL check.
// It exists separately from validateRecordSecurity because os.FileInfo does
// not retain its full path.
func validateRecordPath(path string) error {
	if !windowsRealFile(path) {
		return ErrUnsafePath
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || !windowssecurity.OwnerMatchesSID(path, system) || !windowssecurity.ProtectedDACLMatches(path, windowsEligibilityRecordDACL) {
		return ErrUnsafePath
	}
	return nil
}
