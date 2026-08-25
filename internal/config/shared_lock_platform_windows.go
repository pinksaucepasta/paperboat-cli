//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

// Windows does not reliably use the SID named by a SECURITY_DESCRIPTOR as the
// filesystem owner's default when the effective token is an elevated or SSH
// network token. Shared-lock directories are therefore created with an
// explicit descriptor and an isolated token whose default owner is the stable
// interactive user SID.
func prepareSharedLockParent(path string) error {
	path, err := filepath.Abs(filepath.Clean(path))
	if err != nil || path == "." {
		return fmt.Errorf("prepare shared lock parent: %w", ErrCredentialStoreUnavailable)
	}
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return secureExistingSharedLockDirectory(path, owner)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	missing := make([]string, 0, 4)
	boundary := path
	for {
		_, statErr := os.Lstat(boundary)
		if statErr == nil {
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		parent := filepath.Dir(boundary)
		if parent == boundary {
			return fmt.Errorf("prepare shared lock parent %s: missing trusted ancestor", path)
		}
		missing = append(missing, boundary)
		boundary = parent
	}
	if err := validateSharedLockBoundary(boundary, owner); err != nil {
		return err
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := createSharedLockDirectory(missing[index]); err != nil {
			if !os.IsExist(err) {
				return err
			}
			if err := validateSharedLockDirectory(missing[index]); err != nil {
				return err
			}
		}
	}
	return validateSharedLockDirectory(path)
}

func createSharedLockDirectory(path string) (resultErr error) {
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	created := false
	resultErr = windowssecurity.WithRestorePrivilegeAndOwner(owner, func() error {
		if err := windows.CreateDirectory(pathUTF16, &attributes); err != nil {
			if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
				return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
			}
			return err
		}
		created = true
		handle, err := openSharedLockDirectory(path, true)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		if !windowssecurity.HandleOwnerMatchesSID(handle, owner) || !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
			return windows.ERROR_INVALID_SECURITY_DESCR
		}
		return nil
	})
	runtime.KeepAlive(descriptor)
	if resultErr != nil && created {
		removeErr := os.Remove(path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		resultErr = errors.Join(resultErr, removeErr)
	}
	return resultErr
}

func validateSharedLockBoundary(path string, owner *windows.SID) error {
	handle, err := openSharedLockDirectory(path, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
		return fmt.Errorf("shared lock parent %s has a foreign owner: %w", path, ErrCredentialStoreUnavailable)
	}
	return nil
}

func secureExistingSharedLockDirectory(path string, owner *windows.SID) error {
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	handle, err := openSharedLockDirectory(path, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
		return fmt.Errorf("shared lock parent %s has a foreign owner: %w", path, ErrCredentialStoreUnavailable)
	}
	if windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		return nil
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
	defer runtime.KeepAlive(absolute)
	if err := windowssecurity.WithRestorePrivilege(func() error {
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return err
		}
		runtime.KeepAlive(absolute)
		if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
			return windows.ERROR_INVALID_SECURITY_DESCR
		}
		return nil
	}); err != nil {
		return err
	}
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) || !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		return windows.ERROR_INVALID_SECURITY_DESCR
	}
	return nil
}

func validateSharedLockDirectory(path string) error {
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	handle, err := openSharedLockDirectory(path, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
		return fmt.Errorf("shared lock directory %s has a foreign owner: %w", path, ErrCredentialStoreUnavailable)
	}
	if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		return fmt.Errorf("shared lock directory %s has an unexpected protected DACL: %w", path, ErrCredentialStoreUnavailable)
	}
	return nil
}

func openSharedLockDirectory(path string, writable bool) (windows.Handle, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if writable {
		access |= windows.WRITE_DAC
	}
	handle, err := windows.CreateFile(pathUTF16, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("shared lock path %s is not an ordinary directory: %w", path, ErrCredentialStoreUnavailable)
	}
	if !windowssecurity.HandlePathMatches(handle, path) {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("shared lock path %s resolves through a different filesystem object: %w", path, ErrCredentialStoreUnavailable)
	}
	return handle, nil
}

func writeSharedLockOwner(path string, data []byte) (resultErr error) {
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	parent, err := openSharedLockDirectory(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(parent)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var handle windows.Handle
	created := false
	resultErr = windowssecurity.WithRestorePrivilegeAndOwner(owner, func() error {
		handle, err = windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
				return &os.PathError{Op: "open", Path: path, Err: os.ErrExist}
			}
			return err
		}
		created = true
		var information windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
			return err
		}
		if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.NumberOfLinks != 1 {
			return fmt.Errorf("owner metadata is not an ordinary file: %w", ErrCredentialStoreUnavailable)
		}
		if !windowssecurity.HandleOwnerMatchesSID(handle, owner) || !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
			return windows.ERROR_INVALID_SECURITY_DESCR
		}
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			return errors.New("wrap shared lock owner handle")
		}
		handle = 0
		if _, err := file.Write(data); err != nil {
			return errors.Join(err, file.Close())
		}
		if err := file.Sync(); err != nil {
			return errors.Join(err, file.Close())
		}
		return file.Close()
	})
	runtime.KeepAlive(descriptor)
	if handle != 0 {
		closeErr := windows.CloseHandle(handle)
		resultErr = errors.Join(resultErr, closeErr)
	}
	if resultErr != nil && created {
		removeErr := os.Remove(path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		resultErr = errors.Join(resultErr, removeErr)
	}
	return resultErr
}

func quarantineSharedLock(path, stalePath string) error {
	if err := validateSharedLockDirectory(path); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=runtime-auth reason=validated-stale-lock-quarantine
	if err := os.Rename(path, stalePath); err != nil {
		return err
	}
	if err := validateSharedLockDirectory(stalePath); err != nil {
		return err
	}
	return removeSharedLock(stalePath)
}

// cleanupNewSharedLock only removes the empty directory that this process
// created. It never recursively removes a path after owner metadata exists,
// so a concurrent replacement cannot turn an error path into data loss.
func cleanupNewSharedLock(path string) error {
	if err := validateSharedLockDirectory(path); err != nil {
		return err
	}
	ownerPath := filepath.Join(path, "owner.json")
	if _, err := os.Lstat(ownerPath); err == nil {
		return fmt.Errorf("refusing to remove shared lock with owner metadata: %w", ErrCredentialStoreUnavailable)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
