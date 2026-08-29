//go:build windows

package localdaemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const processLockSecurity = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"

type processLock struct {
	file      *os.File
	region    windows.Overlapped
	ownerPath string
	mu        sync.Mutex
}

func acquireProcessLock(path, ownerSID string) (*processLock, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateWindowsOwnerSID(ownerSID) != nil {
		return nil, ErrInvalidInventoryConfig
	}
	if err := ensureWindowsLockParent(filepath.Dir(path), ownerSID); err != nil {
		return nil, err
	}
	_, statErr := os.Lstat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, statErr
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	closeWith := func(cause error) (*processLock, error) {
		_ = file.Close()
		return nil, cause
	}
	if err := validateWindowsLockFile(path); err != nil {
		return closeWith(err)
	}
	if created {
		if err := setWindowsLockACL(path, ownerSID); err != nil {
			return closeWith(err)
		}
	} else if err := verifyWindowsLockACL(path, ownerSID); err != nil {
		return closeWith(localapi.ErrUnsafeSocket)
	}
	lock := &processLock{file: file}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.region)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return closeWith(localapi.ErrAlreadyRunning)
	}
	if err != nil {
		return closeWith(err)
	}
	if err := file.Truncate(0); err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = fmt.Fprintf(file, "%d\r\n", os.Getpid())
	}
	if err == nil {
		err = file.Sync()
	}
	ownerPath := path + ".owner.json"
	if err == nil {
		var record windowsDaemonOwnerRecord
		record, err = currentWindowsDaemonOwnerRecord()
		if err == nil {
			err = writeWindowsDaemonOwnerRecord(ownerPath, ownerSID, record)
		}
	}
	if err != nil {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &lock.region)
		return closeWith(fmt.Errorf("record local daemon PID: %w", err))
	}
	lock.ownerPath = ownerPath
	return lock, nil
}

func ensureWindowsLockParent(path, ownerSID string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateWindowsOwnerSID(ownerSID) != nil {
		return ErrInvalidInventoryConfig
	}
	if err := rejectWindowsReparseAncestors(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := rejectWindowsReparseAncestors(path); err != nil {
		return err
	}
	// S4U logon SIDs are session-scoped. Replace the directory's default DACL
	// from inside the enrolled user process before creating the owner record so
	// future service sessions inherit access through the permanent account SID.
	return setWindowsLockParentDACL(path, ownerSID)
}

func rejectWindowsReparseAncestors(path string) error {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		return ErrInvalidInventoryConfig
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalidInventoryConfig
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return localapi.ErrUnsafeSocket
		}
		attributes, attrErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return localapi.ErrUnsafeSocket
		}
	}
	return nil
}

func validateWindowsLockFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return localapi.ErrUnsafeSocket
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return localapi.ErrUnsafeSocket
	}
	return nil
}

func windowsLockSDDL(ownerSID string) string { return processLockSecurity + ownerSID + ")" }

func windowsOwnerStateDirectorySDDL(ownerSID string) string {
	return windowssecurity.OwnerFullControlDirectoryDACL(ownerSID)
}

func setWindowsLockParentDACL(path, ownerSID string) error {
	sddl := windowsOwnerStateDirectorySDDL(ownerSID)
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
	handle, err := openWindowsLockParent(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	runtime.KeepAlive(absolute)
	if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		return localapi.ErrUnsafeSocket
	}
	return nil
}

func openWindowsLockParent(path string, access uint32) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
	handle, err := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(handle)
		return 0, localapi.ErrUnsafeSocket
	}
	return handle, nil
}

func setWindowsLockACL(path, ownerSID string) error {
	descriptor, err := windows.SecurityDescriptorFromString(windowsLockSDDL(ownerSID))
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

func verifyWindowsLockACL(path, ownerSID string) error {
	// Windows can serialize a protected DACL as D:PAI even when the requested
	// descriptor was D:P. The inherited-ACL marker is not a permission grant;
	// compare the protected DACL's exact ACE set instead of its raw SDDL.
	if !windowssecurity.ProtectedDACLMatches(path, windowsLockSDDL(ownerSID)) {
		return localapi.ErrUnsafeSocket
	}
	return nil
}

func (l *processLock) CanRemoveStaleSocket(context.Context, string) bool {
	return l != nil && l.file != nil
}

func (l *processLock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &l.region)
	closeErr := file.Close()
	removeErr := os.Remove(l.ownerPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(unlockErr, closeErr, removeErr)
}
