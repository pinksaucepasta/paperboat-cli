//go:build windows

package hoststate

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

type processLock struct {
	file   *os.File
	region windows.Overlapped
}

func ensurePrivateDirectory(name string) error {
	if err := os.MkdirAll(name, 0o700); err != nil {
		return err
	}
	return protectWindowsObject(name, true)
}

func acquireProcessLock(name string) (*processLock, error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	closeWith := func(cause error) (*processLock, error) {
		_ = file.Close()
		return nil, cause
	}
	if err := protectWindowsObject(name, false); err != nil {
		return closeWith(err)
	}
	lock := &processLock{file: file}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.region)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return closeWith(ErrLocked)
	}
	if err != nil {
		return closeWith(err)
	}
	if err := file.Truncate(0); err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = file.WriteString(strconv.Itoa(os.Getpid()) + "\r\n")
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &lock.region)
		return closeWith(fmt.Errorf("write host state lock owner: %w", err))
	}
	return lock, nil
}

func (l *processLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return errors.Join(windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &l.region), file.Close())
}

func readPrivateFile(name string, limit int64) ([]byte, error) {
	if err := validateWindowsFile(name); err != nil {
		return nil, err
	}
	if err := protectWindowsObject(name, false); err != nil {
		return nil, err
	}
	info, err := os.Stat(name)
	if err != nil || info.Size() < 0 || info.Size() > limit {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidState
	}
	return os.ReadFile(name)
}

// State publication uses MOVEFILE_WRITE_THROUGH. A directory FlushFileBuffers
// call is not consistently supported on Windows filesystems, so no additional
// directory operation is required here.
func syncDirectory(string) error { return nil }

func validateWindowsFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidState
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(name))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidState
	}
	return nil
}

func protectWindowsObject(name string, directory bool) error {
	info, err := os.Lstat(name)
	if err != nil || info.IsDir() != directory || info.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return err
		}
		return ErrInvalidState
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(name))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidState
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return ErrInvalidState
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")"
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
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	runtime.KeepAlive(absolute)
	if !windowssecurity.ProtectedDACLMatches(name, sddl) {
		return ErrInvalidState
	}
	return nil
}
