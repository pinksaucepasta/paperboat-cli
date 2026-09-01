//go:build windows

package tunnelcreatejournal

import (
	"errors"
	"io"
	"os"
	"runtime"

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
	return lock, nil
}

func (lock *processLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return errors.Join(windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &lock.region), file.Close())
}

func readPrivateFile(name string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validateWindowsFile(name); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(name)
	if err != nil || pathErr != nil || !os.SameFile(info, pathInfo) || info.Size() < 0 || info.Size() > limit {
		return nil, ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrInvalid
	}
	return body, nil
}

func removePrivateFile(name string) error {
	if err := validateWindowsFile(name); err != nil {
		return err
	}
	return os.Remove(name)
}

func syncDirectory(string) error { return nil }

func validateWindowsFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(name))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalid
	}
	return nil
}

func protectWindowsObject(name string, directory bool) error {
	info, err := os.Lstat(name)
	if err != nil || info.IsDir() != directory || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(name))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalid
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return ErrInvalid
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
		return ErrInvalid
	}
	return nil
}
