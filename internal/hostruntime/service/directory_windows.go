//go:build windows

package service

import (
	"os"

	"golang.org/x/sys/windows"
)

func prepareAtomicDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(directory))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidDefinition
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// atomicfile.Write uses MOVEFILE_WRITE_THROUGH on Windows. Opening a directory
// with os.Open and calling Sync returns access denied, so there is no second
// POSIX-style directory fsync to perform after declaration removal.
func syncServiceDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidDefinition
	}
	return nil
}
