//go:build windows

package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type Stage string

const (
	StageValidate Stage = "validate"
	StageCreate   Stage = "create"
	StageWrite    Stage = "write"
	StageOwner    Stage = "owner"
	StageReplace  Stage = "replace"
	StageSyncDir  Stage = "sync_parent"
)

type Error struct {
	Stage Stage
	Path  string
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("atomic file %s %s: %v", e.Stage, e.Path, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

type Options struct {
	Mode     fs.FileMode
	OwnerUID int
	OwnerGID int
	// SecurityDescriptor is an optional SDDL descriptor. If empty, Write uses
	// the protected SYSTEM-and-Administrators-only descriptor below. Windows
	// does not have meaningful POSIX UID/GID ownership, so callers must leave
	// OwnerUID and OwnerGID as -1 and use an ACL instead.
	SecurityDescriptor string
}

const defaultSecurityDescriptor = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// Write creates a same-directory temporary file, installs a protected DACL
// before writing its contents, flushes it, then replaces the destination with
// MOVEFILE_WRITE_THROUGH. It deliberately rejects POSIX ownership requests:
// treating a Windows token as a UID would be fake security.
func Write(path string, data []byte, options Options) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || options.Mode.Perm() == 0 || options.Mode&^fs.ModePerm != 0 || options.OwnerUID != -1 || options.OwnerGID != -1 {
		return &Error{Stage: StageValidate, Path: path, Err: errors.New("invalid Windows path, mode, or POSIX owner")}
	}
	parent := filepath.Dir(path)
	if err := secureDirectory(parent); err != nil {
		return &Error{Stage: StageValidate, Path: path, Err: err}
	}
	if err := regularNonReparse(path, true); err != nil {
		return &Error{Stage: StageValidate, Path: path, Err: err}
	}
	descriptor := options.SecurityDescriptor
	if descriptor == "" {
		descriptor = defaultSecurityDescriptor
	}
	if _, err := windows.SecurityDescriptorFromString(descriptor); err != nil {
		return &Error{Stage: StageValidate, Path: path, Err: err}
	}
	temporary, err := os.CreateTemp(parent, ".paperboat-*")
	if err != nil {
		return &Error{Stage: StageCreate, Path: path, Err: err}
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := applySecurityDescriptor(temporaryPath, descriptor); err != nil {
		temporary.Close()
		return &Error{Stage: StageOwner, Path: path, Err: err}
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return &Error{Stage: StageWrite, Path: path, Err: err}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return &Error{Stage: StageWrite, Path: path, Err: err}
	}
	if err := temporary.Close(); err != nil {
		return &Error{Stage: StageWrite, Path: path, Err: err}
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return &Error{Stage: StageReplace, Path: path, Err: err}
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return &Error{Stage: StageReplace, Path: path, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &Error{Stage: StageReplace, Path: path, Err: err}
	}
	return nil
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("parent is not a real directory")
		}
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		if err == nil {
			err = errors.New("parent is a reparse point")
		}
		return err
	}
	return nil
}

func regularNonReparse(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("destination is not a regular file")
		}
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		if err == nil {
			err = errors.New("destination is a reparse point")
		}
		return err
	}
	return nil
}

func applySecurityDescriptor(path, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
