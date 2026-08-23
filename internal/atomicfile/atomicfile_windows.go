//go:build windows

package atomicfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

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
	// a protected descriptor for the current owner, SYSTEM, and Administrators.
	// Windows does not have meaningful POSIX UID/GID ownership, so callers must
	// leave OwnerUID and OwnerGID as -1 and use a security descriptor instead.
	SecurityDescriptor string
}

// Write creates a same-directory temporary file with its final protected
// security descriptor in CreateFileW, writes and flushes its contents, then
// replaces the destination with MOVEFILE_WRITE_THROUGH. It deliberately
// rejects POSIX ownership requests: treating a Windows token as a UID would
// be fake security.
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
		resolved, err := currentOwnerSecurityDescriptor()
		if err != nil {
			return &Error{Stage: StageOwner, Path: path, Err: err}
		}
		descriptor = resolved
	}
	if _, err := windows.SecurityDescriptorFromString(descriptor); err != nil {
		return &Error{Stage: StageValidate, Path: path, Err: err}
	}
	//paperboat:allow-source-policy atomic-replacement owner=atomicfile-windows reason=same-directory-protected-staging
	temporary, temporaryPath, err := createProtectedTemporary(parent, descriptor)
	if err != nil {
		return &Error{Stage: StageCreate, Path: path, Err: err}
	}
	defer os.Remove(temporaryPath)
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

func createProtectedTemporary(parent, descriptor string) (*os.File, string, error) {
	securityDescriptor, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return nil, "", err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}
	for attempt := 0; attempt < 16; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", err
		}
		path := filepath.Join(parent, ".paperboat-"+hex.EncodeToString(random))
		pathUTF16, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, "", err
		}
		handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		runtime.KeepAlive(securityDescriptor)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			windows.CloseHandle(handle)
			return nil, "", errors.New("wrap protected temporary file handle")
		}
		return file, path, nil
	}
	return nil, "", windows.ERROR_FILE_EXISTS
}

func currentOwnerSecurityDescriptor() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		if err == nil {
			err = errors.New("current Windows token has no valid owner SID")
		}
		return "", err
	}
	sid := user.User.Sid.String()
	descriptor := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if sid != "S-1-5-18" {
		descriptor += "(A;;FA;;;" + sid + ")"
	}
	return descriptor, nil
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
