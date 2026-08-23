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
	"strings"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
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
	finalDescriptor, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return nil, "", err
	}
	creationDescriptorText := descriptor
	finalOwner, _, ownerErr := finalDescriptor.Owner()
	systemOwner, systemOwnerErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	transitionToSystem := ownerErr == nil && systemOwnerErr == nil && finalOwner != nil && finalOwner.Equals(systemOwner)
	var administratorsOwner *windows.SID
	if transitionToSystem {
		if !strings.HasPrefix(descriptor, "O:SY") {
			return nil, "", windows.ERROR_INVALID_SECURITY_DESCR
		}
		creationDescriptorText = strings.TrimPrefix(descriptor, "O:SY")
		administratorsOwner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return nil, "", err
		}
	}
	creationDescriptor, err := windows.SecurityDescriptorFromString(creationDescriptorText)
	if err != nil {
		return nil, "", err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: creationDescriptor,
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
		var handle windows.Handle
		create := func() error {
			var createErr error
			handle, createErr = windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			return createErr
		}
		if transitionToSystem {
			err = windowssecurity.WithRestorePrivilegeAndOwner(administratorsOwner, create)
		} else {
			err = create()
		}
		runtime.KeepAlive(creationDescriptor)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if err != nil {
			if handle != 0 {
				closeErr := windows.CloseHandle(handle)
				removeErr := os.Remove(path)
				if errors.Is(removeErr, os.ErrNotExist) {
					removeErr = nil
				}
				err = errors.Join(err, closeErr, removeErr)
			}
			return nil, "", err
		}
		if transitionToSystem {
			transitionErr := error(nil)
			if !windowssecurity.HandleOwnerMatchesSID(handle, administratorsOwner) {
				transitionErr = fmt.Errorf("validate protected temporary creation owner: %w", windows.ERROR_INVALID_SECURITY_DESCR)
			} else if !windowssecurity.ProtectedHandleDACLMatches(handle, creationDescriptorText) {
				transitionErr = fmt.Errorf("validate protected temporary creation DACL: %w", windows.ERROR_INVALID_SECURITY_DESCR)
			}
			absoluteDescriptor, absoluteErr := finalDescriptor.ToAbsolute()
			transitionErr = errors.Join(transitionErr, absoluteErr)
			var dacl *windows.ACL
			var daclErr error
			if transitionErr == nil {
				dacl, _, daclErr = absoluteDescriptor.DACL()
			}
			transitionErr = errors.Join(transitionErr, daclErr)
			if transitionErr == nil {
				transitionErr = windowssecurity.WithRestorePrivilege(func() error {
					if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
						return err
					}
					runtime.KeepAlive(absoluteDescriptor)
					if !windowssecurity.ProtectedHandleDACLMatches(handle, descriptor) {
						return fmt.Errorf("validate protected temporary final DACL: %w", windows.ERROR_INVALID_SECURITY_DESCR)
					}
					return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, systemOwner, nil, nil, nil)
				})
				runtime.KeepAlive(absoluteDescriptor)
			}
			if transitionErr == nil && !windowssecurity.HandleOwnerMatchesSID(handle, systemOwner) {
				actual := "unavailable"
				if current, queryErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); queryErr == nil && current != nil {
					if currentOwner, _, ownerQueryErr := current.Owner(); ownerQueryErr == nil && currentOwner != nil {
						actual = currentOwner.String()
					}
				}
				transitionErr = fmt.Errorf("validate protected temporary final owner (got %s want %s): %w", actual, systemOwner.String(), windows.ERROR_INVALID_SECURITY_DESCR)
			} else if transitionErr == nil && !windowssecurity.ProtectedHandleDACLMatches(handle, descriptor) {
				transitionErr = fmt.Errorf("validate protected temporary final DACL: %w", windows.ERROR_INVALID_SECURITY_DESCR)
			}
			if transitionErr != nil {
				windows.CloseHandle(handle)
				_ = os.Remove(path)
				return nil, "", transitionErr
			}
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
