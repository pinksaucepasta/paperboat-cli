//go:build windows

package supportbundle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validatePlatformOutputPath(outputPath string) error {
	parent, err := openWindowsOutputParent(outputPath)
	if err != nil {
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle", Cause: err}
	}
	defer windows.CloseHandle(parent)

	handle, err := openWindowsRelative(parent, filepath.Base(outputPath), windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT)
	if err != nil {
		if windowsObjectMissing(err) {
			return nil
		}
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle", Cause: err}
	}
	defer windows.CloseHandle(handle)
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle", Cause: err}
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &Error{Code: ErrorOutputSymlink, Operation: "write support bundle"}
	}
	return &Error{Code: ErrorOutputExists, Operation: "write support bundle"}
}

// openWindowsOutputParent opens the final parent without delete sharing, which
// pins it against replacement. Comparing its final handle path to the requested
// path rejects reparse points in every ancestor, not only the last component.
func openWindowsOutputParent(outputPath string) (windows.Handle, error) {
	parent := filepath.Dir(outputPath)
	pointer, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
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
		return 0, windows.ERROR_REPARSE_TAG_MISMATCH
	}
	finalPath, err := windowsFinalPath(handle)
	if err != nil || !strings.EqualFold(filepath.Clean(finalPath), filepath.Clean(parent)) {
		windows.CloseHandle(handle)
		if err != nil {
			return 0, err
		}
		return 0, windows.ERROR_REPARSE_TAG_MISMATCH
	}
	return handle, nil
}

func windowsFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			path := windows.UTF16ToString(buffer[:n])
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return `\\` + strings.TrimPrefix(path, `\\?\UNC\`), nil
			}
			return strings.TrimPrefix(path, `\\?\`), nil
		}
		buffer = make([]uint16, n+1)
	}
}

func (b *Builder) writeAtomic(ctx context.Context, outputPath string, body []byte) (err error) {
	if err := ctx.Err(); err != nil {
		return contextError("write support bundle", err)
	}
	parent, err := openWindowsOutputParent(outputPath)
	if err != nil {
		return &Error{Code: ErrorInvalidOutput, Operation: "create support bundle output", Cause: err}
	}
	defer windows.CloseHandle(parent)

	temporaryName, temporary, err := createProtectedWindowsTemporary(parent)
	if err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "create support bundle output", Cause: err}
	}
	temporaryPath := filepath.Join(filepath.Dir(outputPath), temporaryName)
	defer func() {
		cleanupErr := markWindowsFileForDeletion(windows.Handle(temporary.Fd()))
		closeErr := temporary.Close()
		if err == nil && (cleanupErr != nil || closeErr != nil) {
			err = &Error{Code: ErrorWriteFailed, Operation: "remove support bundle temporary output", Cause: errors.Join(cleanupErr, closeErr)}
		}
	}()
	if err := writeContext(ctx, temporary, body); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "sync support bundle output", Cause: err}
	}
	if err := ctx.Err(); err != nil {
		return contextError("write support bundle", err)
	}
	if b.beforePublish != nil {
		if err := b.beforePublish(temporaryPath); err != nil {
			return &Error{Code: ErrorWriteFailed, Operation: "publish support bundle output", Cause: err}
		}
	}
	if err := ctx.Err(); err != nil {
		return contextError("write support bundle", err)
	}
	if err := linkWindowsRelative(windows.Handle(temporary.Fd()), parent, filepath.Base(outputPath)); err != nil {
		if windowsObjectExists(err) {
			return &Error{Code: ErrorOutputExists, Operation: "publish support bundle output", Cause: err}
		}
		return &Error{Code: ErrorWriteFailed, Operation: "publish support bundle output", Cause: err}
	}
	return nil
}

func createProtectedWindowsTemporary(parent windows.Handle) (string, *os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", nil, errors.Join(err, windows.ERROR_INVALID_OWNER)
	}
	// Set the owner explicitly as well as the protected DACL. Without an owner
	// field, NTFS may retain the parent directory's owner when this temporary
	// file is created, and the hard-link publication would carry that incorrect
	// owner to the final support bundle.
	descriptorText := "O:" + user.User.Sid.String() + "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if user.User.Sid.String() != "S-1-5-18" {
		descriptorText += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	descriptor, err := windows.SecurityDescriptorFromString(descriptorText)
	if err != nil {
		return "", nil, err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return "", nil, err
	}
	for attempt := 0; attempt < temporaryCreateAttempts; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, err
		}
		name := ".paperboat-support-bundle-" + hex.EncodeToString(random)
		handle, err := openWindowsRelativeWithSecurity(parent, name,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL,
			windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
			absolute)
		runtime.KeepAlive(absolute)
		if windowsObjectExists(err) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		file := os.NewFile(uintptr(handle), name)
		if file == nil {
			windows.CloseHandle(handle)
			return "", nil, windows.ERROR_INVALID_HANDLE
		}
		return name, file, nil
	}
	return "", nil, windows.ERROR_FILE_EXISTS
}

func markWindowsFileForDeletion(handle windows.Handle) error {
	deleteFile := byte(1)
	return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1)
}

func openWindowsRelative(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
	return openWindowsRelativeWithSecurity(parent, name, access, disposition, options, nil)
}

func openWindowsRelativeWithSecurity(parent windows.Handle, name string, access, disposition, options uint32, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: descriptor,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	var allocationSize int64
	err = windows.NtCreateFile(&handle, access, attributes, &status, &allocationSize, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options, 0, 0)
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(descriptor)
	return handle, err
}

func linkWindowsRelative(file, parent windows.Handle, name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameUTF16 = nameUTF16[:len(nameUTF16)-1]
	rootOffset := uintptr(8)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		rootOffset = 4
	}
	lengthOffset := rootOffset + unsafe.Sizeof(parent)
	nameOffset := lengthOffset + 4
	buffer := make([]byte, int(nameOffset)+len(nameUTF16)*2)
	*(*windows.Handle)(unsafe.Pointer(&buffer[rootOffset])) = parent
	*(*uint32)(unsafe.Pointer(&buffer[lengthOffset])) = uint32(len(nameUTF16) * 2)
	copy(buffer[nameOffset:], unsafe.Slice((*byte)(unsafe.Pointer(&nameUTF16[0])), len(nameUTF16)*2))
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(file, &status, &buffer[0], uint32(len(buffer)), windows.FileLinkInformation)
}

func windowsObjectMissing(err error) bool {
	return err == windows.STATUS_OBJECT_NAME_NOT_FOUND || err == windows.STATUS_OBJECT_PATH_NOT_FOUND || errors.Is(err, os.ErrNotExist)
}

func windowsObjectExists(err error) bool {
	return err == windows.STATUS_OBJECT_NAME_COLLISION || errors.Is(err, os.ErrExist) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}
