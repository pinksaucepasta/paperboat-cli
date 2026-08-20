//go:build windows

package filetransfer

import (
	"os"

	"golang.org/x/sys/windows"
)

// openSourceFile pins the validated descriptor while retaining normal Windows
// rename/delete semantics. os.Open omits FILE_SHARE_DELETE, which would make a
// long-running transfer unexpectedly lock the user's source pathname.
func openSourceFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
