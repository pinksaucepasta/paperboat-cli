//go:build windows

package hostruntimecmd

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows does not expose POSIX file modes. The Paperboat runtime creates the
// token in a user-private state directory with a protected ACL; here we reject
// links and reparse points before reading it so the command cannot be diverted
// through a user-controlled filesystem indirection.
func readPreviewAuthorizationToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4096 {
		return nil, errors.New("local host-runtime preview authorization is unavailable")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("local host-runtime preview authorization is unavailable")
	}
	return os.ReadFile(path)
}
