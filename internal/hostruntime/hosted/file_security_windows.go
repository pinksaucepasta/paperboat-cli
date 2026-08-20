//go:build windows

package hosted

import (
	"os"

	"golang.org/x/sys/windows"
)

func secureIdentityFile(path string, info os.FileInfo, maximum int64) bool {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
