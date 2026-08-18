//go:build windows

package process

import (
	"io/fs"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func platformExecutable(path string, info fs.FileInfo) bool {
	if !strings.EqualFold(filepath.Ext(info.Name()), ".exe") {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
