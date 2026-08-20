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

func platformShellArguments(path string) []string {
	switch strings.ToLower(filepath.Base(path)) {
	case "powershell.exe", "pwsh.exe":
		return []string{"-NoLogo"}
	case "cmd.exe":
		return []string{"/d"}
	default:
		return nil
	}
}
