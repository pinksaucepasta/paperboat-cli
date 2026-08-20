//go:build windows

package configsync

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func privateControlFile(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	return err == nil && controlFileDACL(descriptor.String()) == controlFileDACL(want.String())
}

func controlFileDACL(value string) string {
	index := strings.Index(value, "D:")
	if index < 0 {
		return ""
	}
	open := strings.IndexByte(value[index:], '(')
	if open < 0 {
		return ""
	}
	return "D:" + value[index+open:]
}
