//go:build windows

package enrollment

import (
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"os"

	"golang.org/x/sys/windows"
)

func secureIdentityFile(path string, info os.FileInfo, maximum int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum || !windowsHasSingleLink(path) {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return false
	}
	descriptor := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if user.User.Sid.String() != "S-1-5-18" {
		descriptor += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	want, err := windows.SecurityDescriptorFromString(descriptor)
	return err == nil && windowssecurity.ProtectedDACLMatches(path, want.String())
}

func windowsHasSingleLink(path string) bool {
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(handle, &info) == nil && info.NumberOfLinks == 1
}
