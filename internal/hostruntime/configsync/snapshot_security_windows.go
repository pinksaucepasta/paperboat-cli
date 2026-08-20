//go:build windows

package configsync

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func safeSnapshotPermissions(path string, _ fs.FileInfo) bool {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	if owner.Equals(user.User.Sid) {
		return true
	}
	member, err := windows.GetCurrentProcessToken().IsMember(owner)
	return err == nil && member
}

// Windows has no POSIX executable bits. Managed regular files use a stable
// private-file policy in snapshots so Windows and Unix peers do not oscillate
// solely because os.FileMode reports synthetic 0666 bits on Windows.
func snapshotFileMode(fs.FileInfo) os.FileMode { return 0o600 }
