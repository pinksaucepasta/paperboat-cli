//go:build windows

package enrollment

import (
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
	"os"
)

func secureEnrollmentConfigFile(path string, info os.FileInfo, maximum int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum || !windowsHasSingleLink(path) {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if user.User.Sid.String() != "S-1-5-18" {
		sddl += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	want, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return false
	}
	return windowssecurity.ProtectedDACLMatches(path, want.String())
}
