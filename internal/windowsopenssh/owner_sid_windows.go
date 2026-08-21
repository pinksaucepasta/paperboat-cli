//go:build windows

package windowsopenssh

import "golang.org/x/sys/windows"

func platformOwnerSID() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return ""
	}
	return user.User.Sid.String()
}
