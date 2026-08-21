//go:build windows

package auth

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func secureJWKSFile(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	want, err := currentJWKSDescriptor()
	if err != nil {
		return false
	}
	got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || got == nil {
		return false
	}
	control, _, err := got.Control()
	return err == nil && control&windows.SE_DACL_PROTECTED != 0 && daclSection(got.String()) == daclSection(want.String())
}

func currentJWKSDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
}

func daclSection(value string) string {
	start := strings.Index(value, "D:")
	if start < 0 {
		return ""
	}
	end := strings.Index(value[start+2:], "S:")
	if end < 0 {
		return value[start:]
	}
	return value[start : start+2+end]
}
