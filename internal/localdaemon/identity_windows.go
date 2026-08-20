//go:build windows

package localdaemon

import (
	"errors"

	"golang.org/x/sys/windows"
)

var errInvalidWindowsOwner = errors.New("invalid Windows daemon owner SID")

func currentWindowsUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errInvalidWindowsOwner
	}
	return user.User.Sid.String(), nil
}

func validateWindowsOwnerSID(value string) error {
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() || sid.String() != value {
		return errInvalidWindowsOwner
	}
	return nil
}

func resolveWindowsOwnerSID(configured string) (string, error) {
	current, err := currentWindowsUserSID()
	if err != nil {
		return "", err
	}
	if configured == "" {
		return current, nil
	}
	if err := validateWindowsOwnerSID(configured); err != nil || configured != current {
		return "", errInvalidWindowsOwner
	}
	return configured, nil
}
