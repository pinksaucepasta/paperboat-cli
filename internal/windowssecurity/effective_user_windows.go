//go:build windows

package windowssecurity

import (
	"errors"

	"golang.org/x/sys/windows"
)

type threadTokenOpener func(*windows.Token) error
type processTokenOpener func() (windows.Token, error)

// CurrentEffectiveUserSID returns the user SID from the calling thread's
// impersonation token. It falls back to the process token only when the thread
// has no token, preserving the identity used for Windows access checks.
func CurrentEffectiveUserSID() (*windows.SID, error) {
	token, err := currentEffectiveUserToken(
		func(token *windows.Token) error {
			return windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, token)
		},
		windows.OpenCurrentProcessToken,
	)
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, windows.ERROR_INVALID_SID
	}
	return windows.StringToSid(user.User.Sid.String())
}

func currentEffectiveUserToken(openThread threadTokenOpener, openProcess processTokenOpener) (windows.Token, error) {
	if openThread == nil || openProcess == nil {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	var token windows.Token
	err := openThread(&token)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		return openProcess()
	}
	if err != nil {
		return 0, err
	}
	return token, nil
}
