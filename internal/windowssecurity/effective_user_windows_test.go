//go:build windows

package windowssecurity

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCurrentEffectiveUserTokenFallsBackOnlyWhenThreadHasNoToken(t *testing.T) {
	processCalled := false
	token, err := currentEffectiveUserToken(
		func(*windows.Token) error { return windows.ERROR_NO_TOKEN },
		func() (windows.Token, error) {
			processCalled = true
			return windows.OpenCurrentProcessToken()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	if !processCalled {
		t.Fatal("process-token fallback was not used for ERROR_NO_TOKEN")
	}
	if user, err := token.GetTokenUser(); err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("fallback returned an invalid process token: %v", err)
	}
}

func TestCurrentEffectiveUserTokenRejectsThreadFailureWithoutFallback(t *testing.T) {
	processCalled := false
	token, err := currentEffectiveUserToken(
		func(*windows.Token) error { return windows.ERROR_ACCESS_DENIED },
		func() (windows.Token, error) {
			processCalled = true
			return windows.OpenCurrentProcessToken()
		},
	)
	if token != 0 {
		token.Close()
		t.Fatal("thread-token failure returned a token")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("thread-token failure = %v, want access denied", err)
	}
	if processCalled {
		t.Fatal("thread-token failure silently fell back to the process token")
	}
}

func TestCurrentEffectiveUserTokenPreservesThreadToken(t *testing.T) {
	const threadToken = windows.Token(0x1234)
	processCalled := false
	token, err := currentEffectiveUserToken(
		func(target *windows.Token) error {
			*target = threadToken
			return nil
		},
		func() (windows.Token, error) {
			processCalled = true
			return windows.OpenCurrentProcessToken()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if processCalled {
		t.Fatal("available thread token was replaced with the process token")
	}
	if token != threadToken {
		t.Fatal("effective token helper did not preserve the opened thread token")
	}
}
