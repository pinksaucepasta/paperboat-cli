//go:build windows

package config

import (
	"errors"
	"github.com/danieljoos/wincred"
	"syscall"
)

type KeyringStore struct{}

func windowsCredentialName(ref string) string { return keyringService + "/" + ref }
func (KeyringStore) Set(ref, value string) error {
	c := wincred.NewGenericCredential(windowsCredentialName(ref))
	c.UserName = ref
	c.CredentialBlob = []byte(value)
	return c.Write()
}
func (KeyringStore) Get(ref string) (string, error) {
	c, err := wincred.GetGenericCredential(windowsCredentialName(ref))
	if err != nil {
		return "", err
	}
	return string(c.CredentialBlob), nil
}
func (KeyringStore) Delete(ref string) error {
	c, err := wincred.GetGenericCredential(windowsCredentialName(ref))
	if errors.Is(err, syscall.ERROR_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	return c.Delete()
}
