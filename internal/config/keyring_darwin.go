//go:build darwin

package config

import (
	"errors"
	"github.com/zalando/go-keyring"
)

type KeyringStore struct{}

func (KeyringStore) Set(ref, value string) error    { return keyring.Set(keyringService, ref, value) }
func (KeyringStore) Get(ref string) (string, error) { return keyring.Get(keyringService, ref) }
func (KeyringStore) Delete(ref string) error {
	err := keyring.Delete(keyringService, ref)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
