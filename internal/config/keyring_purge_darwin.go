//go:build darwin

package config

import (
	"errors"

	"github.com/zalando/go-keyring"
)

func purgeCredentialStore() error {
	err := keyring.DeleteAll(keyringService)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
