//go:build windows

package config

import (
	"errors"
	"os"
)

func purgeCredentialStore() error {
	directory, err := dpapiCredentialDirectory()
	if err != nil {
		return err
	}
	err = os.RemoveAll(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
