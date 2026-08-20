//go:build !darwin && !linux && !windows

package config

import "errors"

type KeyringStore struct{}

func (KeyringStore) Set(string, string) error {
	return errors.New("OS credential store is unsupported on this platform")
}
func (KeyringStore) Get(string) (string, error) {
	return "", errors.New("OS credential store is unsupported on this platform")
}
func (KeyringStore) Delete(string) error {
	return errors.New("OS credential store is unsupported on this platform")
}
