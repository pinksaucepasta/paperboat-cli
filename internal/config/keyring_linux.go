//go:build linux

package config

import (
	"errors"
	"fmt"
	dbus "github.com/godbus/dbus/v5"
	secretservice "github.com/zalando/go-keyring/secret_service"
)

type KeyringStore struct{}

var errKeyringSecretNotFound = errors.New("credential not found")

func unavailableCredentialStore(err error) error {
	return fmt.Errorf("%w: %v", ErrCredentialStoreUnavailable, err)
}

func linuxSecretAttributes(ref string) map[string]string {
	return map[string]string{"service": keyringService, "account": ref}
}
func linuxSecretItem(service *secretservice.SecretService, ref string) (dbus.ObjectPath, error) {
	collection := service.GetLoginCollection()
	if err := service.Unlock(collection.Path()); err != nil {
		return "", err
	}
	items, err := service.SearchItems(collection, linuxSecretAttributes(ref))
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", errKeyringSecretNotFound
	}
	return items[0], nil
}
func (KeyringStore) Set(ref, value string) error {
	service, err := secretservice.NewSecretService()
	if err != nil {
		return unavailableCredentialStore(err)
	}
	session, err := service.OpenSession()
	if err != nil {
		return unavailableCredentialStore(err)
	}
	defer service.Close(session)
	collection := service.GetLoginCollection()
	if err := service.Unlock(collection.Path()); err != nil {
		return unavailableCredentialStore(err)
	}
	if err := service.CreateItem(collection, fmt.Sprintf("%s/%s", keyringService, ref), linuxSecretAttributes(ref), secretservice.NewSecret(session.Path(), value)); err != nil {
		return unavailableCredentialStore(err)
	}
	return nil
}
func (KeyringStore) Get(ref string) (string, error) {
	service, err := secretservice.NewSecretService()
	if err != nil {
		return "", err
	}
	item, err := linuxSecretItem(service, ref)
	if err != nil {
		return "", err
	}
	session, err := service.OpenSession()
	if err != nil {
		return "", err
	}
	defer service.Close(session)
	if err := service.Unlock(item); err != nil {
		return "", err
	}
	secret, err := service.GetSecret(item, session.Path())
	if err != nil {
		return "", err
	}
	return string(secret.Value), nil
}
func (KeyringStore) Delete(ref string) error {
	service, err := secretservice.NewSecretService()
	if err != nil {
		return err
	}
	item, err := linuxSecretItem(service, ref)
	if errors.Is(err, errKeyringSecretNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return service.Delete(item)
}
