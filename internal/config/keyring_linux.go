//go:build linux

package config

import (
	"errors"
	"fmt"
	dbus "github.com/godbus/dbus/v5"
	secretservice "github.com/zalando/go-keyring/secret_service"
	"os"
)

type KeyringStore struct{}

var errKeyringSecretNotFound = errors.New("credential not found")

func unavailableCredentialStore(err error) error {
	return fmt.Errorf("%w: %v", ErrCredentialStoreUnavailable, err)
}

func linuxSecretAttributes(ref string) map[string]string {
	return map[string]string{"service": keyringService, "account": ref}
}

// CredentialStoreAvailable reports whether a Secret Service owner is
// discoverable on the current login session. Headless Linux sessions often
// have no D-Bus session at all; callers can select the protected owner-only
// file store before attempting to persist credentials in that case.
func CredentialStoreAvailable() bool {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return false
	}
	bus, err := dbus.SessionBus()
	if err != nil {
		return false
	}
	defer bus.Close()
	var owned bool
	if err := bus.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.freedesktop.secrets").Store(&owned); err != nil {
		return false
	}
	return owned
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
		return "", unavailableCredentialStore(err)
	}
	item, err := linuxSecretItem(service, ref)
	if errors.Is(err, errKeyringSecretNotFound) {
		return "", ErrSecretNotFound
	}
	if err != nil {
		return "", unavailableCredentialStore(err)
	}
	session, err := service.OpenSession()
	if err != nil {
		return "", unavailableCredentialStore(err)
	}
	defer service.Close(session)
	if err := service.Unlock(item); err != nil {
		return "", unavailableCredentialStore(err)
	}
	secret, err := service.GetSecret(item, session.Path())
	if err != nil {
		return "", unavailableCredentialStore(err)
	}
	return string(secret.Value), nil
}
func (KeyringStore) Delete(ref string) error {
	service, err := secretservice.NewSecretService()
	if err != nil {
		return unavailableCredentialStore(err)
	}
	item, err := linuxSecretItem(service, ref)
	if errors.Is(err, errKeyringSecretNotFound) {
		return nil
	}
	if err != nil {
		return unavailableCredentialStore(err)
	}
	if err := service.Delete(item); err != nil {
		return unavailableCredentialStore(err)
	}
	return nil
}
