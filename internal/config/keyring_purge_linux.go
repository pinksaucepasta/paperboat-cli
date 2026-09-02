//go:build linux

package config

import (
	"errors"

	secretservice "github.com/zalando/go-keyring/secret_service"
)

func purgeCredentialStore() error {
	if !CredentialStoreAvailable() {
		return nil
	}
	service, err := secretservice.NewSecretService()
	if err != nil {
		return unavailableCredentialStore(err)
	}
	defer service.Conn.Close()
	collection := service.GetLoginCollection()
	if err := service.Unlock(collection.Path()); err != nil {
		return unavailableCredentialStore(err)
	}
	items, err := service.SearchItems(collection, map[string]string{"service": keyringService})
	if err != nil {
		return unavailableCredentialStore(err)
	}
	var result error
	for _, item := range items {
		if err := service.Delete(item); err != nil {
			result = errors.Join(result, unavailableCredentialStore(err))
		}
	}
	return result
}
