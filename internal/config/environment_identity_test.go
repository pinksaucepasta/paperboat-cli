package config

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type environmentSecureMemoryStore struct {
	values map[string]string
}

func (*environmentSecureMemoryStore) EnvironmentSecureStore() {}

func (store *environmentSecureMemoryStore) Set(ref, value string) error {
	if store.values == nil {
		store.values = make(map[string]string)
	}
	store.values[ref] = value
	return nil
}

func (store *environmentSecureMemoryStore) Get(ref string) (string, error) {
	value, ok := store.values[ref]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (store *environmentSecureMemoryStore) Delete(ref string) error {
	delete(store.values, ref)
	return nil
}

func TestEnvironmentManagerIdentityUsesSeparateSecureKeysAndRecoveryConfirmation(t *testing.T) {
	secrets := &environmentSecureMemoryStore{}
	store := ProfileStore{Path: t.TempDir(), Secrets: secrets}
	identity, err := store.CreateEnvironmentManagerIdentity("https://api.example.test", "account_1", "cli_1", true)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	if identity.KeyGeneration != 1 || identity.RecoveryPrivate == nil || !identity.RecoveryRequired || identity.RecoveryExportConfirmed || identity.SigningSeed == [32]byte{} || identity.RecipientPrivate == [32]byte{} || identity.SigningSeed == identity.RecipientPrivate || identity.SigningSeed == *identity.RecoveryPrivate || identity.RecipientPrivate == *identity.RecoveryPrivate {
		t.Fatalf("identity state = %+v", identity)
	}
	ref := environmentManagerIdentitySecretRef("https://api.example.test", "account_1", "cli_1")
	stored := secrets.values[ref]
	if bytes.Contains([]byte(stored), identity.SigningSeed[:]) || bytes.Contains([]byte(stored), identity.RecipientPrivate[:]) || bytes.Contains([]byte(stored), identity.RecoveryPrivate[:]) {
		t.Fatal("raw ENV private key bytes appeared in the serialized secure-store record")
	}

	loaded, err := store.LoadEnvironmentManagerIdentity("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if loaded.SigningSeed != identity.SigningSeed || loaded.RecipientPrivate != identity.RecipientPrivate || loaded.RecoveryPrivate == nil || *loaded.RecoveryPrivate != *identity.RecoveryPrivate {
		t.Fatal("ENV identity did not round trip")
	}
	recovery := *identity.RecoveryPrivate
	if err := store.ConfirmEnvironmentRecoveryExport("https://api.example.test", "account_1", "cli_1", recovery); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.LoadEnvironmentManagerIdentity("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer confirmed.Clear()
	if confirmed.RecoveryPrivate != nil || !confirmed.RecoveryExportConfirmed || !confirmed.RecoveryRequired || strings.Contains(secrets.values[ref], "recovery_private") {
		t.Fatalf("recovery confirmation did not delete online key: %+v", confirmed)
	}
}

func TestEnvironmentAuthorityHighWaterRejectsSkipRollbackAndFork(t *testing.T) {
	store := ProfileStore{Path: t.TempDir(), Secrets: &environmentSecureMemoryStore{}}
	identity, err := store.CreateEnvironmentManagerIdentity("https://api.example.test", "account_1", "cli_1", false)
	if err != nil {
		t.Fatal(err)
	}
	identity.Clear()
	first := "sha256:" + strings.Repeat("1", 64)
	second := "sha256:" + strings.Repeat("2", 64)
	if err := store.CommitEnvironmentAuthorityHighWater("https://api.example.test", "account_1", "cli_1", 1, first); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitEnvironmentAuthorityHighWater("https://api.example.test", "account_1", "cli_1", 1, first); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitEnvironmentAuthorityHighWater("https://api.example.test", "account_1", "cli_1", 1, second); err == nil || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("fork error = %v", err)
	}
	if err := store.CommitEnvironmentAuthorityHighWater("https://api.example.test", "account_1", "cli_1", 3, second); err == nil || !strings.Contains(err.Error(), "sequential") {
		t.Fatalf("skip error = %v", err)
	}
	if err := store.CommitEnvironmentAuthorityHighWater("https://api.example.test", "account_1", "cli_1", 2, second); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentIdentityRejectsPlainFileFallback(t *testing.T) {
	store := ProfileStore{Path: t.TempDir(), Secrets: FileSecretStore{Dir: t.TempDir()}}
	if _, err := store.CreateEnvironmentManagerIdentity("https://api.example.test", "account_1", "cli_1", false); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("file fallback error = %v", err)
	}
}
