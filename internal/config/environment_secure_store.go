package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
)

// EnvironmentSecureSecretStore marks a SecretStore implementation whose
// persistence is protected by an OS secure-storage boundary. It is exported
// so platform adapters and deterministic test stores can declare that
// property; the owner-only FileSecretStore deliberately does not implement it.
type EnvironmentSecureSecretStore interface {
	SecretStore
	EnvironmentSecureStore()
}

func (KeyringStore) EnvironmentSecureStore() {}

// RequireEnvironmentSecureStore prevents ENV private keys from using the
// general owner-only file fallback. KeyringStore is backed by Keychain,
// Secret Service, or DPAPI on supported platforms; an unavailable backend
// fails when the first secret is accessed.
func (s ProfileStore) RequireEnvironmentSecureStore() error {
	if s.Path == "" || s.Secrets == nil {
		return ErrCredentialStoreUnavailable
	}
	if _, ok := s.Secrets.(EnvironmentSecureSecretStore); !ok {
		return fmt.Errorf("%w: ENV Injection requires the OS secure credential store", ErrCredentialStoreUnavailable)
	}
	return nil
}

// LockEnvironmentHostKey serializes creation and genesis-marker transitions
// for one host installation across CLI and host-runtime processes. The key
// itself remains in the platform credential store; this lock is only a
// short-lived coordination record and never contains secret material.
//
// KeyringStore is intentionally the only production implementation. Keeping
// this operation on the secure-store adapter lets callers fail closed when a
// custom SecretStore cannot provide cross-process coordination.
func (KeyringStore) LockEnvironmentHostKey(machineID string, generation uint64) (func() error, error) {
	if machineID == "" || generation == 0 {
		return nil, ErrCredentialStoreUnavailable
	}
	directory, err := DefaultCredentialDir()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(machineID + "\x00" + strconv.FormatUint(generation, 10) + "\x00environment-host-key"))
	lock := newSharedLock(filepath.Join(directory, "environment-host-key-"+hex.EncodeToString(digest[:16])+".lock"))
	if err := lock.Lock(); err != nil {
		return nil, errors.Join(ErrCredentialStoreUnavailable, err)
	}
	return lock.Unlock, nil
}
