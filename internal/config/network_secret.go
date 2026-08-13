package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
)

const networkFingerprintSecretBytes = 32

var ErrSecretNotFound = errors.New("credential secret not found")

// NetworkFingerprintSecret loads or creates the installation-scoped HMAC key
// used to derive opaque network fingerprints. The key never enters profile
// metadata and is serialized across processes sharing this profile root.
func (s ProfileStore) NetworkFingerprintSecret() (secret []byte, resultErr error) {
	if s.Path == "" || !filepath.IsAbs(s.Path) || s.Secrets == nil {
		return nil, ErrCredentialStoreUnavailable
	}
	root := filepath.Clean(s.Path)
	return s.networkFingerprintSecret(root, newSharedLock(filepath.Join(root, "network-fingerprint-secret.lock")))
}

type credentialLock interface {
	Lock() error
	Unlock() error
}

func (s ProfileStore) networkFingerprintSecret(root string, lock credentialLock) (secret []byte, resultErr error) {
	if root == "" || lock == nil {
		return nil, ErrCredentialStoreUnavailable
	}
	if err := lock.Lock(); err != nil {
		return nil, fmt.Errorf("lock network fingerprint secret: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clear(secret)
			secret = nil
		}
	}()
	refDigest := sha256.Sum256([]byte(root))
	ref := "network-fingerprint-v1-" + hex.EncodeToString(refDigest[:16])
	encoded, err := s.Secrets.Get(ref)
	if err == nil {
		return decodeNetworkFingerprintSecret(encoded)
	}
	if !errors.Is(err, ErrSecretNotFound) {
		return nil, fmt.Errorf("load network fingerprint secret: %w", err)
	}
	secret = make([]byte, networkFingerprintSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate network fingerprint secret: %w", err)
	}
	encoded = base64.RawURLEncoding.EncodeToString(secret)
	if err := s.Secrets.Set(ref, encoded); err != nil {
		clear(secret)
		return nil, fmt.Errorf("store network fingerprint secret: %w", err)
	}
	return secret, nil
}

func decodeNetworkFingerprintSecret(encoded string) ([]byte, error) {
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(secret) != networkFingerprintSecretBytes || base64.RawURLEncoding.EncodeToString(secret) != encoded {
		clear(secret)
		return nil, errors.New("network fingerprint secret is invalid")
	}
	return secret, nil
}
