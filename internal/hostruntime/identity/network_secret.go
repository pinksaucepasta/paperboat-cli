package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const networkFingerprintSecretSize = 32

func (s *Store) NetworkFingerprintSecret() ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.config.StateRoot, "network-fingerprint-secret.json")
	info, err := os.Lstat(path)
	if err == nil {
		if !secureIdentityPath(path, info, true) || info.Size() > 1024 {
			return nil, ErrInvalidStore
		}
		encoded, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		return decodeNetworkFingerprintSecret(encoded)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, networkFingerprintSecretSize)
	if _, err := io.ReadFull(s.config.Random, secret); err != nil {
		clear(secret)
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Version int    `json:"version"`
		Secret  string `json:"secret_base64url"`
	}{1, base64.RawURLEncoding.EncodeToString(secret)})
	if err != nil {
		clear(secret)
		return nil, err
	}
	if err := s.writePrivateDocument("network-fingerprint-secret.json", ".network-fingerprint-secret-*", encoded); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

func decodeNetworkFingerprintSecret(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document struct {
		Version int    `json:"version"`
		Secret  string `json:"secret_base64url"`
	}
	var extra any
	if decoder.Decode(&document) != nil || decoder.Decode(&extra) != io.EOF || document.Version != 1 {
		return nil, ErrInvalidStore
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(document.Secret)
	canonical, marshalErr := json.Marshal(document)
	if err != nil || len(secret) != networkFingerprintSecretSize || base64.RawURLEncoding.EncodeToString(secret) != document.Secret || marshalErr != nil || !bytes.Equal(canonical, encoded) {
		clear(secret)
		return nil, ErrInvalidStore
	}
	return secret, nil
}
