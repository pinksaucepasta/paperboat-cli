package trustedkeys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

var ErrInvalid = errors.New("invalid trusted E2EE key set")

// FromAPI validates and decodes the server's canonical public trust metadata.
// Key IDs are deterministic fingerprints, which prevents a caller from
// selecting one public key while claiming another key's identifier.
func FromAPI(values []api.E2EEKey) ([]endpointidentity.TrustedKey, error) {
	if len(values) == 0 {
		return nil, ErrInvalid
	}
	decoded := make([]endpointidentity.TrustedKey, 0, len(values))
	for _, value := range values {
		public, err := base64.RawURLEncoding.Strict().DecodeString(value.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != value.PublicKey {
			clear(public)
			return nil, ErrInvalid
		}
		fingerprintBytes, err := hex.DecodeString(value.Fingerprint)
		if err != nil || len(fingerprintBytes) != sha256.Size || hex.EncodeToString(fingerprintBytes) != value.Fingerprint {
			clear(public)
			clear(fingerprintBytes)
			return nil, ErrInvalid
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], fingerprintBytes)
		clear(fingerprintBytes)
		if fingerprint != sha256.Sum256(public) || value.KeyID != "aek_"+hex.EncodeToString(fingerprint[:]) {
			clear(public)
			return nil, ErrInvalid
		}
		decoded = append(decoded, endpointidentity.TrustedKey{KeyID: value.KeyID, PublicKey: ed25519.PublicKey(public), Fingerprint: fingerprint, Generation: value.Generation})
	}
	validated, err := endpointidentity.ValidateTrustedKeySet(decoded)
	Clear(decoded)
	if err != nil {
		return nil, ErrInvalid
	}
	return validated, nil
}

func Root(root api.E2EERoot) ([]endpointidentity.TrustedKey, error) {
	if root.Version != 1 {
		return nil, ErrInvalid
	}
	return FromAPI(root.TrustedKeys)
}

func Bootstrap(result api.E2EEBootstrapResult) ([]endpointidentity.TrustedKey, error) {
	if result.KeyID == "" {
		return nil, ErrInvalid
	}
	keys, err := FromAPI(result.TrustedKeys)
	if err != nil {
		return nil, err
	}
	if _, ok := endpointidentity.TrustedKeyFor(keys, result.KeyID); !ok {
		Clear(keys)
		return nil, ErrInvalid
	}
	return keys, nil
}

func ByPublic(keys []endpointidentity.TrustedKey, public ed25519.PublicKey) (endpointidentity.TrustedKey, bool) {
	for _, key := range keys {
		if endpointidentity.TrustedKeyMatchesPublic(key, public) {
			return key, true
		}
	}
	return endpointidentity.TrustedKey{}, false
}

func FingerprintString(key endpointidentity.TrustedKey) string {
	return hex.EncodeToString(key.Fingerprint[:])
}

// Clear releases the public-key buffers retained by a trusted-key set.
// Although public material is not secret, callers use this when replacing an
// authority so stale trust cannot accidentally survive a refresh.
func Clear(keys []endpointidentity.TrustedKey) {
	for index := range keys {
		clear(keys[index].PublicKey)
	}
}
