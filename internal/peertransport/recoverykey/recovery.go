// Package recoverykey encodes the user-held Paperboat E2EE account-root seed.
package recoverykey

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2s"
)

const (
	Prefix       = "pb-e2ee-recovery-v1-"
	SeedSize     = 32
	checksumSize = 5
)

var ErrInvalid = errors.New("invalid Paperboat E2EE recovery key")

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Encode returns the canonical, versioned recovery-key representation.
func Encode(seed []byte) (string, error) {
	if len(seed) != SeedSize {
		return "", ErrInvalid
	}
	payload := make([]byte, 0, SeedSize+checksumSize)
	payload = append(payload, seed...)
	checksum := recoveryChecksum(seed)
	payload = append(payload, checksum[:]...)
	encoded := strings.ToLower(encoding.EncodeToString(payload))
	clear(payload)
	return Prefix + encoded, nil
}

// Decode validates a canonical recovery key and returns an independent seed.
// The caller must clear the returned seed after importing it into credential storage.
func Decode(value string) ([]byte, error) {
	if !strings.HasPrefix(value, Prefix) || strings.TrimSpace(value) != value {
		return nil, ErrInvalid
	}
	encoded := strings.TrimPrefix(value, Prefix)
	if encoded == "" || encoded != strings.ToLower(encoded) {
		return nil, ErrInvalid
	}
	payload, err := encoding.DecodeString(strings.ToUpper(encoded))
	if err != nil || len(payload) != SeedSize+checksumSize || strings.ToLower(encoding.EncodeToString(payload)) != encoded {
		clear(payload)
		return nil, ErrInvalid
	}
	want := recoveryChecksum(payload[:SeedSize])
	if subtle.ConstantTimeCompare(payload[SeedSize:], want[:]) != 1 {
		clear(payload)
		return nil, ErrInvalid
	}
	seed := append([]byte(nil), payload[:SeedSize]...)
	clear(payload)
	return seed, nil
}

func recoveryChecksum(seed []byte) [checksumSize]byte {
	const domain = "paperboat-e2ee-recovery-v1\x00"
	var input [len(domain) + SeedSize]byte
	copy(input[:], domain)
	copy(input[len(domain):], seed)
	digest := blake2s.Sum256(input[:])
	var checksum [checksumSize]byte
	copy(checksum[:], digest[:checksumSize])
	clear(input[:])
	clear(digest[:])
	return checksum
}
