package candidatelease

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var ErrInvalid = errors.New("invalid candidate lease")

// ID identifies one authenticated physical candidate, not a descriptor.
type ID string

func NewID(transcript []byte, intent string, attempt uint64, path string) (ID, error) {
	if len(transcript) == 0 || intent == "" || attempt == 0 || path == "" {
		return "", ErrInvalid
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("paperboat-candidate-v1\x00"))
	h.Write(transcript)
	h.Write([]byte{0})
	h.Write([]byte(intent))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(raw)
	return ID(hex.EncodeToString(h.Sum(nil)[:16])), nil
}
