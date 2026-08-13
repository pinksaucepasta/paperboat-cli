package managedssh

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

const MaxHostKeyBytes = 8192

var ErrHostKeyInventory = errors.New("managed SSH host-key inventory is invalid")

type HostPublicKey struct {
	Fingerprint [32]byte
	Algorithm   string
	PublicKey   string
}

type HostKeyInventory struct {
	Keys        []HostPublicKey
	Fingerprint [32]byte
}

func ParseHostPublicKeys(values []string) ([]HostPublicKey, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, ErrHostKeyInventory
	}
	result := make([]HostPublicKey, 0, len(values))
	seen := make(map[[32]byte]bool, len(values))
	for _, value := range values {
		public, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
		if err != nil || !validHostKeyAlgorithm(public.Type()) || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || strings.ContainsAny(comment, "\r\n\x00") {
			return nil, ErrHostKeyInventory
		}
		fingerprint := sha256.Sum256(public.Marshal())
		if seen[fingerprint] {
			return nil, ErrHostKeyInventory
		}
		seen[fingerprint] = true
		result = append(result, HostPublicKey{Fingerprint: fingerprint, Algorithm: public.Type(), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))})
	}
	return result, nil
}

func ReadHostPublicKeys(paths []string, ownerUID uint32) (HostKeyInventory, error) {
	if len(paths) == 0 || len(paths) > 16 {
		return HostKeyInventory{}, ErrHostKeyInventory
	}
	result := HostKeyInventory{Keys: make([]HostPublicKey, 0, len(paths))}
	seenPaths := make(map[string]bool, len(paths))
	seenKeys := make(map[[32]byte]bool, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) || filepath.Ext(path) != ".pub" || seenPaths[path] {
			return HostKeyInventory{}, ErrHostKeyInventory
		}
		seenPaths[path] = true
		value, err := readOwnedPublicFile(path, ownerUID, MaxHostKeyBytes)
		if err != nil {
			return HostKeyInventory{}, fmt.Errorf("read SSH host public key: %w", err)
		}
		public, comment, options, rest, err := ssh.ParseAuthorizedKey(value)
		if err != nil || !validHostKeyAlgorithm(public.Type()) || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || strings.ContainsAny(comment, "\r\n\x00") {
			return HostKeyInventory{}, ErrHostKeyInventory
		}
		fingerprint := sha256.Sum256(public.Marshal())
		if seenKeys[fingerprint] {
			return HostKeyInventory{}, ErrHostKeyInventory
		}
		seenKeys[fingerprint] = true
		result.Keys = append(result.Keys, HostPublicKey{Fingerprint: fingerprint, Algorithm: public.Type(), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))})
	}
	slices.SortFunc(result.Keys, func(a, b HostPublicKey) int {
		return strings.Compare(string(a.Fingerprint[:]), string(b.Fingerprint[:]))
	})
	result.Fingerprint = hostKeySetFingerprint(result.Keys)
	return result, nil
}

func hostKeySetFingerprint(keys []HostPublicKey) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("paperboat-ssh-host-key-set-v1"))
	for _, key := range keys {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(key.PublicKey)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(key.PublicKey))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validHostKeyAlgorithm(value string) bool {
	switch value {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return true
	default:
		return false
	}
}

func readOwnedPublicFile(path string, ownerUID uint32, limit int64) ([]byte, error) {
	file, err := openOwnedPublicFile(path, ownerUID)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || int64(len(value)) > limit {
		return nil, ErrHostKeyInventory
	}
	return value, nil
}
