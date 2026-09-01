package environmentkey

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	CredentialName = "paperboat-environment-host-key"
	privateKeySize = 32
)

var (
	ErrUnavailable    = errors.New("secure environment host key storage is unavailable")
	ErrInvalid        = errors.New("environment host key is invalid")
	ErrSecretNotFound = errors.New("environment host key is not stored")
)

// Material is the dedicated X25519 recipient key for one host installation.
// Callers must call Destroy as soon as they no longer need the private bytes.
type Material struct {
	Generation uint64
	Private    [privateKeySize]byte
}

func (m *Material) Destroy() {
	if m == nil {
		return
	}
	clear(m.Private[:])
}

func (m Material) Public() ([privateKeySize]byte, error) {
	private, err := ecdh.X25519().NewPrivateKey(m.Private[:])
	if err != nil {
		return [privateKeySize]byte{}, ErrInvalid
	}
	var public [privateKeySize]byte
	copy(public[:], private.PublicKey().Bytes())
	return public, nil
}

// StateIntegrityKey derives a host-local key for authenticating monotonic ENV
// state. It is domain-separated from HPKE and never leaves the host.
func (m Material) StateIntegrityKey() ([sha256.Size]byte, error) {
	if m.Generation == 0 {
		return [sha256.Size]byte{}, ErrInvalid
	}
	if _, err := m.Public(); err != nil {
		return [sha256.Size]byte{}, err
	}
	mac := hmac.New(sha256.New, m.Private[:])
	_, _ = mac.Write([]byte("paperboat-environment-host-state-integrity-key-v1\x00"))
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], m.Generation)
	_, _ = mac.Write(generation[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

type Source interface {
	Load(context.Context) (Material, error)
}

type SecretStore interface {
	Set(string, string) error
	Get(string) (string, error)
	Delete(string) error
}

// environmentSecureStore is deliberately a separate marker from SecretStore.
// The latter also includes owner-only file stores used by unrelated config
// data; those stores are never an acceptable custody boundary for the host
// recipient private key.
type environmentSecureStore interface {
	SecretStore
	EnvironmentSecureStore()
}

// environmentHostKeyLocker is implemented by the production OS credential
// store adapter. It must coordinate the complete key/marker transaction
// across processes, not only goroutines in this process. A secure store that
// cannot provide that boundary is rejected rather than falling back to an
// unsafe check-then-set sequence.
type environmentHostKeyLocker interface {
	LockEnvironmentHostKey(string, uint64) (func() error, error)
}

// KeyringSource is used only where the platform's approved OS key store is
// available to the host service. It never falls back to an owner-only file.
type KeyringSource struct {
	Store      SecretStore
	MachineID  string
	Generation uint64
	Random     io.Reader
	NotFound   func(error) bool
}

func (s KeyringSource) Load(context.Context) (result Material, resultErr error) {
	if err := s.validate(); err != nil {
		return Material{}, err
	}
	unlock, err := s.lockEnvironmentHostKey()
	if err != nil {
		return Material{}, err
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			result.Destroy()
			result = Material{}
			resultErr = errors.Join(resultErr, ErrUnavailable, unlockErr)
		}
		if resultErr != nil {
			result.Destroy()
			result = Material{}
		}
	}()
	material, created, err := s.loadMaterial()
	if err != nil {
		return Material{}, err
	}
	result = material
	genesisMarkerMu.Lock()
	defer genesisMarkerMu.Unlock()
	if _, err := s.readGenesisMarker(material); err == nil {
		return result, nil
	} else if !errors.Is(err, ErrGenesisMarkerMissing) {
		return Material{}, err
	} else if !created {
		// A previously provisioned key without its installation marker is
		// unrecoverable. Never recreate the marker from a surviving key.
		return Material{}, ErrGenesisMarkerMissing
	}
	if err := s.createGenesisMarker(material); err != nil {
		return Material{}, err
	}
	return result, nil
}

func (s KeyringSource) validate() error {
	if s.Store == nil || s.NotFound == nil || !validIdentity(s.MachineID) || s.Generation == 0 {
		return ErrInvalid
	}
	if _, ok := s.Store.(environmentSecureStore); !ok {
		return ErrUnavailable
	}
	return nil
}

func (s KeyringSource) lockEnvironmentHostKey() (func() error, error) {
	locker, ok := s.Store.(environmentHostKeyLocker)
	if !ok {
		return nil, ErrUnavailable
	}
	unlock, err := locker.LockEnvironmentHostKey(s.MachineID, s.Generation)
	if err != nil || unlock == nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return unlock, nil
}

func (s KeyringSource) loadMaterial() (Material, bool, error) {
	if err := s.validate(); err != nil {
		return Material{}, false, err
	}
	ref := fmt.Sprintf("environment-host/%s/%d", s.MachineID, s.Generation)
	encoded, err := s.Store.Get(ref)
	created := false
	if err != nil && s.NotFound(err) {
		// A marker surviving key loss is evidence of an existing installation.
		// Do not generate a replacement key that could be paired with it.
		if _, markerErr := s.Store.Get(s.genesisReference()); markerErr == nil {
			return Material{}, false, ErrGenesisMarkerInvalid
		} else if !s.NotFound(markerErr) {
			return Material{}, false, errors.Join(ErrUnavailable, markerErr)
		}
		random := s.Random
		if random == nil {
			random = rand.Reader
		}
		seed := make([]byte, privateKeySize)
		if _, randomErr := io.ReadFull(random, seed); randomErr != nil {
			return Material{}, false, errors.Join(ErrUnavailable, randomErr)
		}
		encoded = base64.RawURLEncoding.EncodeToString(seed)
		clear(seed)
		if setErr := s.Store.Set(ref, encoded); setErr != nil {
			return Material{}, false, errors.Join(ErrUnavailable, setErr)
		}
		created = true
		// Read after write. This catches stores that created a duplicate item or
		// silently failed to replace the exact reference.
		encoded, err = s.Store.Get(ref)
	} else if err != nil {
		return Material{}, false, errors.Join(ErrUnavailable, err)
	}
	if err != nil {
		return Material{}, false, errors.Join(ErrUnavailable, err)
	}
	result, err := materialFromEncoded(encoded, s.Generation)
	if err != nil {
		return Material{}, false, err
	}
	return result, created, nil
}

func (s KeyringSource) loadExistingMaterial() (Material, error) {
	if err := s.validate(); err != nil {
		return Material{}, err
	}
	ref := fmt.Sprintf("environment-host/%s/%d", s.MachineID, s.Generation)
	encoded, err := s.Store.Get(ref)
	if err != nil {
		if s.NotFound(err) {
			return Material{}, ErrHostKeyMissing
		}
		return Material{}, errors.Join(ErrUnavailable, err)
	}
	return materialFromEncoded(encoded, s.Generation)
}

func materialFromEncoded(encoded string, generation uint64) (Material, error) {
	private, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(private) != privateKeySize || encoded != base64.RawURLEncoding.EncodeToString(private) {
		clear(private)
		return Material{}, ErrInvalid
	}
	var result Material
	result.Generation = generation
	copy(result.Private[:], private)
	clear(private)
	if _, err := result.Public(); err != nil {
		result.Destroy()
		return Material{}, err
	}
	return result, nil
}

func validIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
