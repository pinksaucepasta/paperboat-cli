package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var (
	ErrInvalidStore = errors.New("invalid machine identity store")
	ErrKeyConflict  = errors.New("machine identity key changed")
)

type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type Config struct {
	StateRoot string
	Random    io.Reader
	Clock     Clock
}

type Key struct {
	ID         string
	Thumbprint string
	CreatedAt  time.Time
	private    ed25519.PrivateKey
}

const environmentWrappingDomain = "paperboat-environment-host-at-rest-wrap-v1\x00"

func (k Key) Public() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), k.private.Public().(ed25519.PublicKey)...)
}
func (k Key) Sign(message []byte) []byte { return ed25519.Sign(k.private, message) }

// EnvironmentWrappingKey derives the local-only root used to seal the
// dedicated ENV recipient key. It is deliberately separate from the ENV key
// itself and from signing operations: callers only receive a derived key, and
// the machine identity seed never leaves this package.
func (k Key) EnvironmentWrappingKey() ([32]byte, error) {
	if len(k.private) != ed25519.PrivateKeySize || k.ID == "" {
		return [32]byte{}, ErrInvalidStore
	}
	public := k.private.Public().(ed25519.PublicKey)
	if k.ID != "ed25519:"+jwkThumbprint(public) {
		return [32]byte{}, ErrInvalidStore
	}
	seed := k.private.Seed()
	defer clear(seed)
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(environmentWrappingDomain))
	_, _ = mac.Write(public)
	derived := mac.Sum(nil)
	defer clear(derived)
	var result [32]byte
	copy(result[:], derived)
	return result, nil
}

type document struct {
	Version   int       `json:"version"`
	KeyID     string    `json:"key_id"`
	Seed      string    `json:"seed_base64url"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	mu     sync.RWMutex
	config Config
	path   string
	key    Key
}

func Open(config Config) (*Store, error) {
	if !filepath.IsAbs(config.StateRoot) {
		return nil, ErrInvalidStore
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if err := privateDirectory(config.StateRoot); err != nil {
		return nil, err
	}
	store := &Store{config: config, path: filepath.Join(config.StateRoot, "machine-identity.json")}
	key, err := store.load()
	if errors.Is(err, os.ErrNotExist) {
		key, err = store.generate()
		if err == nil {
			err = store.write(key)
		}
	}
	if err != nil {
		return nil, err
	}
	store.key = key
	return store, nil
}

func (s *Store) Current() Key { s.mu.RLock(); defer s.mu.RUnlock(); return cloneKey(s.key) }

// EnvironmentWrappingKey derives the local-only root for portable ENV key
// custody from the current machine identity.
func (s *Store) EnvironmentWrappingKey() ([32]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key.EnvironmentWrappingKey()
}

func (s *Store) Rotate(expectedKeyID string) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedKeyID == "" || s.key.ID != expectedKeyID {
		return Key{}, ErrKeyConflict
	}
	next, err := s.generate()
	if err != nil {
		return Key{}, err
	}
	if err := s.write(next); err != nil {
		return Key{}, err
	}
	s.key = next
	return cloneKey(next), nil
}

func (s *Store) generate() (Key, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(s.config.Random, seed); err != nil {
		return Key{}, err
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	thumbprint := jwkThumbprint(public)
	return Key{ID: "ed25519:" + thumbprint, Thumbprint: thumbprint, CreatedAt: s.config.Clock.Now().UTC(), private: private}, nil
}

func (s *Store) load() (Key, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return Key{}, err
	}
	if !secureIdentityPath(s.path, info, true) {
		return Key{}, ErrInvalidStore
	}
	encoded, err := os.ReadFile(s.path)
	if err != nil {
		return Key{}, err
	}
	if len(encoded) > 4096 {
		return Key{}, ErrInvalidStore
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return Key{}, ErrInvalidStore
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value document
	if err := decoder.Decode(&value); err != nil {
		return Key{}, ErrInvalidStore
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Key{}, ErrInvalidStore
	}
	seed, err := base64.RawURLEncoding.DecodeString(value.Seed)
	if err != nil || value.Version != 1 || len(seed) != ed25519.SeedSize || value.CreatedAt.IsZero() {
		return Key{}, ErrInvalidStore
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	thumbprint := jwkThumbprint(public)
	if value.KeyID != "ed25519:"+thumbprint {
		return Key{}, ErrInvalidStore
	}
	return Key{ID: value.KeyID, Thumbprint: thumbprint, CreatedAt: value.CreatedAt, private: private}, nil
}

func (s *Store) write(key Key) error {
	if info, err := os.Lstat(s.path); err == nil {
		if !secureIdentityPath(s.path, info, false) {
			return ErrInvalidStore
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	seed := key.private.Seed()
	encoded, err := json.Marshal(document{Version: 1, KeyID: key.ID, Seed: base64.RawURLEncoding.EncodeToString(seed), CreatedAt: key.CreatedAt})
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, encoded, atomicfile.CurrentOwnerOptions(0o600))
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidStore
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return nil
}

func jwkThumbprint(public ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(public) + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return ErrInvalidStore
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidStore
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidStore
	}
	return nil
}

func cloneKey(key Key) Key { key.private = append(ed25519.PrivateKey(nil), key.private...); return key }
