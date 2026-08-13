package transfercrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

var ErrKeyUnavailable = errors.New("transfer key unavailable")

const maxPersistedKeySize = 4096

type SecretStore interface {
	Set(string, string) error
	Get(string) (string, error)
	Delete(string) error
}

type KeyVault struct {
	store SecretStore
	now   func() time.Time
}

type persistedKey struct {
	Version     uint8                `json:"version"`
	TransferID  string               `json:"transfer_id"`
	Generation  uint64               `json:"generation"`
	ExpiresAt   time.Time            `json:"expires_at"`
	Ownership   string               `json:"ownership"`
	KeyMaterial string               `json:"key_material"`
	PeerContext *peercontext.Context `json:"peer_context,omitempty"`
}

const (
	keyOwnershipLocal    = "local"
	keyOwnershipReceived = "received"
)

func NewKeyVault(store SecretStore) (*KeyVault, error) {
	if store == nil {
		return nil, errors.New("transfer key secret store is required")
	}
	return &KeyVault{store: store, now: time.Now}, nil
}

func (v *KeyVault) Save(transferID string, generation uint64, material KeyMaterial, expiresAt time.Time) error {
	return v.save(transferID, generation, material, expiresAt, keyOwnershipLocal, nil)
}

func (v *KeyVault) SaveBound(transferID string, generation uint64, material KeyMaterial, expiresAt time.Time, context peercontext.Context) error {
	return v.saveBound(transferID, generation, material, expiresAt, keyOwnershipReceived, context)
}

func (v *KeyVault) SaveLocalBound(transferID string, generation uint64, material KeyMaterial, expiresAt time.Time, context peercontext.Context) error {
	return v.saveBound(transferID, generation, material, expiresAt, keyOwnershipLocal, context)
}

func (v *KeyVault) saveBound(transferID string, generation uint64, material KeyMaterial, expiresAt time.Time, ownership string, context peercontext.Context) error {
	if context.OperationID == "" || context.Consumer != "file_transfer_key" {
		return ErrInvalid
	}
	if _, err := context.MarshalBinary(); err != nil {
		return ErrInvalid
	}
	return v.save(transferID, generation, material, expiresAt, ownership, &context)
}

func (v *KeyVault) save(transferID string, generation uint64, material KeyMaterial, expiresAt time.Time, ownership string, context *peercontext.Context) error {
	if v == nil || v.store == nil || !validTransferID(transferID) || generation == 0 || !material.Valid() || expiresAt.IsZero() || ownership != keyOwnershipLocal && ownership != keyOwnershipReceived {
		return ErrInvalid
	}
	if !expiresAt.After(v.now()) {
		return ErrInvalid
	}
	encoded, err := material.MarshalBinary()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(persistedKey{Version: ProtocolVersion, TransferID: transferID, Generation: generation, ExpiresAt: expiresAt.UTC(), Ownership: ownership, KeyMaterial: base64.RawStdEncoding.EncodeToString(encoded), PeerContext: context})
	if err != nil {
		return fmt.Errorf("encode transfer key: %w", err)
	}
	if err := v.store.Set(keyRef(transferID), string(payload)); err != nil {
		return fmt.Errorf("persist transfer key: %w", err)
	}
	return nil
}

func (v *KeyVault) LoadBound(transferID string, generation uint64) (KeyMaterial, peercontext.Context, error) {
	material, persisted, err := v.load(transferID, generation)
	if err != nil || persisted.PeerContext == nil || persisted.PeerContext.Consumer != "file_transfer_key" || persisted.PeerContext.OperationID == "" {
		material.Destroy()
		return KeyMaterial{}, peercontext.Context{}, ErrKeyUnavailable
	}
	if _, err := persisted.PeerContext.MarshalBinary(); err != nil {
		material.Destroy()
		return KeyMaterial{}, peercontext.Context{}, ErrKeyUnavailable
	}
	return material, *persisted.PeerContext, nil
}

func (v *KeyVault) LoadLocal(transferID string, generation uint64) (KeyMaterial, peercontext.Context, error) {
	material, persisted, err := v.load(transferID, generation)
	if err != nil || persisted.Ownership != keyOwnershipLocal {
		material.Destroy()
		return KeyMaterial{}, peercontext.Context{}, ErrKeyUnavailable
	}
	if persisted.PeerContext == nil {
		return material, peercontext.Context{}, nil
	}
	if _, err := persisted.PeerContext.MarshalBinary(); err != nil {
		material.Destroy()
		return KeyMaterial{}, peercontext.Context{}, ErrKeyUnavailable
	}
	return material, *persisted.PeerContext, nil
}

func (v *KeyVault) Load(transferID string, generation uint64) (KeyMaterial, error) {
	material, _, err := v.load(transferID, generation)
	return material, err
}

func (v *KeyVault) load(transferID string, generation uint64) (KeyMaterial, persistedKey, error) {
	if v == nil || v.store == nil || !validTransferID(transferID) || generation == 0 {
		return KeyMaterial{}, persistedKey{}, ErrInvalid
	}
	value, err := v.store.Get(keyRef(transferID))
	if err != nil {
		return KeyMaterial{}, persistedKey{}, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	persisted, err := decodePersistedKey(value)
	if err != nil || persisted.Version != ProtocolVersion || persisted.TransferID != transferID || persisted.Generation != generation || persisted.ExpiresAt.IsZero() || persisted.Ownership != keyOwnershipLocal && persisted.Ownership != keyOwnershipReceived {
		return KeyMaterial{}, persistedKey{}, ErrKeyUnavailable
	}
	if !persisted.ExpiresAt.After(v.now()) {
		if err := v.store.Delete(keyRef(transferID)); err != nil {
			return KeyMaterial{}, persistedKey{}, errors.Join(ErrKeyUnavailable, fmt.Errorf("delete expired transfer key: %w", err))
		}
		return KeyMaterial{}, persistedKey{}, ErrKeyUnavailable
	}
	encoded, err := base64.RawStdEncoding.DecodeString(persisted.KeyMaterial)
	if err != nil {
		return KeyMaterial{}, persistedKey{}, ErrKeyUnavailable
	}
	material, err := ParseKeyMaterial(encoded)
	if err != nil {
		return KeyMaterial{}, persistedKey{}, ErrKeyUnavailable
	}
	return material, persisted, nil
}

func decodePersistedKey(value string) (persistedKey, error) {
	var persisted persistedKey
	if len(value) == 0 || len(value) > maxPersistedKeySize {
		return persisted, ErrInvalid
	}

	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return persistedKey{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return persistedKey{}, ErrInvalid
	}

	canonicalPersisted := persisted
	canonicalPersisted.ExpiresAt = canonicalPersisted.ExpiresAt.UTC()
	canonical, err := json.Marshal(canonicalPersisted)
	if err != nil {
		return persistedKey{}, err
	}
	if !bytes.Equal(canonical, []byte(value)) {
		return persistedKey{}, ErrInvalid
	}
	return persisted, nil
}

func (v *KeyVault) Delete(transferID string) error {
	if v == nil || v.store == nil || !validTransferID(transferID) {
		return ErrInvalid
	}
	if err := v.store.Delete(keyRef(transferID)); err != nil {
		return fmt.Errorf("delete transfer key: %w", err)
	}
	return nil
}

var transferIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func validTransferID(value string) bool { return transferIDPattern.MatchString(value) }

func keyRef(transferID string) string {
	digest := sha256.Sum256([]byte(transferID))
	return "transfer-" + hex.EncodeToString(digest[:])
}
