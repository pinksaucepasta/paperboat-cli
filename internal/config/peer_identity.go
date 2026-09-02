package config

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

func (s ProfileStore) ExportPeerAccountRootSeed(issuer, accountID string) (seed []byte, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) {
		return nil, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clear(seed)
			seed = nil
		}
	}()
	seed, found, err := loadPeerKey(s.Secrets, peerIdentitySecretRef(issuer, accountID, "account-root"), "account_root_seed")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrSecretNotFound
	}
	return seed, nil
}

func (s ProfileStore) ImportPeerAccountRootSeed(issuer, accountID string, seed []byte) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || len(seed) != ed25519.SeedSize {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := peerIdentitySecretRef(issuer, accountID, "account-root")
	existing, found, err := loadPeerKey(s.Secrets, ref, "account_root_seed")
	if err != nil {
		return err
	}
	defer clear(existing)
	if found {
		if subtle.ConstantTimeCompare(existing, seed) != 1 {
			return errors.New("peer account root conflicts with local state")
		}
		return nil
	}
	return storePeerKey(s.Secrets, ref, "account_root_seed", seed)
}

// LoadPeerAccountRootPublic returns the account root public key without
// requiring custody of the account root private seed. Newly enrolled CLI
// endpoints use this verifier-only record when validating peer certificates.
func (s ProfileStore) LoadPeerAccountRootPublic(issuer, accountID string) (public ed25519.PublicKey, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) {
		return nil, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clear(public)
			public = nil
		}
	}()
	value, found, err := loadPeerKey(s.Secrets, peerIdentitySecretRef(issuer, accountID, "account-root-public"), "account_root_public")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrSecretNotFound
	}
	return ed25519.PublicKey(value), nil
}

// SavePeerAccountRootPublic persists the verifier-only account root public
// key. It is idempotent but rejects replacement, so an account cannot be
// silently rebound to a different root after enrollment.
func (s ProfileStore) SavePeerAccountRootPublic(issuer, accountID string, public ed25519.PublicKey) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || len(public) != ed25519.PublicKeySize {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := peerIdentitySecretRef(issuer, accountID, "account-root-public")
	existing, found, err := loadPeerKey(s.Secrets, ref, "account_root_public")
	if err != nil {
		return err
	}
	defer clear(existing)
	if found {
		if subtle.ConstantTimeCompare(existing, public) != 1 {
			return errors.New("peer account root public key conflicts with local state")
		}
		return nil
	}
	return storePeerKey(s.Secrets, ref, "account_root_public", public)
}

type PeerIdentityKeys struct {
	RootPrivate  ed25519.PrivateKey
	NoisePrivate [32]byte
	NoisePublic  [32]byte
	QUICPrivate  ed25519.PrivateKey
}

type peerKeyRecord struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Key     string `json:"key"`
}

type PeerCertificateState struct {
	Raw []byte
}

func (s ProfileStore) LoadPeerCertificate(issuer, endpointID string) (PeerCertificateState, error) {
	return s.peerCertificate(issuer, endpointID, nil)
}

func (s ProfileStore) SavePeerCertificate(issuer, endpointID string, raw []byte) (PeerCertificateState, error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return PeerCertificateState{}, errors.New("peer endpoint certificate is invalid")
	}
	return s.peerCertificate(issuer, endpointID, raw)
}

func (s ProfileStore) peerCertificate(issuer, endpointID string, proposed []byte) (state PeerCertificateState, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(endpointID) {
		return PeerCertificateState{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return PeerCertificateState{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-certificate.lock")
	if err := lock.Lock(); err != nil {
		return PeerCertificateState{}, fmt.Errorf("lock peer certificate: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clear(state.Raw)
			state = PeerCertificateState{}
		}
	}()
	ref := peerIdentitySecretRef(issuer, endpointID, "endpoint-certificate")
	existing, found, err := loadPeerCertificate(s.Secrets, ref)
	if err != nil {
		return PeerCertificateState{}, err
	}
	if found {
		if proposed != nil && !equalSecret(existing, proposed) {
			clear(existing)
			return PeerCertificateState{}, errors.New("peer endpoint certificate conflicts with local state")
		}
		return PeerCertificateState{Raw: existing}, nil
	}
	if proposed == nil {
		return PeerCertificateState{}, ErrSecretNotFound
	}
	record, err := json.Marshal(peerKeyRecord{Version: 1, Kind: "endpoint_certificate", Key: base64.RawURLEncoding.EncodeToString(proposed)})
	if err != nil {
		return PeerCertificateState{}, err
	}
	if err := s.Secrets.Set(ref, string(record)); err != nil {
		return PeerCertificateState{}, fmt.Errorf("store peer endpoint certificate: %w", err)
	}
	return PeerCertificateState{Raw: append([]byte(nil), proposed...)}, nil
}

func loadPeerCertificate(store SecretStore, ref string) ([]byte, bool, error) {
	encoded, err := store.Get(ref)
	if errors.Is(err, ErrSecretNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var record peerKeyRecord
	if json.Unmarshal([]byte(encoded), &record) != nil || record.Version != 1 || record.Kind != "endpoint_certificate" {
		return nil, false, errors.New("peer endpoint certificate record is invalid")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(record.Key)
	canonical, marshalErr := json.Marshal(record)
	if err != nil || len(raw) == 0 || len(raw) > 1024 || base64.RawURLEncoding.EncodeToString(raw) != record.Key || marshalErr != nil || string(canonical) != encoded {
		clear(raw)
		return nil, false, errors.New("peer endpoint certificate record is invalid")
	}
	return raw, true, nil
}

func equalSecret(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func (s ProfileStore) PeerIdentityKeys(issuer, accountID, endpointID string) (identity PeerIdentityKeys, resultErr error) {
	return s.peerIdentityKeys(issuer, accountID, endpointID, true)
}

func (s ProfileStore) PeerIdentityKeysForExistingRoot(issuer, accountID, endpointID string) (identity PeerIdentityKeys, resultErr error) {
	return s.peerIdentityKeys(issuer, accountID, endpointID, false)
}

// FreshPeerIdentityKeys loads or creates the signing and transport identity
// for one freshly issued endpoint session. Unlike PeerIdentityKeys, the
// signing seed is scoped to the endpoint session rather than the account
// root. This is required for a fresh enrollment into an account that already
// has an active device key: reusing the account root would make the server
// reject the new session as a key/session conflict.
//
// The identity is durable and keyed by endpointID, so a retry of the same
// pending enrollment presents the same public keys and idempotency operation.
// A different endpoint session gets a different signing identity. Existing
// account-root custody and normal resume behavior are never changed.
func (s ProfileStore) FreshPeerIdentityKeys(issuer, accountID, endpointID string) (identity PeerIdentityKeys, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || !validCredentialID(endpointID) {
		return PeerIdentityKeys{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return PeerIdentityKeys{}, fmt.Errorf("lock peer identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clearPeerIdentity(&identity)
		}
	}()

	signingRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-signing")
	noiseRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-noise")
	quicRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-quic")
	signingSeed, signingExists, err := loadPeerKey(s.Secrets, signingRef, "endpoint_signing_seed")
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	noisePrivate, noiseExists, err := loadPeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519")
	if err != nil {
		clear(signingSeed)
		return PeerIdentityKeys{}, err
	}
	quicSeed, quicExists, err := loadPeerKey(s.Secrets, quicRef, "endpoint_quic_seed")
	if err != nil {
		clear(signingSeed)
		clear(noisePrivate)
		return PeerIdentityKeys{}, err
	}
	defer clear(signingSeed)
	defer clear(noisePrivate)
	defer clear(quicSeed)
	if noiseExists != quicExists || signingExists && !noiseExists {
		return PeerIdentityKeys{}, errors.New("fresh peer endpoint identity is incomplete")
	}

	created := make([]string, 0, 3)
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			_ = s.Secrets.Delete(created[index])
		}
	}
	if !signingExists {
		signingSeed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(signingSeed); err != nil {
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint signing identity: %w", err)
		}
		if err := storePeerKey(s.Secrets, signingRef, "endpoint_signing_seed", signingSeed); err != nil {
			return PeerIdentityKeys{}, err
		}
		created = append(created, signingRef)
	}
	if !noiseExists {
		noiseKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			rollback()
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint Noise identity: %w", err)
		}
		noisePrivate = append([]byte(nil), noiseKey.Bytes()...)
		quicSeed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(quicSeed); err != nil {
			rollback()
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint QUIC identity: %w", err)
		}
		if err := storePeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519", noisePrivate); err != nil {
			rollback()
			return PeerIdentityKeys{}, err
		}
		created = append(created, noiseRef)
		if err := storePeerKey(s.Secrets, quicRef, "endpoint_quic_seed", quicSeed); err != nil {
			rollback()
			return PeerIdentityKeys{}, err
		}
		created = append(created, quicRef)
	}

	if len(signingSeed) != ed25519.SeedSize || len(noisePrivate) != 32 || len(quicSeed) != ed25519.SeedSize {
		rollback()
		return PeerIdentityKeys{}, errors.New("fresh peer endpoint identity key size is invalid")
	}
	noiseKey, err := ecdh.X25519().NewPrivateKey(noisePrivate)
	if err != nil {
		rollback()
		return PeerIdentityKeys{}, errors.New("fresh peer Noise identity is invalid")
	}
	identity.RootPrivate = ed25519.NewKeyFromSeed(signingSeed)
	identity.QUICPrivate = ed25519.NewKeyFromSeed(quicSeed)
	copy(identity.NoisePrivate[:], noisePrivate)
	copy(identity.NoisePublic[:], noiseKey.PublicKey().Bytes())
	return identity, nil
}

// PeerEndpointKeys loads or creates only the endpoint transport keys. It never
// creates or loads an account root private key, which is the required custody
// boundary for a CLI enrolled into an account that already has a root.
func (s ProfileStore) PeerEndpointKeys(issuer, accountID, endpointID string) (identity PeerIdentityKeys, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || !validCredentialID(endpointID) {
		return PeerIdentityKeys{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return PeerIdentityKeys{}, fmt.Errorf("lock peer identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clearPeerIdentity(&identity)
		}
	}()

	noiseRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-noise")
	quicRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-quic")
	noisePrivate, noiseExists, err := loadPeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519")
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	quicSeed, quicExists, err := loadPeerKey(s.Secrets, quicRef, "endpoint_quic_seed")
	if err != nil {
		clear(noisePrivate)
		return PeerIdentityKeys{}, err
	}
	defer clear(noisePrivate)
	defer clear(quicSeed)
	if noiseExists != quicExists {
		return PeerIdentityKeys{}, errors.New("peer endpoint identity is incomplete")
	}

	created := make([]string, 0, 2)
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			_ = s.Secrets.Delete(created[index])
		}
	}
	if !noiseExists {
		noiseKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint Noise identity: %w", err)
		}
		noisePrivate = append([]byte(nil), noiseKey.Bytes()...)
		quicSeed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(quicSeed); err != nil {
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint QUIC identity: %w", err)
		}
		if err := storePeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519", noisePrivate); err != nil {
			return PeerIdentityKeys{}, err
		}
		created = append(created, noiseRef)
		if err := storePeerKey(s.Secrets, quicRef, "endpoint_quic_seed", quicSeed); err != nil {
			rollback()
			return PeerIdentityKeys{}, err
		}
		created = append(created, quicRef)
	}
	if len(noisePrivate) != 32 || len(quicSeed) != ed25519.SeedSize {
		rollback()
		return PeerIdentityKeys{}, errors.New("peer endpoint key size is invalid")
	}
	noiseKey, err := ecdh.X25519().NewPrivateKey(noisePrivate)
	if err != nil {
		rollback()
		return PeerIdentityKeys{}, errors.New("peer Noise identity is invalid")
	}
	identity.QUICPrivate = ed25519.NewKeyFromSeed(quicSeed)
	copy(identity.NoisePrivate[:], noisePrivate)
	copy(identity.NoisePublic[:], noiseKey.PublicKey().Bytes())
	return identity, nil
}

func (s ProfileStore) DeletePeerEndpointIdentity(issuer, endpointID string) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(endpointID) {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	resultErr = errors.Join(
		s.Secrets.Delete(peerIdentitySecretRef(issuer, endpointID, "endpoint-noise")),
		s.Secrets.Delete(peerIdentitySecretRef(issuer, endpointID, "endpoint-quic")),
		s.Secrets.Delete(peerIdentitySecretRef(issuer, endpointID, "endpoint-signing")),
		lock.Unlock(),
	)
	certificateLock := newSharedLock(s.profilePath(issuer) + ".peer-certificate.lock")
	if err := certificateLock.Lock(); err != nil {
		return errors.Join(resultErr, err)
	}
	return errors.Join(resultErr, s.Secrets.Delete(peerIdentitySecretRef(issuer, endpointID, "endpoint-certificate")), certificateLock.Unlock())
}

func (s ProfileStore) DeletePeerAccountRoot(issuer, accountID string) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || accountID == "" {
		return nil
	}
	if !validCredentialID(accountID) {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	return errors.Join(
		s.Secrets.Delete(peerIdentitySecretRef(issuer, accountID, "account-root")),
		s.Secrets.Delete(peerIdentitySecretRef(issuer, accountID, "account-root-public")),
	)
}

func (s ProfileStore) peerIdentityKeys(issuer, accountID, endpointID string, createRoot bool) (identity PeerIdentityKeys, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || !validCredentialID(endpointID) {
		return PeerIdentityKeys{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".peer-identity.lock")
	if err := lock.Lock(); err != nil {
		return PeerIdentityKeys{}, fmt.Errorf("lock peer identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			clearPeerIdentity(&identity)
		}
	}()

	rootRef := peerIdentitySecretRef(issuer, accountID, "account-root")
	noiseRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-noise")
	quicRef := peerIdentitySecretRef(issuer, endpointID, "endpoint-quic")
	rootSeed, rootExists, err := loadPeerKey(s.Secrets, rootRef, "account_root_seed")
	if err != nil {
		return PeerIdentityKeys{}, err
	}
	noisePrivate, noiseExists, err := loadPeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519")
	if err != nil {
		clear(rootSeed)
		return PeerIdentityKeys{}, err
	}
	quicSeed, quicExists, err := loadPeerKey(s.Secrets, quicRef, "endpoint_quic_seed")
	if err != nil {
		clear(rootSeed)
		clear(noisePrivate)
		return PeerIdentityKeys{}, err
	}
	defer clear(rootSeed)
	defer clear(noisePrivate)
	defer clear(quicSeed)
	if noiseExists != quicExists {
		return PeerIdentityKeys{}, errors.New("peer endpoint identity is incomplete")
	}

	created := make([]string, 0, 3)
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			_ = s.Secrets.Delete(created[index])
		}
	}
	if !rootExists {
		if !createRoot {
			return PeerIdentityKeys{}, ErrSecretNotFound
		}
		rootSeed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(rootSeed); err != nil {
			return PeerIdentityKeys{}, fmt.Errorf("generate account root: %w", err)
		}
		if err := storePeerKey(s.Secrets, rootRef, "account_root_seed", rootSeed); err != nil {
			return PeerIdentityKeys{}, err
		}
		created = append(created, rootRef)
	}
	if !noiseExists {
		noiseKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			rollback()
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint Noise identity: %w", err)
		}
		noisePrivate = append([]byte(nil), noiseKey.Bytes()...)
		quicSeed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(quicSeed); err != nil {
			rollback()
			return PeerIdentityKeys{}, fmt.Errorf("generate endpoint QUIC identity: %w", err)
		}
		if err := storePeerKey(s.Secrets, noiseRef, "endpoint_noise_x25519", noisePrivate); err != nil {
			rollback()
			return PeerIdentityKeys{}, err
		}
		created = append(created, noiseRef)
		if err := storePeerKey(s.Secrets, quicRef, "endpoint_quic_seed", quicSeed); err != nil {
			rollback()
			return PeerIdentityKeys{}, err
		}
		created = append(created, quicRef)
	}

	if len(rootSeed) != ed25519.SeedSize || len(noisePrivate) != 32 || len(quicSeed) != ed25519.SeedSize {
		rollback()
		return PeerIdentityKeys{}, errors.New("peer identity key size is invalid")
	}
	noiseKey, err := ecdh.X25519().NewPrivateKey(noisePrivate)
	if err != nil {
		rollback()
		return PeerIdentityKeys{}, errors.New("peer Noise identity is invalid")
	}
	identity.RootPrivate = ed25519.NewKeyFromSeed(rootSeed)
	identity.QUICPrivate = ed25519.NewKeyFromSeed(quicSeed)
	copy(identity.NoisePrivate[:], noisePrivate)
	copy(identity.NoisePublic[:], noiseKey.PublicKey().Bytes())
	return identity, nil
}

func loadPeerKey(store SecretStore, ref, kind string) ([]byte, bool, error) {
	encoded, err := store.Get(ref)
	if errors.Is(err, ErrSecretNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load %s: %w", kind, err)
	}
	var record peerKeyRecord
	if json.Unmarshal([]byte(encoded), &record) != nil || record.Version != 1 || record.Kind != kind {
		return nil, false, fmt.Errorf("%s record is invalid", kind)
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(record.Key)
	if err != nil || base64.RawURLEncoding.EncodeToString(key) != record.Key || len(key) != 32 {
		clear(key)
		return nil, false, fmt.Errorf("%s record is invalid", kind)
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != encoded {
		clear(key)
		return nil, false, fmt.Errorf("%s record is not canonical", kind)
	}
	return key, true, nil
}

func storePeerKey(store SecretStore, ref, kind string, key []byte) error {
	if len(key) != 32 {
		return errors.New("peer identity key size is invalid")
	}
	encoded, err := json.Marshal(peerKeyRecord{Version: 1, Kind: kind, Key: base64.RawURLEncoding.EncodeToString(key)})
	if err != nil {
		return err
	}
	if err := store.Set(ref, string(encoded)); err != nil {
		return fmt.Errorf("store %s: %w", kind, err)
	}
	return nil
}

func peerIdentitySecretRef(issuer, identity, kind string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + identity + "\x00" + kind))
	return "peer-identity-v1-" + kind + "-" + hex.EncodeToString(digest[:16])
}

func clearPeerIdentity(identity *PeerIdentityKeys) {
	if identity == nil {
		return
	}
	clear(identity.RootPrivate)
	clear(identity.NoisePrivate[:])
	clear(identity.NoisePublic[:])
	clear(identity.QUICPrivate)
	*identity = PeerIdentityKeys{}
}
