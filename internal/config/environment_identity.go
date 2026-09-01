package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const environmentIdentityVersion = 1
const maximumEnvironmentIdentityGeneration = int64(1<<53 - 1)

// EnvironmentManagerIdentity is the local ENV-only identity for one enrolled
// management CLI. These keys are unrelated to peer transport and account root
// keys. Call Clear as soon as the operation using the private bytes ends.
type EnvironmentManagerIdentity struct {
	KeyGeneration           int64
	SigningSeed             [32]byte
	RecipientPrivate        [32]byte
	RecoveryPrivate         *[32]byte
	RecoveryPublic          [32]byte
	RecoveryRequired        bool
	RecoveryExportConfirmed bool
	AuthorityGeneration     int64
	AuthorityID             string
}

func (identity *EnvironmentManagerIdentity) Clear() {
	if identity == nil {
		return
	}
	clear(identity.SigningSeed[:])
	clear(identity.RecipientPrivate[:])
	if identity.RecoveryPrivate != nil {
		clear(identity.RecoveryPrivate[:])
	}
	clear(identity.RecoveryPublic[:])
	*identity = EnvironmentManagerIdentity{}
}

type environmentManagerIdentityRecord struct {
	Version                 int    `json:"version"`
	Kind                    string `json:"kind"`
	AccountID               string `json:"account_id"`
	SubjectID               string `json:"subject_id"`
	KeyGeneration           int64  `json:"key_generation"`
	SigningSeed             string `json:"signing_seed"`
	RecipientPrivate        string `json:"recipient_private"`
	RecoveryPrivate         string `json:"recovery_private,omitempty"`
	RecoveryPublic          string `json:"recovery_public,omitempty"`
	RecoveryRequired        bool   `json:"recovery_required,omitempty"`
	RecoveryExportConfirmed bool   `json:"recovery_export_confirmed,omitempty"`
	AuthorityGeneration     int64  `json:"authority_generation,omitempty"`
	AuthorityID             string `json:"authority_id,omitempty"`
}

// CreateEnvironmentManagerIdentity creates one atomic secure-store record.
// includeRecovery is true only for ENV authority genesis. Joining managers
// must use false so they can never replace the account recovery recipient.
func (s ProfileStore) CreateEnvironmentManagerIdentity(issuer, accountID, subjectID string, includeRecovery bool) (identity EnvironmentManagerIdentity, resultErr error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	if !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return EnvironmentManagerIdentity{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentManagerIdentity{}, fmt.Errorf("lock ENV manager identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			identity.Clear()
		}
	}()

	record, found, err := loadEnvironmentManagerIdentityRecord(s.Secrets, environmentManagerIdentitySecretRef(issuer, accountID, subjectID), accountID, subjectID)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	if found {
		if includeRecovery && !record.RecoveryRequired {
			return EnvironmentManagerIdentity{}, errors.New("existing ENV manager identity was not created for authority genesis")
		}
		return environmentIdentityFromRecord(record)
	}

	record = environmentManagerIdentityRecord{
		Version:          environmentIdentityVersion,
		Kind:             "environment_manager",
		AccountID:        accountID,
		SubjectID:        subjectID,
		KeyGeneration:    1,
		RecoveryRequired: includeRecovery,
	}
	keyMaterial := make([]byte, 64)
	if includeRecovery {
		keyMaterial = make([]byte, 96)
	}
	defer clear(keyMaterial)
	if _, err := rand.Read(keyMaterial); err != nil {
		return EnvironmentManagerIdentity{}, fmt.Errorf("generate ENV manager identity: %w", err)
	}
	record.SigningSeed = base64.RawURLEncoding.EncodeToString(keyMaterial[:32])
	record.RecipientPrivate = base64.RawURLEncoding.EncodeToString(keyMaterial[32:64])
	if includeRecovery {
		private, keyErr := ecdh.X25519().NewPrivateKey(keyMaterial[64:96])
		if keyErr != nil {
			return EnvironmentManagerIdentity{}, errors.New("generate ENV recovery identity")
		}
		canonicalPrivate := private.Bytes()
		record.RecoveryPrivate = base64.RawURLEncoding.EncodeToString(canonicalPrivate)
		clear(canonicalPrivate)
		public := private.PublicKey().Bytes()
		record.RecoveryPublic = base64.RawURLEncoding.EncodeToString(public)
		clear(public)
	}
	if err := storeEnvironmentManagerIdentityRecord(s.Secrets, environmentManagerIdentitySecretRef(issuer, accountID, subjectID), record); err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	return environmentIdentityFromRecord(record)
}

func (s ProfileStore) LoadEnvironmentManagerIdentity(issuer, accountID, subjectID string) (identity EnvironmentManagerIdentity, resultErr error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	if !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return EnvironmentManagerIdentity{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentManagerIdentity{}, fmt.Errorf("lock ENV manager identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			identity.Clear()
		}
	}()
	record, found, err := loadEnvironmentManagerIdentityRecord(s.Secrets, environmentManagerIdentitySecretRef(issuer, accountID, subjectID), accountID, subjectID)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	if !found {
		return EnvironmentManagerIdentity{}, ErrSecretNotFound
	}
	return environmentIdentityFromRecord(record)
}

// ConfirmEnvironmentRecoveryExport atomically removes the genesis recovery
// private key from online storage while retaining a durable confirmation bit.
func (s ProfileStore) ConfirmEnvironmentRecoveryExport(issuer, accountID, subjectID string, expectedPrivate [32]byte) (resultErr error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return err
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV manager identity: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := environmentManagerIdentitySecretRef(issuer, accountID, subjectID)
	record, found, err := loadEnvironmentManagerIdentityRecord(s.Secrets, ref, accountID, subjectID)
	if err != nil {
		return err
	}
	if !found {
		return ErrSecretNotFound
	}
	if record.RecoveryExportConfirmed && record.RecoveryPrivate == "" {
		return nil
	}
	if !record.RecoveryRequired || record.RecoveryPrivate == "" {
		return errors.New("ENV recovery export is not pending")
	}
	raw, err := decodeEnvironmentIdentityKey(record.RecoveryPrivate)
	if err != nil {
		return err
	}
	defer clear(raw)
	if subtle.ConstantTimeCompare(raw, expectedPrivate[:]) != 1 {
		return errors.New("ENV recovery export confirmation does not match local state")
	}
	record.RecoveryPrivate = ""
	record.RecoveryExportConfirmed = true
	return storeEnvironmentManagerIdentityRecord(s.Secrets, ref, record)
}

// CommitEnvironmentAuthorityHighWater persists one already verified
// sequential authority step. Rollback, fork, or skipped generations fail
// closed at the storage boundary too.
func (s ProfileStore) CommitEnvironmentAuthorityHighWater(issuer, accountID, subjectID string, generation int64, authorityID string) (resultErr error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return err
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || !validCredentialID(subjectID) || generation < 1 || generation > maximumEnvironmentIdentityGeneration || !environmentAuthorityIDPattern.MatchString(authorityID) {
		return errors.New("ENV authority high-water is invalid")
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV manager identity: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := environmentManagerIdentitySecretRef(issuer, accountID, subjectID)
	record, found, err := loadEnvironmentManagerIdentityRecord(s.Secrets, ref, accountID, subjectID)
	if err != nil {
		return err
	}
	if !found {
		return ErrSecretNotFound
	}
	if generation == record.AuthorityGeneration {
		if authorityID == record.AuthorityID {
			return nil
		}
		return errors.New("ENV authority fork conflicts with local high-water")
	}
	if generation != record.AuthorityGeneration+1 {
		return errors.New("ENV authority generation is not the next sequential step")
	}
	record.AuthorityGeneration = generation
	record.AuthorityID = authorityID
	return storeEnvironmentManagerIdentityRecord(s.Secrets, ref, record)
}

func (s ProfileStore) DeleteEnvironmentManagerIdentity(issuer, accountID, subjectID string) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV manager identity: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	return s.Secrets.Delete(environmentManagerIdentitySecretRef(issuer, accountID, subjectID))
}

// deleteEnvironmentManagerIdentityForProfile is used by auth cleanup paths
// where older profiles may legitimately have no account ID. A missing or
// malformed identity coordinate means there cannot be a valid ENV identity
// record for that profile and must not prevent logout.
func (s ProfileStore) deleteEnvironmentManagerIdentityForProfile(issuer, accountID, subjectID string) error {
	if !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return nil
	}
	return s.DeleteEnvironmentManagerIdentity(issuer, accountID, subjectID)
}

func environmentIdentityFromRecord(record environmentManagerIdentityRecord) (EnvironmentManagerIdentity, error) {
	signing, err := decodeEnvironmentIdentityKey(record.SigningSeed)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	defer clear(signing)
	recipient, err := decodeEnvironmentIdentityKey(record.RecipientPrivate)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	defer clear(recipient)
	identity := EnvironmentManagerIdentity{
		KeyGeneration:           record.KeyGeneration,
		RecoveryRequired:        record.RecoveryRequired,
		RecoveryExportConfirmed: record.RecoveryExportConfirmed,
		AuthorityGeneration:     record.AuthorityGeneration,
		AuthorityID:             record.AuthorityID,
	}
	if record.RecoveryPublic != "" {
		public, err := decodeEnvironmentIdentityKey(record.RecoveryPublic)
		if err != nil {
			identity.Clear()
			return EnvironmentManagerIdentity{}, err
		}
		copy(identity.RecoveryPublic[:], public)
		clear(public)
	}
	copy(identity.SigningSeed[:], signing)
	copy(identity.RecipientPrivate[:], recipient)
	if record.RecoveryPrivate != "" {
		recovery, err := decodeEnvironmentIdentityKey(record.RecoveryPrivate)
		if err != nil {
			identity.Clear()
			return EnvironmentManagerIdentity{}, err
		}
		identity.RecoveryPrivate = new([32]byte)
		copy(identity.RecoveryPrivate[:], recovery)
		clear(recovery)
	}
	return identity, nil
}

func loadEnvironmentManagerIdentityRecord(store SecretStore, ref, accountID, subjectID string) (environmentManagerIdentityRecord, bool, error) {
	encoded, err := store.Get(ref)
	if errors.Is(err, ErrSecretNotFound) {
		return environmentManagerIdentityRecord{}, false, nil
	}
	if err != nil {
		return environmentManagerIdentityRecord{}, false, fmt.Errorf("load ENV manager identity: %w", err)
	}
	var record environmentManagerIdentityRecord
	if json.Unmarshal([]byte(encoded), &record) != nil || record.Version != environmentIdentityVersion || record.Kind != "environment_manager" || record.AccountID != accountID || record.SubjectID != subjectID || record.KeyGeneration < 1 || record.KeyGeneration > maximumEnvironmentIdentityGeneration {
		return environmentManagerIdentityRecord{}, false, errors.New("ENV manager identity record is invalid")
	}
	canonical, marshalErr := json.Marshal(record)
	if marshalErr != nil || string(canonical) != encoded {
		return environmentManagerIdentityRecord{}, false, errors.New("ENV manager identity record is not canonical")
	}
	signing, err := decodeEnvironmentIdentityKey(record.SigningSeed)
	if err != nil {
		return environmentManagerIdentityRecord{}, false, err
	}
	clear(signing)
	recipient, err := decodeEnvironmentIdentityKey(record.RecipientPrivate)
	if err != nil {
		return environmentManagerIdentityRecord{}, false, err
	}
	clear(recipient)
	var recovery []byte
	if record.RecoveryPrivate != "" {
		recovery, err = decodeEnvironmentIdentityKey(record.RecoveryPrivate)
		if err != nil {
			return environmentManagerIdentityRecord{}, false, err
		}
		defer clear(recovery)
	}
	if record.RecoveryRequired {
		public, err := decodeEnvironmentIdentityKey(record.RecoveryPublic)
		if err != nil {
			return environmentManagerIdentityRecord{}, false, err
		}
		defer clear(public)
		if recovery != nil {
			private, keyErr := ecdh.X25519().NewPrivateKey(recovery)
			derived := []byte(nil)
			if keyErr == nil {
				derived = private.PublicKey().Bytes()
			}
			if keyErr != nil || subtle.ConstantTimeCompare(derived, public) != 1 {
				clear(derived)
				return environmentManagerIdentityRecord{}, false, errors.New("ENV recovery public key is invalid")
			}
			clear(derived)
		}
	} else if record.RecoveryPublic != "" {
		return environmentManagerIdentityRecord{}, false, errors.New("ENV recovery identity state is invalid")
	}
	if record.RecoveryRequired != (record.RecoveryPrivate != "" || record.RecoveryExportConfirmed) || record.RecoveryExportConfirmed && record.RecoveryPrivate != "" || !record.RecoveryRequired && record.RecoveryExportConfirmed {
		return environmentManagerIdentityRecord{}, false, errors.New("ENV recovery identity state is invalid")
	}
	if record.AuthorityGeneration == 0 && record.AuthorityID != "" || record.AuthorityGeneration > 0 && (record.AuthorityGeneration > maximumEnvironmentIdentityGeneration || !environmentAuthorityIDPattern.MatchString(record.AuthorityID)) {
		return environmentManagerIdentityRecord{}, false, errors.New("ENV authority high-water is invalid")
	}
	return record, true, nil
}

func storeEnvironmentManagerIdentityRecord(store SecretStore, ref string, record environmentManagerIdentityRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := store.Set(ref, string(encoded)); err != nil {
		return fmt.Errorf("store ENV manager identity: %w", err)
	}
	return nil
}

func decodeEnvironmentIdentityKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != encoded {
		clear(key)
		return nil, errors.New("ENV manager identity key is invalid")
	}
	return key, nil
}

func environmentManagerIdentitySecretRef(issuer, accountID, subjectID string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + subjectID + "\x00environment-manager"))
	return "environment-identity-v1-manager-" + hex.EncodeToString(digest[:16])
}

var environmentAuthorityIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// LockEnvironmentMutations serializes ciphertext draft creation and retry for
// one management identity across CLI processes. The returned function must be
// called exactly once.
func (s ProfileStore) LockEnvironmentMutations(issuer, accountID, subjectID string) (func() error, error) {
	if s.Path == "" || !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return nil, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + subjectID + "\x00environment-mutations"))
	lock := newSharedLock(s.profilePath(issuer) + ".environment-mutations-" + hex.EncodeToString(digest[:8]) + ".lock")
	if err := lock.Lock(); err != nil {
		return nil, fmt.Errorf("lock ENV mutations: %w", err)
	}
	return lock.Unlock, nil
}
