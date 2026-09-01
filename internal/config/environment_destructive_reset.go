package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

const environmentDestructiveResetVersion = 1

// EnvironmentDestructiveResetPreparation exposes only public key metadata and
// a caller-owned recovery export. All manager private keys remain in the OS
// secure store. Recovery is present only until its exact export is confirmed.
type EnvironmentDestructiveResetPreparation struct {
	Handle                  string
	Recovery                []byte
	ManagerSigningPublic    []byte
	ManagerSigningKeyID     string
	ManagerRecipientPublic  []byte
	ManagerRecipientKeyID   string
	RecoveryRecipientPublic []byte
	RecoveryRecipientKeyID  string
	KeyGeneration           int64
	ExportConfirmed         bool
}

func (value *EnvironmentDestructiveResetPreparation) Clear() {
	if value == nil {
		return
	}
	clear(value.Recovery)
	clear(value.ManagerSigningPublic)
	clear(value.ManagerRecipientPublic)
	clear(value.RecoveryRecipientPublic)
	*value = EnvironmentDestructiveResetPreparation{}
}

type environmentDestructiveResetRecord struct {
	Version          int    `json:"version"`
	Kind             string `json:"kind"`
	AccountID        string `json:"account_id"`
	SubjectID        string `json:"subject_id"`
	KeyGeneration    int64  `json:"key_generation"`
	SigningSeed      string `json:"signing_seed"`
	RecipientPrivate string `json:"recipient_private"`
	RecoveryPrivate  string `json:"recovery_private,omitempty"`
	RecoveryPublic   string `json:"recovery_public"`
	ExportConfirmed  bool   `json:"export_confirmed,omitempty"`
}

func (s ProfileStore) BeginEnvironmentDestructiveResetPreparation(issuer, accountID, subjectID string) (EnvironmentDestructiveResetPreparation, error) {
	issuer, handle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentDestructiveResetPreparation{}, fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer lock.Unlock()
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, environmentDestructiveResetRef(issuer, accountID, handle), accountID, subjectID)
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	if !found {
		material := make([]byte, 96)
		defer clear(material)
		if _, err := rand.Read(material); err != nil {
			return EnvironmentDestructiveResetPreparation{}, fmt.Errorf("generate ENV destructive reset keys: %w", err)
		}
		recoveryKey, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(material[64:96])
		if err != nil {
			return EnvironmentDestructiveResetPreparation{}, errors.New("generate ENV destructive reset recovery key")
		}
		// X25519 canonicalizes the private scalar before it is used. Store the
		// exact scalar represented by the recovery export, not the random input
		// bytes, so confirmation survives the encode/decode round trip.
		recoveryPrivate, err := recoveryKey.Bytes()
		if err != nil {
			return EnvironmentDestructiveResetPreparation{}, errors.New("generate ENV destructive reset recovery key")
		}
		defer clear(recoveryPrivate)
		recoveryPublic := recoveryKey.PublicKey().Bytes()
		defer clear(recoveryPublic)
		record = environmentDestructiveResetRecord{
			Version: environmentDestructiveResetVersion, Kind: "environment_destructive_reset",
			AccountID: accountID, SubjectID: subjectID, KeyGeneration: 1,
			SigningSeed: base64.RawURLEncoding.EncodeToString(material[:32]), RecipientPrivate: base64.RawURLEncoding.EncodeToString(material[32:64]),
			RecoveryPrivate: base64.RawURLEncoding.EncodeToString(recoveryPrivate), RecoveryPublic: base64.RawURLEncoding.EncodeToString(recoveryPublic),
		}
		if err := storeEnvironmentDestructiveResetRecord(s.Secrets, environmentDestructiveResetRef(issuer, accountID, handle), record); err != nil {
			return EnvironmentDestructiveResetPreparation{}, err
		}
	}
	return destructiveResetPreparation(handle, record)
}

func (s ProfileStore) ResumeEnvironmentDestructiveResetPreparation(issuer, accountID, subjectID string) (EnvironmentDestructiveResetPreparation, error) {
	issuer, handle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentDestructiveResetPreparation{}, fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer lock.Unlock()
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, environmentDestructiveResetRef(issuer, accountID, handle), accountID, subjectID)
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	if !found {
		return EnvironmentDestructiveResetPreparation{}, ErrSecretNotFound
	}
	return destructiveResetPreparation(handle, record)
}

// ConfirmEnvironmentDestructiveResetExport verifies the exact offline export
// and erases the replacement recovery private key before any server mutation.
func (s ProfileStore) ConfirmEnvironmentDestructiveResetExport(issuer, accountID, subjectID, handle string, encoded []byte) (resultErr error) {
	decoded, err := environmente2ee.DecodeRecoveryBytes(encoded)
	if err != nil {
		return errors.New("ENV destructive reset recovery confirmation is invalid")
	}
	defer clear(decoded)
	issuer, expectedHandle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil || handle != expectedHandle {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := environmentDestructiveResetRef(issuer, accountID, handle)
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, ref, accountID, subjectID)
	if err != nil {
		return err
	}
	if !found {
		return ErrSecretNotFound
	}
	if record.ExportConfirmed && record.RecoveryPrivate == "" {
		return nil
	}
	private, err := decodeEnvironmentIdentityKey(record.RecoveryPrivate)
	if err != nil {
		return err
	}
	defer clear(private)
	if subtle.ConstantTimeCompare(private, decoded) != 1 {
		return errors.New("ENV destructive reset recovery confirmation does not match")
	}
	record.RecoveryPrivate = ""
	record.ExportConfirmed = true
	return storeEnvironmentDestructiveResetRecord(s.Secrets, ref, record)
}

// UpdateEnvironmentDestructiveResetKeyGeneration records the successor
// manager's monotonic key generation before its authority binding is signed.
// A total reset reuses the current CLI endpoint subject, so replacing a prior
// manager binding must advance that subject's manager-key generation.
func (s ProfileStore) UpdateEnvironmentDestructiveResetKeyGeneration(issuer, accountID, subjectID, handle string, keyGeneration int64) (resultErr error) {
	issuer, expectedHandle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil || handle != expectedHandle || keyGeneration < 1 || keyGeneration > maximumEnvironmentIdentityGeneration {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := environmentDestructiveResetRef(issuer, accountID, handle)
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, ref, accountID, subjectID)
	if err != nil {
		return err
	}
	if !found {
		return ErrSecretNotFound
	}
	if !record.ExportConfirmed || record.RecoveryPrivate != "" {
		return errors.New("ENV destructive reset recovery export confirmation required")
	}
	if record.KeyGeneration == keyGeneration {
		return nil
	}
	record.KeyGeneration = keyGeneration
	return storeEnvironmentDestructiveResetRecord(s.Secrets, ref, record)
}

// LoadConfirmedEnvironmentDestructiveResetIdentity returns a detached copy of
// the fresh manager identity. The replacement recovery private key is already
// absent; only its public recipient remains.
func (s ProfileStore) LoadConfirmedEnvironmentDestructiveResetIdentity(issuer, accountID, subjectID, handle string) (EnvironmentManagerIdentity, error) {
	issuer, expectedHandle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil || handle != expectedHandle {
		return EnvironmentManagerIdentity{}, ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentManagerIdentity{}, fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer lock.Unlock()
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, environmentDestructiveResetRef(issuer, accountID, handle), accountID, subjectID)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	if !found {
		return EnvironmentManagerIdentity{}, ErrSecretNotFound
	}
	return destructiveResetIdentity(record)
}

// CommitEnvironmentDestructiveResetIdentity installs the prepared manager only
// after atomic server activation. Repeating after a crash is safe, including
// when the preparation was already erased.
func (s ProfileStore) CommitEnvironmentDestructiveResetIdentity(issuer, accountID, subjectID, handle string, generation int64, authorityID string) (resultErr error) {
	issuer, expectedHandle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil || handle != expectedHandle || generation < 1 || generation > maximumEnvironmentIdentityGeneration || !environmentAuthorityIDPattern.MatchString(authorityID) {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := environmentDestructiveResetRef(issuer, accountID, handle)
	record, found, err := loadEnvironmentDestructiveResetRecord(s.Secrets, ref, accountID, subjectID)
	if err != nil {
		return err
	}
	primaryRef := environmentManagerIdentitySecretRef(issuer, accountID, subjectID)
	if !found {
		primary, exists, loadErr := loadEnvironmentManagerIdentityRecord(s.Secrets, primaryRef, accountID, subjectID)
		if loadErr != nil {
			return loadErr
		}
		if exists && primary.RecoveryRequired && primary.RecoveryExportConfirmed && primary.RecoveryPrivate == "" && primary.AuthorityGeneration == generation && primary.AuthorityID == authorityID {
			return nil
		}
		return ErrSecretNotFound
	}
	if !record.ExportConfirmed || record.RecoveryPrivate != "" {
		return errors.New("ENV destructive reset recovery export confirmation required")
	}
	primary := environmentManagerIdentityRecord{
		Version: environmentIdentityVersion, Kind: "environment_manager", AccountID: accountID, SubjectID: subjectID,
		KeyGeneration: record.KeyGeneration, SigningSeed: record.SigningSeed, RecipientPrivate: record.RecipientPrivate,
		RecoveryPublic: record.RecoveryPublic, RecoveryRequired: true, RecoveryExportConfirmed: true,
		AuthorityGeneration: generation, AuthorityID: authorityID,
	}
	if err := storeEnvironmentManagerIdentityRecord(s.Secrets, primaryRef, primary); err != nil {
		return err
	}
	if err := s.Secrets.Delete(ref); err != nil && !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	return nil
}

func (s ProfileStore) CancelEnvironmentDestructiveResetPreparation(issuer, accountID, subjectID, handle string) (resultErr error) {
	issuer, expectedHandle, err := environmentDestructiveResetCoordinates(s, issuer, accountID, subjectID)
	if err != nil || handle != expectedHandle {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-identity.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV destructive reset: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	err = s.Secrets.Delete(environmentDestructiveResetRef(issuer, accountID, handle))
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	return err
}

func destructiveResetPreparation(handle string, record environmentDestructiveResetRecord) (result EnvironmentDestructiveResetPreparation, resultErr error) {
	identity, err := destructiveResetIdentityUnchecked(record)
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	defer identity.Clear()
	signingPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signingPrivate)
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	recipientKey, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		return EnvironmentDestructiveResetPreparation{}, err
	}
	recipientPublic := recipientKey.PublicKey().Bytes()
	signingID, err := environmente2ee.KeyIDEd25519(signingPublic)
	if err != nil {
		clear(recipientPublic)
		return EnvironmentDestructiveResetPreparation{}, err
	}
	recipientID, err := environmente2ee.KeyIDX25519(recipientPublic)
	if err != nil {
		clear(recipientPublic)
		return EnvironmentDestructiveResetPreparation{}, err
	}
	recoveryPublic := append([]byte(nil), identity.RecoveryPublic[:]...)
	recoveryID, err := environmente2ee.KeyIDX25519(recoveryPublic)
	if err != nil {
		clear(recipientPublic)
		clear(recoveryPublic)
		return EnvironmentDestructiveResetPreparation{}, err
	}
	result = EnvironmentDestructiveResetPreparation{
		Handle: handle, ManagerSigningPublic: append([]byte(nil), signingPublic...), ManagerSigningKeyID: signingID,
		ManagerRecipientPublic: recipientPublic, ManagerRecipientKeyID: recipientID,
		RecoveryRecipientPublic: recoveryPublic, RecoveryRecipientKeyID: recoveryID,
		KeyGeneration: record.KeyGeneration, ExportConfirmed: record.ExportConfirmed,
	}
	if !record.ExportConfirmed {
		private, err := decodeEnvironmentIdentityKey(record.RecoveryPrivate)
		if err != nil {
			result.Clear()
			return EnvironmentDestructiveResetPreparation{}, err
		}
		result.Recovery, err = environmente2ee.EncodeRecoveryBytes(private)
		clear(private)
		if err != nil {
			result.Clear()
			return EnvironmentDestructiveResetPreparation{}, err
		}
	}
	return result, nil
}

func destructiveResetIdentity(record environmentDestructiveResetRecord) (EnvironmentManagerIdentity, error) {
	if !record.ExportConfirmed || record.RecoveryPrivate != "" {
		return EnvironmentManagerIdentity{}, errors.New("ENV destructive reset recovery export confirmation required")
	}
	return destructiveResetIdentityUnchecked(record)
}

func destructiveResetIdentityUnchecked(record environmentDestructiveResetRecord) (EnvironmentManagerIdentity, error) {
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
	recoveryPublic, err := decodeEnvironmentIdentityKey(record.RecoveryPublic)
	if err != nil {
		return EnvironmentManagerIdentity{}, err
	}
	defer clear(recoveryPublic)
	identity := EnvironmentManagerIdentity{KeyGeneration: record.KeyGeneration, RecoveryRequired: true, RecoveryExportConfirmed: record.ExportConfirmed}
	copy(identity.SigningSeed[:], signing)
	copy(identity.RecipientPrivate[:], recipient)
	copy(identity.RecoveryPublic[:], recoveryPublic)
	return identity, nil
}

func environmentDestructiveResetCoordinates(s ProfileStore, issuer, accountID, subjectID string) (string, string, error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return "", "", err
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return "", "", ErrCredentialStoreUnavailable
	}
	digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + subjectID + "\x00environment-destructive-reset"))
	return issuer, "envreset_" + hex.EncodeToString(digest[:16]), nil
}

func environmentDestructiveResetRef(issuer, accountID, handle string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + handle + "\x00environment-destructive-reset-custody"))
	return "environment-identity-v1-destructive-reset-" + hex.EncodeToString(digest[:16])
}

func loadEnvironmentDestructiveResetRecord(store SecretStore, ref, accountID, subjectID string) (environmentDestructiveResetRecord, bool, error) {
	encoded, err := store.Get(ref)
	if errors.Is(err, ErrSecretNotFound) {
		return environmentDestructiveResetRecord{}, false, nil
	}
	if err != nil {
		return environmentDestructiveResetRecord{}, false, err
	}
	var record environmentDestructiveResetRecord
	if json.Unmarshal([]byte(encoded), &record) != nil || record.Version != environmentDestructiveResetVersion || record.Kind != "environment_destructive_reset" || record.AccountID != accountID || record.SubjectID != subjectID || record.KeyGeneration < 1 || record.KeyGeneration > maximumEnvironmentIdentityGeneration {
		return environmentDestructiveResetRecord{}, false, errors.New("ENV destructive reset record is invalid")
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != encoded {
		clear(canonical)
		return environmentDestructiveResetRecord{}, false, errors.New("ENV destructive reset record is invalid")
	}
	clear(canonical)
	signing, e1 := decodeEnvironmentIdentityKey(record.SigningSeed)
	recipient, e2 := decodeEnvironmentIdentityKey(record.RecipientPrivate)
	recoveryPublic, e3 := decodeEnvironmentIdentityKey(record.RecoveryPublic)
	defer clear(signing)
	defer clear(recipient)
	defer clear(recoveryPublic)
	if e1 != nil || e2 != nil || e3 != nil || record.ExportConfirmed != (record.RecoveryPrivate == "") {
		return environmentDestructiveResetRecord{}, false, errors.New("ENV destructive reset record is invalid")
	}
	if record.RecoveryPrivate != "" {
		recovery, err := decodeEnvironmentIdentityKey(record.RecoveryPrivate)
		if err != nil {
			return environmentDestructiveResetRecord{}, false, err
		}
		defer clear(recovery)
		private, err := ecdh.X25519().NewPrivateKey(recovery)
		if err != nil {
			return environmentDestructiveResetRecord{}, false, err
		}
		derived := private.PublicKey().Bytes()
		defer clear(derived)
		if subtle.ConstantTimeCompare(derived, recoveryPublic) != 1 {
			return environmentDestructiveResetRecord{}, false, errors.New("ENV destructive reset recovery key is invalid")
		}
	}
	if bytes.Equal(signing, recipient) || bytes.Equal(signing, recoveryPublic) || bytes.Equal(recipient, recoveryPublic) {
		return environmentDestructiveResetRecord{}, false, errors.New("ENV destructive reset keys are not independent")
	}
	return record, true, nil
}

func storeEnvironmentDestructiveResetRecord(store SecretStore, ref string, record environmentDestructiveResetRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := store.Set(ref, string(encoded)); err != nil {
		return fmt.Errorf("store ENV destructive reset: %w", err)
	}
	return nil
}
