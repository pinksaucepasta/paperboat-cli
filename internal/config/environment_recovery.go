package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

const environmentRecoveryCustodyVersion = 1

type EnvironmentReplacementRecovery struct {
	Handle          string
	Recovery        []byte
	RecipientPublic []byte
	RecipientKeyID  string
}

func (value *EnvironmentReplacementRecovery) Clear() {
	if value == nil {
		return
	}
	clear(value.Recovery)
	clear(value.RecipientPublic)
	*value = EnvironmentReplacementRecovery{}
}

type environmentRecoveryCustodyRecord struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	AccountID string `json:"account_id"`
	Private   string `json:"private"`
	Confirmed bool   `json:"confirmed,omitempty"`
}

// ImportEnvironmentRecoveryTemporary stores an imported recovery scalar only
// in the OS secure store and returns an opaque local handle.
func (s ProfileStore) ImportEnvironmentRecoveryTemporary(issuer, accountID string, encoded []byte) (string, error) {
	private, err := environmente2ee.DecodeRecoveryBytes(encoded)
	if err != nil {
		return "", errors.New("ENV recovery import is invalid")
	}
	defer clear(private)
	return s.storeEnvironmentRecoveryCustody(issuer, accountID, "temporary_import", private, true)
}

func (s ProfileStore) LoadEnvironmentRecoveryTemporary(issuer, accountID, handle string) ([32]byte, error) {
	record, err := s.loadEnvironmentRecoveryCustody(issuer, accountID, handle, "temporary_import", true)
	if err != nil {
		return [32]byte{}, err
	}
	private, err := decodeEnvironmentIdentityKey(record.Private)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(private)
	var result [32]byte
	copy(result[:], private)
	return result, nil
}

func (s ProfileStore) DeleteEnvironmentRecoveryTemporary(issuer, accountID, handle string) error {
	return s.deleteEnvironmentRecoveryCustody(issuer, accountID, handle, "temporary_import")
}

// BeginEnvironmentReplacementRecovery creates a new recovery recipient in the
// secure store. Recovery is a mutable export buffer owned by the caller.
func (s ProfileStore) BeginEnvironmentReplacementRecovery(issuer, accountID string) (EnvironmentReplacementRecovery, error) {
	private, public, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		return EnvironmentReplacementRecovery{}, err
	}
	defer clear(private)
	handle, err := s.storeEnvironmentRecoveryCustody(issuer, accountID, "replacement", private, false)
	if err != nil {
		clear(public)
		return EnvironmentReplacementRecovery{}, err
	}
	recovery, err := environmente2ee.EncodeRecoveryBytes(private)
	if err != nil {
		clear(public)
		_ = s.deleteEnvironmentRecoveryCustody(issuer, accountID, handle, "replacement")
		return EnvironmentReplacementRecovery{}, err
	}
	keyID, err := environmente2ee.KeyIDX25519(public)
	if err != nil {
		clear(public)
		clear(recovery)
		_ = s.deleteEnvironmentRecoveryCustody(issuer, accountID, handle, "replacement")
		return EnvironmentReplacementRecovery{}, err
	}
	return EnvironmentReplacementRecovery{Handle: handle, Recovery: recovery, RecipientPublic: public, RecipientKeyID: keyID}, nil
}

// ConfirmEnvironmentReplacementRecoveryExport durably records that the exact
// exported recovery bytes were confirmed. The private key remains in secure
// custody until the atomic rotation activates.
func (s ProfileStore) ConfirmEnvironmentReplacementRecoveryExport(issuer, accountID, handle string, encoded []byte) error {
	decoded, err := environmente2ee.DecodeRecoveryBytes(encoded)
	if err != nil {
		return errors.New("ENV replacement recovery confirmation is invalid")
	}
	defer clear(decoded)
	issuer, err = normalizeEnvironmentRecoveryInput(s, issuer, accountID, handle)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer lock.Unlock()
	ref := environmentRecoveryCustodyRef(issuer, accountID, handle)
	record, err := loadEnvironmentRecoveryRecord(s.Secrets, ref, accountID, "replacement")
	if err != nil {
		return err
	}
	private, err := decodeEnvironmentIdentityKey(record.Private)
	if err != nil {
		return err
	}
	defer clear(private)
	if subtle.ConstantTimeCompare(private, decoded) != 1 {
		return errors.New("ENV replacement recovery confirmation does not match")
	}
	if record.Confirmed {
		return nil
	}
	record.Confirmed = true
	return storeEnvironmentRecoveryRecord(s.Secrets, ref, record)
}

func (s ProfileStore) LoadConfirmedEnvironmentReplacementRecovery(issuer, accountID, handle string) ([32]byte, error) {
	record, err := s.loadEnvironmentRecoveryCustody(issuer, accountID, handle, "replacement", true)
	if err != nil {
		return [32]byte{}, err
	}
	private, err := decodeEnvironmentIdentityKey(record.Private)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(private)
	var result [32]byte
	copy(result[:], private)
	return result, nil
}

// CompleteEnvironmentReplacementRecovery removes the online replacement key
// only after the caller has observed atomic authority activation.
func (s ProfileStore) CompleteEnvironmentReplacementRecovery(issuer, accountID, handle string) error {
	return s.deleteEnvironmentRecoveryCustody(issuer, accountID, handle, "replacement")
}

// CompleteEnvironmentRecoveryRotation erases both temporary online recovery
// keys after the caller has observed atomic activation. It is idempotent so a
// process crash between secure-store deletions can be repaired safely.
func (s ProfileStore) CompleteEnvironmentRecoveryRotation(issuer, accountID, importedHandle, replacementHandle string) (resultErr error) {
	issuer, err := normalizeEnvironmentRecoveryInput(s, issuer, accountID, importedHandle)
	if err != nil || !environmentRecoveryHandlePattern.MatchString(replacementHandle) || importedHandle == replacementHandle {
		return ErrCredentialStoreUnavailable
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	for _, item := range []struct {
		handle string
		kind   string
	}{{importedHandle, "temporary_import"}, {replacementHandle, "replacement"}} {
		ref := environmentRecoveryCustodyRef(issuer, accountID, item.handle)
		if _, err := loadEnvironmentRecoveryRecord(s.Secrets, ref, accountID, item.kind); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		if err := s.Secrets.Delete(ref); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
	}
	return nil
}

func (s ProfileStore) storeEnvironmentRecoveryCustody(issuer, accountID, kind string, private []byte, confirmed bool) (string, error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return "", err
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || len(private) != 32 || kind != "temporary_import" && kind != "replacement" {
		return "", ErrCredentialStoreUnavailable
	}
	handleBytes := make([]byte, 16)
	defer clear(handleBytes)
	if _, err := rand.Read(handleBytes); err != nil {
		return "", err
	}
	handle := "envrec_" + hex.EncodeToString(handleBytes)
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return "", fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer lock.Unlock()
	record := environmentRecoveryCustodyRecord{Version: environmentRecoveryCustodyVersion, Kind: kind, AccountID: accountID, Private: base64.RawURLEncoding.EncodeToString(private), Confirmed: confirmed}
	if err := storeEnvironmentRecoveryRecord(s.Secrets, environmentRecoveryCustodyRef(issuer, accountID, handle), record); err != nil {
		return "", err
	}
	return handle, nil
}

func (s ProfileStore) loadEnvironmentRecoveryCustody(issuer, accountID, handle, kind string, requireConfirmed bool) (environmentRecoveryCustodyRecord, error) {
	issuer, err := normalizeEnvironmentRecoveryInput(s, issuer, accountID, handle)
	if err != nil {
		return environmentRecoveryCustodyRecord{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return environmentRecoveryCustodyRecord{}, fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer lock.Unlock()
	record, err := loadEnvironmentRecoveryRecord(s.Secrets, environmentRecoveryCustodyRef(issuer, accountID, handle), accountID, kind)
	if err != nil {
		return environmentRecoveryCustodyRecord{}, err
	}
	if requireConfirmed && !record.Confirmed {
		return environmentRecoveryCustodyRecord{}, errors.New("ENV recovery export confirmation required")
	}
	return record, nil
}

func (s ProfileStore) deleteEnvironmentRecoveryCustody(issuer, accountID, handle, kind string) error {
	issuer, err := normalizeEnvironmentRecoveryInput(s, issuer, accountID, handle)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer lock.Unlock()
	ref := environmentRecoveryCustodyRef(issuer, accountID, handle)
	if _, err := loadEnvironmentRecoveryRecord(s.Secrets, ref, accountID, kind); err != nil {
		return err
	}
	return s.Secrets.Delete(ref)
}

func normalizeEnvironmentRecoveryInput(s ProfileStore, issuer, accountID, handle string) (string, error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return "", err
	}
	normalized, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || !environmentRecoveryHandlePattern.MatchString(handle) {
		return "", ErrCredentialStoreUnavailable
	}
	return normalized, nil
}

func loadEnvironmentRecoveryRecord(store SecretStore, ref, accountID, kind string) (environmentRecoveryCustodyRecord, error) {
	encoded, err := store.Get(ref)
	if err != nil {
		return environmentRecoveryCustodyRecord{}, err
	}
	var record environmentRecoveryCustodyRecord
	if json.Unmarshal([]byte(encoded), &record) != nil || record.Version != environmentRecoveryCustodyVersion || record.Kind != kind || record.AccountID != accountID {
		return environmentRecoveryCustodyRecord{}, errors.New("ENV recovery custody record is invalid")
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != encoded {
		clear(canonical)
		return environmentRecoveryCustodyRecord{}, errors.New("ENV recovery custody record is invalid")
	}
	clear(canonical)
	private, err := decodeEnvironmentIdentityKey(record.Private)
	clear(private)
	if err != nil {
		return environmentRecoveryCustodyRecord{}, err
	}
	return record, nil
}

func storeEnvironmentRecoveryRecord(store SecretStore, ref string, record environmentRecoveryCustodyRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(raw)
	return store.Set(ref, string(raw))
}

func environmentRecoveryCustodyRef(issuer, accountID, handle string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + handle + "\x00environment-recovery"))
	return "environment-recovery-v1-" + hex.EncodeToString(digest[:16])
}

var environmentRecoveryHandlePattern = regexp.MustCompile(`^envrec_[0-9a-f]{32}$`)
