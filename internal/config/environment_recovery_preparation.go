package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

// EnvironmentRecoveryPreparation is nonsecret metadata plus a caller-owned,
// mutable offline export buffer. The deterministic opaque handles make an
// interrupted preparation discoverable without persisting private bytes in a
// general file.
type EnvironmentRecoveryPreparation struct {
	ImportedHandle    string
	ReplacementHandle string
	Recovery          []byte
	RecipientPublic   []byte
	RecipientKeyID    string
	ExportConfirmed   bool
}

func (value *EnvironmentRecoveryPreparation) Clear() {
	if value == nil {
		return
	}
	clear(value.Recovery)
	clear(value.RecipientPublic)
	*value = EnvironmentRecoveryPreparation{}
}

func (s ProfileStore) BeginEnvironmentRecoveryPreparation(issuer, accountID, subjectID string, importedRecovery []byte) (result EnvironmentRecoveryPreparation, resultErr error) {
	private, err := environmente2ee.DecodeRecoveryBytes(importedRecovery)
	if err != nil {
		return EnvironmentRecoveryPreparation{}, errors.New("ENV recovery import is invalid")
	}
	defer clear(private)
	issuer, importedHandle, replacementHandle, err := environmentRecoveryPreparationCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentRecoveryPreparation{}, fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			result.Clear()
		}
	}()
	importedRef := environmentRecoveryCustodyRef(issuer, accountID, importedHandle)
	imported, loadErr := loadEnvironmentRecoveryRecord(s.Secrets, importedRef, accountID, "temporary_import")
	if errors.Is(loadErr, ErrSecretNotFound) {
		imported = environmentRecoveryCustodyRecord{Version: environmentRecoveryCustodyVersion, Kind: "temporary_import", AccountID: accountID, Private: encodeEnvironmentIdentityKey(private), Confirmed: true}
		if err := storeEnvironmentRecoveryRecord(s.Secrets, importedRef, imported); err != nil {
			return EnvironmentRecoveryPreparation{}, err
		}
	} else if loadErr != nil {
		return EnvironmentRecoveryPreparation{}, loadErr
	} else {
		stored, err := decodeEnvironmentIdentityKey(imported.Private)
		if err != nil {
			return EnvironmentRecoveryPreparation{}, err
		}
		defer clear(stored)
		if !bytes.Equal(stored, private) {
			return EnvironmentRecoveryPreparation{}, errors.New("a different ENV recovery preparation is already pending")
		}
	}
	return loadOrCreateReplacementPreparation(s, issuer, accountID, importedHandle, replacementHandle)
}

func (s ProfileStore) ResumeEnvironmentRecoveryPreparation(issuer, accountID, subjectID string) (result EnvironmentRecoveryPreparation, resultErr error) {
	issuer, importedHandle, replacementHandle, err := environmentRecoveryPreparationCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".environment-recovery.lock")
	if err := lock.Lock(); err != nil {
		return EnvironmentRecoveryPreparation{}, fmt.Errorf("lock ENV recovery custody: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			result.Clear()
		}
	}()
	if _, err := loadEnvironmentRecoveryRecord(s.Secrets, environmentRecoveryCustodyRef(issuer, accountID, importedHandle), accountID, "temporary_import"); err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	return loadOrCreateReplacementPreparation(s, issuer, accountID, importedHandle, replacementHandle)
}

func (s ProfileStore) ConfirmEnvironmentRecoveryPreparationExport(issuer, accountID, subjectID string, encoded []byte) error {
	_, _, replacementHandle, err := environmentRecoveryPreparationCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return err
	}
	return s.ConfirmEnvironmentReplacementRecoveryExport(issuer, accountID, replacementHandle, encoded)
}

func (s ProfileStore) CancelEnvironmentRecoveryPreparation(issuer, accountID, subjectID string) error {
	_, importedHandle, replacementHandle, err := environmentRecoveryPreparationCoordinates(s, issuer, accountID, subjectID)
	if err != nil {
		return err
	}
	return s.CompleteEnvironmentRecoveryRotation(issuer, accountID, importedHandle, replacementHandle)
}

func loadOrCreateReplacementPreparation(s ProfileStore, issuer, accountID, importedHandle, replacementHandle string) (EnvironmentRecoveryPreparation, error) {
	ref := environmentRecoveryCustodyRef(issuer, accountID, replacementHandle)
	record, err := loadEnvironmentRecoveryRecord(s.Secrets, ref, accountID, "replacement")
	if errors.Is(err, ErrSecretNotFound) {
		private, _, keyErr := environmente2ee.GenerateRecipientKey()
		if keyErr != nil {
			return EnvironmentRecoveryPreparation{}, keyErr
		}
		defer clear(private)
		record = environmentRecoveryCustodyRecord{Version: environmentRecoveryCustodyVersion, Kind: "replacement", AccountID: accountID, Private: encodeEnvironmentIdentityKey(private)}
		if err := storeEnvironmentRecoveryRecord(s.Secrets, ref, record); err != nil {
			return EnvironmentRecoveryPreparation{}, err
		}
	} else if err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	private, err := decodeEnvironmentIdentityKey(record.Private)
	if err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	defer clear(private)
	recovery, err := environmente2ee.EncodeRecoveryBytes(private)
	if err != nil {
		return EnvironmentRecoveryPreparation{}, err
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		clear(recovery)
		return EnvironmentRecoveryPreparation{}, err
	}
	public := key.PublicKey().Bytes()
	keyID, err := environmente2ee.KeyIDX25519(public)
	if err != nil {
		clear(recovery)
		clear(public)
		return EnvironmentRecoveryPreparation{}, err
	}
	return EnvironmentRecoveryPreparation{ImportedHandle: importedHandle, ReplacementHandle: replacementHandle, Recovery: recovery, RecipientPublic: public, RecipientKeyID: keyID, ExportConfirmed: record.Confirmed}, nil
}

func environmentRecoveryPreparationCoordinates(s ProfileStore, issuer, accountID, subjectID string) (string, string, string, error) {
	if err := s.RequireEnvironmentSecureStore(); err != nil {
		return "", "", "", err
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil || !validCredentialID(accountID) || !validCredentialID(subjectID) {
		return "", "", "", ErrCredentialStoreUnavailable
	}
	handle := func(kind string) string {
		digest := sha256.Sum256([]byte(issuer + "\x00" + accountID + "\x00" + subjectID + "\x00" + kind))
		return "envrec_" + hex.EncodeToString(digest[:16])
	}
	return issuer, handle("recovery-import"), handle("recovery-replacement"), nil
}

func encodeEnvironmentIdentityKey(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
