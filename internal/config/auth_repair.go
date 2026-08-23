package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Repair replaces a profile whose credential pair can no longer be read. The
// old profile remains authoritative until the complete new pair and metadata
// commit. A readable old refresh token is retained for later revocation.
func (s ProfileStore) Repair(expectedSessionID string, p Profile, cred Credential) (resultErr error) {
	if err := validateCredential(cred); err != nil {
		return err
	}
	issuer, err := NormalizeIssuer(p.Issuer)
	if err != nil {
		return err
	}
	p.Issuer = issuer
	p.Version = ProfileVersion
	p.UpdatedAt = time.Now().UTC()
	path := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	if err := s.recoverTransactionsLocked(issuer); err != nil {
		return err
	}
	previous, err := s.loadNormalized(issuer)
	if err != nil {
		return err
	}
	if previous.CLIClientSessionID != expectedSessionID {
		return ErrProfileChanged
	}
	if _, err := s.credentialForProfile(previous); err == nil {
		return errors.New("Paperboat credential profile is healthy; refusing repair replacement")
	}
	if previous.CLIClientSessionID == p.CLIClientSessionID {
		return errors.New("Paperboat credential repair requires a newly authorized client session")
	}

	oldRefresh, oldRefreshErr := s.Secrets.Get(previous.RefreshSecretRef)
	queuePrevious := oldRefreshErr == nil && strings.TrimSpace(oldRefresh) != ""
	p.AccessSecretRef, p.RefreshSecretRef, err = newSecretRefs(issuer)
	if err != nil {
		return err
	}
	tx, err := s.prepareNextProfileLocked("repair", expectedSessionID, previous, p, queuePrevious)
	if err != nil {
		return err
	}
	if queuePrevious {
		accountID := previous.Account.ID
		if accountID != "" && !validCredentialID(accountID) {
			accountID = ""
		}
		if err := s.queueRevocationLocked(issuer, previous.CLIClientSessionID, oldRefresh, accountID); err != nil {
			return errors.Join(err, s.abortAuthTransactionLocked(tx))
		}
	}
	rollback := func(cause error) error {
		// Repair may be entered after the previous credential has already
		// become unreadable. If the newly issued session was staged before the
		// metadata commit failed, retain its refresh token for remote revocation
		// before deleting the staged pair.
		return errors.Join(cause, s.retainAndAbortAuthTransactionLocked(tx))
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return rollback(fmt.Errorf("store repair refresh token: %w", err))
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(fmt.Errorf("store repair access token: %w", err))
	}
	p.ObsoleteSecretRefs = obsoleteSecretRefs(previous, p)
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err := s.writeActiveProfile(path, append(b, '\n')); err != nil {
		return rollback(err)
	}
	s.finishAuthTransactionLocked(tx, p)
	return nil
}
