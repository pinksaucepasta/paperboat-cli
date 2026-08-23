package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuthTransaction is the durable prepare record for a profile mutation. It
// contains only metadata and secret references, never token values. A record
// is written before any newly issued secret is stored. On restart the active
// profile and the staged references decide whether the transaction committed
// or must be discarded.
type AuthTransaction struct {
	Version           int       `json:"version"`
	Operation         string    `json:"operation"`
	Issuer            string    `json:"issuer"`
	ExpectedSessionID string    `json:"expected_session_id,omitempty"`
	Previous          Profile   `json:"previous,omitempty"`
	Next              Profile   `json:"next"`
	QueuePrevious     bool      `json:"queue_previous,omitempty"`
	State             string    `json:"state"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const (
	authTransactionVersion   = 1
	authTransactionPrepared  = "prepared"
	authTransactionCommitted = "committed"
)

var ErrAuthTransactionChanged = errors.New("Paperboat credential transaction found a changed active profile")

func (s ProfileStore) authTransactionPath(issuer string) string {
	return filepath.Join(s.Path, "transactions", profileKey(issuer)+".json")
}

func (s ProfileStore) loadAuthTransaction(issuer string) (AuthTransaction, error) {
	path := s.authTransactionPath(issuer)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return AuthTransaction{}, os.ErrNotExist
	}
	if err != nil {
		return AuthTransaction{}, err
	}
	var tx AuthTransaction
	if err := json.Unmarshal(b, &tx); err != nil {
		return AuthTransaction{}, fmt.Errorf("parse auth transaction: %w", err)
	}
	if tx.Version != authTransactionVersion || tx.Issuer != issuer || tx.State == "" {
		return AuthTransaction{}, errors.New("unsupported or mismatched auth transaction")
	}
	if tx.Next.Issuer != issuer || tx.Next.AccessSecretRef == "" || tx.Next.RefreshSecretRef == "" {
		return AuthTransaction{}, errors.New("invalid auth transaction secret references")
	}
	if tx.Operation == "" {
		return AuthTransaction{}, errors.New("auth transaction operation is missing")
	}
	return tx, nil
}

func (s ProfileStore) writeAuthTransaction(tx AuthTransaction) error {
	if tx.Version == 0 {
		tx.Version = authTransactionVersion
	}
	if tx.State == "" {
		tx.State = authTransactionPrepared
	}
	if tx.CreatedAt.IsZero() {
		tx.CreatedAt = time.Now().UTC()
	}
	tx.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return err
	}
	path := s.authTransactionPath(tx.Issuer)
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'), 0o600)
}

func (s ProfileStore) removeAuthTransaction(issuer string) error {
	err := os.Remove(s.authTransactionPath(issuer))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func profileRefsMatch(a, b Profile) bool {
	return a.Issuer == b.Issuer &&
		a.CLIClientSessionID == b.CLIClientSessionID &&
		a.AccessSecretRef == b.AccessSecretRef &&
		a.RefreshSecretRef == b.RefreshSecretRef
}

func (s ProfileStore) deleteStagedAuthSecrets(tx AuthTransaction, active *Profile) error {
	refs := []string{tx.Next.AccessSecretRef, tx.Next.RefreshSecretRef}
	var errs []error
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if active != nil && (ref == active.AccessSecretRef || ref == active.RefreshSecretRef) {
			continue
		}
		errs = append(errs, s.Secrets.Delete(ref))
	}
	return errors.Join(errs...)
}

// AuthTransactionCredential reads the staged refresh credential without
// exposing it in transaction metadata. It is provided for callers that want
// to drain a transaction explicitly; Recover uses the same operation before
// deleting abandoned staged references.
func (s ProfileStore) AuthTransactionCredential(tx AuthTransaction) (Credential, error) {
	issuer, err := NormalizeIssuer(tx.Issuer)
	if err != nil {
		return Credential{}, err
	}
	if tx.Next.Issuer != issuer || tx.Next.RefreshSecretRef == "" {
		return Credential{}, errors.New("invalid auth transaction")
	}
	refresh, err := s.Secrets.Get(tx.Next.RefreshSecretRef)
	if err != nil {
		return Credential{}, fmt.Errorf("read staged refresh token: %w", err)
	}
	if strings.TrimSpace(refresh) == "" {
		return Credential{}, errors.New("staged refresh token is empty")
	}
	return Credential{RefreshToken: refresh, TokenType: "Bearer"}, nil
}

// pendingAuthTransaction returns the single transaction for issuer, if any.
// It is intentionally read-only and does not acquire the profile lock; callers
// that need a consistent recovery decision should use Recover.
func (s ProfileStore) pendingAuthTransaction(issuer string) (AuthTransaction, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return AuthTransaction{}, err
	}
	return s.loadAuthTransaction(issuer)
}

// PendingAuthTransactions returns the durable transaction for issuer, if one
// exists. It is intended for diagnostics or a caller that wants to inspect
// staged state before invoking Recover.
func (s ProfileStore) PendingAuthTransactions(issuer string) ([]AuthTransaction, error) {
	tx, err := s.pendingAuthTransaction(issuer)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []AuthTransaction{tx}, nil
}

func (s ProfileStore) retainStagedAuthSessionLocked(tx AuthTransaction, active *Profile) error {
	if strings.TrimSpace(tx.Next.CLIClientSessionID) == "" {
		return nil
	}
	// A staged token carrying the same session ID as the still-active profile
	// must never be sent through the active-session revocation queue. Same-session
	// refreshes use the existing refs and refresh-first ordering instead.
	if active != nil && active.CLIClientSessionID == tx.Next.CLIClientSessionID {
		return nil
	}
	credential, err := s.AuthTransactionCredential(tx)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	accountID := tx.Next.Account.ID
	if accountID != "" && !validCredentialID(accountID) {
		accountID = ""
	}
	return s.queueRevocationLocked(tx.Issuer, tx.Next.CLIClientSessionID, credential.RefreshToken, accountID)
}

// recoverAuthTransactionLocked resolves one transaction while the issuer
// profile lock is held. It never rewrites a matching active profile. A staged
// profile that is now active is committed; otherwise staged secrets and any
// pre-queued old-session revocation are discarded.
func (s ProfileStore) recoverAuthTransactionLocked(tx AuthTransaction) error {
	active, loadErr := s.loadNormalized(tx.Issuer)
	if loadErr != nil && !errors.Is(loadErr, ErrNoCredentials) {
		return loadErr
	}
	activePresent := loadErr == nil

	if activePresent && profileRefsMatch(active, tx.Next) {
		// The profile swap is authoritative. Old references remain listed in the
		// active metadata and can be cleaned on a later successful mutation.
		s.cleanupObsoleteSecrets(active)
		return s.removeAuthTransaction(tx.Issuer)
	}

	previousMatches := activePresent && profileRefsMatch(active, tx.Previous)
	if activePresent && !previousMatches {
		// Another profile won the lock after this transaction was abandoned, or
		// the metadata was externally changed. Never delete references in that
		// profile; leave the record for an explicit repair decision.
		return ErrAuthTransactionChanged
	}
	var activeProfile *Profile
	if activePresent {
		activeProfile = &active
	}
	if err := s.retainStagedAuthSessionLocked(tx, activeProfile); err != nil {
		return fmt.Errorf("retain staged auth session: %w", err)
	}
	if err := s.deleteStagedAuthSecrets(tx, activeProfile); err != nil {
		return fmt.Errorf("discard staged auth secrets: %w", err)
	}
	if tx.QueuePrevious && tx.Previous.CLIClientSessionID != "" {
		if err := s.DiscardRevocation(tx.Issuer, tx.Previous.CLIClientSessionID); err != nil {
			return fmt.Errorf("discard staged session revocation: %w", err)
		}
	}
	return s.removeAuthTransaction(tx.Issuer)
}

// retainAndAbortAuthTransactionLocked keeps the newly issued session
// revocable before deleting staged references. It is separate from recovery
// so handled write failures follow the same durable path as a process crash.
func (s ProfileStore) retainAndAbortAuthTransactionLocked(tx AuthTransaction) error {
	active, err := s.loadNormalized(tx.Issuer)
	if err != nil && !errors.Is(err, ErrNoCredentials) {
		return err
	}
	var activeProfile *Profile
	if err == nil {
		activeProfile = &active
	}
	if err := s.retainStagedAuthSessionLocked(tx, activeProfile); err != nil {
		return fmt.Errorf("retain staged auth session: %w", err)
	}
	if err := s.deleteStagedAuthSecrets(tx, activeProfile); err != nil {
		return fmt.Errorf("discard staged auth secrets: %w", err)
	}
	if tx.QueuePrevious && tx.Previous.CLIClientSessionID != "" {
		if err := s.DiscardRevocation(tx.Issuer, tx.Previous.CLIClientSessionID); err != nil {
			return fmt.Errorf("discard staged session revocation: %w", err)
		}
	}
	return s.removeAuthTransaction(tx.Issuer)
}

// recoverTransactionsLocked resolves any interrupted mutation for issuer.
// Callers must hold the issuer profile lock.
func (s ProfileStore) recoverTransactionsLocked(issuer string) error {
	tx, err := s.loadAuthTransaction(issuer)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.recoverAuthTransactionLocked(tx)
}

// Recover resumes or rolls back an interrupted profile mutation. It is safe
// to call on every process start and before every auth operation.
func (s ProfileStore) Recover(issuer string) (resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	path := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	return s.recoverTransactionsLocked(issuer)
}

// RecoverPending is an explicit alias for callers that want to make the
// startup-recovery intent clear.
func (s ProfileStore) RecoverPending(issuer string) error { return s.Recover(issuer) }

func (s ProfileStore) beginAuthTransactionLocked(tx AuthTransaction) error {
	if err := s.recoverTransactionsLocked(tx.Issuer); err != nil {
		return err
	}
	if _, err := s.loadAuthTransaction(tx.Issuer); err == nil {
		return errors.New("auth transaction already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tx.Version = authTransactionVersion
	tx.State = authTransactionPrepared
	tx.CreatedAt = time.Now().UTC()
	return s.writeAuthTransaction(tx)
}

// abortAuthTransactionLocked removes all staged state after a handled write
// failure. The caller still owns the newly issued token and is responsible for
// remote cleanup; crash recovery uses retainAndAbortAuthTransactionLocked,
// because a crashed caller no longer has that token in memory.
func (s ProfileStore) abortAuthTransactionLocked(tx AuthTransaction) error {
	var errs []error
	errs = append(errs, s.deleteStagedAuthSecrets(tx, nil))
	if tx.QueuePrevious && tx.Previous.CLIClientSessionID != "" {
		errs = append(errs, s.DiscardRevocation(tx.Issuer, tx.Previous.CLIClientSessionID))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return s.removeAuthTransaction(tx.Issuer)
}

// finishAuthTransactionLocked records the commit and then performs best-effort
// old-reference cleanup. The active profile is already authoritative, so any
// transaction-marker or cleanup failure is intentionally not returned to the
// caller. Recovery will reconcile a marker left on disk.
func (s ProfileStore) finishAuthTransactionLocked(tx AuthTransaction, active Profile) {
	tx.State = authTransactionCommitted
	_ = s.writeAuthTransaction(tx)
	s.cleanupObsoleteSecrets(active)
	_ = s.removeAuthTransaction(tx.Issuer)
}

// RecoverAll scans the transaction directory and resolves every valid
// transaction. It is useful for startup repair when the configured issuer is
// not known yet. Transactions with malformed metadata are returned and left
// untouched for diagnostics.
func (s ProfileStore) RecoverAll() error {
	dir := filepath.Join(s.Path, "transactions")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			errs = append(errs, readErr)
			continue
		}
		var tx AuthTransaction
		if decodeErr := json.Unmarshal(b, &tx); decodeErr != nil || tx.Issuer == "" {
			if decodeErr == nil {
				decodeErr = errors.New("auth transaction issuer is missing")
			}
			errs = append(errs, decodeErr)
			continue
		}
		if recoverErr := s.Recover(tx.Issuer); recoverErr != nil {
			errs = append(errs, recoverErr)
		}
	}
	return errors.Join(errs...)
}

func (s ProfileStore) prepareNextProfileLocked(operation, expected string, previous Profile, next Profile, queuePrevious bool) (AuthTransaction, error) {
	if strings.TrimSpace(next.Issuer) == "" || next.AccessSecretRef == "" || next.RefreshSecretRef == "" {
		return AuthTransaction{}, errors.New("auth transaction requires staged profile secret references")
	}
	tx := AuthTransaction{Operation: operation, Issuer: next.Issuer, ExpectedSessionID: expected, Previous: previous, Next: next, QueuePrevious: queuePrevious}
	if err := s.beginAuthTransactionLocked(tx); err != nil {
		return AuthTransaction{}, err
	}
	return tx, nil
}
