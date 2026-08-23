package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/userpaths"
)

const ProfileVersion = 1
const keyringService = "paperboat"

var ErrCredentialStoreUnavailable = errors.New("OS credential store unavailable")

const sharedLockRemoteStaleAfter = 30 * time.Minute

type sharedLockOwner struct {
	PID       int       `json:"pid"`
	Hostname  string    `json:"hostname"`
	CreatedAt time.Time `json:"created_at"`
	Token     string    `json:"token"`
}

type sharedLock struct {
	path  string
	token string
	local *sync.Mutex
}

var sharedLockMu sync.Map

func newSharedLock(path string) *sharedLock {
	key := path + ".d"
	local, _ := sharedLockMu.LoadOrStore(key, &sync.Mutex{})
	return &sharedLock{path: key, local: local.(*sync.Mutex)}
}

func (l *sharedLock) Lock() error {
	if l.local != nil {
		l.local.Lock()
	}
	locked := false
	defer func() {
		if !locked && l.local != nil {
			l.local.Unlock()
		}
	}()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	l.token = strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	owner := sharedLockOwner{PID: os.Getpid(), Hostname: hostname, CreatedAt: time.Now().UTC(), Token: l.token}
	encoded, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := os.Mkdir(l.path, 0o700); err == nil {
			if err := os.WriteFile(filepath.Join(l.path, "owner.json"), append(encoded, '\n'), 0o600); err != nil {
				_ = os.RemoveAll(l.path)
				return err
			}
			locked = true
			return nil
		} else if !os.IsExist(err) {
			return err
		}
		stale, err := sharedLockIsStale(l.path, hostname)
		if err == nil && stale {
			stalePath := l.path + ".stale-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			//paperboat:allow-source-policy atomic-replacement owner=runtime-auth reason=stale-lock-quarantine
			if os.Rename(l.path, stalePath) == nil {
				_ = os.RemoveAll(stalePath)
				continue
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for shared credential lock %s", l.path)
		}
		//paperboat:allow-source-policy sleep owner=runtime-auth reason=bounded-cross-process-lock-poll
		time.Sleep(25 * time.Millisecond)
	}
}

func sharedLockIsStale(path, hostname string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(path, "owner.json"))
	if err != nil {
		info, statErr := os.Stat(path)
		return statErr == nil && time.Since(info.ModTime()) > sharedLockRemoteStaleAfter, err
	}
	var owner sharedLockOwner
	if err := json.Unmarshal(b, &owner); err != nil {
		info, statErr := os.Stat(path)
		return statErr == nil && time.Since(info.ModTime()) > sharedLockRemoteStaleAfter, err
	}
	if owner.Hostname != hostname {
		return time.Since(owner.CreatedAt) > sharedLockRemoteStaleAfter, nil
	}
	return !processAlive(owner.PID), nil
}

func (l *sharedLock) Unlock() error {
	defer func() {
		if l.local != nil {
			l.local.Unlock()
		}
	}()
	b, err := os.ReadFile(filepath.Join(l.path, "owner.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var owner sharedLockOwner
	if err := json.Unmarshal(b, &owner); err != nil {
		return err
	}
	if owner.Token != l.token {
		return nil
	}
	return removeSharedLock(l.path)
}

var (
	ErrNoCredentials  = errors.New("not signed in to Paperboat")
	ErrProfileExists  = errors.New("Paperboat credential profile already exists")
	ErrProfileChanged = errors.New("Paperboat credential profile changed")
)

type Credential struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
}

type Account struct {
	ID          string `json:"id,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type Profile struct {
	Version            int       `json:"version"`
	Issuer             string    `json:"issuer"`
	Account            Account   `json:"account,omitempty"`
	CLIClientSessionID string    `json:"cli_client_session_id"`
	AccessExpiresAt    time.Time `json:"access_expires_at"`
	AccessSecretRef    string    `json:"access_secret_ref"`
	RefreshSecretRef   string    `json:"refresh_secret_ref"`
	ObsoleteSecretRefs []string  `json:"obsolete_secret_refs,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type PendingRevocation struct {
	Version            int       `json:"version"`
	Issuer             string    `json:"issuer"`
	CLIClientSessionID string    `json:"cli_client_session_id"`
	AccountID          string    `json:"account_id,omitempty"`
	RefreshSecretRef   string    `json:"refresh_secret_ref"`
	CreatedAt          time.Time `json:"created_at"`
	ServerRevoked      bool      `json:"server_revoked,omitempty"`
	Cancelled          bool      `json:"cancelled,omitempty"`
}

type SecretStore interface {
	Set(ref, value string) error
	Get(ref string) (string, error)
	Delete(ref string) error
}

type FileSecretStore struct{ Dir string }

func (s FileSecretStore) path(ref string) string { return filepath.Join(s.Dir, ref+".secret") }
func (s FileSecretStore) Set(ref, value string) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := validateCredentialDirectory(s.Dir); err != nil {
		return err
	}
	return writeCredentialFile(s.path(ref), []byte(value))
}
func (s FileSecretStore) Get(ref string) (string, error) {
	if err := validateCredentialDirectory(s.Dir); err != nil {
		if os.IsNotExist(err) {
			return "", ErrSecretNotFound
		}
		return "", err
	}
	b, err := readCredentialFile(s.path(ref))
	if os.IsNotExist(err) {
		return "", ErrSecretNotFound
	}
	return string(b), err
}
func (s FileSecretStore) Delete(ref string) error {
	if err := validateCredentialDirectory(s.Dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	err := os.Remove(s.path(ref))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type AuthSource interface{ Credential() (Credential, error) }

type NoCredentialsSource struct{}

func (NoCredentialsSource) Credential() (Credential, error) {
	return Credential{}, ErrNoCredentials
}

type ProfileStore struct {
	Path    string
	Secrets SecretStore
	write   func(string, []byte, os.FileMode) error
}

func NormalizeIssuer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Paperboat server URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		if strings.Contains(hostname, ":") {
			u.Host = "[" + hostname + "]"
		} else {
			u.Host = hostname
		}
	} else {
		u.Host = net.JoinHostPort(hostname, port)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func profileKey(issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return hex.EncodeToString(sum[:16])
}
func newSecretRefs(issuer string) (access, refresh string, err error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	prefix := "profile-" + profileKey(issuer) + "-" + hex.EncodeToString(nonce[:])
	return prefix + "-access", prefix + "-refresh", nil
}

func validateCredential(cred Credential) error {
	if strings.TrimSpace(cred.AccessToken) == "" || strings.TrimSpace(cred.RefreshToken) == "" {
		return errors.New("Paperboat credential requires non-empty access and refresh tokens")
	}
	return nil
}

func (s ProfileStore) writeActiveProfile(path string, data []byte) error {
	if s.write != nil {
		return s.write(path, data, 0o600)
	}
	return atomicWrite(path, data, 0o600)
}

func obsoleteSecretRefs(previous Profile, next Profile) []string {
	seen := map[string]struct{}{next.AccessSecretRef: {}, next.RefreshSecretRef: {}}
	refs := make([]string, 0, len(previous.ObsoleteSecretRefs)+2)
	for _, ref := range append(append([]string(nil), previous.ObsoleteSecretRefs...), previous.AccessSecretRef, previous.RefreshSecretRef) {
		if ref == "" {
			continue
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

// cleanupObsoleteSecrets is best-effort after the new profile is committed.
// Failed deletions remain named by the authoritative profile and are retried
// by the next successful profile mutation. A cleanup failure must never make a
// committed login look uncommitted to its caller.
func (s ProfileStore) cleanupObsoleteSecrets(p Profile) {
	remaining := make([]string, 0, len(p.ObsoleteSecretRefs))
	for _, ref := range p.ObsoleteSecretRefs {
		if ref == p.AccessSecretRef || ref == p.RefreshSecretRef {
			remaining = append(remaining, ref)
			continue
		}
		if err := s.Secrets.Delete(ref); err != nil {
			remaining = append(remaining, ref)
		}
	}
	if len(remaining) == len(p.ObsoleteSecretRefs) {
		return
	}
	p.ObsoleteSecretRefs = remaining
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return
	}
	// If publishing the reduced list fails, the previous profile still names
	// every cleanup candidate, including already-deleted idempotent entries.
	_ = s.writeActiveProfile(s.profilePath(p.Issuer), append(b, '\n'))
}

func pendingRevocationKey(issuer, cliClientSessionID string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + cliClientSessionID))
	return hex.EncodeToString(sum[:16])
}

func pendingRefreshRef(issuer, cliClientSessionID string) string {
	return "revocation-" + pendingRevocationKey(issuer, cliClientSessionID) + "-refresh"
}

func (s ProfileStore) profilePath(issuer string) string {
	return filepath.Join(s.Path, "profiles", profileKey(issuer)+".json")
}

func (s ProfileStore) pendingRevocationPath(issuer, cliClientSessionID string) string {
	return filepath.Join(s.Path, "pending-revocations", profileKey(issuer)+"-"+pendingRevocationKey(issuer, cliClientSessionID)+".json")
}

func (s ProfileStore) existingPendingRevocationPath(issuer, cliClientSessionID string) string {
	path := s.pendingRevocationPath(issuer, cliClientSessionID)
	if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
		return path
	}
	return filepath.Join(s.Path, "pending-revocations", pendingRevocationKey(issuer, cliClientSessionID)+".json")
}

func (s ProfileStore) Load(issuer string) (Profile, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return Profile{}, err
	}
	return s.loadNormalized(issuer)
}

func (s ProfileStore) loadNormalized(issuer string) (Profile, error) {
	b, err := os.ReadFile(s.profilePath(issuer))
	if os.IsNotExist(err) {
		return Profile{}, ErrNoCredentials
	}
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("parse credential profile: %w", err)
	}
	if p.Version != ProfileVersion || p.Issuer != issuer {
		return Profile{}, fmt.Errorf("unsupported or mismatched credential profile")
	}
	return p, nil
}

func (s ProfileStore) Save(p Profile, cred Credential) (resultErr error) {
	if err := validateCredential(cred); err != nil {
		return err
	}
	issuer, err := NormalizeIssuer(p.Issuer)
	if err != nil {
		return err
	}
	p.Issuer = issuer
	p.Version = ProfileVersion
	p.ObsoleteSecretRefs = nil
	p.UpdatedAt = time.Now().UTC()
	lock := newSharedLock(s.profilePath(issuer) + ".lock")
	if err := ensureProfileDirectory(filepath.Dir(s.profilePath(issuer))); err != nil {
		return err
	}
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	if err := s.recoverTransactionsLocked(issuer); err != nil {
		return err
	}
	if _, err := os.Stat(s.profilePath(issuer)); err == nil {
		return ErrProfileExists
	} else if !os.IsNotExist(err) {
		return err
	}
	p.AccessSecretRef, p.RefreshSecretRef, err = newSecretRefs(issuer)
	if err != nil {
		return err
	}
	tx, err := s.prepareNextProfileLocked("save", "", Profile{}, p, false)
	if err != nil {
		return err
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return errors.Join(fmt.Errorf("store refresh token: %w", err), s.abortAuthTransactionLocked(tx))
	}
	rollback := func(cause error) error {
		cleanupErr := s.abortAuthTransactionLocked(tx)
		if cleanupErr != nil {
			return errors.Join(cause, fmt.Errorf("remove incomplete credentials: %w", cleanupErr))
		}
		return cause
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(fmt.Errorf("store access token: %w", err))
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err := s.writeActiveProfile(s.profilePath(p.Issuer), append(b, '\n')); err != nil {
		return rollback(err)
	}
	s.finishAuthTransactionLocked(tx, p)
	return nil
}

// Replace preserves the currently active profile if persisting its replacement
// fails. This is separate from refresh persistence because a rotated refresh
// token must never be rolled back to its server-invalid predecessor.
func (s ProfileStore) Replace(p Profile, cred Credential) (resultErr error) {
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
	if _, err := s.credentialForProfile(previous); err != nil {
		return err
	}
	p.AccessSecretRef, p.RefreshSecretRef, err = newSecretRefs(issuer)
	if err != nil {
		return err
	}
	tx, err := s.prepareNextProfileLocked("replace", previous.CLIClientSessionID, previous, p, false)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		if rollbackErr := s.abortAuthTransactionLocked(tx); rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("remove replacement credentials: %w", rollbackErr))
		}
		return cause
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return errors.Join(fmt.Errorf("store replacement refresh token: %w", err), s.abortAuthTransactionLocked(tx))
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(fmt.Errorf("store replacement access token: %w", err))
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

// Switch compares, retains, and replaces the active session under one issuer
// lock so overlapping account switches cannot associate credentials with a
// stale client session ID. Replaying the current session replaces its
// credentials without queuing that same active session for revocation.
func (s ProfileStore) Switch(expectedSessionID string, p Profile, cred Credential) (resultErr error) {
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
	// A replay of the active session is a refresh, not an account switch.
	// Keep its references stable and write the rotated refresh value first so a
	// crash cannot restore a server-invalid predecessor or enqueue the active
	// session for revocation.
	if previous.CLIClientSessionID == p.CLIClientSessionID {
		p.AccessSecretRef = previous.AccessSecretRef
		p.RefreshSecretRef = previous.RefreshSecretRef
		p.ObsoleteSecretRefs = previous.ObsoleteSecretRefs
		if err := s.saveLocked(p, cred); err != nil {
			return err
		}
		s.cleanupObsoleteSecrets(p)
		return nil
	}
	previousCred, err := s.credentialForProfile(previous)
	if err != nil {
		return err
	}
	queuePrevious := previous.CLIClientSessionID != p.CLIClientSessionID
	p.AccessSecretRef, p.RefreshSecretRef, err = newSecretRefs(issuer)
	if err != nil {
		return err
	}
	tx, err := s.prepareNextProfileLocked("switch", expectedSessionID, previous, p, queuePrevious)
	if err != nil {
		return err
	}
	if queuePrevious {
		accountID := previous.Account.ID
		if accountID != "" && !validCredentialID(accountID) {
			accountID = ""
		}
		if err := s.queueRevocationLocked(issuer, previous.CLIClientSessionID, previousCred.RefreshToken, accountID); err != nil {
			return errors.Join(err, s.abortAuthTransactionLocked(tx))
		}
	}
	rollback := func(cause error) error {
		return errors.Join(cause, s.abortAuthTransactionLocked(tx))
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return rollback(err)
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(err)
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

func (s ProfileStore) saveLocked(p Profile, cred Credential) error {
	if err := validateCredential(cred); err != nil {
		return err
	}
	// Refresh tokens rotate at the server before this method runs. Atomically
	// replace the active refresh value first so every crash point retains the
	// server-valid token. The old access token and expired profile metadata are
	// safe retry state until their subsequent atomic writes complete.
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return fmt.Errorf("store access token: %w", err)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return s.writeActiveProfile(s.profilePath(p.Issuer), append(b, '\n'))
}

func (s ProfileStore) Delete(issuer string) error {
	_, err := s.Remove(issuer)
	if errors.Is(err, ErrNoCredentials) {
		return nil
	}
	return err
}

// Remove atomically reads and deletes a profile and its secrets. The returned
// refresh credential lets logout revoke remotely after local cleanup succeeds.
func (s ProfileStore) Remove(issuer string) (Credential, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return Credential{}, err
	}
	path := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return Credential{}, err
	}
	lock := newSharedLock(path + ".lock")
	return s.removeCredential(issuer, lock)
}

func (s ProfileStore) removeCredential(issuer string, lock credentialLock) (credential Credential, resultErr error) {
	if issuer == "" || lock == nil {
		return Credential{}, ErrCredentialStoreUnavailable
	}
	if err := lock.Lock(); err != nil {
		return Credential{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			credential = Credential{}
		}
	}()
	p, err := s.loadNormalized(issuer)
	if errors.Is(err, ErrNoCredentials) {
		return Credential{}, ErrNoCredentials
	}
	if err != nil {
		return Credential{}, err
	}
	cred, credentialErr := s.credentialForProfile(p)
	var errs []error
	errs = append(errs, s.Secrets.Delete(p.AccessSecretRef), s.Secrets.Delete(p.RefreshSecretRef), s.DeleteManagedSSHIdentity(p.Issuer, p.CLIClientSessionID), s.DeletePeerEndpointIdentity(p.Issuer, p.CLIClientSessionID), s.DeletePeerAccountRoot(p.Issuer, p.Account.ID))
	for _, ref := range p.ObsoleteSecretRefs {
		errs = append(errs, s.Secrets.Delete(ref))
	}
	if err := os.Remove(s.profilePath(p.Issuer)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return Credential{}, err
	}
	return cred, credentialErr
}

// QueueRevocation durably retains a refresh token until server revocation is
// confirmed. Re-queueing the same client session is idempotent.
func (s ProfileStore) QueueRevocation(issuer, cliClientSessionID, refreshToken string, accountID ...string) (resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	profilePath := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(profilePath)); err != nil {
		return err
	}
	profileLock := newSharedLock(profilePath + ".lock")
	if err := profileLock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, profileLock.Unlock()) }()
	return s.queueRevocationLocked(issuer, cliClientSessionID, refreshToken, accountID...)
}

// queueRevocationLocked writes a revocation while the issuer profile lock is
// already held. Keeping one lock order prevents logout, switch, and recovery
// from losing each other's session records.
func (s ProfileStore) queueRevocationLocked(issuer, cliClientSessionID, refreshToken string, accountID ...string) (resultErr error) {
	if strings.TrimSpace(cliClientSessionID) == "" || strings.TrimSpace(refreshToken) == "" {
		return errors.New("pending revocation requires client session id and refresh token")
	}
	account := ""
	if len(accountID) > 0 {
		account = accountID[0]
		if account != "" && !validCredentialID(account) {
			return errors.New("pending revocation account id is invalid")
		}
	}
	path := s.pendingRevocationPath(issuer, cliClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	ref := pendingRefreshRef(issuer, cliClientSessionID)
	if err := s.Secrets.Set(ref, refreshToken); err != nil {
		return fmt.Errorf("store pending revocation token: %w", err)
	}
	record := PendingRevocation{Version: ProfileVersion, Issuer: issuer, CLIClientSessionID: cliClientSessionID, AccountID: account, RefreshSecretRef: ref, CreatedAt: time.Now().UTC()}
	b, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(path, append(b, '\n'), 0o600); err != nil {
		_ = s.Secrets.Delete(ref)
		return err
	}
	return nil
}

func (s ProfileStore) PendingRevocations(issuer string) (records []PendingRevocation, resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	profileLock := newSharedLock(s.profilePath(issuer) + ".lock")
	if err := ensureProfileDirectory(filepath.Dir(s.profilePath(issuer))); err != nil {
		return nil, err
	}
	if err := profileLock.Lock(); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, profileLock.Unlock()) }()
	activeSessionID := ""
	active, err := s.loadNormalized(issuer)
	if err == nil {
		activeSessionID = active.CLIClientSessionID
	} else if !errors.Is(err, ErrNoCredentials) {
		return nil, err
	}
	return s.pendingRevocationsLocked(issuer, activeSessionID)
}

func (s ProfileStore) pendingRevocationsLocked(issuer, activeSessionID string) ([]PendingRevocation, error) {
	var records []PendingRevocation
	dir := filepath.Join(s.Path, "pending-revocations")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := profileKey(issuer) + "-"
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var record PendingRevocation
		if err := json.Unmarshal(b, &record); err != nil {
			return nil, fmt.Errorf("parse pending revocation: %w", err)
		}
		if record.Issuer == issuer {
			if record.Version != ProfileVersion {
				return nil, errors.New("unsupported pending revocation version")
			}
			if record.CLIClientSessionID == activeSessionID {
				// Revoking any refresh token from the active session can revoke
				// the whole rotated-token family. Keep every same-session record
				// staged until a different profile becomes authoritative.
				continue
			}
			records = append(records, record)
		}
	}
	return records, nil
}

func (s ProfileStore) PendingRevocationCredential(record PendingRevocation) (Credential, error) {
	refresh, err := s.Secrets.Get(record.RefreshSecretRef)
	if err != nil {
		return Credential{}, fmt.Errorf("read pending revocation token: %w", err)
	}
	return Credential{RefreshToken: refresh, TokenType: "Bearer"}, nil
}

func (s ProfileStore) CompleteRevocation(record PendingRevocation) (resultErr error) {
	issuer, err := NormalizeIssuer(record.Issuer)
	if err != nil {
		return err
	}
	profilePath := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(profilePath)); err != nil {
		return err
	}
	profileLock := newSharedLock(profilePath + ".lock")
	if err := profileLock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, profileLock.Unlock()) }()
	path := s.existingPendingRevocationPath(record.Issuer, record.CLIClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	active, activeErr := s.loadNormalized(issuer)
	if err := s.Secrets.Delete(record.RefreshSecretRef); err != nil {
		return err
	}
	if activeErr != nil || active.CLIClientSessionID != record.CLIClientSessionID {
		if err := s.DeleteManagedSSHIdentity(record.Issuer, record.CLIClientSessionID); err != nil {
			return err
		}
		if err := s.DeletePeerEndpointIdentity(record.Issuer, record.CLIClientSessionID); err != nil {
			return err
		}
	}
	if record.AccountID != "" {
		if errors.Is(activeErr, ErrNoCredentials) || activeErr == nil && active.Account.ID != record.AccountID {
			if err := s.DeletePeerAccountRoot(record.Issuer, record.AccountID); err != nil {
				return err
			}
		} else if activeErr != nil {
			return activeErr
		}
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DiscardRevocation removes a queued copy without revoking the server session.
// It is used to roll back an account switch whose active-profile replacement
// did not commit.
func (s ProfileStore) DiscardRevocation(issuer, cliClientSessionID string) (resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	path := s.existingPendingRevocationPath(issuer, cliClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var record PendingRevocation
	if err := json.Unmarshal(b, &record); err != nil {
		return err
	}
	record.Cancelled = true
	b, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := s.Secrets.Delete(record.RefreshSecretRef); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DiscardPendingRevocations removes every local revocation record for issuer.
// Logout uses this after abandoning best-effort server revocation. It tolerates
// partially written metadata so corrupt historical entries cannot trap a user
// in a locally signed-in state.
func (s ProfileStore) DiscardPendingRevocations(issuer string) (resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.Path, "pending-revocations")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := profileKey(issuer) + "-"
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		lock := newSharedLock(path + ".lock")
		if lockErr := lock.Lock(); lockErr != nil {
			errs = append(errs, lockErr)
			continue
		}
		func() {
			defer func() {
				if unlockErr := lock.Unlock(); unlockErr != nil {
					errs = append(errs, unlockErr)
				}
			}()
			var record PendingRevocation
			if data, readErr := os.ReadFile(path); readErr == nil {
				_ = json.Unmarshal(data, &record)
			}
			if strings.HasPrefix(record.RefreshSecretRef, "revocation-") {
				errs = append(errs, s.Secrets.Delete(record.RefreshSecretRef))
			}
			if record.CLIClientSessionID != "" {
				errs = append(errs, s.DeleteManagedSSHIdentity(issuer, record.CLIClientSessionID))
			}
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				errs = append(errs, removeErr)
			}
		}()
	}
	return errors.Join(errs...)
}

func (s ProfileStore) MarkRevocationSucceeded(record PendingRevocation) (result PendingRevocation, resultErr error) {
	path := s.existingPendingRevocationPath(record.Issuer, record.CLIClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return PendingRevocation{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			result = PendingRevocation{}
		}
	}()
	record.ServerRevoked = true
	b, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return PendingRevocation{}, err
	}
	if err := atomicWrite(path, append(b, '\n'), 0o600); err != nil {
		return PendingRevocation{}, err
	}
	return record, nil
}

// QueueActiveRevocation moves the active profile into the durable revocation
// queue before removing its normal credential references.
func (s ProfileStore) QueueActiveRevocation(issuer string) (resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	profilePath := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(profilePath)); err != nil {
		return err
	}
	lock := newSharedLock(profilePath + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	p, err := s.loadNormalized(issuer)
	if err != nil {
		return err
	}
	pendingPath := s.pendingRevocationPath(p.Issuer, p.CLIClientSessionID)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		refreshToken, getErr := s.Secrets.Get(p.RefreshSecretRef)
		if getErr != nil {
			return getErr
		}
		if err := s.queueRevocationLocked(p.Issuer, p.CLIClientSessionID, refreshToken, p.Account.ID); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var deleteErrs []error
	deleteErrs = append(deleteErrs, s.Secrets.Delete(p.AccessSecretRef), s.Secrets.Delete(p.RefreshSecretRef), s.DeleteManagedSSHIdentity(p.Issuer, p.CLIClientSessionID))
	for _, ref := range p.ObsoleteSecretRefs {
		deleteErrs = append(deleteErrs, s.Secrets.Delete(ref))
	}
	if err := errors.Join(deleteErrs...); err != nil {
		return err
	}
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s ProfileStore) CredentialFor(issuer string) (Credential, error) {
	p, err := s.Load(issuer)
	if err != nil {
		return Credential{}, err
	}
	return s.credentialForProfile(p)
}

func (s ProfileStore) credentialForProfile(p Profile) (Credential, error) {
	a, err := s.Secrets.Get(p.AccessSecretRef)
	if err != nil {
		return Credential{}, fmt.Errorf("read access token: %w", err)
	}
	r, err := s.Secrets.Get(p.RefreshSecretRef)
	if err != nil {
		return Credential{}, fmt.Errorf("read refresh token: %w", err)
	}
	credential := Credential{AccessToken: a, RefreshToken: r, TokenType: "Bearer", ExpiresAt: p.AccessExpiresAt}
	if err := validateCredential(credential); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

type RefreshFunc func(Credential) (Credential, string, error)

// CredentialWithRefresh serializes the complete read-refresh-write operation.
// It rechecks expiry after taking the lock because another process may have
// refreshed while this process was waiting.
func (s ProfileStore) CredentialWithRefresh(issuer string, refreshBefore time.Duration, refresh RefreshFunc) (Credential, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return Credential{}, err
	}
	path := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(path)); err != nil {
		return Credential{}, err
	}
	lock := newSharedLock(path + ".lock")
	return s.credentialWithRefresh(issuer, refreshBefore, refresh, lock)
}

func (s ProfileStore) credentialWithRefresh(issuer string, refreshBefore time.Duration, refresh RefreshFunc, lock credentialLock) (credential Credential, resultErr error) {
	if issuer == "" || lock == nil {
		return Credential{}, ErrCredentialStoreUnavailable
	}
	path := s.profilePath(issuer)
	if err := lock.Lock(); err != nil {
		return Credential{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			credential = Credential{}
		}
	}()
	p, err := s.loadNormalized(issuer)
	if err != nil {
		return Credential{}, err
	}
	cred, err := s.credentialForProfile(p)
	if err != nil {
		return Credential{}, err
	}
	if refresh == nil || time.Now().Add(refreshBefore).Before(p.AccessExpiresAt) {
		return cred, nil
	}
	next, sessionID, err := refresh(cred)
	if err != nil {
		return Credential{}, err
	}
	if sessionID != p.CLIClientSessionID {
		recoverySessionID := sessionID
		if recoverySessionID == "" {
			recoverySessionID = p.CLIClientSessionID
		}
		if queueErr := s.queueRevocationLocked(issuer, recoverySessionID, next.RefreshToken); queueErr != nil {
			return Credential{}, errors.Join(errors.New("refreshed credential changed client session"), fmt.Errorf("retain rotated credential: %w", queueErr))
		}
		var cleanupErrs []error
		cleanupErrs = append(cleanupErrs, s.Secrets.Delete(p.AccessSecretRef), s.Secrets.Delete(p.RefreshSecretRef))
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			cleanupErrs = append(cleanupErrs, removeErr)
		}
		return Credential{}, errors.Join(errors.New("refreshed credential changed client session"), errors.Join(cleanupErrs...))
	}
	p.AccessExpiresAt = next.ExpiresAt
	if err := s.saveLocked(p, next); err != nil {
		return Credential{}, err
	}
	return next, nil
}

func ProfileStoreFor(cfg *Config) (ProfileStore, error) {
	defaultDir, err := DefaultCredentialDir()
	if err != nil {
		return ProfileStore{}, err
	}
	dir := cfg.Auth.ProfileDir
	if dir == "" {
		dir = defaultDir
	} else if !filepath.IsAbs(dir) {
		return ProfileStore{}, errors.New("auth.profile_dir must be an absolute path")
	}
	dir = filepath.Clean(dir)
	if err := publishCredentialLocation(defaultDir, dir); err != nil {
		return ProfileStore{}, err
	}
	var secrets SecretStore = KeyringStore{}
	if cfg.Auth.AllowFileFallback {
		secrets = FileSecretStore{Dir: filepath.Join(dir, "secrets")}
	}
	return ProfileStore{Path: dir, Secrets: secrets}, nil
}

func publishCredentialLocation(defaultDir, dir string) error {
	location := struct {
		Version    int    `json:"version"`
		ProfileDir string `json:"profile_dir"`
	}{Version: ProfileVersion, ProfileDir: dir}
	b, err := json.MarshalIndent(location, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(filepath.Dir(defaultDir), "credentials-location.json"), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("publish shared credential location: %w", err)
	}
	return nil
}
func DefaultCredentialDir() (string, error) {
	return userpaths.Config("paperboat/credentials")
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, data, atomicfile.Options{Mode: mode, OwnerUID: -1, OwnerGID: -1})
}
