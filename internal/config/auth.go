package config

import (
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
	"time"
)

const ProfileVersion = 1
const keyringService = "paperboat"
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
}

func newSharedLock(path string) *sharedLock { return &sharedLock{path: path + ".d"} }

func (l *sharedLock) Lock() error {
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
			return nil
		} else if !os.IsExist(err) {
			return err
		}
		stale, err := sharedLockIsStale(l.path, hostname)
		if err == nil && stale {
			stalePath := l.path + ".stale-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			if os.Rename(l.path, stalePath) == nil {
				_ = os.RemoveAll(stalePath)
				continue
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for shared credential lock %s", l.path)
		}
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
	return os.RemoveAll(l.path)
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
	Version          int       `json:"version"`
	Issuer           string    `json:"issuer"`
	Account          Account   `json:"account,omitempty"`
	ClientSessionID  string    `json:"client_session_id"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	AccessSecretRef  string    `json:"access_secret_ref"`
	RefreshSecretRef string    `json:"refresh_secret_ref"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type PendingRevocation struct {
	Version          int       `json:"version"`
	Issuer           string    `json:"issuer"`
	ClientSessionID  string    `json:"client_session_id"`
	RefreshSecretRef string    `json:"refresh_secret_ref"`
	CreatedAt        time.Time `json:"created_at"`
	ServerRevoked    bool      `json:"server_revoked,omitempty"`
	Cancelled        bool      `json:"cancelled,omitempty"`
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
	return atomicWrite(s.path(ref), []byte(value), 0o600)
}
func (s FileSecretStore) Get(ref string) (string, error) {
	p := s.path(ref)
	info, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("insecure credential file permissions %o; require 0600", info.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	return string(b), err
}
func (s FileSecretStore) Delete(ref string) error {
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
func secretRef(issuer, kind string) string { return "profile-" + profileKey(issuer) + "-" + kind }

func pendingRevocationKey(issuer, clientSessionID string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientSessionID))
	return hex.EncodeToString(sum[:16])
}

func pendingRefreshRef(issuer, clientSessionID string) string {
	return "revocation-" + pendingRevocationKey(issuer, clientSessionID) + "-refresh"
}

func (s ProfileStore) profilePath(issuer string) string {
	return filepath.Join(s.Path, "profiles", profileKey(issuer)+".json")
}

func (s ProfileStore) pendingRevocationPath(issuer, clientSessionID string) string {
	return filepath.Join(s.Path, "pending-revocations", profileKey(issuer)+"-"+pendingRevocationKey(issuer, clientSessionID)+".json")
}

func (s ProfileStore) existingPendingRevocationPath(issuer, clientSessionID string) string {
	path := s.pendingRevocationPath(issuer, clientSessionID)
	if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
		return path
	}
	return filepath.Join(s.Path, "pending-revocations", pendingRevocationKey(issuer, clientSessionID)+".json")
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

func (s ProfileStore) Save(p Profile, cred Credential) error {
	issuer, err := NormalizeIssuer(p.Issuer)
	if err != nil {
		return err
	}
	p.Issuer = issuer
	p.Version = ProfileVersion
	p.AccessSecretRef = secretRef(issuer, "access")
	p.RefreshSecretRef = secretRef(issuer, "refresh")
	p.UpdatedAt = time.Now().UTC()
	lock := newSharedLock(s.profilePath(issuer) + ".lock")
	if err := os.MkdirAll(filepath.Dir(s.profilePath(issuer)), 0o700); err != nil {
		return err
	}
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if _, err := os.Stat(s.profilePath(issuer)); err == nil {
		return ErrProfileExists
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	rollback := func(cause error) error {
		cleanupErr := errors.Join(
			s.Secrets.Delete(p.AccessSecretRef),
			s.Secrets.Delete(p.RefreshSecretRef),
		)
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
	if err := atomicWrite(s.profilePath(p.Issuer), append(b, '\n'), 0o600); err != nil {
		return rollback(err)
	}
	return nil
}

// Replace preserves the currently active profile if persisting its replacement
// fails. This is separate from refresh persistence because a rotated refresh
// token must never be rolled back to its server-invalid predecessor.
func (s ProfileStore) Replace(p Profile, cred Credential) error {
	issuer, err := NormalizeIssuer(p.Issuer)
	if err != nil {
		return err
	}
	p.Issuer = issuer
	p.Version = ProfileVersion
	p.AccessSecretRef = secretRef(issuer, "access")
	p.RefreshSecretRef = secretRef(issuer, "refresh")
	p.UpdatedAt = time.Now().UTC()
	path := s.profilePath(issuer)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	previous, err := s.loadNormalized(issuer)
	if err != nil {
		return err
	}
	previousCred, err := s.credentialForProfile(previous)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		var rollbackErrs []error
		rollbackErrs = append(rollbackErrs,
			s.Secrets.Set(previous.RefreshSecretRef, previousCred.RefreshToken),
			s.Secrets.Set(previous.AccessSecretRef, previousCred.AccessToken),
		)
		if rollbackErr := errors.Join(rollbackErrs...); rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("restore previous credentials: %w", rollbackErr))
		}
		return cause
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return fmt.Errorf("store replacement refresh token: %w", err)
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(fmt.Errorf("store replacement access token: %w", err))
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err := atomicWrite(path, append(b, '\n'), 0o600); err != nil {
		return rollback(err)
	}
	return nil
}

// Switch compares, retains, and replaces the active session under one issuer
// lock so overlapping account switches cannot associate credentials with a
// stale client session ID.
func (s ProfileStore) Switch(expectedSessionID string, p Profile, cred Credential) error {
	issuer, err := NormalizeIssuer(p.Issuer)
	if err != nil {
		return err
	}
	p.Issuer = issuer
	p.Version = ProfileVersion
	p.AccessSecretRef = secretRef(issuer, "access")
	p.RefreshSecretRef = secretRef(issuer, "refresh")
	p.UpdatedAt = time.Now().UTC()
	path := s.profilePath(issuer)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	previous, err := s.loadNormalized(issuer)
	if err != nil {
		return err
	}
	if previous.ClientSessionID != expectedSessionID {
		return ErrProfileChanged
	}
	previousCred, err := s.credentialForProfile(previous)
	if err != nil {
		return err
	}
	if err := s.QueueRevocation(issuer, previous.ClientSessionID, previousCred.RefreshToken); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var rollbackErrs []error
		rollbackErrs = append(rollbackErrs,
			s.Secrets.Set(previous.RefreshSecretRef, previousCred.RefreshToken),
			s.Secrets.Set(previous.AccessSecretRef, previousCred.AccessToken),
			s.DiscardRevocation(issuer, previous.ClientSessionID),
		)
		return errors.Join(cause, errors.Join(rollbackErrs...))
	}
	if err := s.Secrets.Set(p.RefreshSecretRef, cred.RefreshToken); err != nil {
		return rollback(err)
	}
	if err := s.Secrets.Set(p.AccessSecretRef, cred.AccessToken); err != nil {
		return rollback(err)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err := atomicWrite(path, append(b, '\n'), 0o600); err != nil {
		return rollback(err)
	}
	return nil
}

func (s ProfileStore) saveLocked(p Profile, cred Credential) error {
	// Refresh tokens rotate on every use. Persist the new refresh token first so
	// any later failure can retry with the still-valid token instead of replaying
	// the server-invalidated predecessor and revoking the session family.
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
	b = append(b, '\n')
	return atomicWrite(s.profilePath(p.Issuer), b, 0o600)
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Credential{}, err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return Credential{}, err
	}
	defer lock.Unlock()
	p, err := s.loadNormalized(issuer)
	if errors.Is(err, ErrNoCredentials) {
		return Credential{}, ErrNoCredentials
	}
	if err != nil {
		return Credential{}, err
	}
	cred, credentialErr := s.credentialForProfile(p)
	var errs []error
	errs = append(errs, s.Secrets.Delete(p.AccessSecretRef), s.Secrets.Delete(p.RefreshSecretRef))
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
func (s ProfileStore) QueueRevocation(issuer, clientSessionID, refreshToken string) error {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	if strings.TrimSpace(clientSessionID) == "" || strings.TrimSpace(refreshToken) == "" {
		return errors.New("pending revocation requires client session id and refresh token")
	}
	path := s.pendingRevocationPath(issuer, clientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	ref := pendingRefreshRef(issuer, clientSessionID)
	if err := s.Secrets.Set(ref, refreshToken); err != nil {
		return fmt.Errorf("store pending revocation token: %w", err)
	}
	record := PendingRevocation{Version: ProfileVersion, Issuer: issuer, ClientSessionID: clientSessionID, RefreshSecretRef: ref, CreatedAt: time.Now().UTC()}
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

func (s ProfileStore) PendingRevocations(issuer string) ([]PendingRevocation, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(s.Path, "pending-revocations")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []PendingRevocation
	prefix := profileKey(issuer) + "-"
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		// Current records are issuer-namespaced in their filename. Legacy
		// unprefixed records are decoded best-effort for migration compatibility;
		// malformed legacy records cannot be attributed and therefore cannot block
		// an unrelated issuer.
		matchingNamespace := strings.HasPrefix(entry.Name(), prefix)
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			if matchingNamespace {
				return nil, err
			}
			continue
		}
		var record PendingRevocation
		if err := json.Unmarshal(b, &record); err != nil {
			if matchingNamespace {
				return nil, fmt.Errorf("parse pending revocation: %w", err)
			}
			continue
		}
		if record.Issuer == issuer {
			if record.Version != ProfileVersion {
				return nil, errors.New("unsupported pending revocation version")
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

func (s ProfileStore) CompleteRevocation(record PendingRevocation) error {
	path := s.existingPendingRevocationPath(record.Issuer, record.ClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := s.Secrets.Delete(record.RefreshSecretRef); err != nil {
		return err
	}
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DiscardRevocation removes a queued copy without revoking the server session.
// It is used to roll back an account switch whose active-profile replacement
// did not commit.
func (s ProfileStore) DiscardRevocation(issuer, clientSessionID string) error {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	path := s.existingPendingRevocationPath(issuer, clientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
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

func (s ProfileStore) MarkRevocationSucceeded(record PendingRevocation) (PendingRevocation, error) {
	path := s.existingPendingRevocationPath(record.Issuer, record.ClientSessionID)
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return PendingRevocation{}, err
	}
	defer lock.Unlock()
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
func (s ProfileStore) QueueActiveRevocation(issuer string) error {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	profilePath := s.profilePath(issuer)
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		return err
	}
	lock := newSharedLock(profilePath + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	p, err := s.loadNormalized(issuer)
	if err != nil {
		return err
	}
	pendingPath := s.pendingRevocationPath(p.Issuer, p.ClientSessionID)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		refreshToken, getErr := s.Secrets.Get(p.RefreshSecretRef)
		if getErr != nil {
			return getErr
		}
		if err := s.QueueRevocation(p.Issuer, p.ClientSessionID, refreshToken); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var deleteErrs []error
	deleteErrs = append(deleteErrs, s.Secrets.Delete(p.AccessSecretRef), s.Secrets.Delete(p.RefreshSecretRef))
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
	return Credential{AccessToken: a, RefreshToken: r, TokenType: "Bearer", ExpiresAt: p.AccessExpiresAt}, nil
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Credential{}, err
	}
	lock := newSharedLock(path + ".lock")
	if err := lock.Lock(); err != nil {
		return Credential{}, err
	}
	defer lock.Unlock()
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
	if sessionID != p.ClientSessionID {
		recoverySessionID := sessionID
		if recoverySessionID == "" {
			recoverySessionID = p.ClientSessionID
		}
		if queueErr := s.QueueRevocation(issuer, recoverySessionID, next.RefreshToken); queueErr != nil {
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
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "paperboat", "credentials"), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
