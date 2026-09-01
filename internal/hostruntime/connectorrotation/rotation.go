// Package connectorrotation owns the host-side half of credential rotation.
//
// The control protocol owns the wire messages and the server owns policy and
// durable operation state. This package owns the small, security-sensitive
// boundary between those messages and a host credential store. In particular,
// private keys never enter a protocol message, a host-state snapshot, or a
// recovery record. A KeyStore implementation is expected to keep the private
// key in the platform credential facility and expose only signing by
// reference.
package connectorrotation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

var (
	ErrInvalidConfig      = errors.New("invalid connector rotation configuration")
	ErrOperationConflict  = errors.New("connector rotation operation conflicts with durable state")
	ErrOperationNotFound  = errors.New("connector rotation operation was not found")
	ErrRecoveryRequired   = errors.New("connector rotation requires recovery")
	ErrKeyUnavailable     = errors.New("connector rotation key is unavailable")
	ErrInstallationFailed = errors.New("replacement credential installation failed")
	ErrRevocationFailed   = errors.New("old credential revocation failed")
	ErrStaleMessage       = errors.New("connector rotation message is stale")
	ErrAlreadyTerminal    = errors.New("connector rotation is already terminal")
	ErrJournalCorrupt     = errors.New("connector rotation journal is corrupt")
	ErrJournalUncertain   = errors.New("connector rotation journal outcome is uncertain")
)

const (
	journalVersion    = 1
	maxJournalRecords = 64
	maxJournalBytes   = 1 << 20
)

type Phase string

const (
	PhaseChallenged    Phase = "challenged"
	PhaseProofAccepted Phase = "proof_accepted"
	PhaseInstalled     Phase = "installed"
	PhaseReady         Phase = "ready"
	PhaseRevoking      Phase = "revoking"
	PhaseRevoked       Phase = "revoked"
)

func phaseAtLeast(value, threshold Phase) bool {
	order := map[Phase]int{
		PhaseChallenged:    1,
		PhaseProofAccepted: 2,
		PhaseInstalled:     3,
		PhaseReady:         4,
		PhaseRevoking:      5,
		PhaseRevoked:       6,
	}
	return order[value] >= order[threshold]
}

func validPhase(p Phase) bool {
	switch p {
	case PhaseChallenged, PhaseProofAccepted, PhaseInstalled, PhaseReady, PhaseRevoking, PhaseRevoked:
		return true
	default:
		return false
	}
}

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// KeyReference is safe to persist. PublicKey is public identity material,
// never a private key. Reference must point at a platform credential store.
type KeyReference struct {
	Reference  string `json:"reference"`
	KeyID      string `json:"key_id"`
	Thumbprint string `json:"thumbprint"`
	PublicKey  []byte `json:"public_key"`
}

func (r KeyReference) Validate() error {
	if err := connectorprotocol.ValidateCredentialReference(r.Reference); err != nil ||
		connectorprotocol.ValidateIdentityKey(r.KeyID, r.Thumbprint) != nil ||
		len(r.PublicKey) != ed25519.PublicKeySize {
		return ErrInvalidConfig
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(r.PublicKey))
	if err != nil || thumbprint != r.Thumbprint || r.KeyID != "ed25519:"+thumbprint {
		return ErrInvalidConfig
	}
	return nil
}

func (r KeyReference) clone() KeyReference {
	r.PublicKey = append([]byte(nil), r.PublicKey...)
	return r
}

// KeyStore is deliberately reference-oriented. Put receives a newly-created
// private key only so the implementation can place it into Keychain,
// Credential Manager, Secret Service, TPM-backed storage, or an equivalent
// protected facility. Callers can never retrieve private bytes through this
// interface. Sign also keeps key material inside that facility.
type KeyStore interface {
	Put(context.Context, ed25519.PrivateKey) (KeyReference, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	// Delete must be idempotent. A missing reference is success because a
	// process can crash after deletion and before its terminal journal save.
	Delete(context.Context, string) error
}

// GenerateReplacementKey creates a fresh Ed25519 key using the supplied
// cryptographically secure reader and immediately transfers the private key
// to the injected platform store. The private slice is cleared before return.
func GenerateReplacementKey(ctx context.Context, store KeyStore, random io.Reader) (KeyReference, error) {
	if ctx == nil || store == nil {
		return KeyReference{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return KeyReference{}, err
	}
	if random == nil {
		random = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return KeyReference{}, err
	}
	defer clear(private)

	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		return KeyReference{}, err
	}
	want := KeyReference{
		KeyID:      "ed25519:" + thumbprint,
		Thumbprint: thumbprint,
		PublicKey:  append([]byte(nil), public...),
	}
	got, err := store.Put(ctx, private)
	if err != nil {
		return KeyReference{}, err
	}
	if err := ctx.Err(); err != nil {
		if got.Reference != "" {
			_ = store.Delete(context.Background(), got.Reference)
		}
		return KeyReference{}, err
	}
	if err := got.Validate(); err != nil || got.KeyID != want.KeyID || got.Thumbprint != want.Thumbprint || !equalBytes(got.PublicKey, want.PublicKey) {
		if got.Reference != "" {
			_ = store.Delete(context.Background(), got.Reference)
		}
		return KeyReference{}, ErrKeyUnavailable
	}
	return got.clone(), nil
}

// Installer applies a replacement credential to the host's replacement
// connector process and later stops the old process/session. Both methods
// must be idempotent for the exact operation and generation. No private key is
// passed: the runtime resolves NewCredentialReference through KeyStore.
type Installer interface {
	Install(context.Context, connectorprotocol.CredentialRotationInstall) error
	Revoke(context.Context, connectorprotocol.CredentialRotationRevoke) error
}

// Journal is the durable metadata boundary for one or more rotations. A
// journal stores references and protocol metadata only. Implementations must
// make Save idempotent for the same operation and reject identity changes.
type Journal interface {
	Load(context.Context, string) (Record, error)
	Save(context.Context, Record) error
}

type Config struct {
	AccountID               string
	TunnelID                string
	ConnectorID             string
	HostID                  string
	OldCredentialReference  string
	OldIdentityKeyID        string
	OldIdentityThumbprint   string
	OldCredentialGeneration uint64
	KeyStore                KeyStore
	Journal                 Journal
	Installer               Installer
	Clock                   Clock
	Random                  io.Reader
}

func (c Config) validate() error {
	if connectorprotocol.ValidateIdentifier(c.AccountID) != nil ||
		connectorprotocol.ValidateIdentifier(c.TunnelID) != nil ||
		connectorprotocol.ValidateIdentifier(c.ConnectorID) != nil ||
		connectorprotocol.ValidateIdentifier(c.HostID) != nil ||
		connectorprotocol.ValidateCredentialReference(c.OldCredentialReference) != nil ||
		connectorprotocol.ValidateIdentityKey(c.OldIdentityKeyID, c.OldIdentityThumbprint) != nil ||
		c.OldCredentialGeneration == 0 || c.KeyStore == nil || c.Journal == nil || c.Installer == nil {
		return ErrInvalidConfig
	}
	return nil
}

// Record is the restart-safe host journal representation. It intentionally
// excludes CredentialRotationProof, because detached signatures are not
// needed for recovery and retaining fewer bytes reduces accidental disclosure.
// All fields are either identity, public key, credential reference, or timing
// metadata. There is no private key, bearer, enrollment token, or secret.
type Record struct {
	Version                 int                                            `json:"version"`
	AccountID               string                                         `json:"account_id"`
	TunnelID                string                                         `json:"tunnel_id"`
	OperationID             string                                         `json:"operation_id"`
	ConnectorID             string                                         `json:"connector_id"`
	HostID                  string                                         `json:"host_id"`
	TargetSetHash           string                                         `json:"target_set_hash"`
	OldCredentialReference  string                                         `json:"old_credential_reference"`
	OldIdentityKeyID        string                                         `json:"old_identity_key_id"`
	OldIdentityThumbprint   string                                         `json:"old_identity_key_thumbprint"`
	OldCredentialGeneration uint64                                         `json:"old_credential_generation"`
	NewCredentialGeneration uint64                                         `json:"new_credential_generation"`
	NewKey                  KeyReference                                   `json:"new_key"`
	Challenge               *connectorprotocol.CredentialRotationChallenge `json:"challenge,omitempty"`
	Install                 *connectorprotocol.CredentialRotationInstall   `json:"install,omitempty"`
	Ready                   *connectorprotocol.CredentialRotationReady     `json:"ready,omitempty"`
	Revoke                  *connectorprotocol.CredentialRotationRevoke    `json:"revoke,omitempty"`
	Phase                   Phase                                          `json:"phase"`
	UpdatedAt               time.Time                                      `json:"updated_at"`
}

func (r Record) Validate(now time.Time) error {
	if r.Version != journalVersion || connectorprotocol.ValidateIdentifier(r.AccountID) != nil ||
		connectorprotocol.ValidateIdentifier(r.TunnelID) != nil || connectorprotocol.ValidateIdentifier(r.OperationID) != nil ||
		connectorprotocol.ValidateIdentifier(r.ConnectorID) != nil || connectorprotocol.ValidateIdentifier(r.HostID) != nil ||
		!validSHA256Hash(r.TargetSetHash) ||
		connectorprotocol.ValidateCredentialReference(r.OldCredentialReference) != nil ||
		connectorprotocol.ValidateIdentityKey(r.OldIdentityKeyID, r.OldIdentityThumbprint) != nil ||
		r.OldCredentialGeneration == 0 || r.NewCredentialGeneration == 0 || r.NewCredentialGeneration != r.OldCredentialGeneration+1 ||
		!validPhase(r.Phase) || r.UpdatedAt.IsZero() {
		return ErrJournalCorrupt
	}
	if err := r.NewKey.Validate(); err != nil {
		return ErrJournalCorrupt
	}
	if r.Challenge == nil {
		return ErrJournalCorrupt
	}
	if err := r.Challenge.Validate(time.Time{}); err != nil ||
		r.Challenge.AccountID != r.AccountID || r.Challenge.TunnelID != r.TunnelID ||
		r.Challenge.OperationID != r.OperationID || r.Challenge.ConnectorID != r.ConnectorID ||
		r.Challenge.HostID != r.HostID || r.Challenge.TargetSetHash != r.TargetSetHash ||
		r.Challenge.OldCredentialGeneration != r.OldCredentialGeneration ||
		r.Challenge.NewCredentialGeneration != r.NewCredentialGeneration ||
		r.Challenge.OldIdentityKeyID != r.OldIdentityKeyID ||
		r.Challenge.OldIdentityKeyThumbprint != r.OldIdentityThumbprint {
		return ErrJournalCorrupt
	}
	if phaseAtLeast(r.Phase, PhaseInstalled) {
		if r.Install == nil || r.Install.Validate(time.Time{}) != nil || !r.installMatches(*r.Install) {
			return ErrJournalCorrupt
		}
	}
	if phaseAtLeast(r.Phase, PhaseReady) {
		if r.Ready == nil || r.Ready.Validate(time.Time{}) != nil || !r.readyMatches(*r.Ready) {
			return ErrJournalCorrupt
		}
	}
	if phaseAtLeast(r.Phase, PhaseRevoking) {
		if r.Revoke == nil || r.Revoke.Validate(time.Time{}) != nil || !r.revokeMatches(*r.Revoke) {
			return ErrJournalCorrupt
		}
	}
	if !now.IsZero() && r.UpdatedAt.After(now.Add(connectorprotocol.MaxClockSkew)) {
		return ErrJournalCorrupt
	}
	return nil
}

func (r Record) installMatches(install connectorprotocol.CredentialRotationInstall) bool {
	return install.AccountID == r.AccountID && install.TunnelID == r.TunnelID && install.OperationID == r.OperationID && install.ConnectorID == r.ConnectorID && install.HostID == r.HostID && install.TargetSetHash == r.TargetSetHash && install.OldCredentialGeneration == r.OldCredentialGeneration && install.NewCredentialGeneration == r.NewCredentialGeneration && install.NewIdentityKeyID == r.NewKey.KeyID && install.NewIdentityKeyThumbprint == r.NewKey.Thumbprint && install.NewCredentialReference == r.NewKey.Reference && equalStringBytes(install.NewPublicKey, r.NewKey.PublicKey) && install.SessionID == r.Challenge.SessionID && install.ProcessGeneration == r.Challenge.ProcessGeneration && install.ChallengeNonce == r.Challenge.ChallengeNonce && install.OverlapUntil.Equal(r.Challenge.OverlapUntil) && install.NewCredentialValidUntil.Equal(r.Challenge.NewCredentialValidUntil)
}

func (r Record) readyMatches(ready connectorprotocol.CredentialRotationReady) bool {
	return ready.AccountID == r.AccountID && ready.TunnelID == r.TunnelID && ready.OperationID == r.OperationID && ready.ConnectorID == r.ConnectorID && ready.HostID == r.HostID && ready.TargetSetHash == r.TargetSetHash && ready.OldCredentialGeneration == r.OldCredentialGeneration && ready.NewCredentialGeneration == r.NewCredentialGeneration && ready.NewIdentityKeyID == r.NewKey.KeyID && ready.NewIdentityKeyThumbprint == r.NewKey.Thumbprint && ready.NewCredentialReference == r.NewKey.Reference && equalStringBytes(ready.NewPublicKey, r.NewKey.PublicKey) && ready.PreviousSessionID == r.Install.SessionID && ready.ProcessGeneration == r.Install.ReplacementProcessGeneration && ready.NewCredentialValidUntil.Equal(r.Install.NewCredentialValidUntil)
}

func (r Record) revokeMatches(revoke connectorprotocol.CredentialRotationRevoke) bool {
	sameReadySession := revoke.SessionID == r.Ready.SessionID && revoke.ProcessGeneration == r.Ready.ProcessGeneration
	reboundSession := revoke.SessionID != r.Ready.SessionID && revoke.ProcessGeneration > r.Ready.ProcessGeneration
	return revoke.AccountID == r.AccountID && revoke.TunnelID == r.TunnelID && revoke.OperationID == r.OperationID && revoke.ConnectorID == r.ConnectorID && revoke.HostID == r.HostID && revoke.TargetSetHash == r.TargetSetHash && (sameReadySession || reboundSession) && revoke.OldCredentialGeneration == r.OldCredentialGeneration && revoke.NewCredentialGeneration == r.NewCredentialGeneration
}

func (r Record) clone() Record {
	r.NewKey = r.NewKey.clone()
	if r.Challenge != nil {
		copy := *r.Challenge
		r.Challenge = &copy
	}
	if r.Install != nil {
		copy := *r.Install
		r.Install = &copy
	}
	if r.Ready != nil {
		copy := *r.Ready
		r.Ready = &copy
	}
	if r.Revoke != nil {
		copy := *r.Revoke
		r.Revoke = &copy
	}
	return r
}

type Manager struct {
	mu     sync.Mutex
	config Config
	record *Record
}

func New(config Config) (*Manager, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Manager{config: config}, nil
}

// Recover loads one operation and verifies every durable identity binding. It
// does not issue a message or mutate the key store, so calling it repeatedly
// after a process restart is safe.
func (m *Manager) Recover(ctx context.Context, operationID string) error {
	if m == nil || ctx == nil || connectorprotocol.ValidateIdentifier(operationID) != nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := m.config.Journal.Load(ctx, operationID)
	if err != nil {
		return err
	}
	if err := record.Validate(m.config.Clock.Now().UTC()); err != nil {
		return err
	}
	if record.OperationID != operationID || !m.identityMatches(record) {
		return ErrOperationConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record != nil && m.record.OperationID != record.OperationID {
		return ErrOperationConflict
	}
	copy := record.clone()
	m.record = &copy
	return nil
}

func (m *Manager) identityMatches(record Record) bool {
	return record.AccountID == m.config.AccountID && record.TunnelID == m.config.TunnelID && record.ConnectorID == m.config.ConnectorID && record.HostID == m.config.HostID && record.OldCredentialReference == m.config.OldCredentialReference && record.OldIdentityKeyID == m.config.OldIdentityKeyID && record.OldIdentityThumbprint == m.config.OldIdentityThumbprint && record.OldCredentialGeneration == m.config.OldCredentialGeneration
}

// Record returns only safe restart metadata. It never returns a private key.
func (m *Manager) Record() (Record, bool) {
	if m == nil {
		return Record{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		return Record{}, false
	}
	return m.record.clone(), true
}

func (m *Manager) AcceptChallenge(ctx context.Context, challenge connectorprotocol.CredentialRotationChallenge) (connectorprotocol.CredentialRotationProof, error) {
	if m == nil || ctx == nil {
		return connectorprotocol.CredentialRotationProof{}, ErrInvalidConfig
	}
	now := m.config.Clock.Now().UTC()
	if err := challenge.Validate(now); err != nil {
		return connectorprotocol.CredentialRotationProof{}, err
	}
	if !m.challengeIdentityMatches(challenge) {
		return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeIdentityMismatch, connectorprotocol.ReasonAuthentication, false, ErrOperationConflict)
	}
	if err := ctx.Err(); err != nil {
		return connectorprotocol.CredentialRotationProof{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		persisted, loadErr := m.config.Journal.Load(ctx, challenge.OperationID)
		switch {
		case loadErr == nil:
			if persisted.Validate(time.Time{}) != nil || !m.identityMatches(persisted) {
				return connectorprotocol.CredentialRotationProof{}, ErrOperationConflict
			}
			copy := persisted.clone()
			m.record = &copy
		case !errors.Is(loadErr, ErrOperationNotFound):
			return connectorprotocol.CredentialRotationProof{}, loadErr
		}
	}
	if m.record != nil {
		if !m.sameChallengeTarget(*m.record.Challenge, challenge) {
			return connectorprotocol.CredentialRotationProof{}, ErrOperationConflict
		}
		if m.record.Phase == PhaseRevoked {
			return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeStaleGeneration, connectorprotocol.ReasonStaleGeneration, false, ErrAlreadyTerminal)
		}
		if m.record.Phase != PhaseChallenged && m.record.Phase != PhaseProofAccepted {
			return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeStaleGeneration, connectorprotocol.ReasonStaleGeneration, false, ErrStaleMessage)
		}
		if !m.sameChallenge(*m.record.Challenge, challenge) {
			updated := m.record.clone()
			updated.Challenge = cloneChallenge(challenge)
			updated.Install = nil
			updated.Ready = nil
			updated.Revoke = nil
			updated.Phase = PhaseChallenged
			updated.UpdatedAt = now
			if err := m.saveLocked(ctx, updated); err != nil {
				return connectorprotocol.CredentialRotationProof{}, err
			}
		}
	} else {
		newKey, err := GenerateReplacementKey(ctx, m.config.KeyStore, m.config.Random)
		if err != nil {
			return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, err)
		}
		record := Record{
			Version: journalVersion, AccountID: challenge.AccountID, TunnelID: challenge.TunnelID,
			OperationID: challenge.OperationID, ConnectorID: challenge.ConnectorID, HostID: challenge.HostID,
			TargetSetHash: challenge.TargetSetHash, OldCredentialReference: m.config.OldCredentialReference,
			OldIdentityKeyID: challenge.OldIdentityKeyID, OldIdentityThumbprint: challenge.OldIdentityKeyThumbprint,
			OldCredentialGeneration: challenge.OldCredentialGeneration, NewCredentialGeneration: challenge.NewCredentialGeneration,
			NewKey: newKey, Challenge: cloneChallenge(challenge), Phase: PhaseChallenged, UpdatedAt: now,
		}
		if err := record.Validate(time.Time{}); err != nil {
			_ = m.config.KeyStore.Delete(context.Background(), newKey.Reference)
			return connectorprotocol.CredentialRotationProof{}, err
		}
		if err := m.config.Journal.Save(ctx, record); err != nil {
			_ = m.config.KeyStore.Delete(context.Background(), newKey.Reference)
			return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, err)
		}
		m.record = &record
	}
	proof, err := m.signProofLocked(ctx, *m.record)
	if err != nil {
		return connectorprotocol.CredentialRotationProof{}, err
	}
	if m.record.Phase == PhaseChallenged {
		next := m.record.clone()
		next.Phase = PhaseProofAccepted
		next.UpdatedAt = now
		if err := m.saveLocked(ctx, next); err != nil {
			return connectorprotocol.CredentialRotationProof{}, err
		}
	}
	return proof, nil
}

func (m *Manager) challengeIdentityMatches(challenge connectorprotocol.CredentialRotationChallenge) bool {
	return challenge.AccountID == m.config.AccountID && challenge.TunnelID == m.config.TunnelID && challenge.ConnectorID == m.config.ConnectorID && challenge.HostID == m.config.HostID && challenge.OldCredentialGeneration == m.config.OldCredentialGeneration && challenge.OldIdentityKeyID == m.config.OldIdentityKeyID && challenge.OldIdentityKeyThumbprint == m.config.OldIdentityThumbprint
}

func (m *Manager) signProofLocked(ctx context.Context, record Record) (connectorprotocol.CredentialRotationProof, error) {
	publicKey := base64.RawURLEncoding.EncodeToString(record.NewKey.PublicKey)
	proof := connectorprotocol.CredentialRotationProof{
		AccountID: record.AccountID, TunnelID: record.TunnelID, OperationID: record.OperationID,
		ConnectorID: record.ConnectorID, HostID: record.HostID, SessionID: record.Challenge.SessionID,
		ProcessGeneration: record.Challenge.ProcessGeneration, TargetSetHash: record.TargetSetHash,
		OldCredentialGeneration: record.OldCredentialGeneration, NewCredentialGeneration: record.NewCredentialGeneration,
		OldIdentityKeyID: record.OldIdentityKeyID, OldIdentityKeyThumbprint: record.OldIdentityThumbprint,
		NewIdentityKeyID: record.NewKey.KeyID, NewIdentityKeyThumbprint: record.NewKey.Thumbprint,
		NewPublicKey: publicKey, NewCredentialReference: record.NewKey.Reference,
		ChallengeNonce: record.Challenge.ChallengeNonce, IssuedAt: record.Challenge.IssuedAt,
		NewCredentialValidUntil: record.Challenge.NewCredentialValidUntil,
	}
	payload, err := connectorprotocol.CredentialRotationProofPayload(proof)
	if err != nil {
		return connectorprotocol.CredentialRotationProof{}, err
	}
	oldSignature, err := m.config.KeyStore.Sign(ctx, m.config.OldCredentialReference, payload)
	if err != nil {
		return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeAuthenticationFailed, connectorprotocol.ReasonAuthentication, true, errors.Join(ErrKeyUnavailable, err))
	}
	newSignature, err := m.config.KeyStore.Sign(ctx, record.NewKey.Reference, payload)
	if err != nil {
		return connectorprotocol.CredentialRotationProof{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, errors.Join(ErrKeyUnavailable, err))
	}
	proof.OldSignedProof = base64.RawURLEncoding.EncodeToString(oldSignature)
	proof.NewSignedProof = base64.RawURLEncoding.EncodeToString(newSignature)
	if err := proof.Validate(nowUTC(m.config.Clock)); err != nil {
		return connectorprotocol.CredentialRotationProof{}, err
	}
	return proof, nil
}

func (m *Manager) AcceptInstall(ctx context.Context, install connectorprotocol.CredentialRotationInstall) (connectorprotocol.CredentialRotationAck, error) {
	if m == nil || ctx == nil {
		return connectorprotocol.CredentialRotationAck{}, ErrInvalidConfig
	}
	now := nowUTC(m.config.Clock)
	if err := install.Validate(now); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		return connectorprotocol.CredentialRotationAck{}, ErrOperationNotFound
	}
	record := *m.record
	if !record.installMatches(install) || install.NewCredentialValidUntil.Before(now) {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeIdentityMismatch, connectorprotocol.ReasonAuthentication, false, ErrOperationConflict)
	}
	if phaseAtLeast(record.Phase, PhaseInstalled) {
		return installAck(install), nil
	}
	if record.Phase != PhaseProofAccepted {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeStaleGeneration, connectorprotocol.ReasonStaleGeneration, false, ErrStaleMessage)
	}
	if err := ctx.Err(); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	if err := m.config.Installer.Install(ctx, install); err != nil {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, errors.Join(ErrInstallationFailed, err))
	}
	record.Install = cloneInstall(install)
	record.Phase = PhaseInstalled
	record.UpdatedAt = now
	if err := m.saveLocked(ctx, record); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	return installAck(install), nil
}

// MarkReady emits credential-aware replacement-session readiness. It refuses
// the old process generation and carries the exact replacement key identity,
// reference, configuration generation, and content hash.
func (m *Manager) MarkReady(ctx context.Context, sessionID string, processGeneration, configGeneration uint64, configContentHash string, edgeReady, routeReady, originReady bool) (connectorprotocol.CredentialRotationReady, error) {
	if m == nil || ctx == nil || connectorprotocol.ValidateIdentifier(sessionID) != nil {
		return connectorprotocol.CredentialRotationReady{}, ErrInvalidConfig
	}
	now := nowUTC(m.config.Clock)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil || m.record.Install == nil {
		return connectorprotocol.CredentialRotationReady{}, ErrOperationNotFound
	}
	record := *m.record
	if phaseAtLeast(record.Phase, PhaseReady) {
		if record.Ready != nil && record.Ready.SessionID == sessionID && record.Ready.ProcessGeneration == processGeneration && record.Ready.ConfigGeneration == configGeneration && record.Ready.ConfigContentHash == configContentHash {
			return *record.Ready, nil
		}
		return connectorprotocol.CredentialRotationReady{}, typed(connectorprotocol.CodeStaleGeneration, connectorprotocol.ReasonStaleGeneration, false, ErrStaleMessage)
	}
	if record.Phase != PhaseInstalled || sessionID == record.Install.SessionID || processGeneration < record.Install.ReplacementProcessGeneration {
		return connectorprotocol.CredentialRotationReady{}, typed(connectorprotocol.CodeIdentityMismatch, connectorprotocol.ReasonAuthentication, false, ErrOperationConflict)
	}
	if configGeneration == 0 || !validSHA256Hash(configContentHash) {
		return connectorprotocol.CredentialRotationReady{}, ErrInvalidConfig
	}
	ready := connectorprotocol.CredentialRotationReady{
		AccountID: record.AccountID, TunnelID: record.TunnelID, OperationID: record.OperationID,
		ConnectorID: record.ConnectorID, HostID: record.HostID, SessionID: sessionID,
		PreviousSessionID: record.Install.SessionID, ProcessGeneration: processGeneration,
		TargetSetHash: record.TargetSetHash, OldCredentialGeneration: record.OldCredentialGeneration,
		NewCredentialGeneration: record.NewCredentialGeneration, NewIdentityKeyID: record.NewKey.KeyID,
		NewIdentityKeyThumbprint: record.NewKey.Thumbprint,
		NewPublicKey:             base64.RawURLEncoding.EncodeToString(record.NewKey.PublicKey),
		NewCredentialReference:   record.NewKey.Reference, NewCredentialValidUntil: record.Install.NewCredentialValidUntil,
		ConfigGeneration: configGeneration, ConfigContentHash: configContentHash,
		EdgeReady: edgeReady, RouteReady: routeReady, OriginReady: originReady, ReadyAt: now,
	}
	if err := ready.Validate(now); err != nil {
		return connectorprotocol.CredentialRotationReady{}, err
	}
	if err := ctx.Err(); err != nil {
		return connectorprotocol.CredentialRotationReady{}, err
	}
	record.Ready = cloneReady(ready)
	record.Phase = PhaseReady
	record.UpdatedAt = now
	if err := m.saveLocked(ctx, record); err != nil {
		return connectorprotocol.CredentialRotationReady{}, err
	}
	return ready, nil
}

// AcceptRevoke deletes the old private key only after exact operation,
// connector, target-generation, replacement-session, and process-generation
// checks. New key material remains available for the replacement session.
func (m *Manager) AcceptRevoke(ctx context.Context, revoke connectorprotocol.CredentialRotationRevoke) (connectorprotocol.CredentialRotationAck, error) {
	if m == nil || ctx == nil {
		return connectorprotocol.CredentialRotationAck{}, ErrInvalidConfig
	}
	now := nowUTC(m.config.Clock)
	if err := revoke.Validate(now); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil || m.record.Ready == nil {
		return connectorprotocol.CredentialRotationAck{}, ErrOperationNotFound
	}
	record := *m.record
	if record.Phase == PhaseRevoked {
		if record.Revoke != nil && record.revokeMatches(revoke) {
			return revokeAck(revoke), nil
		}
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeStaleGeneration, connectorprotocol.ReasonStaleGeneration, false, ErrAlreadyTerminal)
	}
	if (record.Phase != PhaseReady && record.Phase != PhaseRevoking) || !record.revokeMatches(revoke) {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeIdentityMismatch, connectorprotocol.ReasonAuthentication, false, ErrOperationConflict)
	}
	if record.Phase == PhaseReady {
		record.Revoke = cloneRevoke(revoke)
		record.Phase = PhaseRevoking
		record.UpdatedAt = now
		if err := m.saveLocked(ctx, record); err != nil {
			return connectorprotocol.CredentialRotationAck{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	if err := m.config.Installer.Revoke(ctx, revoke); err != nil {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, errors.Join(ErrRevocationFailed, err))
	}
	if err := m.config.KeyStore.Delete(ctx, m.config.OldCredentialReference); err != nil {
		return connectorprotocol.CredentialRotationAck{}, typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, errors.Join(ErrRevocationFailed, err))
	}
	record.Phase = PhaseRevoked
	record.UpdatedAt = nowUTC(m.config.Clock)
	if err := m.saveLocked(ctx, record); err != nil {
		return connectorprotocol.CredentialRotationAck{}, err
	}
	return revokeAck(revoke), nil
}

func (m *Manager) sameChallenge(a, b connectorprotocol.CredentialRotationChallenge) bool {
	return a.AccountID == b.AccountID && a.TunnelID == b.TunnelID && a.OperationID == b.OperationID && a.ConnectorID == b.ConnectorID && a.HostID == b.HostID && a.SessionID == b.SessionID && a.ProcessGeneration == b.ProcessGeneration && a.TargetSetHash == b.TargetSetHash && a.Target == b.Target && a.OldCredentialGeneration == b.OldCredentialGeneration && a.NewCredentialGeneration == b.NewCredentialGeneration && a.OldIdentityKeyID == b.OldIdentityKeyID && a.OldIdentityKeyThumbprint == b.OldIdentityKeyThumbprint && a.ChallengeNonce == b.ChallengeNonce && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.OverlapUntil.Equal(b.OverlapUntil) && a.NewCredentialValidUntil.Equal(b.NewCredentialValidUntil)
}

func (m *Manager) sameChallengeTarget(a, b connectorprotocol.CredentialRotationChallenge) bool {
	return a.AccountID == b.AccountID && a.TunnelID == b.TunnelID && a.OperationID == b.OperationID && a.ConnectorID == b.ConnectorID && a.HostID == b.HostID && a.TargetSetHash == b.TargetSetHash && a.Target == b.Target && a.OldCredentialGeneration == b.OldCredentialGeneration && a.NewCredentialGeneration == b.NewCredentialGeneration && a.OldIdentityKeyID == b.OldIdentityKeyID && a.OldIdentityKeyThumbprint == b.OldIdentityKeyThumbprint && a.OverlapUntil.Equal(b.OverlapUntil) && a.NewCredentialValidUntil.Equal(b.NewCredentialValidUntil)
}

func (m *Manager) saveLocked(ctx context.Context, record Record) error {
	if err := record.Validate(time.Time{}); err != nil {
		return err
	}
	if err := m.config.Journal.Save(ctx, record); err != nil {
		return typed(connectorprotocol.CodeCredentialRotationFailed, connectorprotocol.ReasonCredentialRotation, true, errors.Join(ErrRecoveryRequired, err))
	}
	copy := record.clone()
	m.record = &copy
	return nil
}

func typed(code connectorprotocol.Code, reason connectorprotocol.DisconnectReason, retryable bool, cause error) error {
	return &connectorprotocol.Error{Code: code, Reason: reason, Retryable: retryable, Cause: cause}
}

func nowUTC(clock Clock) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock.Now().UTC()
}

func installAck(install connectorprotocol.CredentialRotationInstall) connectorprotocol.CredentialRotationAck {
	return connectorprotocol.CredentialRotationAck{AccountID: install.AccountID, TunnelID: install.TunnelID, OperationID: install.OperationID, ConnectorID: install.ConnectorID, HostID: install.HostID, SessionID: install.SessionID, ProcessGeneration: install.ProcessGeneration, TargetSetHash: install.TargetSetHash, OldCredentialGeneration: install.OldCredentialGeneration, NewCredentialGeneration: install.NewCredentialGeneration, Status: connectorprotocol.RotationAckInstalled}
}

func revokeAck(revoke connectorprotocol.CredentialRotationRevoke) connectorprotocol.CredentialRotationAck {
	return connectorprotocol.CredentialRotationAck{AccountID: revoke.AccountID, TunnelID: revoke.TunnelID, OperationID: revoke.OperationID, ConnectorID: revoke.ConnectorID, HostID: revoke.HostID, SessionID: revoke.SessionID, ProcessGeneration: revoke.ProcessGeneration, TargetSetHash: revoke.TargetSetHash, OldCredentialGeneration: revoke.OldCredentialGeneration, NewCredentialGeneration: revoke.NewCredentialGeneration, Status: connectorprotocol.RotationAckRevoked}
}

func cloneChallenge(value connectorprotocol.CredentialRotationChallenge) *connectorprotocol.CredentialRotationChallenge {
	return &value
}
func cloneInstall(value connectorprotocol.CredentialRotationInstall) *connectorprotocol.CredentialRotationInstall {
	return &value
}
func cloneReady(value connectorprotocol.CredentialRotationReady) *connectorprotocol.CredentialRotationReady {
	return &value
}
func cloneRevoke(value connectorprotocol.CredentialRotationRevoke) *connectorprotocol.CredentialRotationRevoke {
	return &value
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStringBytes(encoded string, raw []byte) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && equalBytes(decoded, raw)
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func validSHA256Hash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// MemoryJournal is useful for deterministic unit tests and embedders that
// already provide a durable transaction around this package.
type MemoryJournal struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryJournal() *MemoryJournal { return &MemoryJournal{records: make(map[string]Record)} }

func (j *MemoryJournal) Load(ctx context.Context, operationID string) (Record, error) {
	if j == nil || ctx == nil {
		return Record{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[operationID]
	if !ok {
		return Record{}, ErrOperationNotFound
	}
	return record.clone(), nil
}

func (j *MemoryJournal) Save(ctx context.Context, record Record) error {
	if j == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(time.Time{}); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, ok := j.records[record.OperationID]; ok && !sameStableRecord(existing, record) {
		return ErrOperationConflict
	}
	j.records[record.OperationID] = record.clone()
	return nil
}

func sameStableRecord(a, b Record) bool {
	return a.Version == b.Version && a.AccountID == b.AccountID && a.TunnelID == b.TunnelID && a.OperationID == b.OperationID && a.ConnectorID == b.ConnectorID && a.HostID == b.HostID && a.TargetSetHash == b.TargetSetHash && a.OldCredentialReference == b.OldCredentialReference && a.OldIdentityKeyID == b.OldIdentityKeyID && a.OldIdentityThumbprint == b.OldIdentityThumbprint && a.OldCredentialGeneration == b.OldCredentialGeneration && a.NewCredentialGeneration == b.NewCredentialGeneration && a.NewKey.Reference == b.NewKey.Reference && a.NewKey.KeyID == b.NewKey.KeyID && a.NewKey.Thumbprint == b.NewKey.Thumbprint && equalBytes(a.NewKey.PublicKey, b.NewKey.PublicKey)
}

// FileJournal provides a small atomic, 0600 metadata journal. Its checksum and
// last-known-good sidecar make corruption fail closed while still allowing a
// restart to recover the last committed operation phase. It is intentionally
// separate from hoststate.State so in-flight operations cannot be mistaken for
// desired tunnel state.
type FileJournal struct {
	mu          sync.Mutex
	path        string
	records     map[string]Record
	needsRepair bool
}

type fileDocument struct {
	Version  int      `json:"version"`
	Records  []Record `json:"records"`
	Checksum string   `json:"checksum"`
}

type fileDocumentPayload struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

func OpenFileJournal(path string) (*FileJournal, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(path) || clean != path || path == string(filepath.Separator) {
		return nil, ErrInvalidConfig
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidConfig
	}
	journal := &FileJournal{path: path, records: make(map[string]Record)}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return nil, ErrJournalCorrupt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrJournalCorrupt
	}
	records, exists, err := readJournalRecords(path)
	if err == nil && exists {
		journal.records = records
		return journal, nil
	}
	if err == nil && !exists {
		backupRecords, backupExists, backupErr := readJournalRecords(journal.backupPath())
		if backupErr != nil {
			return nil, backupErr
		}
		if backupExists {
			journal.records = backupRecords
			journal.needsRepair = true
		}
		return journal, nil
	}
	backupRecords, backupExists, backupErr := readJournalRecords(journal.backupPath())
	if backupErr != nil || !backupExists {
		if err != nil {
			return nil, ErrJournalCorrupt
		}
		return nil, ErrJournalCorrupt
	}
	journal.records = backupRecords
	journal.needsRepair = true
	return journal, nil
}

func (j *FileJournal) Load(ctx context.Context, operationID string) (Record, error) {
	if j == nil || ctx == nil {
		return Record{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[operationID]
	if !ok {
		return Record{}, ErrOperationNotFound
	}
	return record.clone(), nil
}

func (j *FileJournal) Save(ctx context.Context, record Record) error {
	if j == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(time.Time{}); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, ok := j.records[record.OperationID]; ok && !sameStableRecord(existing, record) {
		return ErrOperationConflict
	}
	next := make(map[string]Record, len(j.records)+1)
	for id, value := range j.records {
		next[id] = value
	}
	next[record.OperationID] = record.clone()
	if len(next) > maxJournalRecords {
		return ErrJournalUncertain
	}
	ids := make([]string, 0, len(next))
	for id := range next {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := fileDocumentPayload{Version: journalVersion, Records: make([]Record, 0, len(ids))}
	for _, id := range ids {
		document.Records = append(document.Records, next[id])
	}
	encoded, err := marshalJournalDocument(document)
	if err != nil {
		return err
	}
	if len(encoded) > maxJournalBytes {
		return ErrJournalUncertain
	}
	if !j.needsRepair {
		if _, exists, err := readJournalRecords(j.path); err != nil {
			return errors.Join(ErrJournalUncertain, err)
		} else if exists {
			previous, readErr := os.ReadFile(j.path)
			if readErr != nil {
				return errors.Join(ErrJournalUncertain, readErr)
			}
			if len(previous) > maxJournalBytes {
				return ErrJournalUncertain
			}
			if err := atomicfile.Write(j.backupPath(), previous, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
				return errors.Join(ErrJournalUncertain, err)
			}
		}
	}
	if err := atomicfile.Write(j.path, encoded, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return errors.Join(ErrJournalUncertain, err)
	}
	j.records = next
	j.needsRepair = false
	return nil
}

func (j *FileJournal) backupPath() string { return j.path + ".bak" }

func marshalJournalDocument(payload fileDocumentPayload) ([]byte, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payloadBytes)
	return json.Marshal(fileDocument{
		Version:  payload.Version,
		Records:  payload.Records,
		Checksum: "sha256:" + hex.EncodeToString(digest[:]),
	})
}

func readJournalRecords(path string) (map[string]Record, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || len(data) == 0 || len(data) > maxJournalBytes {
		return nil, false, ErrJournalCorrupt
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, false, ErrJournalCorrupt
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, false, ErrJournalCorrupt
	}
	var document fileDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || document.Version != journalVersion || len(document.Records) > maxJournalRecords || !validSHA256Hash(document.Checksum) {
		return nil, false, ErrJournalCorrupt
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, false, ErrJournalCorrupt
	}
	payload, err := json.Marshal(fileDocumentPayload{Version: document.Version, Records: document.Records})
	if err != nil {
		return nil, false, ErrJournalCorrupt
	}
	digest := sha256.Sum256(payload)
	if document.Checksum != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, false, ErrJournalCorrupt
	}
	records := make(map[string]Record, len(document.Records))
	for _, record := range document.Records {
		if record.Validate(time.Time{}) != nil {
			return nil, false, ErrJournalCorrupt
		}
		if _, exists := records[record.OperationID]; exists {
			return nil, false, ErrJournalCorrupt
		}
		records[record.OperationID] = record.clone()
	}
	return records, true, nil
}

var _ Journal = (*MemoryJournal)(nil)
var _ Journal = (*FileJournal)(nil)

// rejectDuplicateJSONKeys catches duplicate object members before the strict
// document decoder runs. encoding/json intentionally accepts the last value
// for a duplicate key, which would make a hand-edited or partially corrupted
// recovery journal ambiguous.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrJournalCorrupt
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return ErrJournalCorrupt
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrJournalCorrupt
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return ErrJournalCorrupt
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return ErrJournalCorrupt
		}
	default:
		return ErrJournalCorrupt
	}
	return nil
}
