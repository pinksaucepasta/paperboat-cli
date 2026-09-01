package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrRotationNotFound = errors.New("credential rotation operation is not available")

// Credential rotation is an aggregate operation. The operation is created for
// one tunnel, but every target connector is tracked independently until the
// replacement session is ready and the old credential generation is revoked.
// No private key, bearer, or reusable enrollment token appears in these
// messages.
const (
	MaxRotationTargets            = 256
	MaxRotationMessage            = 512
	MaxRotationCredentialLifetime = 5 * 365 * 24 * time.Hour
)

type RotationTarget struct {
	ConnectorID             string `json:"connector_id"`
	HostID                  string `json:"host_id"`
	OldCredentialGeneration uint64 `json:"old_credential_generation"`
	NewCredentialGeneration uint64 `json:"new_credential_generation"`
}

func (t RotationTarget) Validate() error {
	if ValidateIdentifier(t.ConnectorID) != nil || ValidateIdentifier(t.HostID) != nil ||
		t.OldCredentialGeneration == 0 || t.NewCredentialGeneration != t.OldCredentialGeneration+1 {
		return ErrInvalidInput
	}
	return nil
}

type RotationPlan struct {
	AccountID     string           `json:"account_id"`
	TunnelID      string           `json:"tunnel_id"`
	OperationID   string           `json:"operation_id"`
	TargetSetHash string           `json:"target_set_hash"`
	Targets       []RotationTarget `json:"targets"`
}

type rotationPlanDocument struct {
	Protocol    string           `json:"protocol"`
	Version     string           `json:"version"`
	AccountID   string           `json:"account_id"`
	TunnelID    string           `json:"tunnel_id"`
	OperationID string           `json:"operation_id"`
	Targets     []RotationTarget `json:"targets"`
}

func NewRotationPlan(accountID, tunnelID, operationID string, targets []RotationTarget) (RotationPlan, error) {
	plan := RotationPlan{AccountID: accountID, TunnelID: tunnelID, OperationID: operationID, Targets: append([]RotationTarget(nil), targets...)}
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].ConnectorID < plan.Targets[j].ConnectorID })
	if err := validateRotationPlanFields(plan); err != nil {
		return RotationPlan{}, err
	}
	digest, err := rotationPlanHash(plan)
	if err != nil {
		return RotationPlan{}, err
	}
	plan.TargetSetHash = digest
	return plan, nil
}

func (p RotationPlan) Validate() error {
	if err := validateRotationPlanFields(p); err != nil {
		return err
	}
	expected, err := rotationPlanHash(p)
	if err != nil {
		return err
	}
	if p.TargetSetHash != expected {
		return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, errors.New("rotation target set hash mismatch"))
	}
	return nil
}

func validateRotationPlanFields(p RotationPlan) error {
	if ValidateIdentifier(p.AccountID) != nil || ValidateIdentifier(p.TunnelID) != nil || ValidateIdentifier(p.OperationID) != nil ||
		!hashPattern.MatchString(p.TargetSetHash) && p.TargetSetHash != "" || len(p.Targets) == 0 || len(p.Targets) > MaxRotationTargets {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(p.Targets))
	for index, target := range p.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if index > 0 && p.Targets[index-1].ConnectorID >= target.ConnectorID {
			return ErrInvalidInput
		}
		if _, ok := seen[target.ConnectorID]; ok {
			return ErrInvalidInput
		}
		seen[target.ConnectorID] = struct{}{}
	}
	return nil
}

func rotationPlanHash(plan RotationPlan) (string, error) {
	payload, err := json.Marshal(rotationPlanDocument{Protocol: ProtocolName, Version: ProtocolVersion, AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, Targets: plan.Targets})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (p RotationPlan) Target(connectorID string) (RotationTarget, bool) {
	for _, target := range p.Targets {
		if target.ConnectorID == connectorID {
			return target, true
		}
	}
	return RotationTarget{}, false
}

type CredentialRotationChallenge struct {
	AccountID                string         `json:"account_id"`
	TunnelID                 string         `json:"tunnel_id"`
	OperationID              string         `json:"operation_id"`
	ConnectorID              string         `json:"connector_id"`
	HostID                   string         `json:"host_id"`
	SessionID                string         `json:"session_id"`
	ProcessGeneration        uint64         `json:"process_generation"`
	TargetSetHash            string         `json:"target_set_hash"`
	Target                   RotationTarget `json:"target"`
	OldCredentialGeneration  uint64         `json:"old_credential_generation"`
	NewCredentialGeneration  uint64         `json:"new_credential_generation"`
	OldIdentityKeyID         string         `json:"old_identity_key_id"`
	OldIdentityKeyThumbprint string         `json:"old_identity_key_thumbprint"`
	ChallengeNonce           string         `json:"challenge_nonce"`
	IssuedAt                 time.Time      `json:"issued_at"`
	ExpiresAt                time.Time      `json:"expires_at"`
	OverlapUntil             time.Time      `json:"overlap_until"`
	NewCredentialValidUntil  time.Time      `json:"new_credential_valid_until"`
}

func (c CredentialRotationChallenge) Validate(now time.Time) error {
	if ValidateIdentifier(c.AccountID) != nil || ValidateIdentifier(c.TunnelID) != nil || ValidateIdentifier(c.OperationID) != nil || ValidateIdentifier(c.ConnectorID) != nil || ValidateIdentifier(c.HostID) != nil || ValidateIdentifier(c.SessionID) != nil ||
		c.ProcessGeneration == 0 || !hashPattern.MatchString(c.TargetSetHash) || c.OldCredentialGeneration == 0 || c.NewCredentialGeneration != c.OldCredentialGeneration+1 ||
		ValidateIdentityKey(c.OldIdentityKeyID, c.OldIdentityKeyThumbprint) != nil || !validRotationNonce(c.ChallengeNonce) || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || c.OverlapUntil.IsZero() || c.NewCredentialValidUntil.IsZero() || !c.ExpiresAt.After(c.IssuedAt) || !c.OverlapUntil.After(c.ExpiresAt) || !c.NewCredentialValidUntil.After(c.OverlapUntil) || c.ExpiresAt.Sub(c.IssuedAt) > 15*time.Minute || c.OverlapUntil.Sub(c.IssuedAt) > MaxLease || c.NewCredentialValidUntil.Sub(c.IssuedAt) > MaxRotationCredentialLifetime {
		return ErrInvalidInput
	}
	if err := c.Target.Validate(); err != nil || c.Target.ConnectorID != c.ConnectorID || c.Target.HostID != c.HostID || c.Target.OldCredentialGeneration != c.OldCredentialGeneration || c.Target.NewCredentialGeneration != c.NewCredentialGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, errors.New("rotation challenge target mismatch"))
	}
	if !now.IsZero() && (c.IssuedAt.After(now.Add(MaxClockSkew)) || now.Sub(c.IssuedAt) > MaxClockSkew || !c.ExpiresAt.After(now) || !c.OverlapUntil.After(now)) {
		return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
	}
	return nil
}

type CredentialRotationProof struct {
	AccountID                string    `json:"account_id"`
	TunnelID                 string    `json:"tunnel_id"`
	OperationID              string    `json:"operation_id"`
	ConnectorID              string    `json:"connector_id"`
	HostID                   string    `json:"host_id"`
	SessionID                string    `json:"session_id"`
	ProcessGeneration        uint64    `json:"process_generation"`
	TargetSetHash            string    `json:"target_set_hash"`
	OldCredentialGeneration  uint64    `json:"old_credential_generation"`
	NewCredentialGeneration  uint64    `json:"new_credential_generation"`
	OldIdentityKeyID         string    `json:"old_identity_key_id"`
	OldIdentityKeyThumbprint string    `json:"old_identity_key_thumbprint"`
	NewIdentityKeyID         string    `json:"new_identity_key_id"`
	NewIdentityKeyThumbprint string    `json:"new_identity_key_thumbprint"`
	NewPublicKey             string    `json:"new_public_key"`
	NewCredentialReference   string    `json:"new_credential_reference"`
	ChallengeNonce           string    `json:"challenge_nonce"`
	IssuedAt                 time.Time `json:"issued_at"`
	NewCredentialValidUntil  time.Time `json:"new_credential_valid_until"`
	OldSignedProof           string    `json:"old_signed_proof"`
	NewSignedProof           string    `json:"new_signed_proof"`
}

func (p CredentialRotationProof) Validate(now time.Time) error {
	if err := p.validate(false); err != nil {
		return err
	}
	if ValidateProof(p.OldSignedProof) != nil || ValidateProof(p.NewSignedProof) != nil {
		return ErrInvalidInput
	}
	if !now.IsZero() && (p.IssuedAt.After(now.Add(MaxClockSkew)) || now.Sub(p.IssuedAt) > MaxClockSkew) {
		return codeError(ErrAuthenticationFailed, ReasonAuthentication, false, errors.New("rotation proof is outside clock skew"))
	}
	return nil
}

func (p CredentialRotationProof) validate(_ bool) error {
	if ValidateIdentifier(p.AccountID) != nil || ValidateIdentifier(p.TunnelID) != nil || ValidateIdentifier(p.OperationID) != nil || ValidateIdentifier(p.ConnectorID) != nil || ValidateIdentifier(p.HostID) != nil || ValidateIdentifier(p.SessionID) != nil ||
		p.ProcessGeneration == 0 || !hashPattern.MatchString(p.TargetSetHash) || p.OldCredentialGeneration == 0 || p.NewCredentialGeneration != p.OldCredentialGeneration+1 ||
		ValidateIdentityKey(p.OldIdentityKeyID, p.OldIdentityKeyThumbprint) != nil || ValidateIdentityKey(p.NewIdentityKeyID, p.NewIdentityKeyThumbprint) != nil || p.OldIdentityKeyID == p.NewIdentityKeyID || !validRotationNonce(p.ChallengeNonce) || p.IssuedAt.IsZero() || p.NewCredentialValidUntil.IsZero() || ValidateCredentialReference(p.NewCredentialReference) != nil || !p.NewCredentialValidUntil.After(p.IssuedAt) || p.NewCredentialValidUntil.Sub(p.IssuedAt) > MaxRotationCredentialLifetime {
		return ErrInvalidInput
	}
	publicKey, err := decodeRotationPublicKey(p.NewPublicKey)
	if err != nil {
		return err
	}
	thumbprint, err := IdentityThumbprint(publicKey)
	if err != nil || thumbprint != p.NewIdentityKeyThumbprint {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, errors.New("new rotation key thumbprint mismatch"))
	}
	return nil
}

type rotationProofTranscript struct {
	Domain                   string    `json:"domain"`
	Protocol                 string    `json:"protocol"`
	Version                  string    `json:"version"`
	AccountID                string    `json:"account_id"`
	TunnelID                 string    `json:"tunnel_id"`
	OperationID              string    `json:"operation_id"`
	ConnectorID              string    `json:"connector_id"`
	HostID                   string    `json:"host_id"`
	SessionID                string    `json:"session_id"`
	ProcessGeneration        uint64    `json:"process_generation"`
	TargetSetHash            string    `json:"target_set_hash"`
	OldCredentialGeneration  uint64    `json:"old_credential_generation"`
	NewCredentialGeneration  uint64    `json:"new_credential_generation"`
	OldIdentityKeyID         string    `json:"old_identity_key_id"`
	OldIdentityKeyThumbprint string    `json:"old_identity_key_thumbprint"`
	NewIdentityKeyID         string    `json:"new_identity_key_id"`
	NewIdentityKeyThumbprint string    `json:"new_identity_key_thumbprint"`
	NewPublicKey             string    `json:"new_public_key"`
	NewCredentialReference   string    `json:"new_credential_reference"`
	ChallengeNonce           string    `json:"challenge_nonce"`
	IssuedAt                 time.Time `json:"issued_at"`
	NewCredentialValidUntil  time.Time `json:"new_credential_valid_until"`
}

func CredentialRotationProofPayload(proof CredentialRotationProof) ([]byte, error) {
	if err := proof.validate(false); err != nil {
		return nil, err
	}
	return json.Marshal(rotationProofTranscript{
		Domain: "paperboat.connector.credential-rotation.v1", Protocol: ProtocolName, Version: ProtocolVersion,
		AccountID: proof.AccountID, TunnelID: proof.TunnelID, OperationID: proof.OperationID, ConnectorID: proof.ConnectorID, HostID: proof.HostID,
		SessionID: proof.SessionID, ProcessGeneration: proof.ProcessGeneration, TargetSetHash: proof.TargetSetHash,
		OldCredentialGeneration: proof.OldCredentialGeneration, NewCredentialGeneration: proof.NewCredentialGeneration,
		OldIdentityKeyID: proof.OldIdentityKeyID, OldIdentityKeyThumbprint: proof.OldIdentityKeyThumbprint,
		NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint,
		NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference,
		ChallengeNonce: proof.ChallengeNonce, IssuedAt: proof.IssuedAt, NewCredentialValidUntil: proof.NewCredentialValidUntil,
	})
}

func SignCredentialRotationProof(proof CredentialRotationProof, oldSign, newSign func([]byte) []byte) (CredentialRotationProof, error) {
	if oldSign == nil || newSign == nil {
		return CredentialRotationProof{}, ErrInvalidInput
	}
	payload, err := CredentialRotationProofPayload(proof)
	if err != nil {
		return CredentialRotationProof{}, err
	}
	proof.OldSignedProof, err = SignProofPayload(payload, oldSign)
	if err != nil {
		return CredentialRotationProof{}, err
	}
	proof.NewSignedProof, err = SignProofPayload(payload, newSign)
	if err != nil {
		return CredentialRotationProof{}, err
	}
	return proof, proof.Validate(time.Time{})
}

type RotationOldProofVerifier func(context.Context, CredentialRotationProof, []byte, []byte) error

// VerifyCredentialRotationProof verifies a rotation proof against the current
// wall clock. Callers that already own a clock (for example deterministic
// tests or a server transaction) should use VerifyCredentialRotationProofAt.
// Keeping the default clocked entry point prevents a public verifier from
// accidentally accepting an old signed proof after a restart.
func VerifyCredentialRotationProof(ctx context.Context, proof CredentialRotationProof, verifyOld RotationOldProofVerifier) error {
	return VerifyCredentialRotationProofAt(ctx, proof, verifyOld, time.Now().UTC())
}

// VerifyCredentialRotationProofAt verifies both signatures and the bounded
// freshness of the proof. The old-key callback remains responsible for the
// durable connector/credential lookup.
func VerifyCredentialRotationProofAt(ctx context.Context, proof CredentialRotationProof, verifyOld RotationOldProofVerifier, now time.Time) error {
	if ctx == nil || verifyOld == nil {
		return ErrAuthenticationFailed
	}
	if err := proof.Validate(now); err != nil {
		return err
	}
	payload, err := CredentialRotationProofPayload(proof)
	if err != nil {
		return err
	}
	oldSignature, err := DecodeProof(proof.OldSignedProof)
	if err != nil {
		return err
	}
	if err := verifyOld(ctx, proof, payload, oldSignature); err != nil {
		return codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	newSignature, err := DecodeProof(proof.NewSignedProof)
	if err != nil {
		return err
	}
	publicKey, err := decodeRotationPublicKey(proof.NewPublicKey)
	if err != nil || !ed25519.Verify(publicKey, payload, newSignature) {
		return codeError(ErrAuthenticationFailed, ReasonAuthentication, false, errors.New("new rotation key proof failed"))
	}
	return nil
}

type CredentialRotationInstall struct {
	AccountID                    string    `json:"account_id"`
	TunnelID                     string    `json:"tunnel_id"`
	OperationID                  string    `json:"operation_id"`
	ConnectorID                  string    `json:"connector_id"`
	HostID                       string    `json:"host_id"`
	SessionID                    string    `json:"session_id"`
	ProcessGeneration            uint64    `json:"process_generation"`
	TargetSetHash                string    `json:"target_set_hash"`
	OldCredentialGeneration      uint64    `json:"old_credential_generation"`
	NewCredentialGeneration      uint64    `json:"new_credential_generation"`
	NewIdentityKeyID             string    `json:"new_identity_key_id"`
	NewIdentityKeyThumbprint     string    `json:"new_identity_key_thumbprint"`
	NewPublicKey                 string    `json:"new_public_key"`
	NewCredentialReference       string    `json:"new_credential_reference"`
	ChallengeNonce               string    `json:"challenge_nonce"`
	OverlapUntil                 time.Time `json:"overlap_until"`
	NewCredentialValidUntil      time.Time `json:"new_credential_valid_until"`
	ReplacementProcessGeneration uint64    `json:"replacement_process_generation"`
}

func (i CredentialRotationInstall) Validate(now time.Time) error {
	if ValidateIdentifier(i.AccountID) != nil || ValidateIdentifier(i.TunnelID) != nil || ValidateIdentifier(i.OperationID) != nil || ValidateIdentifier(i.ConnectorID) != nil || ValidateIdentifier(i.HostID) != nil || ValidateIdentifier(i.SessionID) != nil ||
		i.ProcessGeneration == 0 || i.ReplacementProcessGeneration <= i.ProcessGeneration || !hashPattern.MatchString(i.TargetSetHash) || i.OldCredentialGeneration == 0 || i.NewCredentialGeneration != i.OldCredentialGeneration+1 ||
		ValidateIdentityKey(i.NewIdentityKeyID, i.NewIdentityKeyThumbprint) != nil || ValidateCredentialReference(i.NewCredentialReference) != nil || !validRotationNonce(i.ChallengeNonce) || i.OverlapUntil.IsZero() || i.NewCredentialValidUntil.IsZero() || !i.NewCredentialValidUntil.After(i.OverlapUntil) || i.NewCredentialValidUntil.Sub(i.OverlapUntil) > MaxRotationCredentialLifetime {
		return ErrInvalidInput
	}
	publicKey, err := decodeRotationPublicKey(i.NewPublicKey)
	if err != nil {
		return err
	}
	thumbprint, err := IdentityThumbprint(publicKey)
	if err != nil || thumbprint != i.NewIdentityKeyThumbprint {
		return ErrIdentityMismatch
	}
	if !now.IsZero() && !i.OverlapUntil.After(now) {
		return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
	}
	return nil
}

type CredentialRotationReady struct {
	AccountID                string    `json:"account_id"`
	TunnelID                 string    `json:"tunnel_id"`
	OperationID              string    `json:"operation_id"`
	ConnectorID              string    `json:"connector_id"`
	HostID                   string    `json:"host_id"`
	SessionID                string    `json:"session_id"`
	PreviousSessionID        string    `json:"previous_session_id"`
	ProcessGeneration        uint64    `json:"process_generation"`
	TargetSetHash            string    `json:"target_set_hash"`
	OldCredentialGeneration  uint64    `json:"old_credential_generation"`
	NewCredentialGeneration  uint64    `json:"new_credential_generation"`
	NewIdentityKeyID         string    `json:"new_identity_key_id"`
	NewIdentityKeyThumbprint string    `json:"new_identity_key_thumbprint"`
	NewPublicKey             string    `json:"new_public_key"`
	NewCredentialReference   string    `json:"new_credential_reference"`
	NewCredentialValidUntil  time.Time `json:"new_credential_valid_until"`
	ConfigGeneration         uint64    `json:"config_generation"`
	ConfigContentHash        string    `json:"config_content_hash"`
	EdgeReady                bool      `json:"edge_ready"`
	RouteReady               bool      `json:"route_ready"`
	OriginReady              bool      `json:"origin_ready"`
	ReadyAt                  time.Time `json:"ready_at"`
}

func (r CredentialRotationReady) Validate(now time.Time) error {
	if ValidateIdentifier(r.AccountID) != nil || ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.OperationID) != nil || ValidateIdentifier(r.ConnectorID) != nil || ValidateIdentifier(r.HostID) != nil || ValidateIdentifier(r.SessionID) != nil || ValidateIdentifier(r.PreviousSessionID) != nil ||
		r.ProcessGeneration == 0 || !hashPattern.MatchString(r.TargetSetHash) || r.OldCredentialGeneration == 0 || r.NewCredentialGeneration != r.OldCredentialGeneration+1 || ValidateIdentityKey(r.NewIdentityKeyID, r.NewIdentityKeyThumbprint) != nil || ValidateCredentialReference(r.NewCredentialReference) != nil || r.NewCredentialValidUntil.IsZero() || r.ConfigGeneration == 0 || !hashPattern.MatchString(r.ConfigContentHash) || r.ReadyAt.IsZero() {
		return ErrInvalidInput
	}
	publicKey, err := decodeRotationPublicKey(r.NewPublicKey)
	if err != nil {
		return err
	}
	thumbprint, err := IdentityThumbprint(publicKey)
	if err != nil || thumbprint != r.NewIdentityKeyThumbprint {
		return ErrIdentityMismatch
	}
	if !r.EdgeReady || !r.RouteReady || !r.OriginReady {
		return codeError(ErrCredentialRotationNotReady, ReasonSnapshotRejected, true, nil)
	}
	if !now.IsZero() && (!r.NewCredentialValidUntil.After(now) || r.ReadyAt.Before(now.Add(-MaxClockSkew)) || r.ReadyAt.After(now.Add(MaxClockSkew))) {
		if !r.NewCredentialValidUntil.After(now) {
			return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
		}
		return ErrInvalidInput
	}
	return nil
}

type CredentialRotationRevoke struct {
	AccountID               string    `json:"account_id"`
	TunnelID                string    `json:"tunnel_id"`
	OperationID             string    `json:"operation_id"`
	ConnectorID             string    `json:"connector_id"`
	HostID                  string    `json:"host_id"`
	SessionID               string    `json:"session_id"`
	ProcessGeneration       uint64    `json:"process_generation"`
	TargetSetHash           string    `json:"target_set_hash"`
	OldCredentialGeneration uint64    `json:"old_credential_generation"`
	NewCredentialGeneration uint64    `json:"new_credential_generation"`
	RevokeNonce             string    `json:"revoke_nonce"`
	IssuedAt                time.Time `json:"issued_at"`
	Deadline                time.Time `json:"deadline"`
}

func (r CredentialRotationRevoke) Validate(now time.Time) error {
	if ValidateIdentifier(r.AccountID) != nil || ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.OperationID) != nil || ValidateIdentifier(r.ConnectorID) != nil || ValidateIdentifier(r.HostID) != nil || ValidateIdentifier(r.SessionID) != nil || r.ProcessGeneration == 0 || !hashPattern.MatchString(r.TargetSetHash) || r.OldCredentialGeneration == 0 || r.NewCredentialGeneration != r.OldCredentialGeneration+1 || !validRotationNonce(r.RevokeNonce) || r.IssuedAt.IsZero() || r.Deadline.IsZero() || !r.Deadline.After(r.IssuedAt) || r.Deadline.Sub(r.IssuedAt) > DefaultAbortTimeout*2 {
		return ErrInvalidInput
	}
	if !now.IsZero() && (r.IssuedAt.After(now.Add(MaxClockSkew)) || !r.Deadline.After(now)) {
		return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
	}
	return nil
}

type RotationAckStatus string

const (
	RotationAckProofAccepted RotationAckStatus = "proof_accepted"
	RotationAckInstalled     RotationAckStatus = "installed"
	RotationAckReady         RotationAckStatus = "ready"
	RotationAckRevoked       RotationAckStatus = "revoked"
	RotationAckRejected      RotationAckStatus = "rejected"
	RotationAckFailed        RotationAckStatus = "failed"
)

type CredentialRotationAck struct {
	AccountID               string            `json:"account_id"`
	TunnelID                string            `json:"tunnel_id"`
	OperationID             string            `json:"operation_id"`
	ConnectorID             string            `json:"connector_id"`
	HostID                  string            `json:"host_id"`
	SessionID               string            `json:"session_id"`
	ProcessGeneration       uint64            `json:"process_generation"`
	TargetSetHash           string            `json:"target_set_hash"`
	OldCredentialGeneration uint64            `json:"old_credential_generation"`
	NewCredentialGeneration uint64            `json:"new_credential_generation"`
	Status                  RotationAckStatus `json:"status"`
	Code                    Code              `json:"code,omitempty"`
	Message                 string            `json:"message,omitempty"`
}

func (a CredentialRotationAck) Validate() error {
	if ValidateIdentifier(a.AccountID) != nil || ValidateIdentifier(a.TunnelID) != nil || ValidateIdentifier(a.OperationID) != nil || ValidateIdentifier(a.ConnectorID) != nil || ValidateIdentifier(a.HostID) != nil || ValidateIdentifier(a.SessionID) != nil || a.ProcessGeneration == 0 || !hashPattern.MatchString(a.TargetSetHash) || a.OldCredentialGeneration == 0 || a.NewCredentialGeneration != a.OldCredentialGeneration+1 || len(a.Message) > MaxRotationMessage {
		return ErrInvalidInput
	}
	switch a.Status {
	case RotationAckProofAccepted, RotationAckInstalled, RotationAckReady, RotationAckRevoked:
		if a.Code != "" {
			return ErrInvalidInput
		}
	case RotationAckRejected, RotationAckFailed:
		if a.Code == "" || !validCode(a.Code) {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

type RotationTargetState string

const (
	RotationTargetPending    RotationTargetState = "pending"
	RotationTargetChallenged RotationTargetState = "challenged"
	RotationTargetInstalled  RotationTargetState = "installed"
	RotationTargetReady      RotationTargetState = "ready"
	RotationTargetRevoking   RotationTargetState = "revoking"
	RotationTargetRevoked    RotationTargetState = "revoked"
	RotationTargetFailed     RotationTargetState = "failed"
)

func validRotationTargetState(state RotationTargetState) bool {
	switch state {
	case RotationTargetPending, RotationTargetChallenged, RotationTargetInstalled, RotationTargetReady, RotationTargetRevoking, RotationTargetRevoked, RotationTargetFailed:
		return true
	default:
		return false
	}
}

type RotationAggregateStatus string

const (
	RotationAggregatePending   RotationAggregateStatus = "pending"
	RotationAggregateSucceeded RotationAggregateStatus = "succeeded"
	RotationAggregateFailed    RotationAggregateStatus = "failed"
)

type RotationTargetSummary struct {
	Target RotationTarget      `json:"target"`
	State  RotationTargetState `json:"state"`
	Code   Code                `json:"code,omitempty"`
}

type RotationSummary struct {
	AccountID     string                  `json:"account_id"`
	TunnelID      string                  `json:"tunnel_id"`
	OperationID   string                  `json:"operation_id"`
	TargetSetHash string                  `json:"target_set_hash"`
	Status        RotationAggregateStatus `json:"status"`
	Targets       []RotationTargetSummary `json:"targets"`
	CompletedAt   time.Time               `json:"completed_at,omitempty"`
}

// RotationPersistence is deliberately narrower than PersistentControlStore.
// Implementations must insert the target set and challenge nonce atomically,
// persist the new verifier generation in overlap state before returning the
// install acknowledgement, bind readiness to the replacement session, and
// revoke the old generation only after every target is ready.
type RotationPersistence interface {
	BeginCredentialRotation(context.Context, RotationPlan) error
	RecordCredentialRotationChallenge(context.Context, CredentialRotationChallenge) error
	RecordCredentialRotationProof(context.Context, CredentialRotationChallenge, CredentialRotationProof, CredentialRotationInstall) error
	RecordCredentialRotationReady(context.Context, CredentialRotationReady) error
	RecordCredentialRotationRevoke(context.Context, CredentialRotationRevoke) error
	RecordCredentialRotationResult(context.Context, CredentialRotationAck, RotationSummary) error
}

// RotationResume is the durable reconstruction boundary. A server restart
// must not turn an already-installed replacement into an orphaned key or
// issue a second challenge for the same immutable target set. The values are
// protocol metadata only: proofs contain signatures and public keys, never
// private or bearer credential bytes.
type RotationResume struct {
	Plan       RotationPlan           `json:"plan"`
	Started    bool                   `json:"started"`
	FinishedAt time.Time              `json:"finished_at,omitempty"`
	Targets    []RotationResumeTarget `json:"targets"`
}

type RotationResumeTarget struct {
	Target                  RotationTarget
	State                   RotationTargetState
	Code                    Code
	OverlapUntil            time.Time
	NewCredentialValidUntil time.Time
	Challenge               CredentialRotationChallenge
	Proof                   CredentialRotationProof
	Install                 CredentialRotationInstall
	Ready                   CredentialRotationReady
	Revoke                  CredentialRotationRevoke
}

// RotationRecoveryStore is optional at the interface level to keep the pure
// in-memory protocol adapter useful in tests. Production SQL stores implement
// it; a caller that needs restart-safe operation handling must call Resume and
// treats an unavailable recovery store as a deployment error.
type RotationRecoveryStore interface {
	LoadCredentialRotation(context.Context, RotationPlan) (RotationResume, error)
}

// RotationSessionAuthorizer is implemented by the production store. It locks
// the authenticated old session and verifies that the negotiated capability
// and credential generation still match before a challenge is emitted.
type RotationSessionAuthorizer interface {
	AuthorizeCredentialRotationSession(context.Context, CredentialRotationChallenge) error
}

type RotationConfig struct {
	Store          RotationPersistence
	VerifyOldProof RotationOldProofVerifier
	Clock          Clock
}

type rotationTargetState struct {
	target    RotationTarget
	state     RotationTargetState
	code      Code
	challenge CredentialRotationChallenge
	proof     CredentialRotationProof
	install   CredentialRotationInstall
	ready     CredentialRotationReady
	revoke    CredentialRotationRevoke
}

type RotationCoordinator struct {
	mu       sync.Mutex
	plan     RotationPlan
	store    RotationPersistence
	verify   RotationOldProofVerifier
	clock    Clock
	started  bool
	finished time.Time
	targets  map[string]*rotationTargetState
}

func NewRotationCoordinator(plan RotationPlan, config RotationConfig) (*RotationCoordinator, error) {
	if err := plan.Validate(); err != nil || config.Store == nil || config.VerifyOldProof == nil {
		return nil, ErrInvalidInput
	}
	clock := config.Clock
	if clock == nil {
		clock = realClock{}
	}
	targets := make(map[string]*rotationTargetState, len(plan.Targets))
	for _, target := range plan.Targets {
		targets[target.ConnectorID] = &rotationTargetState{target: target, state: RotationTargetPending}
	}
	return &RotationCoordinator{plan: plan, store: config.Store, verify: config.VerifyOldProof, clock: clock, targets: targets}, nil
}

func (c *RotationCoordinator) Start(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if err := c.store.BeginCredentialRotation(ctx, c.plan); err != nil {
		return codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	c.started = true
	return nil
}

// Resume reconstructs coordinator state from the immutable operation target
// set. It is idempotent and refuses a different operation, target hash, or
// target membership. No new wire challenge is emitted while recovering.
func (c *RotationCoordinator) Resume(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	recovery, ok := c.store.(RotationRecoveryStore)
	if !ok {
		return codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation persistence does not support recovery"))
	}
	loaded, err := recovery.LoadCredentialRotation(ctx, c.plan)
	if err != nil {
		return codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, true, err)
	}
	if !loaded.Started || loaded.Plan.AccountID != c.plan.AccountID || loaded.Plan.TunnelID != c.plan.TunnelID || loaded.Plan.OperationID != c.plan.OperationID || loaded.Plan.TargetSetHash != c.plan.TargetSetHash || loaded.Plan.Validate() != nil {
		return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery plan mismatch"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if len(loaded.Targets) != len(c.targets) {
		return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery target count mismatch"))
	}
	seen := make(map[string]struct{}, len(loaded.Targets))
	for _, recovered := range loaded.Targets {
		if _, duplicate := seen[recovered.Target.ConnectorID]; duplicate {
			return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery contains duplicate target"))
		}
		seen[recovered.Target.ConnectorID] = struct{}{}
		state, ok := c.targets[recovered.Target.ConnectorID]
		if !ok || state.target != recovered.Target || !validRotationTargetState(recovered.State) || validateRotationResumeTarget(c.plan, recovered) != nil {
			return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery target or phase mismatch"))
		}
	}
	finished := time.Time{}
	if loaded.FinishedAt.IsZero() {
		// A zero timestamp is the durable representation of a pending or
		// recoverable aggregate. Failed targets may be retained without a
		// completion timestamp while the operation is being reconciled.
	} else {
		// A durable completion timestamp is meaningful only for a terminal
		// aggregate. Success requires every target to be revoked. Failure is
		// terminal as soon as at least one target has a valid failure code, and
		// the remaining targets may still be pending/challenged because the
		// coordinator stops fan-out after the first failure. Never turn a
		// partially recovered running aggregate into a completed success.
		failed := false
		allRevoked := true
		for _, recovered := range loaded.Targets {
			if recovered.State == RotationTargetFailed {
				failed = true
			}
			if recovered.State != RotationTargetRevoked {
				allRevoked = false
			}
		}
		if !failed && !allRevoked {
			return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery finished timestamp does not match target states"))
		}
		if loaded.FinishedAt.After(c.clock.Now().UTC().Add(MaxClockSkew)) {
			return codeError(ErrIdentityMismatch, ReasonCredentialRotation, false, errors.New("rotation recovery finished timestamp is in the future"))
		}
		finished = loaded.FinishedAt
	}
	for _, recovered := range loaded.Targets {
		state := c.targets[recovered.Target.ConnectorID]
		state.state = recovered.State
		state.code = recovered.Code
		state.challenge = recovered.Challenge
		state.proof = recovered.Proof
		state.install = recovered.Install
		state.ready = recovered.Ready
		state.revoke = recovered.Revoke
	}
	c.started = true
	c.finished = finished
	return nil
}

// validateRotationResumeTarget checks the durable phase boundary before any
// recovered state becomes actionable. A corrupt or partially-written phase
// must never be turned into a fresh challenge or a revoke. Failed targets may
// retain the metadata for the phase at which they failed, but may not invent a
// later phase without its predecessor.
func validateRotationResumeTarget(plan RotationPlan, recovered RotationResumeTarget) error {
	if err := recovered.Target.Validate(); err != nil {
		return err
	}
	expected, ok := plan.Target(recovered.Target.ConnectorID)
	if !ok || expected != recovered.Target {
		return ErrIdentityMismatch
	}
	if !validRotationTargetState(recovered.State) {
		return ErrInvalidInput
	}
	if recovered.State == RotationTargetFailed && (recovered.Code == "" || !validCode(recovered.Code)) {
		return ErrInvalidInput
	}
	if recovered.State != RotationTargetFailed && recovered.Code != "" {
		return ErrInvalidInput
	}
	if recovered.OverlapUntil.IsZero() != recovered.NewCredentialValidUntil.IsZero() || !recovered.OverlapUntil.IsZero() && !recovered.NewCredentialValidUntil.After(recovered.OverlapUntil) {
		return ErrInvalidInput
	}

	challengePresent := recovered.Challenge.SessionID != ""
	installPresent := recovered.Install.SessionID != ""
	readyPresent := recovered.Ready.SessionID != ""
	revokePresent := recovered.Revoke.SessionID != ""
	if !challengePresent && (installPresent || readyPresent || revokePresent) {
		return ErrInvalidInput
	}
	if !installPresent && (readyPresent || revokePresent) {
		return ErrInvalidInput
	}
	if !readyPresent && revokePresent {
		return ErrInvalidInput
	}

	if challengePresent {
		if err := recovered.Challenge.Validate(time.Time{}); err != nil || recovered.Challenge.AccountID != plan.AccountID || recovered.Challenge.TunnelID != plan.TunnelID || recovered.Challenge.OperationID != plan.OperationID || recovered.Challenge.TargetSetHash != plan.TargetSetHash || recovered.Challenge.Target != recovered.Target || recovered.Challenge.ConnectorID != recovered.Target.ConnectorID || recovered.Challenge.HostID != recovered.Target.HostID {
			return ErrIdentityMismatch
		}
	}
	if installPresent {
		if err := recovered.Install.Validate(time.Time{}); err != nil || recovered.Install.AccountID != plan.AccountID || recovered.Install.TunnelID != plan.TunnelID || recovered.Install.OperationID != plan.OperationID || recovered.Install.TargetSetHash != plan.TargetSetHash || recovered.Install.ConnectorID != recovered.Target.ConnectorID || recovered.Install.HostID != recovered.Target.HostID || recovered.Install.SessionID != recovered.Challenge.SessionID || recovered.Install.ProcessGeneration != recovered.Challenge.ProcessGeneration || recovered.Install.OldCredentialGeneration != recovered.Target.OldCredentialGeneration || recovered.Install.NewCredentialGeneration != recovered.Target.NewCredentialGeneration || recovered.Install.ChallengeNonce != recovered.Challenge.ChallengeNonce {
			return ErrIdentityMismatch
		}
	}
	if readyPresent {
		if err := recovered.Ready.Validate(time.Time{}); err != nil || recovered.Ready.AccountID != plan.AccountID || recovered.Ready.TunnelID != plan.TunnelID || recovered.Ready.OperationID != plan.OperationID || recovered.Ready.TargetSetHash != plan.TargetSetHash || recovered.Ready.ConnectorID != recovered.Target.ConnectorID || recovered.Ready.HostID != recovered.Target.HostID || recovered.Ready.PreviousSessionID != recovered.Install.SessionID || recovered.Ready.SessionID == recovered.Install.SessionID || recovered.Ready.ProcessGeneration < recovered.Install.ReplacementProcessGeneration || recovered.Ready.OldCredentialGeneration != recovered.Target.OldCredentialGeneration || recovered.Ready.NewCredentialGeneration != recovered.Target.NewCredentialGeneration || recovered.Ready.NewIdentityKeyID != recovered.Install.NewIdentityKeyID || recovered.Ready.NewIdentityKeyThumbprint != recovered.Install.NewIdentityKeyThumbprint || recovered.Ready.NewPublicKey != recovered.Install.NewPublicKey || recovered.Ready.NewCredentialReference != recovered.Install.NewCredentialReference || !recovered.Ready.NewCredentialValidUntil.Equal(recovered.Install.NewCredentialValidUntil) {
			return ErrIdentityMismatch
		}
	}
	if revokePresent {
		sameReadySession := recovered.Revoke.ProcessGeneration == recovered.Ready.ProcessGeneration && recovered.Revoke.SessionID == recovered.Ready.SessionID
		reboundSession := recovered.Revoke.ProcessGeneration > recovered.Ready.ProcessGeneration && recovered.Revoke.SessionID != recovered.Ready.SessionID
		if err := recovered.Revoke.Validate(time.Time{}); err != nil || recovered.Revoke.AccountID != plan.AccountID || recovered.Revoke.TunnelID != plan.TunnelID || recovered.Revoke.OperationID != plan.OperationID || recovered.Revoke.TargetSetHash != plan.TargetSetHash || recovered.Revoke.ConnectorID != recovered.Target.ConnectorID || recovered.Revoke.HostID != recovered.Target.HostID || !sameReadySession && !reboundSession || recovered.Revoke.OldCredentialGeneration != recovered.Target.OldCredentialGeneration || recovered.Revoke.NewCredentialGeneration != recovered.Target.NewCredentialGeneration {
			return ErrIdentityMismatch
		}
	}

	switch recovered.State {
	case RotationTargetPending:
		if challengePresent || installPresent || readyPresent || revokePresent {
			return ErrInvalidInput
		}
	case RotationTargetChallenged:
		if !challengePresent || installPresent || readyPresent || revokePresent {
			return ErrInvalidInput
		}
	case RotationTargetInstalled:
		if !installPresent || readyPresent || revokePresent {
			return ErrInvalidInput
		}
	case RotationTargetReady:
		if !readyPresent || revokePresent {
			return ErrInvalidInput
		}
	case RotationTargetRevoking, RotationTargetRevoked:
		if !revokePresent {
			return ErrInvalidInput
		}
	case RotationTargetFailed:
		// A failed target is valid at any recorded phase, including before a
		// challenge. The predecessor checks above still apply.
	}
	return nil
}

func (c *RotationCoordinator) Challenge(ctx context.Context, connectorID, sessionID string, processGeneration uint64, oldIdentityKeyID, oldIdentityKeyThumbprint, nonce string, issuedAt, expiresAt, overlapUntil time.Time) (CredentialRotationChallenge, error) {
	return c.ChallengeWithCredentialExpiry(ctx, connectorID, sessionID, processGeneration, oldIdentityKeyID, oldIdentityKeyThumbprint, nonce, issuedAt, expiresAt, overlapUntil, overlapUntil.Add(365*24*time.Hour))
}

// ChallengeWithCredentialExpiry is the explicit rotation entry point. The
// credential expiry is carried through the signed proof and install record so
// a successful rotation does not accidentally give the replacement key only
// the overlap window's lifetime.
func (c *RotationCoordinator) ChallengeWithCredentialExpiry(ctx context.Context, connectorID, sessionID string, processGeneration uint64, oldIdentityKeyID, oldIdentityKeyThumbprint, nonce string, issuedAt, expiresAt, overlapUntil, credentialValidUntil time.Time) (CredentialRotationChallenge, error) {
	if c == nil || ctx == nil {
		return CredentialRotationChallenge{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return CredentialRotationChallenge{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.clock.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return CredentialRotationChallenge{}, ErrInvalidInput
	}
	state, ok := c.targets[connectorID]
	if !ok {
		return CredentialRotationChallenge{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if state.state != RotationTargetPending {
		if state.state != RotationTargetChallenged || state.challenge.ExpiresAt.IsZero() || state.challenge.ExpiresAt.After(now) {
			return CredentialRotationChallenge{}, codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
		}
	}
	target := state.target
	challenge := CredentialRotationChallenge{AccountID: c.plan.AccountID, TunnelID: c.plan.TunnelID, OperationID: c.plan.OperationID, ConnectorID: connectorID, HostID: target.HostID, SessionID: sessionID, ProcessGeneration: processGeneration, TargetSetHash: c.plan.TargetSetHash, Target: target, OldCredentialGeneration: target.OldCredentialGeneration, NewCredentialGeneration: target.NewCredentialGeneration, OldIdentityKeyID: oldIdentityKeyID, OldIdentityKeyThumbprint: oldIdentityKeyThumbprint, ChallengeNonce: nonce, IssuedAt: issuedAt, ExpiresAt: expiresAt, OverlapUntil: overlapUntil, NewCredentialValidUntil: credentialValidUntil}
	if err := challenge.Validate(now); err != nil {
		return CredentialRotationChallenge{}, err
	}
	if authorizer, ok := c.store.(RotationSessionAuthorizer); ok {
		if err := authorizer.AuthorizeCredentialRotationSession(ctx, challenge); err != nil {
			return CredentialRotationChallenge{}, err
		}
	}
	if err := c.store.RecordCredentialRotationChallenge(ctx, challenge); err != nil {
		return CredentialRotationChallenge{}, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	state.challenge = challenge
	state.state = RotationTargetChallenged
	return challenge, nil
}

func (c *RotationCoordinator) AcceptProof(ctx context.Context, proof CredentialRotationProof) (CredentialRotationInstall, CredentialRotationAck, error) {
	if c == nil || ctx == nil {
		return CredentialRotationInstall{}, CredentialRotationAck{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return CredentialRotationInstall{}, CredentialRotationAck{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.clock.Now().UTC()
	if err := proof.Validate(now); err != nil {
		return CredentialRotationInstall{}, CredentialRotationAck{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.targets[proof.ConnectorID]
	if !ok || state.state != RotationTargetChallenged {
		return CredentialRotationInstall{}, CredentialRotationAck{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	challenge := state.challenge
	if !rotationProofMatchesChallenge(proof, challenge, state.target) {
		return CredentialRotationInstall{}, CredentialRotationAck{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if err := VerifyCredentialRotationProofAt(ctx, proof, c.verify, now); err != nil {
		return CredentialRotationInstall{}, CredentialRotationAck{}, err
	}
	install := CredentialRotationInstall{AccountID: c.plan.AccountID, TunnelID: c.plan.TunnelID, OperationID: c.plan.OperationID, ConnectorID: proof.ConnectorID, HostID: proof.HostID, SessionID: proof.SessionID, ProcessGeneration: proof.ProcessGeneration, TargetSetHash: c.plan.TargetSetHash, OldCredentialGeneration: proof.OldCredentialGeneration, NewCredentialGeneration: proof.NewCredentialGeneration, NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint, NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference, ChallengeNonce: proof.ChallengeNonce, OverlapUntil: challenge.OverlapUntil, NewCredentialValidUntil: proof.NewCredentialValidUntil, ReplacementProcessGeneration: proof.ProcessGeneration + 1}
	if err := install.Validate(now); err != nil {
		return CredentialRotationInstall{}, CredentialRotationAck{}, err
	}
	if err := c.store.RecordCredentialRotationProof(ctx, challenge, proof, install); err != nil {
		state.state = RotationTargetFailed
		state.code = CodeCredentialRotationFailed
		return CredentialRotationInstall{}, CredentialRotationAck{}, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	state.proof = proof
	state.install = install
	state.state = RotationTargetInstalled
	return install, rotationAckForInstall(install), nil
}

func rotationProofMatchesChallenge(proof CredentialRotationProof, challenge CredentialRotationChallenge, target RotationTarget) bool {
	return proof.AccountID == challenge.AccountID && proof.TunnelID == challenge.TunnelID && proof.OperationID == challenge.OperationID && proof.ConnectorID == challenge.ConnectorID && proof.HostID == challenge.HostID && proof.SessionID == challenge.SessionID && proof.ProcessGeneration == challenge.ProcessGeneration && proof.TargetSetHash == challenge.TargetSetHash && proof.OldCredentialGeneration == target.OldCredentialGeneration && proof.NewCredentialGeneration == target.NewCredentialGeneration && proof.OldIdentityKeyID == challenge.OldIdentityKeyID && proof.OldIdentityKeyThumbprint == challenge.OldIdentityKeyThumbprint && proof.ChallengeNonce == challenge.ChallengeNonce && proof.NewCredentialValidUntil == challenge.NewCredentialValidUntil && !proof.IssuedAt.Before(challenge.IssuedAt) && !proof.IssuedAt.After(challenge.ExpiresAt)
}

func rotationAckForInstall(install CredentialRotationInstall) CredentialRotationAck {
	return CredentialRotationAck{AccountID: install.AccountID, TunnelID: install.TunnelID, OperationID: install.OperationID, ConnectorID: install.ConnectorID, HostID: install.HostID, SessionID: install.SessionID, ProcessGeneration: install.ProcessGeneration, TargetSetHash: install.TargetSetHash, OldCredentialGeneration: install.OldCredentialGeneration, NewCredentialGeneration: install.NewCredentialGeneration, Status: RotationAckInstalled}
}

func (c *RotationCoordinator) MarkReady(ctx context.Context, ready CredentialRotationReady) (CredentialRotationAck, error) {
	if c == nil || ctx == nil {
		return CredentialRotationAck{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return CredentialRotationAck{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.clock.Now().UTC()
	if err := ready.Validate(now); err != nil {
		return rotationRejectedAck(ready, CodeCredentialRotationNotReady), err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.targets[ready.ConnectorID]
	if !ok || state.state != RotationTargetInstalled {
		return CredentialRotationAck{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	install := state.install
	if ready.AccountID != c.plan.AccountID || ready.TunnelID != c.plan.TunnelID || ready.OperationID != c.plan.OperationID || ready.ConnectorID != install.ConnectorID || ready.HostID != install.HostID || ready.TargetSetHash != c.plan.TargetSetHash || ready.SessionID == install.SessionID || ready.PreviousSessionID != install.SessionID || ready.ProcessGeneration < install.ReplacementProcessGeneration || ready.OldCredentialGeneration != install.OldCredentialGeneration || ready.NewCredentialGeneration != install.NewCredentialGeneration || ready.NewIdentityKeyID != install.NewIdentityKeyID || ready.NewIdentityKeyThumbprint != install.NewIdentityKeyThumbprint || ready.NewPublicKey != install.NewPublicKey || ready.NewCredentialReference != install.NewCredentialReference || ready.NewCredentialValidUntil != install.NewCredentialValidUntil {
		return CredentialRotationAck{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if err := c.store.RecordCredentialRotationReady(ctx, ready); err != nil {
		state.state = RotationTargetFailed
		state.code = CodeCredentialRotationFailed
		return CredentialRotationAck{}, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	state.ready = ready
	state.state = RotationTargetReady
	return CredentialRotationAck{AccountID: ready.AccountID, TunnelID: ready.TunnelID, OperationID: ready.OperationID, ConnectorID: ready.ConnectorID, HostID: ready.HostID, SessionID: ready.SessionID, ProcessGeneration: ready.ProcessGeneration, TargetSetHash: ready.TargetSetHash, OldCredentialGeneration: ready.OldCredentialGeneration, NewCredentialGeneration: ready.NewCredentialGeneration, Status: RotationAckReady}, nil
}

func rotationRejectedAck(ready CredentialRotationReady, code Code) CredentialRotationAck {
	return CredentialRotationAck{AccountID: ready.AccountID, TunnelID: ready.TunnelID, OperationID: ready.OperationID, ConnectorID: ready.ConnectorID, HostID: ready.HostID, SessionID: ready.SessionID, ProcessGeneration: ready.ProcessGeneration, TargetSetHash: ready.TargetSetHash, OldCredentialGeneration: ready.OldCredentialGeneration, NewCredentialGeneration: ready.NewCredentialGeneration, Status: RotationAckRejected, Code: code}
}

func (c *RotationCoordinator) Revoke(ctx context.Context, connectorID string) (CredentialRotationRevoke, error) {
	if c == nil || ctx == nil {
		return CredentialRotationRevoke{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return CredentialRotationRevoke{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.clock.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.targets[connectorID]
	if !ok {
		return CredentialRotationRevoke{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if summary := c.summaryLocked(); summary.Status == RotationAggregateFailed {
		return CredentialRotationRevoke{}, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, nil)
	}
	if !c.allReadyLocked() {
		return CredentialRotationRevoke{}, codeError(ErrCredentialRotationNotReady, ReasonSnapshotRejected, true, nil)
	}
	if state.state == RotationTargetRevoking {
		return state.revoke, nil
	}
	if state.state != RotationTargetReady {
		return CredentialRotationRevoke{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	revokeNonce, err := newOpaqueID("rotation-revoke")
	if err != nil {
		return CredentialRotationRevoke{}, err
	}
	revoke := CredentialRotationRevoke{AccountID: c.plan.AccountID, TunnelID: c.plan.TunnelID, OperationID: c.plan.OperationID, ConnectorID: connectorID, HostID: state.target.HostID, SessionID: state.ready.SessionID, ProcessGeneration: state.ready.ProcessGeneration, TargetSetHash: c.plan.TargetSetHash, OldCredentialGeneration: state.target.OldCredentialGeneration, NewCredentialGeneration: state.target.NewCredentialGeneration, RevokeNonce: revokeNonce, IssuedAt: now, Deadline: now.Add(DefaultAbortTimeout)}
	if err := revoke.Validate(now); err != nil {
		return CredentialRotationRevoke{}, err
	}
	if err := c.store.RecordCredentialRotationRevoke(ctx, revoke); err != nil {
		state.state = RotationTargetFailed
		state.code = CodeCredentialRotationFailed
		return CredentialRotationRevoke{}, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	state.revoke = revoke
	state.state = RotationTargetRevoking
	return revoke, nil
}

func (c *RotationCoordinator) HandleAck(ctx context.Context, ack CredentialRotationAck) (RotationSummary, error) {
	if c == nil || ctx == nil {
		return RotationSummary{}, ErrInvalidInput
	}
	if err := ack.Validate(); err != nil {
		return RotationSummary{}, err
	}
	if err := ctx.Err(); err != nil {
		return RotationSummary{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.targets[ack.ConnectorID]
	if !ok || ack.AccountID != c.plan.AccountID || ack.TunnelID != c.plan.TunnelID || ack.OperationID != c.plan.OperationID || ack.TargetSetHash != c.plan.TargetSetHash || ack.HostID != state.target.HostID || ack.OldCredentialGeneration != state.target.OldCredentialGeneration || ack.NewCredentialGeneration != state.target.NewCredentialGeneration {
		return RotationSummary{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if state.state == RotationTargetRevoked || state.state == RotationTargetFailed {
		return c.summaryLocked(), codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	if ack.Status == RotationAckRejected || ack.Status == RotationAckFailed {
		if !rotationNegativeAckMatches(state, ack) {
			return RotationSummary{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
		}
		previousState, previousCode := state.state, state.code
		state.state = RotationTargetFailed
		state.code = ack.Code
		summary := c.summaryLocked()
		if err := c.store.RecordCredentialRotationResult(ctx, ack, summary); err != nil {
			state.state, state.code = previousState, previousCode
			return c.summaryLocked(), codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, errors.Join(ErrCredentialRotationFailed, err))
		}
		return summary, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, errors.New(string(ack.Code)))
	}
	if ack.Status == RotationAckInstalled {
		if state.state != RotationTargetInstalled || ack.SessionID != state.install.SessionID || ack.ProcessGeneration != state.install.ProcessGeneration {
			return RotationSummary{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		// The install acknowledgement confirms delivery of the staged
		// replacement. RecordCredentialRotationProof already durably advanced
		// the target; accepting this idempotently must not advance it a second
		// time or create a terminal operation result.
		return c.summaryLocked(), nil
	}
	if ack.Status == RotationAckReady {
		if state.state != RotationTargetReady || ack.SessionID != state.ready.SessionID || ack.ProcessGeneration != state.ready.ProcessGeneration {
			return RotationSummary{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		// Readiness is durably committed by MarkReady before its ACK is sent.
		// Treat the wire acknowledgement as an idempotent confirmation only.
		return c.summaryLocked(), nil
	}
	if ack.Status != RotationAckRevoked || state.state != RotationTargetRevoking || ack.SessionID != state.revoke.SessionID || ack.ProcessGeneration != state.revoke.ProcessGeneration {
		return RotationSummary{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	state.state = RotationTargetRevoked
	summary := c.summaryLocked()
	if summary.Status == RotationAggregateSucceeded {
		c.finished = c.clock.Now().UTC()
		summary.CompletedAt = c.finished
	}
	if err := c.store.RecordCredentialRotationResult(ctx, ack, summary); err != nil {
		state.state = RotationTargetFailed
		state.code = CodeCredentialRotationFailed
		return c.summaryLocked(), codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	return summary, nil
}

func (c *RotationCoordinator) Fail(ctx context.Context, connectorID string, code Code) (RotationSummary, error) {
	if c == nil || ctx == nil || !validCode(code) || code == "" {
		return RotationSummary{}, ErrInvalidInput
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.targets[connectorID]
	if !ok {
		return RotationSummary{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if state.state == RotationTargetRevoked {
		return c.summaryLocked(), codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	if state.state == RotationTargetFailed {
		return c.summaryLocked(), codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, errors.New(string(state.code)))
	}
	previousState, previousCode := state.state, state.code
	state.state = RotationTargetFailed
	state.code = code
	ack := c.failureAckLocked(state, code)
	summary := c.summaryLocked()
	if err := c.store.RecordCredentialRotationResult(ctx, ack, summary); err != nil {
		state.state, state.code = previousState, previousCode
		return c.summaryLocked(), codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, err)
	}
	return summary, codeError(ErrCredentialRotationFailed, ReasonCredentialRotation, false, errors.New(string(code)))
}

func rotationNegativeAckMatches(state *rotationTargetState, ack CredentialRotationAck) bool {
	if state == nil {
		return false
	}
	sessionID, processGeneration := "", uint64(0)
	switch state.state {
	case RotationTargetChallenged, RotationTargetInstalled:
		sessionID, processGeneration = state.challenge.SessionID, state.challenge.ProcessGeneration
	case RotationTargetReady:
		sessionID, processGeneration = state.ready.SessionID, state.ready.ProcessGeneration
	case RotationTargetRevoking:
		sessionID, processGeneration = state.revoke.SessionID, state.revoke.ProcessGeneration
	default:
		return false
	}
	return sessionID != "" && processGeneration > 0 && ack.SessionID == sessionID && ack.ProcessGeneration == processGeneration
}

func (c *RotationCoordinator) Summary() RotationSummary {
	if c == nil {
		return RotationSummary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.summaryLocked()
}

func (c *RotationCoordinator) summaryLocked() RotationSummary {
	result := RotationSummary{AccountID: c.plan.AccountID, TunnelID: c.plan.TunnelID, OperationID: c.plan.OperationID, TargetSetHash: c.plan.TargetSetHash, Status: RotationAggregatePending, Targets: make([]RotationTargetSummary, 0, len(c.targets))}
	failed := false
	succeeded := true
	for _, target := range c.plan.Targets {
		state := c.targets[target.ConnectorID]
		result.Targets = append(result.Targets, RotationTargetSummary{Target: target, State: state.state, Code: state.code})
		if state.state == RotationTargetFailed {
			failed = true
		}
		if state.state != RotationTargetRevoked {
			succeeded = false
		}
	}
	if failed {
		result.Status = RotationAggregateFailed
	} else if succeeded {
		result.Status = RotationAggregateSucceeded
		result.CompletedAt = c.finished
	}
	return result
}

func (c *RotationCoordinator) allReadyLocked() bool {
	for _, state := range c.targets {
		if state.state != RotationTargetReady && state.state != RotationTargetRevoking && state.state != RotationTargetRevoked {
			return false
		}
	}
	return true
}

func (c *RotationCoordinator) failureAckLocked(state *rotationTargetState, code Code) CredentialRotationAck {
	sessionID := state.challenge.SessionID
	processGeneration := state.challenge.ProcessGeneration
	if state.revoke.SessionID != "" {
		sessionID = state.revoke.SessionID
		processGeneration = state.revoke.ProcessGeneration
	} else if state.ready.SessionID != "" {
		sessionID = state.ready.SessionID
		processGeneration = state.ready.ProcessGeneration
	}
	return CredentialRotationAck{AccountID: c.plan.AccountID, TunnelID: c.plan.TunnelID, OperationID: c.plan.OperationID, ConnectorID: state.target.ConnectorID, HostID: state.target.HostID, SessionID: sessionID, ProcessGeneration: processGeneration, TargetSetHash: c.plan.TargetSetHash, OldCredentialGeneration: state.target.OldCredentialGeneration, NewCredentialGeneration: state.target.NewCredentialGeneration, Status: RotationAckFailed, Code: code}
}

func validRotationNonce(value string) bool {
	return len(value) >= 16 && len(value) <= MaxNonceBytes && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}

func decodeRotationPublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidInput
	}
	return ed25519.PublicKey(decoded), nil
}

// MemoryRotationPersistence is a deterministic test adapter. Production code
// must use the SQL adapter, but this implementation intentionally records every
// transition so unit tests can prove that acknowledgements never precede the
// durable overlap/readiness/revoke write.
type MemoryRotationPersistence struct {
	mu          sync.Mutex
	Failure     error
	Started     []RotationPlan
	Challenges  []CredentialRotationChallenge
	Proofs      []CredentialRotationProof
	Installs    []CredentialRotationInstall
	Readiness   []CredentialRotationReady
	Revocations []CredentialRotationRevoke
	Results     []RotationSummary
}

func (m *MemoryRotationPersistence) fail() error {
	if m == nil {
		return errors.New("rotation persistence is nil")
	}
	return m.Failure
}

func (m *MemoryRotationPersistence) BeginCredentialRotation(_ context.Context, plan RotationPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	for _, started := range m.Started {
		if started.OperationID == plan.OperationID {
			if started.AccountID != plan.AccountID || started.TunnelID != plan.TunnelID || started.TargetSetHash != plan.TargetSetHash || len(started.Targets) != len(plan.Targets) {
				return ErrContentHashMismatch
			}
			return nil
		}
	}
	m.Started = append(m.Started, plan)
	return nil
}

func (m *MemoryRotationPersistence) RecordCredentialRotationChallenge(_ context.Context, challenge CredentialRotationChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.Challenges = append(m.Challenges, challenge)
	return nil
}

func (m *MemoryRotationPersistence) RecordCredentialRotationProof(_ context.Context, _ CredentialRotationChallenge, proof CredentialRotationProof, install CredentialRotationInstall) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.Proofs = append(m.Proofs, proof)
	m.Installs = append(m.Installs, install)
	return nil
}

func (m *MemoryRotationPersistence) RecordCredentialRotationReady(_ context.Context, ready CredentialRotationReady) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.Readiness = append(m.Readiness, ready)
	return nil
}

func (m *MemoryRotationPersistence) RecordCredentialRotationRevoke(_ context.Context, revoke CredentialRotationRevoke) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.Revocations = append(m.Revocations, revoke)
	return nil
}

func (m *MemoryRotationPersistence) RecordCredentialRotationResult(_ context.Context, _ CredentialRotationAck, summary RotationSummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.Results = append(m.Results, summary)
	return nil
}

func (m *MemoryRotationPersistence) LoadCredentialRotation(_ context.Context, plan RotationPlan) (RotationResume, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return RotationResume{}, err
	}
	var started RotationPlan
	for _, candidate := range m.Started {
		if candidate.OperationID == plan.OperationID {
			started = candidate
			break
		}
	}
	if started.OperationID == "" {
		return RotationResume{}, ErrRotationNotFound
	}
	if started.AccountID != plan.AccountID || started.TunnelID != plan.TunnelID || started.TargetSetHash != plan.TargetSetHash || len(started.Targets) != len(plan.Targets) {
		return RotationResume{}, ErrContentHashMismatch
	}
	result := RotationResume{Plan: started, Started: true, Targets: make([]RotationResumeTarget, 0, len(started.Targets))}
	for _, target := range started.Targets {
		entry := RotationResumeTarget{Target: target, State: RotationTargetPending}
		for _, challenge := range m.Challenges {
			if challenge.OperationID == plan.OperationID && challenge.ConnectorID == target.ConnectorID {
				entry.Challenge = challenge
				entry.OverlapUntil = challenge.OverlapUntil
				entry.NewCredentialValidUntil = challenge.NewCredentialValidUntil
				entry.State = RotationTargetChallenged
			}
		}
		for index, proof := range m.Proofs {
			if proof.OperationID == plan.OperationID && proof.ConnectorID == target.ConnectorID {
				entry.Proof = proof
				if index < len(m.Installs) {
					entry.Install = m.Installs[index]
				}
				entry.State = RotationTargetInstalled
			}
		}
		for _, ready := range m.Readiness {
			if ready.OperationID == plan.OperationID && ready.ConnectorID == target.ConnectorID {
				entry.Ready = ready
				entry.State = RotationTargetReady
			}
		}
		for _, revoke := range m.Revocations {
			if revoke.OperationID == plan.OperationID && revoke.ConnectorID == target.ConnectorID {
				entry.Revoke = revoke
				entry.State = RotationTargetRevoking
				for _, summary := range m.Results {
					if summary.OperationID == plan.OperationID {
						for _, summaryTarget := range summary.Targets {
							if summaryTarget.Target.ConnectorID == target.ConnectorID {
								entry.State = summaryTarget.State
								entry.Code = summaryTarget.Code
							}
						}
					}
				}
			}
		}
		result.Targets = append(result.Targets, entry)
	}
	for _, summary := range m.Results {
		if summary.OperationID == plan.OperationID && summary.Status == RotationAggregateSucceeded {
			result.FinishedAt = summary.CompletedAt
		}
	}
	return result, nil
}
