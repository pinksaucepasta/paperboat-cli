package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

var (
	ErrRootAuthorizationRequired = errors.New("account root authorization required")
	ErrEnrollmentExpired         = errors.New("ENV key enrollment expired")
	ErrSafetyCodeMismatch        = errors.New("ENV enrollment safety code does not match")
	ErrNoDecryptingKey           = errors.New("no trusted ENV key can decrypt every required scope")
	ErrTransitionIncomplete      = errors.New("ENV authority transition is staged but incomplete")
	ErrNoPendingEnrollment       = errors.New("no pending ENV manager enrollment")
)

type EnrollmentControlPlane interface {
	ControlPlane
	GetEnvironmentScopeInventory(context.Context) (api.EnvironmentScopeInventory, error)
	CreateEnvironmentKeyEnrollment(context.Context, api.EnvironmentKeyEnrollmentRequest) (api.EnvironmentKeyEnrollmentState, error)
	SubmitEnvironmentKeyEnrollmentProof(context.Context, string, string, api.EnvironmentKeyEnrollmentProof) (api.EnvironmentKeyEnrollmentState, error)
	ListPendingEnvironmentKeyEnrollments(context.Context) ([]api.EnvironmentKeyEnrollmentState, error)
	ApproveEnvironmentKeyEnrollment(context.Context, string, string, api.EnvironmentKeyApproval) (api.EnvironmentAuthorityTransitionState, error)
	StartEnvironmentAuthorityTransition(context.Context, string, api.EnvironmentAuthorityTransition) (api.EnvironmentAuthorityTransitionState, error)
	GetEnvironmentAuthorityTransition(context.Context, string) (api.EnvironmentAuthorityTransitionState, error)
	StageEnvironmentTransitionManifest(context.Context, string, string, string, api.EnvironmentTransitionManifest) (api.EnvironmentAuthorityTransitionState, error)
	AbortEnvironmentAuthorityTransition(context.Context, string, api.EnvironmentAuthorityTransitionAbort) (api.EnvironmentAuthorityTransitionState, error)
}

type EnrollmentResult struct {
	RequestID               string
	SafetyCode              string
	ExpiresAt               time.Time
	Recovery                []byte
	RecoveryExportConfirmed bool
	AuthorityActive         bool
	KeyGeneration           int64
}

type VerifiedPendingEnrollment struct {
	RequestID  string
	Request    environmente2ee.EnrollmentRequest
	SafetyCode string
	ExpiresAt  time.Time
}

func (manager Manager) ResumeManagerEnrollment(ctx context.Context, now time.Time) (result EnrollmentResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || ctx == nil || now.IsZero() {
		return EnrollmentResult{}, errors.New("ENV enrollment manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	draft, found, err := manager.loadPendingEnrollment()
	if err != nil {
		return EnrollmentResult{}, err
	}
	if !found {
		return EnrollmentResult{}, ErrNoPendingEnrollment
	}
	return manager.resumeEnrollmentLocked(ctx, client, draft, now)
}

func (manager Manager) CancelManagerEnrollment() (resultErr error) {
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if _, found, err := manager.loadPendingTransition(); err != nil {
		return err
	} else if found {
		return ErrTransitionIncomplete
	}
	draft, found, err := manager.loadPendingEnrollment()
	if err != nil {
		return err
	}
	if !found {
		return ErrNoPendingEnrollment
	}
	// A canceled genesis request has never authorized this identity. Remove the
	// orphaned local key material as well so a fresh genesis can create a new
	// recovery key. This is safe only before an authority high-water exists.
	if draft.Genesis {
		identity, loadErr := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
		if loadErr != nil && !errors.Is(loadErr, config.ErrSecretNotFound) {
			return loadErr
		}
		if loadErr == nil {
			if identity.AuthorityGeneration != 0 || identity.AuthorityID != "" {
				identity.Clear()
				return ErrTransitionIncomplete
			}
			identity.Clear()
			if deleteErr := manager.Store.DeleteEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID); deleteErr != nil && !errors.Is(deleteErr, config.ErrSecretNotFound) {
				return deleteErr
			}
		}
	}
	return manager.deletePendingEnrollment()
}

// BeginManagerEnrollment creates a dedicated manager identity, proves both
// private keys to the service, and returns only the locally recomputed safety
// code. genesis also creates the offline recovery key, which remains gated
// until ConfirmRecoveryExport succeeds.
func (manager Manager) BeginManagerEnrollment(ctx context.Context, endpointCertificate []byte, subjectGeneration int64, genesis bool, now time.Time) (result EnrollmentResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || ctx == nil || now.IsZero() || subjectGeneration < 1 {
		return EnrollmentResult{}, errors.New("ENV enrollment manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if draft, found, err := manager.loadPendingEnrollment(); err != nil {
		return EnrollmentResult{}, err
	} else if found {
		if draft.Genesis != genesis || draft.Request.SubjectGeneration != subjectGeneration || draft.Request.EndpointCertificate == nil || *draft.Request.EndpointCertificate != base64.RawURLEncoding.EncodeToString(endpointCertificate) {
			return EnrollmentResult{}, ErrIntegrity
		}
		return manager.resumeEnrollmentLocked(ctx, client, draft, now)
	}
	identity, err := manager.Store.CreateEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID, genesis)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer identity.Clear()
	signingPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signingPrivate)
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	signingID, err := environmente2ee.KeyIDEd25519(signingPublic)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	recipientPrivate, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	recipientPublic := recipientPrivate.PublicKey().Bytes()
	defer clear(recipientPublic)
	recipientID, err := environmente2ee.KeyIDX25519(recipientPublic)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	operationID, operation, err := newOperationID(manager.randomSource())
	if err != nil {
		return EnrollmentResult{}, err
	}
	expiresAt := now.UTC().Truncate(time.Second).Add(5 * time.Minute)
	request := environmente2ee.EnrollmentRequest{
		AccountID: manager.AccountID, OperationID: operation,
		SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: manager.SubjectID,
		SubjectGeneration: uint64(subjectGeneration), KeyGeneration: uint64(identity.KeyGeneration),
		EndpointCertificate: append([]byte(nil), endpointCertificate...),
		SigningPublic:       append(ed25519.PublicKey(nil), signingPublic...), SigningKeyID: signingID,
		RecipientPublic: append([]byte(nil), recipientPublic...), RecipientKeyID: recipientID,
		RequestExpiresAt: uint64(expiresAt.Unix()),
	}
	defer clear(request.EndpointCertificate)
	defer clear(request.SigningPublic)
	defer clear(request.RecipientPublic)
	canonical, err := environmente2ee.CanonicalEnrollmentRequest(request)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(canonical)
	signature, err := environmente2ee.SignEnrollmentRequest(request, signingPrivate)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(signature)
	certificate := base64.RawURLEncoding.EncodeToString(endpointCertificate)
	signingEncoded := base64.RawURLEncoding.EncodeToString(signingPublic)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	apiRequest := api.EnvironmentKeyEnrollmentRequest{
		Schema: api.EnvironmentKeyEnrollmentSchemaV1, OperationID: operationID,
		SubjectKind: "manager_cli", SubjectID: manager.SubjectID,
		SubjectGeneration: subjectGeneration, KeyGeneration: identity.KeyGeneration,
		EndpointCertificate: &certificate, SigningPublicKey: &signingEncoded,
		SigningKeyID: &signingID, SigningProof: &signatureEncoded,
		RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipientPublic),
		RecipientKeyID:     recipientID, RequestExpiresAt: expiresAt,
	}
	draft := pendingEnrollment{Schema: pendingEnrollmentSchema, AccountID: manager.AccountID, SubjectID: manager.SubjectID, Genesis: genesis, Request: apiRequest, Canonical: base64.RawURLEncoding.EncodeToString(canonical)}
	if err := manager.storePendingEnrollment(draft); err != nil {
		return EnrollmentResult{}, err
	}
	return manager.resumeEnrollmentLocked(ctx, client, draft, now)
}

func (manager Manager) ConfirmRecoveryExport(value []byte) (resultErr error) {
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return err
	}
	defer identity.Clear()
	decoded, err := environmente2ee.DecodeRecoveryBytes(value)
	if err != nil {
		return ErrIntegrity
	}
	defer clear(decoded)
	public, _, err := recipientPublicAndID(decoded)
	if err != nil || !bytes.Equal(public, identity.RecoveryPublic[:]) {
		clear(public)
		return ErrIntegrity
	}
	clear(public)
	if identity.RecoveryPrivate == nil {
		if identity.RecoveryExportConfirmed {
			return nil
		}
		return ErrRecoveryExportRequired
	}
	// X25519 clamps private scalars. Older unactivated genesis records may hold
	// the pre-clamped random bytes while the recovery format intentionally
	// exports canonical bytes. The public-key comparison above proves they are
	// the same recovery identity; pass the exact stored bytes to the atomic
	// confirmation boundary.
	var expected [32]byte
	copy(expected[:], identity.RecoveryPrivate[:])
	defer clear(expected[:])
	return manager.Store.ConfirmEnvironmentRecoveryExport(manager.Issuer, manager.AccountID, manager.SubjectID, expected)
}

func (manager Manager) ListVerifiedPendingEnrollments(ctx context.Context, now time.Time) ([]VerifiedPendingEnrollment, error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || now.IsZero() {
		return nil, errors.New("ENV enrollment manager is not configured")
	}
	states, err := client.ListPendingEnvironmentKeyEnrollments(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]VerifiedPendingEnrollment, 0, len(states))
	for _, state := range states {
		raw, err := decodeBase64(state.EnrollmentRequest, environmente2ee.MaximumEnrollmentBytes)
		if err != nil {
			return nil, ErrIntegrity
		}
		proof, proofErr := decodeOptionalBase64(state.SigningProof, ed25519.SignatureSize)
		if proofErr != nil {
			clear(raw)
			return nil, ErrIntegrity
		}
		request, safety, verifyErr := environmente2ee.VerifyPendingEnrollment(raw, proof)
		clear(raw)
		clear(proof)
		if verifyErr != nil || request.AccountID != manager.AccountID || state.SafetyCode != safety || state.ExpiresAt.Unix() != int64(request.RequestExpiresAt) || !now.Before(state.ExpiresAt) {
			return nil, ErrIntegrity
		}
		result = append(result, VerifiedPendingEnrollment{RequestID: state.RequestID, Request: request, SafetyCode: safety, ExpiresAt: state.ExpiresAt})
	}
	return result, nil
}

func decodeOptionalBase64(value *string, exact int) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := decodeBase64(*value, exact)
	if err != nil || len(raw) != exact {
		clear(raw)
		return nil, ErrIntegrity
	}
	return raw, nil
}

func enrollmentEqual(left, right environmente2ee.EnrollmentRequest) bool {
	leftRaw, leftErr := environmente2ee.CanonicalEnrollmentRequest(left)
	rightRaw, rightErr := environmente2ee.CanonicalEnrollmentRequest(right)
	defer clear(leftRaw)
	defer clear(rightRaw)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func (manager Manager) rootSigner() (string, ed25519.PrivateKey, environmente2ee.RootKeys, error) {
	seed, err := manager.Store.ExportPeerAccountRootSeed(manager.Issuer, manager.AccountID)
	if err != nil {
		if errors.Is(err, config.ErrSecretNotFound) {
			return "", nil, nil, ErrRootAuthorizationRequired
		}
		return "", nil, nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return "", nil, nil, ErrIntegrity
	}
	private := ed25519.NewKeyFromSeed(seed)
	// An account may authorize multiple independent E2EE roots. The
	// verifier-only public key stored for this endpoint can therefore differ
	// from the private root seed this trusted client actually controls. Bind
	// the ENV authorization to that exact private root; the control plane still
	// verifies it against the account's active root set.
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(public)
	keyID := "aek_" + hex.EncodeToString(digest[:])
	roots := environmente2ee.RootKeys{keyID: public}
	endpointRoots, err := manager.localRoots()
	if err != nil {
		clear(private)
		clearRoots(roots)
		return "", nil, nil, err
	}
	for endpointKeyID, endpointPublic := range endpointRoots {
		if _, exists := roots[endpointKeyID]; !exists {
			roots[endpointKeyID] = append(ed25519.PublicKey(nil), endpointPublic...)
		}
	}
	clearRoots(endpointRoots)
	return keyID, private, roots, nil
}
