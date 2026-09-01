package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

// RecoveryRotationRequest names secure-store handles, never recovery bytes.
// EndpointCertificate must certify this fresh manager subject under the pinned
// account root at SubjectGeneration.
type RecoveryRotationRequest struct {
	ImportedRecoveryHandle    string
	ReplacementRecoveryHandle string
	EndpointCertificate       []byte
	SubjectGeneration         int64
	Now                       time.Time
}

type RecoveryPreparation = config.EnvironmentRecoveryPreparation

func (manager Manager) BeginRecoveryPreparation(importedRecovery []byte) (RecoveryPreparation, error) {
	return manager.Store.BeginEnvironmentRecoveryPreparation(manager.Issuer, manager.AccountID, manager.SubjectID, importedRecovery)
}

func (manager Manager) ResumeRecoveryPreparation() (RecoveryPreparation, error) {
	return manager.Store.ResumeEnvironmentRecoveryPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
}

func (manager Manager) ConfirmRecoveryPreparationExport(encoded []byte) error {
	return manager.Store.ConfirmEnvironmentRecoveryPreparationExport(manager.Issuer, manager.AccountID, manager.SubjectID, encoded)
}

func (manager Manager) CancelRecoveryPreparation() (resultErr error) {
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
	return manager.Store.CancelEnvironmentRecoveryPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
}

// RecoverAndRotate root-authorizes this fresh manager, replaces the offline
// recovery recipient, decrypts every scope with the temporarily imported old
// recovery key, rotates every scope key, and erases both online recovery keys
// only after the server reports atomic activation.
func (manager Manager) RecoverAndRotate(ctx context.Context, request RecoveryRotationRequest) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || ctx == nil || request.Now.IsZero() || request.SubjectGeneration < 1 || len(request.EndpointCertificate) == 0 {
		return TransitionResult{}, errors.New("ENV recovery manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if draft, found, err := manager.loadPendingTransition(); err != nil {
		return TransitionResult{}, err
	} else if found {
		sameRecovery := draft.ImportedRecoveryHandle == request.ImportedRecoveryHandle && draft.ReplacementRecoveryHandle == request.ReplacementRecoveryHandle && draft.ImportedRecoveryHandle != ""
		result, err := manager.resumeAuthorityTransitionLocked(ctx, client, draft)
		if err != nil {
			return TransitionResult{}, err
		}
		if sameRecovery {
			return result, nil
		}
		return result, ErrPendingTransitionReconciled
	}

	identity, err := manager.Store.CreateEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID, false)
	if err != nil {
		return TransitionResult{}, err
	}
	defer identity.Clear()
	imported, err := manager.Store.LoadEnvironmentRecoveryTemporary(manager.Issuer, manager.AccountID, request.ImportedRecoveryHandle)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(imported[:])
	replacement, err := manager.Store.LoadConfirmedEnvironmentReplacementRecovery(manager.Issuer, manager.AccountID, request.ReplacementRecoveryHandle)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(replacement[:])

	rootID, rootPrivate, roots, err := manager.rootSigner()
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(rootPrivate)
	defer clearRoots(roots)
	current, authorityETag, err := manager.syncAuthorityForRecovery(ctx, &identity, roots)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clearAuthority(&current)
	if authorityHasManagerSubject(current, manager.SubjectID) {
		return TransitionResult{}, ErrRootAuthorizationRequired
	}

	oldRecovery, err := recoveryBindingForPrivate(current, imported[:])
	if err != nil {
		return TransitionResult{}, err
	}
	newRecoveryPublic, newRecoveryID, err := recipientPublicAndID(replacement[:])
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(newRecoveryPublic)
	signingPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signingPrivate)
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	signingID, err := environmente2ee.KeyIDEd25519(signingPublic)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	managerRecipientPublic, managerRecipientID, err := recipientPublicAndID(identity.RecipientPrivate[:])
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(managerRecipientPublic)
	notBefore := uint64(request.Now.UTC().Unix())
	if notBefore == 0 {
		return TransitionResult{}, ErrIntegrity
	}
	managerBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: manager.AccountID, SubjectKind: environmente2ee.SubjectManagerCLI,
		SubjectID: manager.SubjectID, SubjectGeneration: uint64(request.SubjectGeneration),
		KeyGeneration: uint64(identity.KeyGeneration), EndpointCertificate: request.EndpointCertificate,
		SigningPublic: signingPublic, SigningKeyID: signingID,
		RecipientPublic: managerRecipientPublic, RecipientKeyID: managerRecipientID,
		NotBefore: notBefore, Serial: current.Generation + 1,
	}, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrRootAuthorizationRequired
	}
	defer clear(managerBinding)
	recoveryBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: manager.AccountID, SubjectKind: environmente2ee.SubjectRecovery,
		SubjectID: "environment_recovery", SubjectGeneration: oldRecovery.SubjectGeneration,
		KeyGeneration: oldRecovery.KeyGeneration + 1, RecipientPublic: newRecoveryPublic,
		RecipientKeyID: newRecoveryID, NotBefore: notBefore, Serial: current.Generation + 1,
	}, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(recoveryBinding)
	bindings, err := changedBindings(current, roots, AuthorityChange{
		Remove:      []SubjectRef{{Kind: environmente2ee.SubjectRecovery, ID: "environment_recovery"}},
		AddBindings: [][]byte{managerBinding, recoveryBinding},
	})
	if err != nil {
		return TransitionResult{}, err
	}
	defer clearByteSlices(bindings)
	operationID, operation, err := newOperationID(manager.randomSource())
	if err != nil {
		return TransitionResult{}, err
	}
	previous := current.ID
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: manager.AccountID, Generation: current.Generation + 1,
		PreviousID: &previous, OperationID: operation, BindingBytes: bindings,
	}, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(authorityRaw)
	proposed, err := environmente2ee.ParseAuthority(authorityRaw, roots)
	if err != nil || environmente2ee.ValidateAuthorityTransition(&current, proposed) != nil {
		clearAuthority(&proposed)
		return TransitionResult{}, ErrIntegrity
	}
	defer clearAuthority(&proposed)
	start := api.EnvironmentAuthorityTransition{
		Schema: api.EnvironmentAuthorityTransitionSchemaV1, ExpectedAuthorityID: current.ID.String(),
		OperationID: operationID, Authority: base64.RawURLEncoding.EncodeToString(authorityRaw),
	}
	draft := newPendingTransition(manager, "start", &current, proposed, authorityETag)
	draft.Start = &start
	draft.ImportedRecoveryHandle = request.ImportedRecoveryHandle
	draft.ReplacementRecoveryHandle = request.ReplacementRecoveryHandle
	if err := manager.storePendingTransition(draft); err != nil {
		return TransitionResult{}, err
	}
	return manager.resumeAuthorityTransitionLocked(ctx, client, draft)
}

func (manager Manager) syncAuthorityForRecovery(ctx context.Context, identity *config.EnvironmentManagerIdentity, roots environmente2ee.RootKeys) (environmente2ee.Authority, string, error) {
	cursorGeneration, cursorID := identity.AuthorityGeneration, identity.AuthorityID
	for {
		page, err := manager.Client.GetEnvironmentAuthorityDocuments(ctx, cursorGeneration, cursorID)
		if err != nil {
			return environmente2ee.Authority{}, "", err
		}
		for _, encoded := range page.AuthorityDocuments {
			raw, decodeErr := decodeBase64(encoded, environmente2ee.MaximumAuthorityBytes)
			if decodeErr != nil {
				return environmente2ee.Authority{}, "", ErrIntegrity
			}
			next, parseErr := environmente2ee.ParseAuthority(raw, roots)
			clear(raw)
			if parseErr != nil || next.AccountID != manager.AccountID || next.Generation != uint64(cursorGeneration+1) || next.PreviousID == nil != (cursorGeneration == 0) || cursorGeneration > 0 && *next.PreviousID != mustDocumentID(cursorID) || cursorGeneration == 0 && environmente2ee.ValidateAuthorityTransition(nil, next) != nil {
				clearAuthority(&next)
				return environmente2ee.Authority{}, "", ErrAuthorityFork
			}
			if err := manager.Store.CommitEnvironmentAuthorityHighWater(manager.Issuer, manager.AccountID, manager.SubjectID, int64(next.Generation), next.ID.String()); err != nil {
				clearAuthority(&next)
				return environmente2ee.Authority{}, "", err
			}
			cursorGeneration, cursorID = int64(next.Generation), next.ID.String()
			identity.AuthorityGeneration, identity.AuthorityID = cursorGeneration, cursorID
			clearAuthority(&next)
		}
		if page.AuthorityHead.Generation < cursorGeneration || page.AuthorityHead.AuthorityID == "" || page.HasMore && len(page.AuthorityDocuments) == 0 {
			return environmente2ee.Authority{}, "", ErrAuthorityFork
		}
		if !page.HasMore {
			if page.AuthorityHead.Generation != cursorGeneration || page.AuthorityHead.AuthorityID != cursorID {
				return environmente2ee.Authority{}, "", ErrAuthorityFork
			}
			break
		}
	}
	current, etag, exists, err := manager.currentAuthority(ctx, roots)
	if err != nil {
		return environmente2ee.Authority{}, "", err
	}
	if !exists || int64(current.Generation) != cursorGeneration || current.ID.String() != cursorID {
		clearAuthority(&current)
		return environmente2ee.Authority{}, "", ErrAuthorityFork
	}
	return current, etag, nil
}

func recoveryBindingForPrivate(authority environmente2ee.Authority, private []byte) (environmente2ee.KeyBinding, error) {
	public, keyID, err := recipientPublicAndID(private)
	if err != nil {
		return environmente2ee.KeyBinding{}, ErrNoDecryptingKey
	}
	defer clear(public)
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectRecovery && binding.SubjectID == "environment_recovery" && binding.RecipientKeyID == keyID && bytes.Equal(binding.RecipientPublic, public) {
			return binding, nil
		}
	}
	return environmente2ee.KeyBinding{}, ErrNoDecryptingKey
}

func recipientPublicAndID(private []byte) ([]byte, string, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, "", err
	}
	public := key.PublicKey().Bytes()
	id, err := environmente2ee.KeyIDX25519(public)
	if err != nil {
		clear(public)
		return nil, "", err
	}
	return public, id, nil
}

func authorityHasManagerSubject(authority environmente2ee.Authority, subjectID string) bool {
	for _, binding := range authority.Bindings {
		if (binding.SubjectKind == environmente2ee.SubjectManagerCLI || binding.SubjectKind == environmente2ee.SubjectManagerBrowser) && binding.SubjectID == subjectID {
			return true
		}
	}
	return false
}

func clearByteSlices(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}
