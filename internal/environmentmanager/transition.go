package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

type SubjectRef struct {
	Kind environmente2ee.SubjectKind
	ID   string
}

type ScopeRef struct {
	Scope     environmente2ee.ScopeKind
	MachineID string
}

type AuthorityChange struct {
	AddBindings  [][]byte
	Remove       []SubjectRef
	RotateScopes []ScopeRef
	ResetScopes  []environmente2ee.ResetScope
}

type TransitionResult struct {
	TransitionID string
	AuthorityID  string
	Generation   int64
	State        string
}

// ApproveEnrollment verifies the pending request independently, root-signs
// its binding and successor authority, then re-encrypts and stages every scope.
func (manager Manager) ApproveEnrollment(ctx context.Context, requestID, expectedSafety string, now time.Time) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || now.IsZero() {
		return TransitionResult{}, errors.New("ENV enrollment manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if draft, found, err := manager.loadPendingTransition(); err != nil {
		return TransitionResult{}, err
	} else if found {
		// Pre-release clients briefly persisted approval transitions with a new
		// operation ID instead of the enrollment operation ID. The service
		// rejects those before creating any transition, so discard only that
		// precisely identifiable local journal and rebuild correct bytes below.
		if draft.Kind == "approval" && draft.RequestID == requestID && draft.Approval != nil {
			if enrollment, exists, loadErr := manager.loadPendingEnrollment(); loadErr != nil {
				return TransitionResult{}, loadErr
			} else if exists && enrollment.RequestID == requestID && draft.Approval.OperationID != enrollment.Request.OperationID {
				if err := manager.deletePendingTransition(); err != nil {
					return TransitionResult{}, err
				}
				found = false
			}
		}
		if !found {
			// Continue and rebuild the approval from the verified enrollment.
		} else {
			sameApproval := draft.Kind == "approval" && draft.RequestID == requestID
			result, err := manager.resumeAuthorityTransitionLocked(ctx, client, draft)
			if err != nil {
				return TransitionResult{}, err
			}
			if sameApproval {
				if enrollment, exists, loadErr := manager.loadPendingEnrollment(); loadErr != nil {
					return TransitionResult{}, loadErr
				} else if exists && enrollment.RequestID == requestID {
					if err := manager.deletePendingEnrollment(); err != nil {
						return TransitionResult{}, err
					}
				}
				return result, nil
			}
			return result, ErrPendingTransitionReconciled
		}
	}
	pending, err := manager.ListVerifiedPendingEnrollments(ctx, now)
	if err != nil {
		return TransitionResult{}, err
	}
	var selected *VerifiedPendingEnrollment
	for index := range pending {
		if pending[index].RequestID == requestID {
			selected = &pending[index]
			break
		}
	}
	if selected == nil {
		return TransitionResult{}, ErrEnrollmentExpired
	}
	if selected.SafetyCode != expectedSafety {
		return TransitionResult{}, ErrSafetyCodeMismatch
	}
	rootID, rootPrivate, roots, err := manager.rootSigner()
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(rootPrivate)
	defer clearRoots(roots)

	current, authorityETag, currentExists, err := manager.currentAuthority(ctx, roots)
	if err != nil {
		return TransitionResult{}, err
	}
	if currentExists {
		defer clearAuthority(&current)
	}
	request := selected.Request
	claims := environmente2ee.KeyBindingClaims{
		AccountID: request.AccountID, SubjectKind: request.SubjectKind,
		SubjectID: request.SubjectID, SubjectGeneration: request.SubjectGeneration,
		KeyGeneration: request.KeyGeneration, EndpointCertificate: request.EndpointCertificate,
		SigningPublic: request.SigningPublic, SigningKeyID: request.SigningKeyID,
		RecipientPublic: request.RecipientPublic, RecipientKeyID: request.RecipientKeyID,
		NotBefore: uint64(now.UTC().Unix()), Serial: uint64(now.UTC().Unix()),
	}
	bindingRaw, err := environmente2ee.SignKeyBinding(claims, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(bindingRaw)

	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer identity.Clear()
	if currentExists {
		verified, activeRecipient, _, activeSigner, activeErr := manager.activeAuthority(ctx, &identity)
		clear(activeRecipient.PrivateKey)
		clear(activeSigner)
		if activeErr != nil {
			clearAuthority(&verified)
			return TransitionResult{}, activeErr
		}
		if verified.ID != current.ID {
			clearAuthority(&verified)
			return TransitionResult{}, ErrAuthorityFork
		}
		clearAuthority(&current)
		current = verified
	}
	authorityClaims := environmente2ee.AuthorityClaims{AccountID: manager.AccountID}
	if currentExists {
		authorityClaims.Generation = current.Generation + 1
		previous := current.ID
		authorityClaims.PreviousID = &previous
		authorityClaims.BindingBytes = appendBindingCopies(current.BindingBytes, bindingRaw)
	} else {
		if request.SubjectKind != environmente2ee.SubjectManagerCLI || request.SubjectID != manager.SubjectID || !identity.RecoveryRequired || !identity.RecoveryExportConfirmed || identity.RecoveryPublic == [32]byte{} {
			return TransitionResult{}, ErrKeyAuthorizationRequired
		}
		authorityClaims.Generation = 1
		recoveryPublic := append([]byte(nil), identity.RecoveryPublic[:]...)
		defer clear(recoveryPublic)
		recoveryID, _ := environmente2ee.KeyIDX25519(recoveryPublic)
		recoveryBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
			AccountID: manager.AccountID, SubjectKind: environmente2ee.SubjectRecovery,
			SubjectID: "environment_recovery", SubjectGeneration: 1, KeyGeneration: 1,
			RecipientPublic: recoveryPublic, RecipientKeyID: recoveryID,
			NotBefore: uint64(now.UTC().Unix()), Serial: 1,
		}, rootID, rootPrivate)
		if err != nil {
			return TransitionResult{}, ErrIntegrity
		}
		defer clear(recoveryBinding)
		authorityClaims.BindingBytes = [][]byte{append([]byte(nil), bindingRaw...), append([]byte(nil), recoveryBinding...)}
	}
	// Genesis approval is the completion of the enrollment operation, not a
	// second independent mutation. Keep the request's operation ID in the
	// signed authority and HTTP idempotency binding so retries are exact.
	operation := request.OperationID
	operationID := "envop_" + hex.EncodeToString(operation[:])
	authorityClaims.OperationID = operation
	authorityRaw, err := environmente2ee.SignAuthority(authorityClaims, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(authorityRaw)
	proposed, err := environmente2ee.ParseAuthority(authorityRaw, roots)
	if err != nil || environmente2ee.ValidateAuthorityTransition(authorityPointer(current, currentExists), proposed) != nil {
		clearAuthority(&proposed)
		return TransitionResult{}, ErrIntegrity
	}
	defer clearAuthority(&proposed)

	expectedAuthorityID := (*string)(nil)
	if currentExists {
		id := current.ID.String()
		expectedAuthorityID = &id
	}
	approval := api.EnvironmentKeyApproval{
		Schema: api.EnvironmentKeyApprovalSchemaV1, ExpectedAuthorityID: expectedAuthorityID,
		OperationID: operationID, Binding: base64.RawURLEncoding.EncodeToString(bindingRaw),
		Authority: base64.RawURLEncoding.EncodeToString(authorityRaw),
	}
	draft := newPendingTransition(manager, "approval", authorityPointer(current, currentExists), proposed, authorityETag)
	draft.RequestID, draft.Approval = requestID, &approval
	if err := manager.storePendingTransition(draft); err != nil {
		return TransitionResult{}, err
	}
	result, err = manager.resumeAuthorityTransitionLocked(ctx, client, draft)
	if err != nil {
		return TransitionResult{}, err
	}
	if enrollment, found, loadErr := manager.loadPendingEnrollment(); loadErr != nil {
		return TransitionResult{}, loadErr
	} else if found && enrollment.RequestID == requestID {
		if err := manager.deletePendingEnrollment(); err != nil {
			return TransitionResult{}, err
		}
	}
	return result, nil
}

// ApplyAuthorityChange signs and stages a complete add/revoke/rotation/reset
// transition. Added bindings must already be root-signed canonical documents.
func (manager Manager) ApplyAuthorityChange(ctx context.Context, change AuthorityChange) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok {
		return TransitionResult{}, errors.New("ENV transition manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if draft, found, err := manager.loadPendingTransition(); err != nil {
		return TransitionResult{}, err
	} else if found {
		result, err := manager.resumeAuthorityTransitionLocked(ctx, client, draft)
		if err != nil {
			return TransitionResult{}, err
		}
		return result, ErrPendingTransitionReconciled
	}
	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer identity.Clear()
	current, recipient, _, signerPrivate, err := manager.activeAuthority(ctx, &identity)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clearAuthority(&current)
	defer clear(recipient.PrivateKey)
	defer clear(signerPrivate)
	state, err := manager.Client.GetEnvironmentAuthority(ctx)
	if err != nil || state.AuthorityID != current.ID.String() || state.Generation != int64(current.Generation) {
		return TransitionResult{}, ErrAuthorityFork
	}
	rootID, rootPrivate, roots, err := manager.rootSigner()
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(rootPrivate)
	defer clearRoots(roots)
	bindings, err := changedBindings(current, roots, change)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() {
		for index := range bindings {
			clear(bindings[index])
		}
	}()
	operationID, operation, err := newOperationID(manager.randomSource())
	if err != nil {
		return TransitionResult{}, err
	}
	previous := current.ID
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: manager.AccountID, Generation: current.Generation + 1,
		PreviousID: &previous, OperationID: operation, BindingBytes: bindings,
		ResetScopes: append([]environmente2ee.ResetScope(nil), change.ResetScopes...),
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
	draft := newPendingTransition(manager, "start", &current, proposed, state.ETag)
	draft.Start = &start
	draft.RotateScopes = append([]ScopeRef(nil), change.RotateScopes...)
	sortScopes(draft.RotateScopes)
	if err := manager.storePendingTransition(draft); err != nil {
		return TransitionResult{}, err
	}
	return manager.resumeAuthorityTransitionLocked(ctx, client, draft)
}

func (manager Manager) AbortAuthorityTransition(ctx context.Context, transitionID string) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok {
		return TransitionResult{}, errors.New("ENV transition manager is not configured")
	}
	if ctx == nil {
		return TransitionResult{}, errors.New("ENV transition manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	rootID, rootPrivate, roots, err := manager.rootSigner()
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(rootPrivate)
	defer clearRoots(roots)
	current, etag, exists, err := manager.currentAuthority(ctx, roots)
	if err != nil || !exists {
		return TransitionResult{}, ErrAuthorityFork
	}
	defer clearAuthority(&current)
	transition, err := environmente2ee.ParseDocumentID(transitionID)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	operationID, operation, err := newOperationID(manager.randomSource())
	if err != nil {
		return TransitionResult{}, err
	}
	raw, err := environmente2ee.SignAuthorityTransitionAbort(environmente2ee.AuthorityTransitionAbortClaims{
		AccountID: manager.AccountID, ActiveAuthorityID: current.ID,
		TransitionID: transition, OperationID: operation,
	}, rootID, rootPrivate)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(raw)
	state, err := client.AbortEnvironmentAuthorityTransition(ctx, etag, api.EnvironmentAuthorityTransitionAbort{
		Schema: api.EnvironmentAuthorityTransitionAbortSchema, ExpectedTransitionID: transitionID,
		OperationID: operationID, Authorization: base64.RawURLEncoding.EncodeToString(raw),
	})
	if err != nil {
		return TransitionResult{}, err
	}
	if draft, found, loadErr := manager.loadPendingTransition(); loadErr != nil {
		return TransitionResult{}, loadErr
	} else if found && draft.TransitionID == transitionID {
		if err := manager.deletePendingTransition(); err != nil {
			return TransitionResult{}, err
		}
		if draft.DestructiveReset {
			if cancelErr := manager.Store.CancelEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID, draft.DestructiveResetHandle); cancelErr != nil && !errors.Is(cancelErr, config.ErrSecretNotFound) {
				return TransitionResult{}, cancelErr
			}
		}
	}
	return transitionResult(state), nil
}

func (manager Manager) stageAllScopes(ctx context.Context, client EnrollmentControlPlane, state api.EnvironmentAuthorityTransitionState, current *environmente2ee.Authority, proposed environmente2ee.Authority, identity config.EnvironmentManagerIdentity, rotate []ScopeRef, operationID string) (TransitionResult, error) {
	recipient, err := managerRecipient(identity, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, ErrIntegrity
	}
	defer clear(recipient.PrivateKey)
	return manager.stageAllScopesWithRecipient(ctx, client, state, current, proposed, identity, recipient, rotate, operationID)
}

func (manager Manager) stageAllScopesWithRecipient(ctx context.Context, client EnrollmentControlPlane, state api.EnvironmentAuthorityTransitionState, current *environmente2ee.Authority, proposed environmente2ee.Authority, identity config.EnvironmentManagerIdentity, recipient environmente2ee.RecipientPrivate, rotate []ScopeRef, operationID string) (TransitionResult, error) {
	signerPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signerPrivate)
	signerID, err := environmente2ee.KeyIDEd25519(signerPrivate.Public().(ed25519.PublicKey))
	if err != nil || !authorityHasSigner(proposed, manager.SubjectID, uint64(identity.KeyGeneration), signerID) {
		return TransitionResult{}, ErrKeyAuthorizationRequired
	}
	operation, err := parseOperationID(operationID)
	if err != nil {
		return TransitionResult{}, err
	}
	for _, scopeName := range state.RequiredScopes {
		machineID, valid := transitionScopeMachineID(scopeName)
		if !valid {
			return TransitionResult{}, ErrIntegrity
		}
		var old *environmente2ee.Manifest
		var oldState api.EnvironmentManifestState
		if current != nil {
			oldState, err = manager.Client.GetEnvironmentManifest(ctx, machineID)
			if err != nil {
				var apiErr *api.APIError
				if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
					return TransitionResult{}, err
				}
			} else {
				raw, decodeErr := decodeBase64(oldState.Envelope, environmente2ee.MaximumManifestBytes)
				if decodeErr != nil {
					return TransitionResult{}, ErrIntegrity
				}
				parsed, parseErr := environmente2ee.ParseManifest(raw, *current)
				clear(raw)
				if parseErr != nil || !manifestMatchesState(parsed, oldState, machineID, manager.AccountID) {
					clearManifest(&parsed)
					return TransitionResult{}, ErrIntegrity
				}
				old = &parsed
			}
		}
		expectedVersion, etag := int64(0), ""
		if old != nil {
			expectedVersion, etag = int64(old.Version), oldState.ETag
		}
		nextRaw, err := manager.buildTransitionManifest(old, current, proposed, recipient, signerID, signerPrivate, machineID, rotate, operation)
		if old != nil {
			clearManifest(old)
		}
		if err != nil {
			return TransitionResult{}, err
		}
		response, err := client.StageEnvironmentTransitionManifest(ctx, state.TransitionID, machineID, etag, api.EnvironmentTransitionManifest{
			Schema: api.EnvironmentTransitionManifestSchemaV1, ExpectedVersion: expectedVersion,
			OperationID: operationID, Envelope: base64.RawURLEncoding.EncodeToString(nextRaw),
		})
		clear(nextRaw)
		if err != nil {
			return TransitionResult{}, err
		}
		state = response
	}
	if state.State != "active" || state.ProposedAuthorityID != proposed.ID.String() {
		return transitionResult(state), ErrTransitionIncomplete
	}
	if err := manager.Store.CommitEnvironmentAuthorityHighWater(manager.Issuer, manager.AccountID, manager.SubjectID, int64(proposed.Generation), proposed.ID.String()); err != nil {
		return TransitionResult{}, err
	}
	return transitionResult(state), nil
}

func (manager Manager) buildTransitionManifest(old *environmente2ee.Manifest, current *environmente2ee.Authority, proposed environmente2ee.Authority, recipient environmente2ee.RecipientPrivate, signerID string, signerPrivate ed25519.PrivateKey, machineID string, rotate []ScopeRef, operation [16]byte) ([]byte, error) {
	scope := environmente2ee.ScopeGlobal
	state := environmente2ee.ScopeActive
	if machineID != "" {
		scope = environmente2ee.ScopeMachine
		if !authorityHasHost(proposed, machineID) {
			state = environmente2ee.ScopeRetired
		}
	}
	reset := authorityHasResetScope(proposed, scope, machineID)
	values := map[string][]byte{}
	var scopeKey []byte
	var err error
	previousVersion, version, epoch := uint64(0), uint64(1), uint64(1)
	mutation := environmente2ee.MutationInitialize
	changed := []string{}
	if old != nil {
		previousVersion, version, epoch = old.Version, old.Version+1, old.KeyEpoch
		if reset {
			mutation = environmente2ee.MutationReset
			changed = append([]string(nil), old.Names...)
			scopeKey, err = randomKey(manager.randomSource())
			if err != nil {
				return nil, err
			}
			defer clear(scopeKey)
			epoch++
		} else {
			decrypted, err := environmente2ee.DecryptManifest(*old, recipient)
			if err != nil {
				return nil, ErrNoDecryptingKey
			}
			defer clearDecrypted(&decrypted)
			values, scopeKey = decrypted.Values, decrypted.ScopeKey
			mutation = environmente2ee.MutationReauthorize
			if state != environmente2ee.ScopeActive || old.State == state {
				if scopeRequested(rotate, scope, machineID) || recipientsRemoved(old.Wraps, proposed, scope, state, machineID) {
					mutation = environmente2ee.MutationRotate
					fresh, err := randomKey(manager.randomSource())
					if err != nil {
						return nil, err
					}
					scopeKey = fresh
					defer clear(scopeKey)
					epoch++
				}
			}
		}
	} else {
		scopeKey, err = randomKey(manager.randomSource())
		if err != nil {
			return nil, err
		}
		defer clear(scopeKey)
		if reset {
			mutation = environmente2ee.MutationReset
		}
	}
	recipients, err := proposed.ExpectedRecipients(scope, state, machineID)
	if err != nil {
		return nil, ErrIntegrity
	}
	raw, err := environmente2ee.BuildManifest(environmente2ee.BuildManifestInput{
		Claims: environmente2ee.ManifestClaims{
			AccountID: manager.AccountID, AuthorityGeneration: proposed.Generation, AuthorityID: proposed.ID,
			Scope: scope, MachineID: machineID, State: state,
			PreviousVersion: previousVersion, Version: version, KeyEpoch: epoch,
			OperationID: operation, Mutation: mutation, ChangedNames: changed,
		},
		Values: values, ScopeKey: scopeKey, Recipients: recipients,
		SignerKeyID: signerID, SignerPrivate: signerPrivate, Random: manager.randomSource(),
	})
	if err != nil {
		return nil, ErrIntegrity
	}
	next, err := environmente2ee.ParseManifest(raw, proposed)
	if err != nil || environmente2ee.ValidateManifestTransition(old, next, current, proposed) != nil {
		clear(raw)
		clearManifest(&next)
		return nil, ErrIntegrity
	}
	clearManifest(&next)
	return raw, nil
}

func parseOperationID(value string) ([16]byte, error) {
	var operation [16]byte
	if !operationIDPattern.MatchString(value) {
		return operation, ErrIntegrity
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "envop_"))
	if err != nil || len(raw) != len(operation) {
		clear(raw)
		return operation, ErrIntegrity
	}
	copy(operation[:], raw)
	clear(raw)
	return operation, nil
}

func (manager Manager) currentAuthority(ctx context.Context, roots environmente2ee.RootKeys) (environmente2ee.Authority, string, bool, error) {
	state, err := manager.Client.GetEnvironmentAuthority(ctx)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "authority_not_initialized" {
			return environmente2ee.Authority{}, "", false, nil
		}
		return environmente2ee.Authority{}, "", false, err
	}
	raw, err := decodeBase64(state.Authority, environmente2ee.MaximumAuthorityBytes)
	if err != nil {
		return environmente2ee.Authority{}, "", false, ErrIntegrity
	}
	defer clear(raw)
	authority, err := environmente2ee.ParseAuthority(raw, roots)
	if err != nil || authority.AccountID != manager.AccountID || authority.ID.String() != state.AuthorityID || int64(authority.Generation) != state.Generation {
		clearAuthority(&authority)
		return environmente2ee.Authority{}, "", false, ErrIntegrity
	}
	return authority, state.ETag, true, nil
}

func changedBindings(current environmente2ee.Authority, roots environmente2ee.RootKeys, change AuthorityChange) ([][]byte, error) {
	if len(change.Remove) == 0 && len(change.AddBindings) == 0 && len(change.RotateScopes) == 0 && len(change.ResetScopes) == 0 {
		return nil, ErrIntegrity
	}
	remove := make(map[SubjectRef]struct{}, len(change.Remove))
	for _, subject := range change.Remove {
		if _, duplicate := remove[subject]; duplicate {
			return nil, ErrIntegrity
		}
		remove[subject] = struct{}{}
	}
	found := make(map[SubjectRef]bool, len(remove))
	existing := make(map[SubjectRef]environmente2ee.KeyBinding, len(current.Bindings))
	keyOwners := make(map[string]SubjectRef, len(current.Bindings)*2)
	result := make([][]byte, 0, len(current.Bindings)+len(change.AddBindings))
	for _, binding := range current.Bindings {
		subject := SubjectRef{Kind: binding.SubjectKind, ID: binding.SubjectID}
		existing[subject] = binding
		if _, removed := remove[subject]; removed {
			found[subject] = true
		} else {
			result = append(result, append([]byte(nil), binding.Raw...))
			keyOwners[binding.RecipientKeyID] = subject
			if binding.SigningKeyID != "" {
				keyOwners[binding.SigningKeyID] = subject
			}
		}
	}
	for subject := range remove {
		if !found[subject] {
			return nil, ErrIntegrity
		}
	}
	added := make(map[SubjectRef]struct{}, len(change.AddBindings))
	for _, raw := range change.AddBindings {
		binding, err := environmente2ee.ParseKeyBinding(raw, roots)
		if err != nil || binding.AccountID != current.AccountID {
			return nil, ErrIntegrity
		}
		subject := SubjectRef{Kind: binding.SubjectKind, ID: binding.SubjectID}
		if _, duplicate := added[subject]; duplicate {
			return nil, ErrIntegrity
		}
		if old, collision := existing[subject]; collision {
			if _, explicitlyRemoved := remove[subject]; !explicitlyRemoved || binding.SubjectGeneration < old.SubjectGeneration || binding.SubjectGeneration == old.SubjectGeneration && binding.KeyGeneration <= old.KeyGeneration {
				return nil, ErrIntegrity
			}
		}
		if _, collision := keyOwners[binding.RecipientKeyID]; collision {
			return nil, ErrIntegrity
		}
		if binding.SigningKeyID != "" {
			if _, collision := keyOwners[binding.SigningKeyID]; collision {
				return nil, ErrIntegrity
			}
		}
		added[subject] = struct{}{}
		keyOwners[binding.RecipientKeyID] = subject
		if binding.SigningKeyID != "" {
			keyOwners[binding.SigningKeyID] = subject
		}
		result = append(result, append([]byte(nil), raw...))
	}
	return result, nil
}

func managerRecipient(identity config.EnvironmentManagerIdentity, subjectID string) (environmente2ee.RecipientPrivate, error) {
	private, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		return environmente2ee.RecipientPrivate{}, err
	}
	id, err := environmente2ee.KeyIDX25519(private.PublicKey().Bytes())
	if err != nil {
		return environmente2ee.RecipientPrivate{}, err
	}
	return environmente2ee.RecipientPrivate{Kind: environmente2ee.RecipientManager, SubjectID: subjectID, KeyGeneration: uint64(identity.KeyGeneration), KeyID: id, PrivateKey: append([]byte(nil), identity.RecipientPrivate[:]...)}, nil
}

func randomKey(source io.Reader) ([]byte, error) {
	if source == nil {
		source = rand.Reader
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil || bytes.Equal(value, make([]byte, 32)) {
		clear(value)
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	return value, nil
}

func appendBindingCopies(existing [][]byte, added []byte) [][]byte {
	result := make([][]byte, 0, len(existing)+1)
	for _, raw := range existing {
		result = append(result, append([]byte(nil), raw...))
	}
	return append(result, append([]byte(nil), added...))
}

func authorityPointer(authority environmente2ee.Authority, exists bool) *environmente2ee.Authority {
	if !exists {
		return nil
	}
	return &authority
}

func authorityHasSigner(authority environmente2ee.Authority, subject string, generation uint64, keyID string) bool {
	for _, binding := range authority.Bindings {
		if (binding.SubjectKind == environmente2ee.SubjectManagerCLI || binding.SubjectKind == environmente2ee.SubjectManagerBrowser) && binding.SubjectID == subject && binding.KeyGeneration == generation && binding.SigningKeyID == keyID {
			return true
		}
	}
	return false
}

func authorityHasHost(authority environmente2ee.Authority, machineID string) bool {
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectHost && binding.SubjectID == machineID {
			return true
		}
	}
	return false
}

func authorityHasResetScope(authority environmente2ee.Authority, scope environmente2ee.ScopeKind, machineID string) bool {
	for _, reset := range authority.ResetScopes {
		if reset.Scope == scope && reset.MachineID == machineID {
			return true
		}
	}
	return false
}

func scopeRequested(scopes []ScopeRef, scope environmente2ee.ScopeKind, machineID string) bool {
	for _, candidate := range scopes {
		if candidate.Scope == scope && candidate.MachineID == machineID {
			return true
		}
	}
	return false
}

func recipientsRemoved(old []environmente2ee.RecipientWrap, proposed environmente2ee.Authority, scope environmente2ee.ScopeKind, state environmente2ee.ScopeState, machineID string) bool {
	expected, err := proposed.ExpectedRecipients(scope, state, machineID)
	if err != nil {
		return true
	}
	for _, prior := range old {
		found := false
		for _, candidate := range expected {
			if prior.Kind == candidate.Kind && prior.SubjectID == candidate.SubjectID && prior.KeyGeneration == candidate.KeyGeneration && prior.KeyID == candidate.KeyID {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func transitionResult(state api.EnvironmentAuthorityTransitionState) TransitionResult {
	return TransitionResult{TransitionID: state.TransitionID, AuthorityID: state.ProposedAuthorityID, Generation: state.ProposedGeneration, State: state.State}
}

func sortScopes(values []ScopeRef) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Scope != values[j].Scope {
			return values[i].Scope < values[j].Scope
		}
		return values[i].MachineID < values[j].MachineID
	})
}
