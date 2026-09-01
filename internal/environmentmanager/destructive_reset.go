package environmentmanager

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

// DestructiveResetPreparation is the public, non-secret reset preparation
// view. The recovery field is an owner-controlled offline export and is
// cleared by callers immediately after writing/verifying it.
type DestructiveResetPreparation = config.EnvironmentDestructiveResetPreparation

func (manager Manager) BeginDestructiveResetPreparation() (DestructiveResetPreparation, error) {
	return manager.Store.BeginEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
}

func (manager Manager) ResumeDestructiveResetPreparation() (DestructiveResetPreparation, error) {
	return manager.Store.ResumeEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
}

// ConfirmDestructiveResetExport verifies the exact encoded recovery export in
// secure storage. This must succeed before StartDestructiveReset can make a
// network request.
func (manager Manager) ConfirmDestructiveResetExport(encoded []byte) error {
	preparation, err := manager.ResumeDestructiveResetPreparation()
	if err != nil {
		return err
	}
	handle := preparation.Handle
	preparation.Clear()
	return manager.Store.ConfirmEnvironmentDestructiveResetExport(manager.Issuer, manager.AccountID, manager.SubjectID, handle, encoded)
}

// CancelDestructiveResetPreparation erases only an uncommitted local
// preparation. A transition journal always wins over cancellation, so an
// interrupted server transition must be completed or root-aborted first.
func (manager Manager) CancelDestructiveResetPreparation() (resultErr error) {
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
	preparation, err := manager.Store.ResumeEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		if errors.Is(err, config.ErrSecretNotFound) {
			return nil
		}
		return err
	}
	handle := preparation.Handle
	preparation.Clear()
	return manager.Store.CancelEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID, handle)
}

// StartDestructiveReset freezes the caller's metadata inventory in an exact,
// durable transition journal and replaces all manager/recovery bindings in a
// single root-authorized successor. endpointCertificate is the existing CLI
// endpoint proof; the manager and recovery key material itself is fresh.
func (manager Manager) StartDestructiveReset(ctx context.Context, endpointCertificate []byte, subjectGeneration int64, inventory api.EnvironmentScopeInventory, confirmation string, now time.Time) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || ctx == nil || now.IsZero() || subjectGeneration < 1 {
		return TransitionResult{}, errors.New("ENV destructive reset manager is not configured")
	}
	if confirmation != "RESET ENV "+manager.AccountID {
		return TransitionResult{}, ErrDestructiveResetConfirmationRequired
	}
	if inventory.Schema != api.EnvironmentScopeInventorySchemaV1 || !validDestructiveResetInventory(inventory.Scopes) {
		return TransitionResult{}, ErrDestructiveResetInventoryChanged
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	draft, found, loadErr := manager.loadPendingTransition()
	if loadErr != nil {
		return TransitionResult{}, loadErr
	} else if found {
		if !draft.DestructiveReset {
			resumed, resumeErr := manager.resumeAuthorityTransitionLocked(ctx, client, draft)
			if resumeErr != nil {
				return TransitionResult{}, resumeErr
			}
			return resumed, ErrPendingTransitionReconciled
		}
		if !draft.DestructiveResetConfirmed {
			return TransitionResult{}, ErrDestructiveResetConfirmationRequired
		}
		if !destructiveResetInventoryEqual(draft.DestructiveResetInventory, inventory.Scopes) {
			return TransitionResult{}, ErrDestructiveResetInventoryChanged
		}
		return manager.resumeAuthorityTransitionLocked(ctx, client, draft)
	}
	preparation, err := manager.Store.ResumeEnvironmentDestructiveResetPreparation(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	if !preparation.ExportConfirmed {
		preparation.Clear()
		return TransitionResult{}, ErrDestructiveResetConfirmationRequired
	}
	handle := preparation.Handle
	defer preparation.Clear()

	// This is the first network operation after export confirmation. The
	// caller's pre-confirmation view and this authenticated view must match.
	latest, err := client.GetEnvironmentScopeInventory(ctx)
	if err != nil {
		return TransitionResult{}, err
	}
	if latest.Schema != inventory.Schema || !destructiveResetInventoryEqual(latest.Scopes, inventory.Scopes) {
		return TransitionResult{}, ErrDestructiveResetInventoryChanged
	}
	rootID, rootPrivate, roots, err := manager.rootSigner()
	if err != nil {
		return TransitionResult{}, err
	}
	defer clear(rootPrivate)
	defer clearRoots(roots)
	current, authorityETag, exists, err := manager.currentAuthority(ctx, roots)
	if err != nil || !exists {
		if err != nil {
			return TransitionResult{}, err
		}
		return TransitionResult{}, ErrAuthorityFork
	}
	defer clearAuthority(&current)
	if err := resetInventoryMatchesAuthority(inventory.Scopes, current); err != nil {
		return TransitionResult{}, err
	}
	nextKeyGeneration := int64(preparation.KeyGeneration)
	for _, binding := range current.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectManagerCLI && binding.SubjectID == manager.SubjectID && int64(binding.KeyGeneration) >= nextKeyGeneration {
			if binding.KeyGeneration >= environmente2ee.MaximumContractInteger {
				return TransitionResult{}, ErrIntegrity
			}
			nextKeyGeneration = int64(binding.KeyGeneration) + 1
		}
	}
	if nextKeyGeneration != preparation.KeyGeneration {
		if err := manager.Store.UpdateEnvironmentDestructiveResetKeyGeneration(manager.Issuer, manager.AccountID, manager.SubjectID, handle, nextKeyGeneration); err != nil {
			return TransitionResult{}, err
		}
		preparation.KeyGeneration = nextKeyGeneration
	}
	identity, err := manager.Store.LoadConfirmedEnvironmentDestructiveResetIdentity(manager.Issuer, manager.AccountID, manager.SubjectID, handle)
	if err != nil {
		return TransitionResult{}, err
	}
	defer identity.Clear()
	bindings, err := buildDestructiveResetBindings(current, identity, manager.SubjectID, endpointCertificate, subjectGeneration, rootID, rootPrivate, now)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clearBindingBytes(bindings)
	operationID, operation, err := newOperationID(manager.randomSource())
	if err != nil {
		return TransitionResult{}, err
	}
	previous := current.ID
	resetScopes := make([]environmente2ee.ResetScope, 0, len(inventory.Scopes))
	for _, scope := range inventory.Scopes {
		if scope.Scope == api.EnvironmentVariableScopeGlobal {
			resetScopes = append(resetScopes, environmente2ee.ResetScope{Scope: environmente2ee.ScopeGlobal})
		} else if scope.MachineID != nil {
			resetScopes = append(resetScopes, environmente2ee.ResetScope{Scope: environmente2ee.ScopeMachine, MachineID: *scope.MachineID})
		}
	}
	sort.Slice(resetScopes, func(i, j int) bool {
		if resetScopes[i].Scope != resetScopes[j].Scope {
			return resetScopes[i].Scope < resetScopes[j].Scope
		}
		return resetScopes[i].MachineID < resetScopes[j].MachineID
	})
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: manager.AccountID, Generation: current.Generation + 1, PreviousID: &previous,
		OperationID: operation, BindingBytes: bindings, ResetScopes: resetScopes,
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
	draft = newPendingTransition(manager, "start", &current, proposed, authorityETag)
	draft.Start = &start
	draft.DestructiveReset = true
	draft.DestructiveResetConfirmed = true
	draft.DestructiveResetHandle = handle
	draft.DestructiveResetInventory = cloneDestructiveResetInventory(inventory.Scopes)
	if err := manager.storePendingTransition(draft); err != nil {
		return TransitionResult{}, err
	}
	return manager.resumeAuthorityTransitionLocked(ctx, client, draft)
}

// ResetEnvironment is the concise alias used by higher-level callers.
func (manager Manager) ResetEnvironment(ctx context.Context, endpointCertificate []byte, subjectGeneration int64, inventory api.EnvironmentScopeInventory, confirmation string, now time.Time) (TransitionResult, error) {
	return manager.StartDestructiveReset(ctx, endpointCertificate, subjectGeneration, inventory, confirmation, now)
}

func buildDestructiveResetBindings(current environmente2ee.Authority, identity config.EnvironmentManagerIdentity, subjectID string, endpointCertificate []byte, subjectGeneration int64, rootID string, rootPrivate ed25519.PrivateKey, now time.Time) ([][]byte, error) {
	if len(endpointCertificate) == 0 || subjectGeneration < 1 {
		return nil, ErrIntegrity
	}
	result := make([][]byte, 0, len(current.Bindings)+2)
	for _, binding := range current.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectHost {
			result = append(result, append([]byte(nil), binding.Raw...))
		}
	}
	signing := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signing)
	signingPublic := append(ed25519.PublicKey(nil), signing.Public().(ed25519.PublicKey)...)
	defer clear(signingPublic)
	signingID, err := environmente2ee.KeyIDEd25519(signingPublic)
	if err != nil {
		clearBindingBytes(result)
		return nil, ErrIntegrity
	}
	recipient, err := ecdhPrivatePublic(identity.RecipientPrivate[:])
	if err != nil {
		clearBindingBytes(result)
		return nil, ErrIntegrity
	}
	recipientPublic, recipientID := recipient.public, recipient.id
	defer clear(recipientPublic)
	managerBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: current.AccountID, SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: subjectID,
		SubjectGeneration: uint64(subjectGeneration), KeyGeneration: uint64(identity.KeyGeneration),
		EndpointCertificate: append([]byte(nil), endpointCertificate...), SigningPublic: signingPublic,
		SigningKeyID: signingID, RecipientPublic: recipientPublic, RecipientKeyID: recipientID,
		NotBefore: uint64(now.UTC().Unix()), Serial: uint64(now.UTC().Unix()),
	}, rootID, rootPrivate)
	if err != nil {
		clearBindingBytes(result)
		return nil, ErrIntegrity
	}
	result = append(result, managerBinding)
	recoveryPublic := append([]byte(nil), identity.RecoveryPublic[:]...)
	defer clear(recoveryPublic)
	recoveryID, err := environmente2ee.KeyIDX25519(recoveryPublic)
	if err != nil {
		clearBindingBytes(result)
		return nil, ErrIntegrity
	}
	recoveryBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: current.AccountID, SubjectKind: environmente2ee.SubjectRecovery, SubjectID: "environment_recovery",
		SubjectGeneration: 1, KeyGeneration: 1, RecipientPublic: recoveryPublic,
		RecipientKeyID: recoveryID, NotBefore: uint64(now.UTC().Unix()), Serial: uint64(now.UTC().Unix()),
	}, rootID, rootPrivate)
	if err != nil {
		clearBindingBytes(result)
		return nil, ErrIntegrity
	}
	return append(result, recoveryBinding), nil
}

type resetRecipientPublic struct {
	public []byte
	id     string
}

func ecdhPrivatePublic(private []byte) (resetRecipientPublic, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return resetRecipientPublic{}, err
	}
	public := key.PublicKey().Bytes()
	id, err := environmente2ee.KeyIDX25519(public)
	if err != nil {
		clear(public)
		return resetRecipientPublic{}, err
	}
	return resetRecipientPublic{public: public, id: id}, nil
}

func resetInventoryMatchesAuthority(scopes []api.EnvironmentScopeMetadata, authority environmente2ee.Authority) error {
	if !validDestructiveResetInventory(scopes) {
		return ErrDestructiveResetInventoryChanged
	}
	machines := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		if scope.Scope == api.EnvironmentVariableScopeMachine && scope.MachineID != nil {
			machines[*scope.MachineID] = scope.ScopeState
		}
	}
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectHost {
			state, ok := machines[binding.SubjectID]
			if !ok || state != "active" {
				return ErrDestructiveResetInventoryChanged
			}
			delete(machines, binding.SubjectID)
		}
	}
	for machineID, state := range machines {
		if state == "active" || authorityHasHost(authority, machineID) {
			return ErrDestructiveResetInventoryChanged
		}
	}
	return nil
}

func cloneDestructiveResetInventory(scopes []api.EnvironmentScopeMetadata) []api.EnvironmentScopeMetadata {
	result := make([]api.EnvironmentScopeMetadata, len(scopes))
	for index, scope := range scopes {
		result[index] = scope
		if scope.MachineID != nil {
			machineID := *scope.MachineID
			result[index].MachineID = &machineID
		}
		result[index].Names = append([]string(nil), scope.Names...)
	}
	return result
}

func clearBindingBytes(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}
