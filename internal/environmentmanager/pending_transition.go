package environmentmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

const pendingTransitionSchema = "paperboat.environment-pending-authority-transition/v1"
const maximumPendingTransitionBytes = int64(environmente2ee.MaximumHosts+1) * int64(2*environmente2ee.MaximumManifestBytes)

var ErrPendingTransitionReconciled = errors.New("a previous ENV authority transition was reconciled")

type pendingTransitionManifest struct {
	Scope           string                            `json:"scope"`
	MachineID       string                            `json:"machine_id,omitempty"`
	ExpectedVersion int64                             `json:"expected_version"`
	ExpectedETag    string                            `json:"expected_etag,omitempty"`
	Request         api.EnvironmentTransitionManifest `json:"request"`
}

type pendingTransition struct {
	Schema                    string                              `json:"schema"`
	AccountID                 string                              `json:"account_id"`
	SubjectID                 string                              `json:"subject_id"`
	Kind                      string                              `json:"kind"`
	TransitionID              string                              `json:"transition_id"`
	ProposedGeneration        int64                               `json:"proposed_generation"`
	CurrentAuthority          string                              `json:"current_authority,omitempty"`
	ProposedAuthority         string                              `json:"proposed_authority"`
	AuthorityETag             string                              `json:"authority_etag,omitempty"`
	RequestID                 string                              `json:"request_id,omitempty"`
	Approval                  *api.EnvironmentKeyApproval         `json:"approval,omitempty"`
	Start                     *api.EnvironmentAuthorityTransition `json:"start,omitempty"`
	RequiredScopes            []string                            `json:"required_scopes,omitempty"`
	Manifests                 []pendingTransitionManifest         `json:"manifests,omitempty"`
	RotateScopes              []ScopeRef                          `json:"rotate_scopes,omitempty"`
	ImportedRecoveryHandle    string                              `json:"imported_recovery_handle,omitempty"`
	ReplacementRecoveryHandle string                              `json:"replacement_recovery_handle,omitempty"`
	DestructiveReset          bool                                `json:"destructive_reset,omitempty"`
	DestructiveResetConfirmed bool                                `json:"destructive_reset_confirmed,omitempty"`
	DestructiveResetHandle    string                              `json:"destructive_reset_handle,omitempty"`
	DestructiveResetInventory []api.EnvironmentScopeMetadata      `json:"destructive_reset_inventory,omitempty"`
}

func (manager Manager) transitionPath() (string, error) {
	root := filepath.Clean(manager.Store.Path)
	if !filepath.IsAbs(root) || root == "." || root == string(filepath.Separator) {
		return "", errors.New("ENV transition state directory is invalid")
	}
	directory := filepath.Join(root, "environment-operations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create ENV transition state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("ENV transition state directory is not private")
	}
	digest := documentDigestText(manager.AccountID + "\x00" + manager.SubjectID + "\x00authority-transition")
	return filepath.Join(directory, "transition-"+digest+".json"), nil
}

func (manager Manager) storePendingTransition(value pendingTransition) error {
	if err := validatePendingTransition(value, manager.AccountID, manager.SubjectID); err != nil {
		return err
	}
	path, err := manager.transitionPath()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil || int64(len(raw)) > maximumPendingTransitionBytes {
		clear(raw)
		return errors.New("pending ENV transition is too large")
	}
	defer clear(raw)
	return atomicfile.Write(path, raw, atomicfile.CurrentOwnerOptions(0o600))
}

func (manager Manager) loadPendingTransition() (pendingTransition, bool, error) {
	path, err := manager.transitionPath()
	if err != nil {
		return pendingTransition{}, false, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return pendingTransition{}, false, nil
	}
	if err != nil {
		return pendingTransition{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumPendingTransitionBytes {
		return pendingTransition{}, false, errors.New("pending ENV transition file is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPendingTransitionBytes+1))
	if err != nil || int64(len(raw)) > maximumPendingTransitionBytes {
		clear(raw)
		return pendingTransition{}, false, errors.New("pending ENV transition file is invalid")
	}
	defer clear(raw)
	var value pendingTransition
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || validatePendingTransition(value, manager.AccountID, manager.SubjectID) != nil {
		return pendingTransition{}, false, errors.New("pending ENV transition file is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytesEqual(canonical, raw) {
		clear(canonical)
		return pendingTransition{}, false, errors.New("pending ENV transition file is invalid")
	}
	clear(canonical)
	return value, true, nil
}

func (manager Manager) deletePendingTransition() error {
	path, err := manager.transitionPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncMutationDirectory(filepath.Dir(path))
}

// ResumeAuthorityTransition retries only the exact persisted start/approval
// and encrypted scope envelopes. It never regenerates cryptographic bytes.
func (manager Manager) ResumeAuthorityTransition(ctx context.Context) (result TransitionResult, resultErr error) {
	client, ok := manager.Client.(EnrollmentControlPlane)
	if !ok || ctx == nil {
		return TransitionResult{}, errors.New("ENV transition manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return TransitionResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	draft, found, err := manager.loadPendingTransition()
	if err != nil {
		return TransitionResult{}, err
	}
	if !found {
		return TransitionResult{}, ErrTransitionIncomplete
	}
	return manager.resumeAuthorityTransitionLocked(ctx, client, draft)
}

func (manager Manager) resumeAuthorityTransitionLocked(ctx context.Context, client EnrollmentControlPlane, draft pendingTransition) (TransitionResult, error) {
	if draft.DestructiveReset && !draft.DestructiveResetConfirmed {
		return TransitionResult{}, ErrDestructiveResetConfirmationRequired
	}
	// A destructive reset is permitted to touch only the exact metadata set
	// the operator reviewed. Re-fetch it before any transition lookup/start or
	// scope staging so a crash/resume cannot proceed against changed state.
	if draft.DestructiveReset {
		inventory, err := client.GetEnvironmentScopeInventory(ctx)
		if err != nil {
			return TransitionResult{}, err
		}
		if !destructiveResetInventoryEqual(inventory.Scopes, draft.DestructiveResetInventory) {
			return TransitionResult{}, ErrDestructiveResetInventoryChanged
		}
	}
	current, proposed, err := manager.verifyPendingTransitionAuthorities(draft)
	if err != nil {
		return TransitionResult{}, err
	}
	defer clearAuthority(&proposed)
	if current != nil {
		defer clearAuthority(current)
	}
	state, err := client.GetEnvironmentAuthorityTransition(ctx, draft.TransitionID)
	if err != nil && !isMissingEnvironmentResource(err) {
		return TransitionResult{}, err
	}
	if err != nil {
		if draft.Kind == "approval" {
			state, err = client.ApproveEnvironmentKeyEnrollment(ctx, draft.RequestID, draft.AuthorityETag, *draft.Approval)
		} else {
			state, err = client.StartEnvironmentAuthorityTransition(ctx, draft.AuthorityETag, *draft.Start)
		}
		if err != nil {
			return TransitionResult{}, err
		}
	}
	if draft.DestructiveReset && !destructiveResetStateMatchesInventory(state, draft.DestructiveResetInventory) {
		return TransitionResult{}, ErrDestructiveResetInventoryChanged
	}
	if !transitionMatchesDraft(state, draft) {
		return TransitionResult{}, ErrIntegrity
	}
	transitionOperationID := ""
	if draft.Approval != nil {
		transitionOperationID = draft.Approval.OperationID
	} else if draft.Start != nil {
		transitionOperationID = draft.Start.OperationID
	}
	legacyManifestOperations := false
	for _, manifest := range draft.Manifests {
		if manifest.Request.OperationID != transitionOperationID {
			legacyManifestOperations = true
			break
		}
	}
	if legacyManifestOperations {
		if len(state.StagedScopes) != 0 {
			return TransitionResult{}, ErrIntegrity
		}
		clearPendingTransitionManifests(draft.Manifests)
		draft.Manifests = nil
		draft.RequiredScopes = nil
	}
	if len(draft.Manifests) > 0 {
		if state.State == "active" {
			if err := manager.verifyActivatedPendingManifests(ctx, draft, proposed); err != nil {
				return TransitionResult{}, err
			}
		} else if err := manager.verifyPendingTransitionManifests(ctx, draft, current, proposed); err != nil {
			return TransitionResult{}, err
		}
	}
	if len(draft.Manifests) == 0 {
		var buildErr error
		draft, buildErr = manager.buildPendingTransitionManifests(ctx, state, draft)
		if buildErr != nil {
			return TransitionResult{}, buildErr
		}
		if err := manager.storePendingTransition(draft); err != nil {
			return TransitionResult{}, err
		}
	}
	for _, manifest := range draft.Manifests {
		if scopeIsStaged(state.StagedScopes, manifest.Scope) {
			continue
		}
		state, err = client.StageEnvironmentTransitionManifest(ctx, draft.TransitionID, manifest.MachineID, manifest.ExpectedETag, manifest.Request)
		if err != nil {
			return TransitionResult{}, err
		}
		if !transitionMatchesDraft(state, draft) {
			return TransitionResult{}, ErrIntegrity
		}
	}
	if state.State != "active" {
		state, err = client.GetEnvironmentAuthorityTransition(ctx, draft.TransitionID)
		if err != nil {
			return TransitionResult{}, err
		}
	}
	if !transitionMatchesDraft(state, draft) || state.State != "active" {
		return transitionResult(state), ErrTransitionIncomplete
	}
	if draft.DestructiveReset {
		if err := manager.Store.CommitEnvironmentDestructiveResetIdentity(manager.Issuer, manager.AccountID, manager.SubjectID, draft.DestructiveResetHandle, draft.ProposedGeneration, draft.TransitionID); err != nil {
			return TransitionResult{}, err
		}
	} else {
		if err := manager.Store.CommitEnvironmentAuthorityHighWater(manager.Issuer, manager.AccountID, manager.SubjectID, draft.ProposedGeneration, draft.TransitionID); err != nil {
			return TransitionResult{}, err
		}
	}
	if draft.ImportedRecoveryHandle != "" {
		if err := manager.Store.CompleteEnvironmentRecoveryRotation(manager.Issuer, manager.AccountID, draft.ImportedRecoveryHandle, draft.ReplacementRecoveryHandle); err != nil {
			return TransitionResult{}, err
		}
	}
	if err := manager.deletePendingTransition(); err != nil {
		return TransitionResult{}, err
	}
	return transitionResult(state), nil
}

func (manager Manager) verifyActivatedPendingManifests(ctx context.Context, draft pendingTransition, proposed environmente2ee.Authority) error {
	for _, item := range draft.Manifests {
		state, err := manager.Client.GetEnvironmentManifest(ctx, item.MachineID)
		if err != nil || state.Envelope != item.Request.Envelope || state.Version != item.ExpectedVersion+1 {
			return ErrIntegrity
		}
		raw, err := decodeBase64(state.Envelope, environmente2ee.MaximumManifestBytes)
		if err != nil {
			return ErrIntegrity
		}
		manifest, parseErr := environmente2ee.ParseManifest(raw, proposed)
		clear(raw)
		if parseErr != nil || !manifestMatchesState(manifest, state, item.MachineID, manager.AccountID) {
			clearManifest(&manifest)
			return ErrIntegrity
		}
		clearManifest(&manifest)
	}
	return nil
}

func (manager Manager) verifyPendingTransitionAuthorities(draft pendingTransition) (*environmente2ee.Authority, environmente2ee.Authority, error) {
	roots, err := manager.localRoots()
	if err != nil {
		return nil, environmente2ee.Authority{}, err
	}
	defer clearRoots(roots)
	proposedRaw, err := decodeBase64(draft.ProposedAuthority, environmente2ee.MaximumAuthorityBytes)
	if err != nil {
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	defer clear(proposedRaw)
	proposed, err := environmente2ee.ParseAuthority(proposedRaw, roots)
	if err != nil || proposed.AccountID != manager.AccountID || proposed.ID.String() != draft.TransitionID || int64(proposed.Generation) != draft.ProposedGeneration {
		clearAuthority(&proposed)
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	requestAuthority := ""
	if draft.Start != nil {
		requestAuthority = draft.Start.Authority
	}
	if draft.Approval != nil {
		requestAuthority = draft.Approval.Authority
	}
	if requestAuthority != draft.ProposedAuthority {
		clearAuthority(&proposed)
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	if draft.CurrentAuthority == "" {
		if environmente2ee.ValidateAuthorityTransition(nil, proposed) != nil || draft.Approval == nil || draft.Approval.ExpectedAuthorityID != nil {
			clearAuthority(&proposed)
			return nil, environmente2ee.Authority{}, ErrIntegrity
		}
		return nil, proposed, nil
	}
	currentRaw, err := decodeBase64(draft.CurrentAuthority, environmente2ee.MaximumAuthorityBytes)
	if err != nil {
		clearAuthority(&proposed)
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	defer clear(currentRaw)
	current, err := environmente2ee.ParseAuthority(currentRaw, roots)
	if err != nil || current.AccountID != manager.AccountID || environmente2ee.ValidateAuthorityTransition(&current, proposed) != nil {
		clearAuthority(&current)
		clearAuthority(&proposed)
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	if draft.Start != nil && draft.Start.ExpectedAuthorityID != current.ID.String() || draft.Approval != nil && (draft.Approval.ExpectedAuthorityID == nil || *draft.Approval.ExpectedAuthorityID != current.ID.String()) {
		clearAuthority(&current)
		clearAuthority(&proposed)
		return nil, environmente2ee.Authority{}, ErrIntegrity
	}
	return &current, proposed, nil
}

func (manager Manager) verifyPendingTransitionManifests(ctx context.Context, draft pendingTransition, current *environmente2ee.Authority, proposed environmente2ee.Authority) error {
	for _, item := range draft.Manifests {
		raw, err := decodeBase64(item.Request.Envelope, environmente2ee.MaximumManifestBytes)
		if err != nil {
			return ErrIntegrity
		}
		next, parseErr := environmente2ee.ParseManifest(raw, proposed)
		clear(raw)
		if parseErr != nil || int64(next.Version) != item.ExpectedVersion+1 || next.MachineID != item.MachineID || next.Scope == environmente2ee.ScopeGlobal != (item.MachineID == "") {
			clearManifest(&next)
			return ErrIntegrity
		}
		var old *environmente2ee.Manifest
		if current != nil {
			state, getErr := manager.Client.GetEnvironmentManifest(ctx, item.MachineID)
			if getErr != nil {
				if !isMissingEnvironmentResource(getErr) {
					clearManifest(&next)
					return getErr
				}
			} else {
				oldRaw, decodeErr := decodeBase64(state.Envelope, environmente2ee.MaximumManifestBytes)
				if decodeErr != nil {
					clearManifest(&next)
					return ErrIntegrity
				}
				parsed, oldErr := environmente2ee.ParseManifest(oldRaw, *current)
				clear(oldRaw)
				if oldErr != nil || !manifestMatchesState(parsed, state, item.MachineID, manager.AccountID) || state.Version != item.ExpectedVersion || state.ETag != item.ExpectedETag {
					clearManifest(&parsed)
					clearManifest(&next)
					return ErrIntegrity
				}
				old = &parsed
			}
		}
		if environmente2ee.ValidateManifestTransition(old, next, current, proposed) != nil {
			if old != nil {
				clearManifest(old)
			}
			clearManifest(&next)
			return ErrIntegrity
		}
		if old != nil {
			clearManifest(old)
		}
		clearManifest(&next)
	}
	return nil
}

func (manager Manager) buildPendingTransitionManifests(ctx context.Context, state api.EnvironmentAuthorityTransitionState, draft pendingTransition) (pendingTransition, error) {
	roots, err := manager.localRoots()
	if err != nil {
		return draft, err
	}
	defer clearRoots(roots)
	proposedRaw, err := decodeBase64(draft.ProposedAuthority, environmente2ee.MaximumAuthorityBytes)
	if err != nil {
		return draft, ErrIntegrity
	}
	defer clear(proposedRaw)
	proposed, err := environmente2ee.ParseAuthority(proposedRaw, roots)
	if err != nil || proposed.ID.String() != draft.TransitionID {
		clearAuthority(&proposed)
		return draft, ErrIntegrity
	}
	defer clearAuthority(&proposed)
	var current *environmente2ee.Authority
	if draft.CurrentAuthority != "" {
		currentRaw, decodeErr := decodeBase64(draft.CurrentAuthority, environmente2ee.MaximumAuthorityBytes)
		if decodeErr != nil {
			return draft, ErrIntegrity
		}
		parsed, parseErr := environmente2ee.ParseAuthority(currentRaw, roots)
		clear(currentRaw)
		if parseErr != nil || environmente2ee.ValidateAuthorityTransition(&parsed, proposed) != nil {
			clearAuthority(&parsed)
			return draft, ErrIntegrity
		}
		current = &parsed
		defer clearAuthority(current)
	} else if environmente2ee.ValidateAuthorityTransition(nil, proposed) != nil {
		return draft, ErrIntegrity
	}
	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if draft.DestructiveReset {
		identity, err = manager.Store.LoadConfirmedEnvironmentDestructiveResetIdentity(manager.Issuer, manager.AccountID, manager.SubjectID, draft.DestructiveResetHandle)
	}
	if err != nil {
		return draft, err
	}
	defer identity.Clear()
	recipient, err := managerRecipient(identity, manager.SubjectID)
	if draft.ImportedRecoveryHandle != "" {
		clear(recipient.PrivateKey)
		imported, loadErr := manager.Store.LoadEnvironmentRecoveryTemporary(manager.Issuer, manager.AccountID, draft.ImportedRecoveryHandle)
		if loadErr != nil {
			return draft, loadErr
		}
		defer clear(imported[:])
		binding, bindingErr := recoveryBindingForPrivate(*current, imported[:])
		if bindingErr != nil {
			return draft, bindingErr
		}
		recipient = environmente2ee.RecipientPrivate{Kind: environmente2ee.RecipientRecovery, SubjectID: binding.SubjectID, KeyGeneration: binding.KeyGeneration, KeyID: binding.RecipientKeyID, PrivateKey: append([]byte(nil), imported[:]...)}
	} else if err != nil && current != nil {
		return draft, ErrNoDecryptingKey
	}
	defer clear(recipient.PrivateKey)
	signer := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signer)
	signerID, err := environmente2ee.KeyIDEd25519(signer.Public().(ed25519.PublicKey))
	if err != nil || !authorityHasSigner(proposed, manager.SubjectID, uint64(identity.KeyGeneration), signerID) {
		return draft, ErrKeyAuthorizationRequired
	}
	transitionOperationID := ""
	if draft.Approval != nil {
		transitionOperationID = draft.Approval.OperationID
	} else if draft.Start != nil {
		transitionOperationID = draft.Start.OperationID
	}
	operation, err := parseOperationID(transitionOperationID)
	if err != nil {
		return draft, ErrIntegrity
	}
	rotations := append([]ScopeRef(nil), draft.RotateScopes...)
	if draft.ImportedRecoveryHandle != "" {
		for _, name := range state.RequiredScopes {
			machineID, valid := transitionScopeMachineID(name)
			if !valid {
				return draft, ErrIntegrity
			}
			if machineID == "" {
				rotations = append(rotations, ScopeRef{Scope: environmente2ee.ScopeGlobal})
			} else {
				rotations = append(rotations, ScopeRef{Scope: environmente2ee.ScopeMachine, MachineID: machineID})
			}
		}
	}
	manifests := make([]pendingTransitionManifest, 0, len(state.RequiredScopes))
	for _, scopeName := range state.RequiredScopes {
		machineID, valid := transitionScopeMachineID(scopeName)
		if !valid {
			clearPendingTransitionManifests(manifests)
			return draft, ErrIntegrity
		}
		var old *environmente2ee.Manifest
		var oldState api.EnvironmentManifestState
		if current != nil {
			oldState, err = manager.Client.GetEnvironmentManifest(ctx, machineID)
			if err != nil {
				if !isMissingEnvironmentResource(err) {
					return draft, err
				}
			} else {
				raw, decodeErr := decodeBase64(oldState.Envelope, environmente2ee.MaximumManifestBytes)
				if decodeErr != nil {
					return draft, ErrIntegrity
				}
				parsed, parseErr := environmente2ee.ParseManifest(raw, *current)
				clear(raw)
				if parseErr != nil || !manifestMatchesState(parsed, oldState, machineID, manager.AccountID) {
					clearManifest(&parsed)
					return draft, ErrIntegrity
				}
				if draft.DestructiveReset {
					metadata, metadataOK := destructiveResetScopeMetadata(draft.DestructiveResetInventory, scopeName)
					if !metadataOK || int64(parsed.Version) != metadata.Version || int64(parsed.KeyEpoch) != metadata.KeyEpoch || parsed.ID.String() != metadata.ManifestID || !equalStringSlices(parsed.Names, metadata.Names) {
						clearManifest(&parsed)
						return draft, ErrDestructiveResetInventoryChanged
					}
				}
				old = &parsed
			}
		}
		expectedVersion, etag := int64(0), ""
		if old != nil {
			expectedVersion, etag = int64(old.Version), oldState.ETag
		}
		raw, buildErr := manager.buildTransitionManifest(old, current, proposed, recipient, signerID, signer, machineID, rotations, operation)
		if old != nil {
			clearManifest(old)
		}
		if buildErr != nil {
			clearPendingTransitionManifests(manifests)
			return draft, buildErr
		}
		manifests = append(manifests, pendingTransitionManifest{Scope: scopeName, MachineID: machineID, ExpectedVersion: expectedVersion, ExpectedETag: etag, Request: api.EnvironmentTransitionManifest{Schema: api.EnvironmentTransitionManifestSchemaV1, ExpectedVersion: expectedVersion, OperationID: transitionOperationID, Envelope: base64.RawURLEncoding.EncodeToString(raw)}})
		clear(raw)
	}
	draft.RequiredScopes = append([]string(nil), state.RequiredScopes...)
	draft.Manifests = manifests
	return draft, nil
}

func validatePendingTransition(value pendingTransition, accountID, subjectID string) error {
	if value.Schema != pendingTransitionSchema || value.AccountID != accountID || value.SubjectID != subjectID || !documentIDPattern.MatchString(value.TransitionID) || value.ProposedGeneration < 1 || value.ProposedAuthority == "" || value.Kind != "start" && value.Kind != "approval" {
		return errors.New("pending ENV transition is invalid")
	}
	if value.Kind == "start" != (value.Start != nil) || value.Kind == "approval" != (value.Approval != nil) || value.Kind == "approval" && value.RequestID == "" {
		return errors.New("pending ENV transition request is invalid")
	}
	if (value.ImportedRecoveryHandle == "") != (value.ReplacementRecoveryHandle == "") {
		return errors.New("pending ENV recovery transition is invalid")
	}
	if value.DestructiveReset {
		if value.Kind != "start" || value.DestructiveResetHandle == "" || len(value.DestructiveResetInventory) == 0 || value.ImportedRecoveryHandle != "" || len(value.RotateScopes) != 0 {
			return errors.New("pending ENV destructive reset is invalid")
		}
		if !validDestructiveResetInventory(value.DestructiveResetInventory) {
			return errors.New("pending ENV destructive reset inventory is invalid")
		}
	} else if value.DestructiveResetConfirmed || value.DestructiveResetHandle != "" || len(value.DestructiveResetInventory) != 0 {
		return errors.New("pending ENV transition has unexpected destructive reset state")
	}
	if len(value.RequiredScopes) != len(value.Manifests) && len(value.Manifests) != 0 {
		return errors.New("pending ENV transition scopes are incomplete")
	}
	if len(value.Manifests) > environmente2ee.MaximumHosts+1 {
		return errors.New("pending ENV transition has too many scopes")
	}
	for index, scope := range value.RotateScopes {
		if scope.Scope != environmente2ee.ScopeGlobal && scope.Scope != environmente2ee.ScopeMachine || scope.Scope == environmente2ee.ScopeGlobal && scope.MachineID != "" || scope.Scope == environmente2ee.ScopeMachine && scope.MachineID == "" {
			return errors.New("pending ENV transition rotation scope is invalid")
		}
		if index > 0 && value.RotateScopes[index-1] == scope {
			return errors.New("pending ENV transition rotation scope is duplicated")
		}
	}
	if len(value.Manifests) > 0 {
		if !sort.StringsAreSorted(value.RequiredScopes) {
			return errors.New("pending ENV transition scopes are not canonical")
		}
		for index, manifest := range value.Manifests {
			if manifest.Scope != value.RequiredScopes[index] || manifest.Request.Schema != api.EnvironmentTransitionManifestSchemaV1 || manifest.Request.ExpectedVersion != manifest.ExpectedVersion || !operationIDPattern.MatchString(manifest.Request.OperationID) || manifest.Request.Envelope == "" {
				return errors.New("pending ENV transition manifest is invalid")
			}
			if manifest.Scope == "g" != (manifest.MachineID == "") {
				return errors.New("pending ENV transition scope is invalid")
			}
		}
	}
	return nil
}

func transitionScopeMachineID(scopeKey string) (string, bool) {
	if scopeKey == "g" {
		return "", true
	}
	if !strings.HasPrefix(scopeKey, "m:") {
		return "", false
	}
	machineID := strings.TrimPrefix(scopeKey, "m:")
	return machineID, destructiveResetIdentifierPattern.MatchString(machineID)
}

func newPendingTransition(manager Manager, kind string, current *environmente2ee.Authority, proposed environmente2ee.Authority, authorityETag string) pendingTransition {
	draft := pendingTransition{
		Schema: pendingTransitionSchema, AccountID: manager.AccountID, SubjectID: manager.SubjectID,
		Kind: kind, TransitionID: proposed.ID.String(), ProposedGeneration: int64(proposed.Generation),
		ProposedAuthority: base64.RawURLEncoding.EncodeToString(proposed.Raw), AuthorityETag: authorityETag,
	}
	if current != nil {
		draft.CurrentAuthority = base64.RawURLEncoding.EncodeToString(current.Raw)
	}
	return draft
}

func transitionMatchesDraft(state api.EnvironmentAuthorityTransitionState, draft pendingTransition) bool {
	return state.TransitionID == draft.TransitionID && state.ProposedAuthorityID == draft.TransitionID && state.ProposedGeneration == draft.ProposedGeneration
}

func scopeIsStaged(values []string, scope string) bool {
	index := sort.SearchStrings(values, scope)
	return index < len(values) && values[index] == scope
}

func isMissingEnvironmentResource(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && (apiErr.Code == "not_found" || apiErr.Code == "not_found_or_forbidden")
}

func clearPendingTransitionManifests(values []pendingTransitionManifest) {
	for index := range values {
		values[index].Request.Envelope = ""
	}
}

func documentDigestText(value string) string {
	digest := sha256Bytes([]byte(value))
	return fmt.Sprintf("%x", digest[:16])
}

func sha256Bytes(value []byte) [32]byte {
	return sha256.Sum256(value)
}
