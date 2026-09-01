package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

var (
	ErrKeyAuthorizationRequired = errors.New("ENV key authorization required")
	ErrRecoveryExportRequired   = errors.New("ENV recovery export confirmation required")
	ErrVariableNotConfigured    = errors.New("environment variable is not configured")
	ErrAuthorityFork            = errors.New("ENV authority history conflicts with local state")
	ErrIntegrity                = errors.New("ENV encrypted state failed verification")
)

type ControlPlane interface {
	GetEnvironmentAuthority(context.Context) (api.EnvironmentAuthorityState, error)
	GetEnvironmentAuthorityDocuments(context.Context, int64, string) (api.EnvironmentAuthorityPage, error)
	GetEnvironmentManifest(context.Context, string) (api.EnvironmentManifestState, error)
	PutEnvironmentManifest(context.Context, string, api.EnvironmentManifestMutation, string) (api.EnvironmentManifestState, error)
}

type Manager struct {
	Client    ControlPlane
	Store     config.ProfileStore
	Issuer    string
	AccountID string
	SubjectID string
	Random    io.Reader
}

type MutationResult struct {
	Name       string
	Version    int64
	KeyEpoch   int64
	ManifestID string
	ETag       string
}

func (manager Manager) Set(ctx context.Context, machineID, name string, value []byte) (MutationResult, error) {
	if err := validateVariable(name, value); err != nil {
		return MutationResult{}, err
	}
	return manager.mutate(ctx, strings.TrimSpace(machineID), name, value, environmente2ee.MutationSet)
}

func (manager Manager) Unset(ctx context.Context, machineID, name string) (MutationResult, error) {
	if err := validateVariableName(name); err != nil {
		return MutationResult{}, err
	}
	return manager.mutate(ctx, strings.TrimSpace(machineID), name, nil, environmente2ee.MutationUnset)
}

func (manager Manager) mutate(ctx context.Context, machineID, requestedName string, value []byte, mutation environmente2ee.MutationKind) (result MutationResult, resultErr error) {
	if ctx == nil || manager.Client == nil || strings.TrimSpace(manager.Issuer) == "" || strings.TrimSpace(manager.AccountID) == "" || strings.TrimSpace(manager.SubjectID) == "" {
		return MutationResult{}, errors.New("ENV manager is not configured")
	}
	unlock, err := manager.Store.LockEnvironmentMutations(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return MutationResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	pending, found, err := manager.loadPendingMutation(machineID)
	if err != nil {
		return MutationResult{}, err
	}
	if found {
		return manager.reconcilePendingMutation(ctx, pending)
	}
	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		if errors.Is(err, config.ErrSecretNotFound) {
			return MutationResult{}, ErrKeyAuthorizationRequired
		}
		return MutationResult{}, err
	}
	defer identity.Clear()
	if identity.RecoveryRequired && !identity.RecoveryExportConfirmed {
		return MutationResult{}, ErrRecoveryExportRequired
	}

	authority, recipient, signerID, signerPrivate, err := manager.activeAuthority(ctx, &identity)
	if err != nil {
		return MutationResult{}, err
	}
	defer clear(signerPrivate)
	defer clear(recipient.PrivateKey)
	defer clearAuthority(&authority)

	state, err := manager.Client.GetEnvironmentManifest(ctx, machineID)
	if err != nil {
		return MutationResult{}, err
	}
	manifestRaw, err := decodeBase64(state.Envelope, environmente2ee.MaximumManifestBytes)
	if err != nil {
		return MutationResult{}, ErrIntegrity
	}
	defer clear(manifestRaw)
	manifest, err := environmente2ee.ParseManifest(manifestRaw, authority)
	if err != nil || !manifestMatchesState(manifest, state, machineID, manager.AccountID) {
		return MutationResult{}, ErrIntegrity
	}
	defer clearManifest(&manifest)
	decrypted, err := environmente2ee.DecryptManifest(manifest, recipient)
	if err != nil {
		return MutationResult{}, ErrIntegrity
	}
	defer clearDecrypted(&decrypted)

	canonicalName, exists := configuredName(decrypted.Values, requestedName)
	switch mutation {
	case environmente2ee.MutationSet:
		if !exists {
			canonicalName = requestedName
		} else {
			clear(decrypted.Values[canonicalName])
		}
		decrypted.Values[canonicalName] = append([]byte(nil), value...)
	case environmente2ee.MutationUnset:
		if !exists {
			return MutationResult{}, ErrVariableNotConfigured
		}
		clear(decrypted.Values[canonicalName])
		delete(decrypted.Values, canonicalName)
	default:
		return MutationResult{}, errors.New("unsupported ENV mutation")
	}

	operationID, operationBytes, err := newOperationID(manager.randomSource())
	if err != nil {
		return MutationResult{}, err
	}
	recipients, err := authority.ExpectedRecipients(manifest.Scope, manifest.State, manifest.MachineID)
	if err != nil {
		return MutationResult{}, ErrIntegrity
	}
	claims := environmente2ee.ManifestClaims{
		AccountID:           manifest.AccountID,
		AuthorityGeneration: manifest.AuthorityGeneration,
		AuthorityID:         manifest.AuthorityID,
		Scope:               manifest.Scope,
		MachineID:           manifest.MachineID,
		State:               manifest.State,
		PreviousVersion:     manifest.Version,
		Version:             manifest.Version + 1,
		KeyEpoch:            manifest.KeyEpoch,
		OperationID:         operationBytes,
		Mutation:            mutation,
		ChangedNames:        []string{canonicalName},
	}
	nextRaw, err := environmente2ee.BuildManifest(environmente2ee.BuildManifestInput{
		Claims: claims, Values: decrypted.Values, ScopeKey: decrypted.ScopeKey,
		Recipients: recipients, SignerKeyID: signerID, SignerPrivate: signerPrivate,
		Random: manager.randomSource(),
	})
	if err != nil {
		return MutationResult{}, fmt.Errorf("build encrypted ENV manifest: %w", err)
	}
	defer clear(nextRaw)
	next, err := environmente2ee.ParseManifest(nextRaw, authority)
	if err != nil || environmente2ee.ValidateManifestTransition(&manifest, next, &authority, authority) != nil {
		return MutationResult{}, ErrIntegrity
	}
	defer clearManifest(&next)

	envelope := base64.RawURLEncoding.EncodeToString(nextRaw)
	mutationName := "set"
	if mutation == environmente2ee.MutationUnset {
		mutationName = "unset"
	}
	pending = pendingMutation{
		Schema: pendingMutationSchema, AccountID: manager.AccountID, SubjectID: manager.SubjectID,
		Scope: func() string {
			if machineID == "" {
				return "global"
			}
			return "machine"
		}(),
		MachineID: machineID, Name: canonicalName, Mutation: mutationName,
		ExpectedVersion: state.Version, ExpectedETag: state.ETag, OperationID: operationID,
		ManifestID: next.ID.String(), KeyEpoch: int64(next.KeyEpoch), Envelope: envelope,
	}
	if err := manager.storePendingMutation(pending); err != nil {
		return MutationResult{}, err
	}
	response, err := manager.Client.PutEnvironmentManifest(ctx, machineID, api.EnvironmentManifestMutation{
		Schema:          api.EnvironmentManifestMutationSchemaV1,
		ExpectedVersion: state.Version,
		OperationID:     operationID,
		Envelope:        envelope,
	}, state.ETag)
	if err != nil {
		return MutationResult{}, err
	}
	if response.ManifestID != next.ID.String() || response.Version != int64(next.Version) || response.KeyEpoch != int64(next.KeyEpoch) {
		return MutationResult{}, ErrIntegrity
	}
	if err := manager.deletePendingMutation(machineID); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Name: canonicalName, Version: response.Version, KeyEpoch: response.KeyEpoch, ManifestID: response.ManifestID, ETag: response.ETag}, nil
}

func (manager Manager) activeAuthority(ctx context.Context, identity *config.EnvironmentManagerIdentity) (environmente2ee.Authority, environmente2ee.RecipientPrivate, string, ed25519.PrivateKey, error) {
	roots, err := manager.localRoots()
	if err != nil {
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, err
	}
	defer clearRoots(roots)
	cursorGeneration, cursorID := identity.AuthorityGeneration, identity.AuthorityID
	for {
		page, err := manager.Client.GetEnvironmentAuthorityDocuments(ctx, cursorGeneration, cursorID)
		if err != nil {
			return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, err
		}
		for _, encoded := range page.AuthorityDocuments {
			raw, err := decodeBase64(encoded, environmente2ee.MaximumAuthorityBytes)
			if err != nil {
				return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrIntegrity
			}
			next, parseErr := environmente2ee.ParseAuthority(raw, roots)
			clear(raw)
			if parseErr != nil || next.AccountID != manager.AccountID || next.Generation != uint64(cursorGeneration+1) || next.PreviousID == nil != (cursorGeneration == 0) || cursorGeneration > 0 && *next.PreviousID != mustDocumentID(cursorID) {
				clearAuthority(&next)
				return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrAuthorityFork
			}
			if cursorGeneration == 0 && environmente2ee.ValidateAuthorityTransition(nil, next) != nil {
				clearAuthority(&next)
				return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrAuthorityFork
			}
			if err := manager.Store.CommitEnvironmentAuthorityHighWater(manager.Issuer, manager.AccountID, manager.SubjectID, int64(next.Generation), next.ID.String()); err != nil {
				clearAuthority(&next)
				return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, err
			}
			cursorGeneration, cursorID = int64(next.Generation), next.ID.String()
			identity.AuthorityGeneration, identity.AuthorityID = cursorGeneration, cursorID
			clearAuthority(&next)
		}
		if page.AuthorityHead.Generation < cursorGeneration || page.AuthorityHead.AuthorityID == "" || page.HasMore && len(page.AuthorityDocuments) == 0 {
			return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrAuthorityFork
		}
		if !page.HasMore {
			if page.AuthorityHead.Generation != cursorGeneration || page.AuthorityHead.AuthorityID != cursorID {
				return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrAuthorityFork
			}
			break
		}
	}

	state, err := manager.Client.GetEnvironmentAuthority(ctx)
	if err != nil {
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, err
	}
	raw, err := decodeBase64(state.Authority, environmente2ee.MaximumAuthorityBytes)
	if err != nil {
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrIntegrity
	}
	defer clear(raw)
	authority, err := environmente2ee.ParseAuthority(raw, roots)
	if err != nil || authority.AccountID != manager.AccountID || int64(authority.Generation) != cursorGeneration || authority.ID.String() != cursorID || state.Generation != cursorGeneration || state.AuthorityID != cursorID {
		clearAuthority(&authority)
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrAuthorityFork
	}

	signingPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	signerID, err := environmente2ee.KeyIDEd25519(signingPublic)
	if err != nil {
		clear(signingPrivate)
		clearAuthority(&authority)
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrIntegrity
	}
	recipientKey, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		clear(signingPrivate)
		clearAuthority(&authority)
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrIntegrity
	}
	recipientPublic := recipientKey.PublicKey().Bytes()
	recipientID, err := environmente2ee.KeyIDX25519(recipientPublic)
	if err != nil {
		clear(signingPrivate)
		clearAuthority(&authority)
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrIntegrity
	}
	authorized := false
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectManagerCLI && binding.SubjectID == manager.SubjectID && binding.KeyGeneration == uint64(identity.KeyGeneration) && binding.SigningKeyID == signerID && binding.RecipientKeyID == recipientID && bytes.Equal(binding.SigningPublic, signingPublic) && bytes.Equal(binding.RecipientPublic, recipientPublic) {
			authorized = true
			break
		}
	}
	clear(recipientPublic)
	if !authorized {
		clear(signingPrivate)
		clearAuthority(&authority)
		return environmente2ee.Authority{}, environmente2ee.RecipientPrivate{}, "", nil, ErrKeyAuthorizationRequired
	}
	recipient := environmente2ee.RecipientPrivate{Kind: environmente2ee.RecipientManager, SubjectID: manager.SubjectID, KeyGeneration: uint64(identity.KeyGeneration), KeyID: recipientID, PrivateKey: append([]byte(nil), identity.RecipientPrivate[:]...)}
	return authority, recipient, signerID, signingPrivate, nil
}

func (manager Manager) localRoots() (environmente2ee.RootKeys, error) {
	roots := environmente2ee.RootKeys{}
	public, err := manager.Store.LoadPeerAccountRootPublic(manager.Issuer, manager.AccountID)
	if err == nil {
		digest := sha256.Sum256(public)
		roots["aek_"+hex.EncodeToString(digest[:])] = public
	} else if !errors.Is(err, config.ErrSecretNotFound) {
		return nil, err
	}
	seed, seedErr := manager.Store.ExportPeerAccountRootSeed(manager.Issuer, manager.AccountID)
	if seedErr == nil {
		defer clear(seed)
		if len(seed) != ed25519.SeedSize {
			clearRoots(roots)
			return nil, ErrIntegrity
		}
		private := ed25519.NewKeyFromSeed(seed)
		owned := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
		clear(private)
		digest := sha256.Sum256(owned)
		keyID := "aek_" + hex.EncodeToString(digest[:])
		if _, exists := roots[keyID]; exists {
			clear(owned)
		} else {
			roots[keyID] = owned
		}
	} else if !errors.Is(seedErr, config.ErrSecretNotFound) {
		clearRoots(roots)
		return nil, seedErr
	}
	if len(roots) == 0 {
		return nil, config.ErrSecretNotFound
	}
	return roots, nil
}

func manifestMatchesState(manifest environmente2ee.Manifest, state api.EnvironmentManifestState, machineID, accountID string) bool {
	expectedScope := environmente2ee.ScopeGlobal
	if machineID != "" {
		expectedScope = environmente2ee.ScopeMachine
	}
	return manifest.AccountID == accountID && manifest.Scope == expectedScope && manifest.MachineID == machineID && int64(manifest.Version) == state.Version && int64(manifest.KeyEpoch) == state.KeyEpoch && manifest.ID.String() == state.ManifestID
}

func configuredName(values map[string][]byte, requested string) (string, bool) {
	for name := range values {
		if strings.EqualFold(name, requested) {
			return name, true
		}
	}
	return "", false
}

func validateVariable(name string, value []byte) error {
	if err := validateVariableName(name); err != nil {
		return err
	}
	if len(value) > environmente2ee.MaximumValueBytes {
		return errors.New("environment variable value exceeds 32767 bytes")
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return errors.New("environment variable value contains NUL")
	}
	if !utf8.Valid(value) {
		return errors.New("environment variable value must be valid UTF-8")
	}
	return nil
}

func validateVariableName(name string) error {
	if len(name) == 0 || len(name) > environmente2ee.MaximumNameBytes || !variableNamePattern.MatchString(name) {
		return errors.New("environment variable name must be 1-128 ASCII letters, numbers, or underscores and start with a letter or underscore")
	}
	upper := strings.ToUpper(name)
	if strings.HasPrefix(upper, "PAPERBOAT_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") || upper == "NODE_OPTIONS" || upper == "PYTHONPATH" || upper == "PYTHONHOME" || upper == "GOTRACEBACK" {
		return errors.New("environment variable name is reserved")
	}
	return nil
}

func (manager Manager) randomSource() io.Reader {
	if manager.Random != nil {
		return manager.Random
	}
	return rand.Reader
}

func newOperationID(random io.Reader) (string, [16]byte, error) {
	var operation [16]byte
	for attempts := 0; attempts < 2; attempts++ {
		if _, err := io.ReadFull(random, operation[:]); err != nil {
			return "", [16]byte{}, fmt.Errorf("generate ENV operation ID: %w", err)
		}
		if operation != [16]byte{} {
			return "envop_" + hex.EncodeToString(operation[:]), operation, nil
		}
	}
	return "", [16]byte{}, errors.New("generate ENV operation ID: random source returned zero")
}

func mustDocumentID(value string) environmente2ee.DocumentID {
	id, _ := environmente2ee.ParseDocumentID(value)
	return id
}

func decodeBase64(value string, maximum int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != value {
		clear(raw)
		return nil, ErrIntegrity
	}
	return raw, nil
}

func clearRoots(roots environmente2ee.RootKeys) {
	for key := range roots {
		clear(roots[key])
		delete(roots, key)
	}
}

func clearAuthority(authority *environmente2ee.Authority) {
	if authority == nil {
		return
	}
	clear(authority.Raw)
	for index := range authority.BindingBytes {
		clear(authority.BindingBytes[index])
	}
	for index := range authority.Bindings {
		clear(authority.Bindings[index].Raw)
		clear(authority.Bindings[index].EndpointCertificate)
		clear(authority.Bindings[index].SigningPublic)
		clear(authority.Bindings[index].RecipientPublic)
	}
	*authority = environmente2ee.Authority{}
}

func clearManifest(manifest *environmente2ee.Manifest) {
	if manifest == nil {
		return
	}
	clear(manifest.Raw)
	clear(manifest.Salt)
	clear(manifest.Nonce)
	clear(manifest.Ciphertext)
	for index := range manifest.Wraps {
		clear(manifest.Wraps[index].EncapsulatedKey)
		clear(manifest.Wraps[index].Ciphertext)
	}
	*manifest = environmente2ee.Manifest{}
}

func clearDecrypted(scope *environmente2ee.DecryptedScope) {
	if scope == nil {
		return
	}
	for name, value := range scope.Values {
		clear(value)
		delete(scope.Values, name)
	}
	clear(scope.ScopeKey)
	*scope = environmente2ee.DecryptedScope{}
}

var variableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
