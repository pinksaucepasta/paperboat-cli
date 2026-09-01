package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

type enrollmentWorkflowPlane struct {
	*managerControlPlane
	pending              []api.EnvironmentKeyEnrollmentState
	staged               []api.EnvironmentTransitionManifest
	etags                []string
	state                api.EnvironmentAuthorityTransitionState
	started              bool
	failStartAfterApply  bool
	failStageAfterApply  bool
	proposed             *environmente2ee.Authority
	activated            map[string]api.EnvironmentManifestState
	enrollmentCreates    []api.EnvironmentKeyEnrollmentRequest
	enrollmentProofs     int
	enrollmentState      api.EnvironmentKeyEnrollmentState
	failCreateAfterApply bool
	failProofAfterApply  bool
}

func (plane *enrollmentWorkflowPlane) GetEnvironmentManifest(ctx context.Context, machineID string) (api.EnvironmentManifestState, error) {
	if state, ok := plane.activated[machineID]; ok {
		return state, nil
	}
	return plane.managerControlPlane.GetEnvironmentManifest(ctx, machineID)
}

func (plane *enrollmentWorkflowPlane) GetEnvironmentScopeInventory(context.Context) (api.EnvironmentScopeInventory, error) {
	manifest := plane.managerControlPlane.manifest
	return api.EnvironmentScopeInventory{
		Schema: api.EnvironmentScopeInventorySchemaV1,
		Scopes: []api.EnvironmentScopeMetadata{{
			Scope: api.EnvironmentVariableScopeGlobal, ScopeState: "active",
			Version: int64(manifest.Version), KeyEpoch: int64(manifest.KeyEpoch),
			ManifestID: manifest.ID.String(), Names: append([]string{}, manifest.Names...),
		}},
	}, nil
}

func (plane *enrollmentWorkflowPlane) CreateEnvironmentKeyEnrollment(_ context.Context, value api.EnvironmentKeyEnrollmentRequest) (api.EnvironmentKeyEnrollmentState, error) {
	plane.enrollmentCreates = append(plane.enrollmentCreates, value)
	if plane.enrollmentState.RequestID == "" {
		operation, err := hex.DecodeString(strings.TrimPrefix(value.OperationID, "envop_"))
		if err != nil || len(operation) != 16 || value.SigningProof == nil || value.EndpointCertificate == nil || value.SigningPublicKey == nil || value.SigningKeyID == nil {
			return api.EnvironmentKeyEnrollmentState{}, ErrIntegrity
		}
		endpoint, e1 := base64.RawURLEncoding.Strict().DecodeString(*value.EndpointCertificate)
		signing, e2 := base64.RawURLEncoding.Strict().DecodeString(*value.SigningPublicKey)
		recipient, e3 := base64.RawURLEncoding.Strict().DecodeString(value.RecipientPublicKey)
		if e1 != nil || e2 != nil || e3 != nil {
			return api.EnvironmentKeyEnrollmentState{}, ErrIntegrity
		}
		defer clear(endpoint)
		defer clear(signing)
		defer clear(recipient)
		request := environmente2ee.EnrollmentRequest{AccountID: plane.authority.AccountID, SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: value.SubjectID, SubjectGeneration: uint64(value.SubjectGeneration), KeyGeneration: uint64(value.KeyGeneration), EndpointCertificate: endpoint, SigningPublic: ed25519.PublicKey(signing), SigningKeyID: *value.SigningKeyID, RecipientPublic: recipient, RecipientKeyID: value.RecipientKeyID, RequestExpiresAt: uint64(value.RequestExpiresAt.Unix())}
		copy(request.OperationID[:], operation)
		canonical, err := environmente2ee.CanonicalEnrollmentRequest(request)
		if err != nil {
			return api.EnvironmentKeyEnrollmentState{}, err
		}
		defer clear(canonical)
		safety, _ := environmente2ee.EnrollmentSafetyCode(request)
		digest, _ := environmente2ee.EnrollmentRequestDigest(request)
		challengeContext := environmente2ee.EnrollmentChallengeContext{AccountID: request.AccountID, RequestID: "envreq_resume_1", OperationID: request.OperationID, RecipientKeyID: request.RecipientKeyID, RequestDigest: digest}
		sealed, challenge, err := environmente2ee.SealEnrollmentChallenge(challengeContext, request.RecipientPublic, bytes.NewReader(bytes.Repeat([]byte{0x45}, 128)))
		clear(challenge)
		if err != nil {
			return api.EnvironmentKeyEnrollmentState{}, err
		}
		defer clear(sealed)
		challengeEncoded := base64.RawURLEncoding.EncodeToString(sealed)
		plane.enrollmentState = api.EnvironmentKeyEnrollmentState{Schema: api.EnvironmentKeyEnrollmentStateSchemaV1, RequestID: challengeContext.RequestID, State: "challenge", ExpiresAt: value.RequestExpiresAt, SafetyCode: safety, EnrollmentRequest: base64.RawURLEncoding.EncodeToString(canonical), SigningProof: value.SigningProof, Challenge: &challengeEncoded}
	}
	if plane.failCreateAfterApply {
		plane.failCreateAfterApply = false
		return api.EnvironmentKeyEnrollmentState{}, errors.New("connection reset after enrollment create")
	}
	return plane.enrollmentState, nil
}
func (plane *enrollmentWorkflowPlane) SubmitEnvironmentKeyEnrollmentProof(context.Context, string, string, api.EnvironmentKeyEnrollmentProof) (api.EnvironmentKeyEnrollmentState, error) {
	plane.enrollmentProofs++
	pending := plane.enrollmentState
	pending.State, pending.Challenge = "pending", nil
	plane.enrollmentState = pending
	if plane.failProofAfterApply {
		plane.failProofAfterApply = false
		return api.EnvironmentKeyEnrollmentState{}, errors.New("connection reset after enrollment proof")
	}
	return pending, nil
}
func (plane *enrollmentWorkflowPlane) ListPendingEnvironmentKeyEnrollments(context.Context) ([]api.EnvironmentKeyEnrollmentState, error) {
	return append([]api.EnvironmentKeyEnrollmentState(nil), plane.pending...), nil
}
func (plane *enrollmentWorkflowPlane) ApproveEnvironmentKeyEnrollment(context.Context, string, string, api.EnvironmentKeyApproval) (api.EnvironmentAuthorityTransitionState, error) {
	return plane.startTransition()
}
func (plane *enrollmentWorkflowPlane) StartEnvironmentAuthorityTransition(context.Context, string, api.EnvironmentAuthorityTransition) (api.EnvironmentAuthorityTransitionState, error) {
	return plane.startTransition()
}
func (plane *enrollmentWorkflowPlane) GetEnvironmentAuthorityTransition(context.Context, string) (api.EnvironmentAuthorityTransitionState, error) {
	if !plane.started {
		return api.EnvironmentAuthorityTransitionState{}, &api.APIError{Status: 404, Code: "not_found_or_forbidden", Message: "missing"}
	}
	return plane.state, nil
}
func (plane *enrollmentWorkflowPlane) StageEnvironmentTransitionManifest(_ context.Context, _ string, _ string, etag string, manifest api.EnvironmentTransitionManifest) (api.EnvironmentAuthorityTransitionState, error) {
	plane.staged = append(plane.staged, manifest)
	plane.etags = append(plane.etags, etag)
	for _, scope := range plane.state.RequiredScopes {
		if manifest.ExpectedVersion == int64(plane.managerControlPlane.manifest.Version) || manifest.ExpectedVersion == 0 {
			if !scopeIsStaged(plane.state.StagedScopes, scope) {
				plane.state.StagedScopes = append(plane.state.StagedScopes, scope)
				sort.Strings(plane.state.StagedScopes)
			}
			break
		}
	}
	if len(plane.state.StagedScopes) == len(plane.state.RequiredScopes) {
		plane.state.State = "active"
		if plane.proposed != nil {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(manifest.Envelope)
			if err != nil {
				return api.EnvironmentAuthorityTransitionState{}, err
			}
			parsed, err := environmente2ee.ParseManifest(raw, *plane.proposed)
			clear(raw)
			if err != nil {
				return api.EnvironmentAuthorityTransitionState{}, err
			}
			if plane.activated == nil {
				plane.activated = make(map[string]api.EnvironmentManifestState)
			}
			plane.activated[parsed.MachineID] = manifestState(parsed)
			clearManifest(&parsed)
		}
	}
	if plane.failStageAfterApply {
		plane.failStageAfterApply = false
		return api.EnvironmentAuthorityTransitionState{}, errors.New("connection reset after transition scope apply")
	}
	return plane.state, nil
}
func (*enrollmentWorkflowPlane) AbortEnvironmentAuthorityTransition(context.Context, string, api.EnvironmentAuthorityTransitionAbort) (api.EnvironmentAuthorityTransitionState, error) {
	return api.EnvironmentAuthorityTransitionState{}, errors.New("not used")
}

func (plane *enrollmentWorkflowPlane) startTransition() (api.EnvironmentAuthorityTransitionState, error) {
	plane.started = true
	if plane.failStartAfterApply {
		plane.failStartAfterApply = false
		return api.EnvironmentAuthorityTransitionState{}, errors.New("connection reset after transition start")
	}
	return plane.state, nil
}

func TestPendingCiphertextArtifactContainsNoPlaintext(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	manager := Manager{
		Client: fixture.control, Store: fixture.store, Issuer: fixture.issuer,
		AccountID: fixture.accountID, SubjectID: fixture.subjectID,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 2<<20)),
	}
	canary := []byte("PB_ENV_DISK_CANARY_9f83c1327a")
	fixture.control.failAfterApply = true
	if _, err := manager.Set(context.Background(), "", "APP_CANARY", canary); err == nil {
		t.Fatal("expected uncertain request result")
	}
	err := filepath.Walk(fixture.store.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		defer clear(raw)
		if bytes.Contains(raw, canary) {
			t.Fatalf("plaintext canary persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, found, err := manager.loadPendingMutation("")
	if err != nil || !found {
		t.Fatalf("pending ciphertext not retained: found=%v err=%v", found, err)
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(pending.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(envelope)
	if bytes.Contains(envelope, canary) {
		t.Fatal("plaintext canary appeared in the signed envelope")
	}
}

func TestManagerEnrollmentResumesExactCreateAndProofAfterLostResponses(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	plane := &enrollmentWorkflowPlane{managerControlPlane: fixture.control, failCreateAfterApply: true, failProofAfterApply: true}
	manager := Manager{Client: plane, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: "cli_new", Random: bytes.NewReader(bytes.Repeat([]byte{0x68}, 2<<20))}
	now := time.Unix(1_780_000_000, 0).UTC()
	certificate := []byte("public-endpoint-certificate")
	if _, err := manager.BeginManagerEnrollment(context.Background(), certificate, 1, false, now); err == nil || !strings.Contains(err.Error(), "enrollment create") {
		t.Fatalf("lost create response error = %v", err)
	}
	draft, found, err := manager.loadPendingEnrollment()
	if err != nil || !found || draft.RequestID != "" {
		t.Fatalf("initial enrollment draft found=%v request=%q err=%v", found, draft.RequestID, err)
	}
	first := draft.Request
	if _, err := manager.BeginManagerEnrollment(context.Background(), certificate, 1, false, now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "enrollment proof") {
		t.Fatalf("lost proof response error = %v", err)
	}
	draft, found, err = manager.loadPendingEnrollment()
	if err != nil || !found || draft.RequestID != "envreq_resume_1" {
		t.Fatalf("proved enrollment draft found=%v request=%q err=%v", found, draft.RequestID, err)
	}
	if len(plane.enrollmentCreates) != 2 || !reflect.DeepEqual(first, plane.enrollmentCreates[0]) || !reflect.DeepEqual(first, plane.enrollmentCreates[1]) {
		t.Fatal("enrollment retry changed the exact create request")
	}
	result, err := manager.BeginManagerEnrollment(context.Background(), certificate, 1, false, now.Add(2*time.Second))
	if err != nil || result.RequestID != "envreq_resume_1" || result.SafetyCode == "" || result.KeyGeneration != 1 {
		t.Fatalf("resumed enrollment result=%+v err=%v", result, err)
	}
	if len(plane.enrollmentCreates) != 3 || !reflect.DeepEqual(first, plane.enrollmentCreates[2]) {
		t.Fatal("proof retry changed the exact enrollment request")
	}
	if plane.enrollmentProofs != 1 {
		t.Fatalf("accepted enrollment proof was replayed %d times", plane.enrollmentProofs)
	}
	identity, err := fixture.store.LoadEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, "cli_new")
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	path, err := manager.enrollmentPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if bytes.Contains(raw, identity.SigningSeed[:]) || bytes.Contains(raw, identity.RecipientPrivate[:]) {
		t.Fatal("enrollment journal contains private key material")
	}
}

func TestBuildTransitionRotatesFreshKeyAndRejectsWrongManagerKey(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	rootSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	clear(rootSeed)
	defer clear(rootPrivate)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	previous := fixture.control.authority.ID
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: fixture.accountID, Generation: 2, PreviousID: &previous,
		OperationID: [16]byte{22}, BindingBytes: fixture.control.authority.BindingBytes,
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(authorityRaw)
	proposed, err := environmente2ee.ParseAuthority(authorityRaw, environmente2ee.RootKeys{rootID: rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	defer clearAuthority(&proposed)
	identity, err := fixture.store.LoadEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, fixture.subjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	signer := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signer)
	signerID, _ := environmente2ee.KeyIDEd25519(signer.Public().(ed25519.PublicKey))
	manager := Manager{Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID, Random: bytes.NewReader(bytes.Repeat([]byte{0x61}, 2<<20))}
	raw, err := manager.buildTransitionManifest(&fixture.control.manifest, &fixture.control.authority, proposed, fixture.control.managerRecipient, signerID, signer, "", []ScopeRef{{Scope: environmente2ee.ScopeGlobal}}, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	manifest, err := environmente2ee.ParseManifest(raw, proposed)
	if err != nil {
		t.Fatal(err)
	}
	defer clearManifest(&manifest)
	if manifest.Mutation != environmente2ee.MutationRotate || manifest.KeyEpoch != fixture.control.manifest.KeyEpoch+1 {
		t.Fatalf("rotation manifest mutation=%d epoch=%d", manifest.Mutation, manifest.KeyEpoch)
	}
	wrong := fixture.control.managerRecipient
	wrong.PrivateKey = bytes.Repeat([]byte{0x77}, 32)
	defer clear(wrong.PrivateKey)
	if _, err := manager.buildTransitionManifest(&fixture.control.manifest, &fixture.control.authority, proposed, wrong, signerID, signer, "", nil, [16]byte{1}); !errors.Is(err, ErrNoDecryptingKey) {
		t.Fatalf("wrong manager key error = %v", err)
	}
}

func TestListPendingEnrollmentRecomputesProofAndSafety(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	binding := findManagerBinding(t, fixture.control.authority, fixture.subjectID)
	signing := ed25519.NewKeyFromSeed(fixture.identity.SigningSeed[:])
	defer clear(signing)
	now := time.Unix(1_780_000_000, 0).UTC()
	request := environmente2ee.EnrollmentRequest{
		AccountID: fixture.accountID, OperationID: [16]byte{24},
		SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: fixture.subjectID,
		SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: binding.EndpointCertificate, SigningPublic: binding.SigningPublic,
		SigningKeyID: binding.SigningKeyID, RecipientPublic: binding.RecipientPublic,
		RecipientKeyID: binding.RecipientKeyID, RequestExpiresAt: uint64(now.Add(4 * time.Minute).Unix()),
	}
	raw, err := environmente2ee.CanonicalEnrollmentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	signature, err := environmente2ee.SignEnrollmentRequest(request, signing)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signature)
	safety, _ := environmente2ee.EnrollmentSafetyCode(request)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	plane := &enrollmentWorkflowPlane{managerControlPlane: fixture.control, pending: []api.EnvironmentKeyEnrollmentState{{
		Schema: api.EnvironmentKeyEnrollmentStateSchemaV1, RequestID: "envreq_01", State: "pending",
		ExpiresAt: now.Add(4 * time.Minute), SafetyCode: safety,
		EnrollmentRequest: base64.RawURLEncoding.EncodeToString(raw), SigningProof: &signatureEncoded,
	}}}
	manager := Manager{Client: plane, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID}
	pending, err := manager.ListVerifiedPendingEnrollments(context.Background(), now)
	if err != nil || len(pending) != 1 || pending[0].SafetyCode != safety {
		t.Fatalf("verified pending = %#v err=%v", pending, err)
	}
	plane.pending[0].SafetyCode = "aaaa-aaaa-aaaa-aaaa"
	if _, err := manager.ListVerifiedPendingEnrollments(context.Background(), now); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("substituted safety code error = %v", err)
	}
}

func TestStageAllScopesUsesExistingCASAndGenesisPrecondition(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	proposed := successorAuthority(t, fixture)
	defer clearAuthority(&proposed)
	if err := fixture.store.CommitEnvironmentAuthorityHighWater(fixture.issuer, fixture.accountID, fixture.subjectID, int64(fixture.control.authority.Generation), fixture.control.authority.ID.String()); err != nil {
		t.Fatal(err)
	}
	plane := &enrollmentWorkflowPlane{managerControlPlane: fixture.control}
	plane.state = api.EnvironmentAuthorityTransitionState{
		Schema: api.EnvironmentTransitionStateSchemaV1, TransitionID: proposed.ID.String(),
		State: "active", ProposedGeneration: int64(proposed.Generation),
		ProposedAuthorityID: proposed.ID.String(), RequiredScopes: []string{"g"}, StagedScopes: []string{"g"},
	}
	manager := Manager{Client: plane, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID, Random: bytes.NewReader(bytes.Repeat([]byte{0x72}, 2<<20))}
	if _, err := manager.stageAllScopes(context.Background(), plane, plane.state, &fixture.control.authority, proposed, fixture.identity, nil, "envop_01010101010101010101010101010101"); err != nil {
		t.Fatal(err)
	}
	if len(plane.staged) != 1 || plane.staged[0].ExpectedVersion != int64(fixture.control.manifest.Version) || plane.etags[0] != manifestState(fixture.control.manifest).ETag {
		t.Fatalf("existing CAS version=%v etag=%v", plane.staged, plane.etags)
	}

	genesisFixture := newManagerFixture(t)
	defer genesisFixture.identity.Clear()
	defer clear(genesisFixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&genesisFixture.control.authority)
	defer clearManifest(&genesisFixture.control.manifest)
	genesisPlane := &enrollmentWorkflowPlane{managerControlPlane: genesisFixture.control}
	genesisPlane.state = api.EnvironmentAuthorityTransitionState{
		Schema: api.EnvironmentTransitionStateSchemaV1, TransitionID: genesisFixture.control.authority.ID.String(),
		State: "active", ProposedGeneration: 1, ProposedAuthorityID: genesisFixture.control.authority.ID.String(),
		RequiredScopes: []string{"g"}, StagedScopes: []string{"g"},
	}
	genesisManager := Manager{Client: genesisPlane, Store: genesisFixture.store, Issuer: genesisFixture.issuer, AccountID: genesisFixture.accountID, SubjectID: genesisFixture.subjectID, Random: bytes.NewReader(bytes.Repeat([]byte{0x73}, 2<<20))}
	if _, err := genesisManager.stageAllScopes(context.Background(), genesisPlane, genesisPlane.state, nil, genesisFixture.control.authority, genesisFixture.identity, nil, "envop_02020202020202020202020202020202"); err != nil {
		t.Fatal(err)
	}
	if len(genesisPlane.staged) != 1 || genesisPlane.staged[0].ExpectedVersion != 0 || genesisPlane.etags[0] != "" {
		t.Fatalf("genesis CAS version=%v etag=%v", genesisPlane.staged, genesisPlane.etags)
	}
}

func TestChangedBindingsRequiresExactRemovalAndExplicitReplacement(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	rootSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	clear(rootSeed)
	defer clear(rootPrivate)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	roots := environmente2ee.RootKeys{rootID: rootPublic}

	if _, err := changedBindings(fixture.control.authority, roots, AuthorityChange{Remove: []SubjectRef{{Kind: environmente2ee.SubjectHost, ID: "missing_host"}}}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing removal error = %v", err)
	}
	managerBinding := findManagerBinding(t, fixture.control.authority, fixture.subjectID)
	if _, err := changedBindings(fixture.control.authority, roots, AuthorityChange{AddBindings: [][]byte{managerBinding.Raw}}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("implicit replacement error = %v", err)
	}
	if _, err := changedBindings(fixture.control.authority, roots, AuthorityChange{Remove: []SubjectRef{{Kind: managerBinding.SubjectKind, ID: managerBinding.SubjectID}}, AddBindings: [][]byte{managerBinding.Raw}}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("non-incrementing replacement error = %v", err)
	}
	if _, err := changedBindings(fixture.control.authority, roots, AuthorityChange{AddBindings: [][]byte{managerBinding.Raw, managerBinding.Raw}}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("duplicate addition error = %v", err)
	}
}

func TestPendingAuthorityTransitionResumesLostStartApprovalAndStageResponses(t *testing.T) {
	for _, kind := range []string{"start", "approval"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newManagerFixture(t)
			defer fixture.identity.Clear()
			defer clear(fixture.control.managerRecipient.PrivateKey)
			defer clearAuthority(&fixture.control.authority)
			defer clearManifest(&fixture.control.manifest)
			proposed := successorAuthority(t, fixture)
			defer clearAuthority(&proposed)
			if err := fixture.store.CommitEnvironmentAuthorityHighWater(fixture.issuer, fixture.accountID, fixture.subjectID, int64(fixture.control.authority.Generation), fixture.control.authority.ID.String()); err != nil {
				t.Fatal(err)
			}
			plane := &enrollmentWorkflowPlane{managerControlPlane: fixture.control, state: api.EnvironmentAuthorityTransitionState{
				Schema: api.EnvironmentTransitionStateSchemaV1, TransitionID: proposed.ID.String(), State: "staging",
				ProposedGeneration: int64(proposed.Generation), ProposedAuthorityID: proposed.ID.String(),
				RequiredScopes: []string{"g"}, StagedScopes: []string{},
			}, failStartAfterApply: true, failStageAfterApply: true, proposed: &proposed}
			manager := Manager{Client: plane, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID, Random: bytes.NewReader(bytes.Repeat([]byte{0x79}, 4<<20))}
			draft := newPendingTransition(manager, kind, &fixture.control.authority, proposed, manifestState(fixture.control.manifest).ETag)
			if kind == "start" {
				draft.AuthorityETag = `"environment-authority-1-` + hex.EncodeToString(fixture.control.authority.ID[:]) + `"`
				draft.Start = &api.EnvironmentAuthorityTransition{Schema: api.EnvironmentAuthorityTransitionSchemaV1, ExpectedAuthorityID: fixture.control.authority.ID.String(), OperationID: "envop_11111111111111111111111111111111", Authority: draft.ProposedAuthority}
			} else {
				draft.AuthorityETag = `"environment-authority-1-` + hex.EncodeToString(fixture.control.authority.ID[:]) + `"`
				draft.RequestID = "envreq_01"
				expected := fixture.control.authority.ID.String()
				draft.Approval = &api.EnvironmentKeyApproval{Schema: api.EnvironmentKeyApprovalSchemaV1, ExpectedAuthorityID: &expected, OperationID: "envop_22222222222222222222222222222222", Binding: base64.RawURLEncoding.EncodeToString(fixture.control.authority.BindingBytes[0]), Authority: draft.ProposedAuthority}
			}
			if err := manager.storePendingTransition(draft); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.ResumeAuthorityTransition(context.Background()); err == nil || !strings.Contains(err.Error(), "transition start") {
				t.Fatalf("lost start response error = %v", err)
			}
			persisted, found, err := manager.loadPendingTransition()
			if err != nil || !found || len(persisted.Manifests) != 0 {
				t.Fatalf("start draft found=%v manifests=%d err=%v", found, len(persisted.Manifests), err)
			}
			if _, err := manager.ResumeAuthorityTransition(context.Background()); err == nil || !strings.Contains(err.Error(), "scope apply") {
				t.Fatalf("lost stage response error = %v", err)
			}
			persisted, found, err = manager.loadPendingTransition()
			if err != nil || !found || len(persisted.Manifests) != 1 || persisted.Manifests[0].Request.Envelope == "" {
				t.Fatalf("scope draft found=%v manifests=%d err=%v", found, len(persisted.Manifests), err)
			}
			exactEnvelope := persisted.Manifests[0].Request.Envelope
			result, err := manager.ResumeAuthorityTransition(context.Background())
			if err != nil || result.State != "active" || result.AuthorityID != proposed.ID.String() {
				t.Fatalf("resume result=%+v err=%v", result, err)
			}
			if len(plane.staged) != 1 || plane.staged[0].Envelope != exactEnvelope {
				t.Fatal("resume regenerated or duplicated the encrypted scope request")
			}
			if _, found, err := manager.loadPendingTransition(); err != nil || found {
				t.Fatalf("completed draft found=%v err=%v", found, err)
			}
		})
	}
}

func TestCancelRecoveryPreparationRefusesWhileTransitionDraftExists(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	oldPrivate, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldPrivate)
	encoded, err := environmente2ee.EncodeRecoveryBytes(oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	manager := Manager{Client: fixture.control, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID}
	prepared, err := manager.BeginRecoveryPreparation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Clear()
	proposed := successorAuthority(t, fixture)
	defer clearAuthority(&proposed)
	draft := newPendingTransition(manager, "start", &fixture.control.authority, proposed, `"environment-authority-1-`+hex.EncodeToString(fixture.control.authority.ID[:])+`"`)
	draft.Start = &api.EnvironmentAuthorityTransition{Schema: api.EnvironmentAuthorityTransitionSchemaV1, ExpectedAuthorityID: fixture.control.authority.ID.String(), OperationID: "envop_33333333333333333333333333333333", Authority: draft.ProposedAuthority}
	draft.ImportedRecoveryHandle, draft.ReplacementRecoveryHandle = prepared.ImportedHandle, prepared.ReplacementHandle
	if err := manager.storePendingTransition(draft); err != nil {
		t.Fatal(err)
	}
	if err := manager.CancelRecoveryPreparation(); !errors.Is(err, ErrTransitionIncomplete) {
		t.Fatalf("cancel with pending transition error = %v", err)
	}
	resumed, err := manager.ResumeRecoveryPreparation()
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Clear()
	if resumed.ImportedHandle != prepared.ImportedHandle || resumed.ReplacementHandle != prepared.ReplacementHandle {
		t.Fatal("cancel deleted recovery keys required by the pending transition")
	}
}

func successorAuthority(t *testing.T, fixture managerFixture) environmente2ee.Authority {
	t.Helper()
	rootSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	clear(rootSeed)
	defer clear(rootPrivate)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	previous := fixture.control.authority.ID
	raw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: fixture.accountID, Generation: fixture.control.authority.Generation + 1,
		PreviousID: &previous, OperationID: [16]byte{25}, BindingBytes: fixture.control.authority.BindingBytes,
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	authority, err := environmente2ee.ParseAuthority(raw, environmente2ee.RootKeys{rootID: rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func findManagerBinding(t *testing.T, authority environmente2ee.Authority, subject string) environmente2ee.KeyBinding {
	t.Helper()
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectManagerCLI && binding.SubjectID == subject {
			return binding
		}
	}
	t.Fatal("manager binding not found")
	return environmente2ee.KeyBinding{}
}
