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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type secureMemoryStore struct{ values map[string]string }

func (*secureMemoryStore) EnvironmentSecureStore() {}
func (store *secureMemoryStore) Set(ref, value string) error {
	if store.values == nil {
		store.values = make(map[string]string)
	}
	store.values[ref] = value
	return nil
}
func (store *secureMemoryStore) Get(ref string) (string, error) {
	value, ok := store.values[ref]
	if !ok {
		return "", config.ErrSecretNotFound
	}
	return value, nil
}
func (store *secureMemoryStore) Delete(ref string) error { delete(store.values, ref); return nil }

type managerControlPlane struct {
	authority        environmente2ee.Authority
	manifest         environmente2ee.Manifest
	put              environmente2ee.Manifest
	managerRecipient environmente2ee.RecipientPrivate
	canary           []byte
	failAfterApply   bool
}

func (control *managerControlPlane) GetEnvironmentAuthority(context.Context) (api.EnvironmentAuthorityState, error) {
	return api.EnvironmentAuthorityState{
		Schema: api.EnvironmentAuthorityStateSchemaV1, Generation: int64(control.authority.Generation),
		AuthorityID: control.authority.ID.String(), Authority: base64.RawURLEncoding.EncodeToString(control.authority.Raw),
		ETag: `"environment-authority-1-` + hex.EncodeToString(control.authority.ID[:]) + `"`,
	}, nil
}

func (control *managerControlPlane) GetEnvironmentAuthorityDocuments(_ context.Context, generation int64, id string) (api.EnvironmentAuthorityPage, error) {
	page := api.EnvironmentAuthorityPage{Schema: api.EnvironmentAuthorityPageSchemaV1, AuthorityHead: api.EnvironmentAuthorityHead{Generation: 1, AuthorityID: control.authority.ID.String()}, AuthorityDocuments: []string{}}
	if generation == 0 && id == "" {
		page.AuthorityDocuments = []string{base64.RawURLEncoding.EncodeToString(control.authority.Raw)}
		return page, nil
	}
	if generation == 1 && id == control.authority.ID.String() {
		return page, nil
	}
	return api.EnvironmentAuthorityPage{}, ErrAuthorityFork
}

func (control *managerControlPlane) GetEnvironmentManifest(context.Context, string) (api.EnvironmentManifestState, error) {
	return manifestState(control.manifest), nil
}

func (control *managerControlPlane) PutEnvironmentManifest(_ context.Context, machineID string, mutation api.EnvironmentManifestMutation, etag string) (api.EnvironmentManifestState, error) {
	if len(control.canary) > 0 && bytes.Contains([]byte(mutation.Envelope), control.canary) {
		return api.EnvironmentManifestState{}, errors.New("plaintext canary appeared in the HTTP envelope")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(mutation.Envelope)
	if err != nil {
		return api.EnvironmentManifestState{}, err
	}
	next, err := environmente2ee.ParseManifest(raw, control.authority)
	clear(raw)
	if err == nil && next.ID == control.manifest.ID && mutation.ExpectedVersion+1 == int64(control.manifest.Version) {
		clearManifest(&next)
		return manifestState(control.manifest), nil
	}
	if machineID != "" || mutation.ExpectedVersion != int64(control.manifest.Version) || etag != manifestState(control.manifest).ETag {
		clearManifest(&next)
		return api.EnvironmentManifestState{}, &api.APIError{Status: 409, Code: "version_conflict", Message: "conflict"}
	}
	if err != nil || environmente2ee.ValidateManifestTransition(&control.manifest, next, &control.authority, control.authority) != nil {
		return api.EnvironmentManifestState{}, ErrIntegrity
	}
	decrypted, err := environmente2ee.DecryptManifest(next, control.managerRecipient)
	if err != nil {
		return api.EnvironmentManifestState{}, err
	}
	if next.Mutation == environmente2ee.MutationSet && len(control.canary) > 0 && !bytes.Equal(decrypted.Values["APP_CANARY"], control.canary) {
		clearDecrypted(&decrypted)
		return api.EnvironmentManifestState{}, errors.New("intended manager could not decrypt the set value")
	}
	if next.Mutation == environmente2ee.MutationUnset && len(decrypted.Values) != 0 {
		clearDecrypted(&decrypted)
		return api.EnvironmentManifestState{}, errors.New("unset manifest retained a value")
	}
	clearDecrypted(&decrypted)
	control.put = next
	if control.failAfterApply {
		control.failAfterApply = false
		clearManifest(&control.manifest)
		control.manifest = next
		control.put = environmente2ee.Manifest{}
		return api.EnvironmentManifestState{}, errors.New("connection reset after request")
	}
	return manifestState(next), nil
}

func TestManagerSetAndUnsetEncryptLocallyAndAdvanceAuthorityHighWater(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	manager := Manager{
		Client: fixture.control, Store: fixture.store, Issuer: fixture.issuer,
		AccountID: fixture.accountID, SubjectID: fixture.subjectID,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x7a}, 2<<20)),
	}
	canary := []byte("pb-env-e2ee-canary-unique-31f4")
	fixture.control.canary = append([]byte(nil), canary...)
	result, err := manager.Set(context.Background(), "", "APP_CANARY", canary)
	clear(canary)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "APP_CANARY" || result.Version != 2 || fixture.control.put.Mutation != environmente2ee.MutationSet || fixture.control.put.ID.String() != result.ManifestID {
		t.Fatalf("set result = %+v manifest=%+v", result, fixture.control.put.ManifestClaims)
	}
	clearManifest(&fixture.control.manifest)
	fixture.control.manifest = fixture.control.put
	fixture.control.put = environmente2ee.Manifest{}

	result, err = manager.Unset(context.Background(), "", "app_canary")
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "APP_CANARY" || result.Version != 3 || fixture.control.put.Mutation != environmente2ee.MutationUnset {
		t.Fatalf("unset result = %+v manifest=%+v", result, fixture.control.put.ManifestClaims)
	}
	loaded, err := fixture.store.LoadEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, fixture.subjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if loaded.AuthorityGeneration != 1 || loaded.AuthorityID != fixture.control.authority.ID.String() {
		t.Fatalf("authority high-water = %d %s", loaded.AuthorityGeneration, loaded.AuthorityID)
	}
}

func TestManagerRejectsUnboundLocalKey(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	other, err := fixture.store.CreateEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, "cli_other", false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Clear()
	manager := Manager{Client: fixture.control, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: "cli_other"}
	_, err = manager.Set(context.Background(), "", "APP_MODE", []byte("safe"))
	if !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatalf("unbound manager error = %v", err)
	}
}

func TestRootSignerUsesCustodiedSeedWhenVerifierRecordNamesAnotherRoot(t *testing.T) {
	const issuer, accountID = "https://api.example.test", "account_1"
	store := config.ProfileStore{Path: t.TempDir(), Secrets: &secureMemoryStore{}}

	seed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	if err := store.ImportPeerAccountRootSeed(issuer, accountID, seed); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(private)
	wanted := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	defer clear(wanted)

	otherSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	other := ed25519.NewKeyFromSeed(otherSeed)
	clear(otherSeed)
	defer clear(other)
	otherPublic := append(ed25519.PublicKey(nil), other.Public().(ed25519.PublicKey)...)
	defer clear(otherPublic)
	if err := store.SavePeerAccountRootPublic(issuer, accountID, otherPublic); err != nil {
		t.Fatal(err)
	}

	manager := Manager{Store: store, Issuer: issuer, AccountID: accountID, SubjectID: "cli_1"}
	keyID, signer, roots, err := manager.rootSigner()
	if err != nil {
		t.Fatalf("root signer error = %v", err)
	}
	defer clear(signer)
	defer clearRoots(roots)

	digest := sha256.Sum256(wanted)
	wantID := "aek_" + hex.EncodeToString(digest[:])
	otherDigest := sha256.Sum256(otherPublic)
	otherID := "aek_" + hex.EncodeToString(otherDigest[:])
	if keyID != wantID || !bytes.Equal(signer.Public().(ed25519.PublicKey), wanted) || len(roots) != 2 ||
		!bytes.Equal(roots[keyID], wanted) || !bytes.Equal(roots[otherID], otherPublic) {
		t.Fatalf("root signer selected key id=%q roots=%v", keyID, roots)
	}
}

func TestLocalRootsIncludesVerifierAndCustodiedRoots(t *testing.T) {
	const issuer, accountID = "https://api.example.test", "account_1"
	store := config.ProfileStore{Path: t.TempDir(), Secrets: &secureMemoryStore{}}
	ownedSeed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	if err := store.ImportPeerAccountRootSeed(issuer, accountID, ownedSeed); err != nil {
		t.Fatal(err)
	}
	owned := ed25519.NewKeyFromSeed(ownedSeed).Public().(ed25519.PublicKey)
	clear(ownedSeed)
	verifierSeed := bytes.Repeat([]byte{0x61}, ed25519.SeedSize)
	verifier := ed25519.NewKeyFromSeed(verifierSeed).Public().(ed25519.PublicKey)
	clear(verifierSeed)
	if err := store.SavePeerAccountRootPublic(issuer, accountID, verifier); err != nil {
		t.Fatal(err)
	}
	roots, err := (Manager{Store: store, Issuer: issuer, AccountID: accountID}).localRoots()
	if err != nil {
		t.Fatal(err)
	}
	defer clearRoots(roots)
	ownedDigest, verifierDigest := sha256.Sum256(owned), sha256.Sum256(verifier)
	if len(roots) != 2 || !bytes.Equal(roots["aek_"+hex.EncodeToString(ownedDigest[:])], owned) || !bytes.Equal(roots["aek_"+hex.EncodeToString(verifierDigest[:])], verifier) {
		t.Fatalf("local roots count = %d", len(roots))
	}
}

func TestManagerRetriesExactCiphertextAfterUncertainResult(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clear(fixture.control.managerRecipient.PrivateKey)
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)
	manager := Manager{Client: fixture.control, Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: fixture.subjectID, Random: bytes.NewReader(bytes.Repeat([]byte{0x63}, 2<<20))}
	fixture.control.failAfterApply = true
	if _, err := manager.Set(context.Background(), "", "APP_CANARY", []byte("uncertain-secret")); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("uncertain mutation error = %v", err)
	}
	if _, found, err := manager.loadPendingMutation(""); err != nil || !found {
		t.Fatalf("pending mutation found=%v err=%v", found, err)
	}
	_, err := manager.Set(context.Background(), "", "SHOULD_NOT_APPLY", []byte("different"))
	if !errors.Is(err, ErrPendingMutationReconciled) {
		t.Fatalf("reconciliation error = %v", err)
	}
	if _, found, err := manager.loadPendingMutation(""); err != nil || found {
		t.Fatalf("pending mutation remained found=%v err=%v", found, err)
	}
	decrypted, err := environmente2ee.DecryptManifest(fixture.control.manifest, fixture.control.managerRecipient)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDecrypted(&decrypted)
	if string(decrypted.Values["APP_CANARY"]) != "uncertain-secret" || decrypted.Values["SHOULD_NOT_APPLY"] != nil {
		t.Fatalf("reconciled values = %#v", decrypted.Values)
	}
}

type managerFixture struct {
	issuer, accountID, subjectID string
	store                        config.ProfileStore
	identity                     config.EnvironmentManagerIdentity
	control                      *managerControlPlane
}

func newManagerFixture(t *testing.T) managerFixture {
	t.Helper()
	const issuer, accountID, subjectID = "https://api.example.test", "account_1", "cli_1"
	store := config.ProfileStore{Path: t.TempDir(), Secrets: &secureMemoryStore{}}
	rootSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	clear(rootSeed)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	if err := store.SavePeerAccountRootPublic(issuer, accountID, rootPublic); err != nil {
		t.Fatal(err)
	}
	identity, err := store.CreateEnvironmentManagerIdentity(issuer, accountID, subjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivate := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	signingID, _ := environmente2ee.KeyIDEd25519(signingPublic)
	recipientPrivateKey, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic := recipientPrivateKey.PublicKey().Bytes()
	recipientID, _ := environmente2ee.KeyIDX25519(recipientPublic)
	quicSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	quicPrivate := ed25519.NewKeyFromSeed(quicSeed)
	clear(quicSeed)
	now := time.Unix(1_780_000_000, 0).UTC()
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: accountID, Role: endpointidentity.RoleCLI, EndpointID: subjectID, NoisePublicKey: [32]byte{1}, QUICPublicKey: quicPrivate.Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certificateRaw, _ := certificate.MarshalBinary()
	managerBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{AccountID: accountID, SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: subjectID, SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: certificateRaw, SigningPublic: signingPublic, SigningKeyID: signingID, RecipientPublic: recipientPublic, RecipientKeyID: recipientID, NotBefore: uint64(now.Unix()), Serial: 1}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPrivate, recoveryPublic, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recoveryPrivate)
	recoveryID, _ := environmente2ee.KeyIDX25519(recoveryPublic)
	recoveryBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{AccountID: accountID, SubjectKind: environmente2ee.SubjectRecovery, SubjectID: "environment_recovery", SubjectGeneration: 1, KeyGeneration: 1, RecipientPublic: recoveryPublic, RecipientKeyID: recoveryID, NotBefore: uint64(now.Unix()), Serial: 1}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{AccountID: accountID, Generation: 1, OperationID: [16]byte{1}, BindingBytes: [][]byte{managerBinding, recoveryBinding}}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := environmente2ee.ParseAuthority(authorityRaw, environmente2ee.RootKeys{rootID: rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := authority.ExpectedRecipients(environmente2ee.ScopeGlobal, environmente2ee.ScopeActive, "")
	manifestRaw, err := environmente2ee.BuildManifest(environmente2ee.BuildManifestInput{Claims: environmente2ee.ManifestClaims{AccountID: accountID, AuthorityGeneration: 1, AuthorityID: authority.ID, Scope: environmente2ee.ScopeGlobal, State: environmente2ee.ScopeActive, PreviousVersion: 0, Version: 1, KeyEpoch: 1, OperationID: [16]byte{2}, Mutation: environmente2ee.MutationInitialize}, Values: map[string][]byte{}, ScopeKey: bytes.Repeat([]byte{0x44}, 32), Recipients: recipients, SignerKeyID: signingID, SignerPrivate: signingPrivate})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := environmente2ee.ParseManifest(manifestRaw, authority)
	if err != nil {
		t.Fatal(err)
	}
	clear(authorityRaw)
	clear(manifestRaw)
	clear(rootPrivate)
	clear(signingPrivate)
	clear(quicPrivate)
	return managerFixture{issuer: issuer, accountID: accountID, subjectID: subjectID, store: store, identity: identity, control: &managerControlPlane{authority: authority, manifest: manifest, managerRecipient: environmente2ee.RecipientPrivate{Kind: environmente2ee.RecipientManager, SubjectID: subjectID, KeyGeneration: 1, KeyID: recipientID, PrivateKey: append([]byte(nil), identity.RecipientPrivate[:]...)}}}
}

func manifestState(manifest environmente2ee.Manifest) api.EnvironmentManifestState {
	return api.EnvironmentManifestState{Schema: api.EnvironmentManifestStateSchemaV1, Scope: api.EnvironmentVariableScopeGlobal, Version: int64(manifest.Version), KeyEpoch: int64(manifest.KeyEpoch), ManifestID: manifest.ID.String(), Envelope: base64.RawURLEncoding.EncodeToString(manifest.Raw), ETag: `"environment-global-` + strconv.FormatUint(manifest.Version, 10) + `"`}
}

func TestManagerRejectsInvalidUTF8BeforeAnyControlPlaneCall(t *testing.T) {
	manager := Manager{}
	if _, err := manager.Set(context.Background(), "", "APP_VALUE", []byte{0xff}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}
