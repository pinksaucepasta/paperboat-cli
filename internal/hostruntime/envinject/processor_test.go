package envinject

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type staticHostKey struct{ material environmentkey.Material }

func (s staticHostKey) Load(context.Context) (environmentkey.Material, error) { return s.material, nil }

func TestCryptoProcessorFirstDeliveryOfflineRestoreAndWrongHostRejection(t *testing.T) {
	fixture := cryptoProcessorFixture(t)
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openCryptoStore(t, path, fixture.source, fixture.rootID, fixture.rootPublic, fixture.hostKeyID)
	if err := store.Apply(context.Background(), Bundle{
		Schema: BundleSchema, AuthorityHead: authorityCursor(fixture.authority), AuthorityDocuments: []string{encodeEnvelope(fixture.authority.Raw)},
	}); err != nil {
		t.Fatal(err)
	}
	if store.BindingState() != BindingActive {
		t.Fatalf("freshly verified authority binding state=%d, want active", store.BindingState())
	}
	if _, err := store.Environment(); err != ErrNotReady {
		t.Fatalf("environment before manifest delivery error=%v", err)
	}
	restartedBeforeManifest := openCryptoStore(t, path, fixture.source, fixture.rootID, fixture.rootPublic, fixture.hostKeyID)
	if restartedBeforeManifest.BindingState() != BindingUnknown {
		t.Fatalf("cached authority-only state was treated as active after restart: %d", restartedBeforeManifest.BindingState())
	}
	bundle := Bundle{
		Schema: BundleSchema, AuthorityHead: authorityCursor(fixture.authority),
		Bootstrap: &AuthorizationBootstrap{
			Authority: authorityCursor(fixture.authority), GlobalManifest: manifestEnvelope(fixture.bootstrapGlobal), MachineManifest: manifestEnvelope(fixture.bootstrapMachine),
		},
		GlobalManifest: ptrManifestEnvelope(fixture.latestGlobal), MachineManifest: ptrManifestEnvelope(fixture.latestMachine),
	}
	if err := store.Apply(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	want := []string{"APP_REGION=value-unique-canary-9274", "EMPTY="}
	if got, err := store.Environment(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("environment=%q error=%v", got, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("value-unique-canary-9274")) {
		t.Fatalf("plaintext reached encrypted cache: %s", body)
	}
	restored := openCryptoStore(t, path, fixture.source, fixture.rootID, fixture.rootPublic, fixture.hostKeyID)
	if got, err := restored.Environment(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("offline environment=%q error=%v", got, err)
	}
	wrong := fixture.source.material
	wrong.Private[0] ^= 0x40
	if _, err := Open(context.Background(), Config{
		Path: path, HighWaterPath: path + ".high-water", IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true, AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1, HostKeyGeneration: 1,
		HostRecipientKeyID: fixture.hostKeyID, GenesisMarker: testStoreConfig(path, nil).GenesisMarker, Processor: mustCryptoProcessor(t, staticHostKey{material: wrong}, fixture.rootID, fixture.rootPublic, fixture.hostKeyID),
	}); err == nil {
		t.Fatal("another host private key restored the encrypted cache")
	}
	bindings := make([][]byte, 0, len(fixture.authority.Bindings)-1)
	for _, binding := range fixture.authority.Bindings {
		if binding.SubjectKind != environmente2ee.SubjectHost {
			bindings = append(bindings, binding.Raw)
		}
	}
	previous := fixture.authority.ID
	revokedRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: 2, PreviousID: &previous, OperationID: [16]byte{12}, BindingBytes: bindings,
	}, fixture.rootID, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	revokedAuthority, err := environmente2ee.ParseAuthority(revokedRaw, environmente2ee.RootKeys{fixture.rootID: fixture.rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(context.Background(), Bundle{
		Schema: BundleSchema, AuthorityHead: authorityCursor(revokedAuthority), AuthorityDocuments: []string{encodeEnvelope(revokedRaw)}, RevocationOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Environment(); err != ErrRevoked {
		t.Fatalf("revoked environment error=%v", err)
	}
}

func TestCryptoProcessorRestoreRejectsBrokenAdjacentAuthorityLink(t *testing.T) {
	fixture := cryptoProcessorFixture(t)
	bindings := make([][]byte, 0, len(fixture.authority.Bindings))
	for _, binding := range fixture.authority.Bindings {
		bindings = append(bindings, binding.Raw)
	}
	wrongPrevious := environmente2ee.DocumentID(sha256.Sum256([]byte("not-the-predecessor")))
	raw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: fixture.authority.Generation + 1, PreviousID: &wrongPrevious,
		OperationID: [16]byte{0x77}, BindingBytes: bindings,
	}, fixture.rootID, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := environmente2ee.ParseAuthority(raw, environmente2ee.RootKeys{fixture.rootID: fixture.rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{
		Schema: cacheSchema, AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1,
		HostKeyGeneration: 1, HostRecipientKeyID: fixture.hostKeyID,
		Authority:          &Cursor{Generation: broken.Generation, AuthorityID: broken.ID.String()},
		AuthorityDocuments: []string{encodeEnvelope(fixture.authority.Raw), encodeEnvelope(raw)},
	}
	processor := mustCryptoProcessor(t, fixture.source, fixture.rootID, fixture.rootPublic, fixture.hostKeyID)
	if _, err := processor.Restore(context.Background(), cache); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("broken adjacent authority link error=%v", err)
	}
}

func TestCryptoProcessorAcceptsAuthoritySignedByEnrolledRootDifferentFromEndpointIssuer(t *testing.T) {
	fixture := cryptoProcessorFixture(t)
	secondPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	secondPublic := secondPrivate.Public().(ed25519.PublicKey)
	secondFingerprint := sha256.Sum256(secondPublic)
	secondID := "aek_" + hex.EncodeToString(secondFingerprint[:])
	allBindings := make([][]byte, 0, len(fixture.authority.Bindings))
	genesisBindings := make([][]byte, 0, len(fixture.authority.Bindings)-1)
	for _, binding := range fixture.authority.Bindings {
		raw, err := environmente2ee.SignKeyBinding(binding.KeyBindingClaims, secondID, secondPrivate)
		if err != nil {
			t.Fatal(err)
		}
		allBindings = append(allBindings, raw)
		if binding.SubjectKind != environmente2ee.SubjectHost {
			genesisBindings = append(genesisBindings, raw)
		}
	}
	firstRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: 1, OperationID: [16]byte{0x29}, BindingBytes: genesisBindings,
	}, secondID, secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	first, err := environmente2ee.ParseAuthority(firstRaw, environmente2ee.RootKeys{
		fixture.rootID: fixture.rootPublic, secondID: secondPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := first.ID
	secondRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: 2, PreviousID: &previous, OperationID: [16]byte{0x2a}, BindingBytes: allBindings,
	}, secondID, secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := environmente2ee.ParseAuthority(secondRaw, environmente2ee.RootKeys{
		fixture.rootID: fixture.rootPublic, secondID: secondPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	managerSigning := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	managerSigningID, err := environmente2ee.KeyIDEd25519(managerSigning.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	globalRecipients, err := second.ExpectedRecipients(environmente2ee.ScopeGlobal, environmente2ee.ScopeActive, "")
	if err != nil {
		t.Fatal(err)
	}
	machineRecipients, err := second.ExpectedRecipients(environmente2ee.ScopeMachine, environmente2ee.ScopeActive, "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapGlobal := buildTestManifest(t, second, environmente2ee.ManifestClaims{
		AccountID: "acct_01", AuthorityGeneration: second.Generation, AuthorityID: second.ID, Scope: environmente2ee.ScopeGlobal, State: environmente2ee.ScopeActive,
		PreviousVersion: 1, Version: 2, KeyEpoch: 1, OperationID: [16]byte{0x30}, Mutation: environmente2ee.MutationReauthorize,
	}, nil, bytes.Repeat([]byte{0x31}, 32), globalRecipients, managerSigningID, managerSigning, 0x32)
	bootstrapMachine := buildTestManifest(t, second, environmente2ee.ManifestClaims{
		AccountID: "acct_01", AuthorityGeneration: second.Generation, AuthorityID: second.ID, Scope: environmente2ee.ScopeMachine, MachineID: "machine_01", State: environmente2ee.ScopeActive,
		Version: 1, KeyEpoch: 1, OperationID: [16]byte{0x33}, Mutation: environmente2ee.MutationInitialize,
	}, nil, bytes.Repeat([]byte{0x34}, 32), machineRecipients, managerSigningID, managerSigning, 0x35)
	trusted := []endpointidentity.TrustedKey{
		{KeyID: fixture.rootID, PublicKey: fixture.rootPublic, Fingerprint: sha256.Sum256(fixture.rootPublic), Generation: 1},
		{KeyID: secondID, PublicKey: secondPublic, Fingerprint: secondFingerprint, Generation: 2},
	}
	processor, err := NewCryptoProcessor(CryptoProcessorConfig{
		AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1,
		HostKeyGeneration: 1, HostRecipientKeyID: fixture.hostKeyID,
		RootKeyID: fixture.rootID, RootPublicKey: fixture.rootPublic, TrustedKeys: trusted,
		Keys: fixture.source,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := Cache{
		Schema: cacheSchema, AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1,
		HostKeyGeneration: 1, HostRecipientKeyID: fixture.hostKeyID,
	}
	next, verified, err := processor.Apply(context.Background(), initial, Bundle{
		Schema: BundleSchema, AuthorityHead: authorityCursor(second),
		AuthorityDocuments: []string{encodeEnvelope(first.Raw), encodeEnvelope(second.Raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if next.Authority == nil || next.Authority.Generation != second.Generation || next.Authority.AuthorityID != second.ID.String() || verified.Authority == nil || verified.Authority.Generation != second.Generation {
		t.Fatalf("authority after alternate-root page = %#v, verified=%#v", next.Authority, verified)
	}
	rootSwitchPrevious := second.ID
	rootSwitchRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: 3, PreviousID: &rootSwitchPrevious, OperationID: [16]byte{0x2b}, BindingBytes: allBindings,
	}, fixture.rootID, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := processor.Apply(context.Background(), next, Bundle{
		Schema: BundleSchema, AuthorityHead: Cursor{Generation: 3, AuthorityID: environmente2ee.DocumentID(rootSwitchRaw).String()},
		AuthorityDocuments: []string{encodeEnvelope(rootSwitchRaw)},
	}); err == nil {
		t.Fatal("authority root switched after initial enrolled-root pin")
	}
	next, verified, err = processor.Apply(context.Background(), next, Bundle{
		Schema: BundleSchema, AuthorityHead: authorityCursor(second),
		Bootstrap: &AuthorizationBootstrap{
			Authority: authorityCursor(second), GlobalManifest: manifestEnvelope(bootstrapGlobal), MachineManifest: manifestEnvelope(bootstrapMachine),
		},
		GlobalManifest: ptrManifestEnvelope(bootstrapGlobal), MachineManifest: ptrManifestEnvelope(bootstrapMachine),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Ready || next.GlobalManifest == nil || next.MachineManifest == nil {
		t.Fatalf("first delivery after alternate-root chain not ready: next=%#v verified=%#v", next, verified)
	}
}

type processorFixture struct {
	rootID, hostKeyID                 string
	rootPrivate                       ed25519.PrivateKey
	rootPublic                        ed25519.PublicKey
	source                            staticHostKey
	authority                         environmente2ee.Authority
	bootstrapGlobal, bootstrapMachine environmente2ee.Manifest
	latestGlobal, latestMachine       environmente2ee.Manifest
}

func cryptoProcessorFixture(t *testing.T) processorFixture {
	t.Helper()
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	now := time.Unix(1788134400, 0).UTC()
	managerSigning := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	managerSigningID, _ := environmente2ee.KeyIDEd25519(managerSigning.Public().(ed25519.PublicKey))
	managerPrivate, managerPublic := deterministicX25519(t, 3)
	_ = managerPrivate
	managerKeyID, _ := environmente2ee.KeyIDX25519(managerPublic)
	managerCertificate := endpointCertificate(t, rootPrivate, "acct_01", endpointidentity.RoleCLI, "cli_01", now, 4)
	managerBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: managerCertificate, SigningPublic: managerSigning.Public().(ed25519.PublicKey), SigningKeyID: managerSigningID,
		RecipientPublic: managerPublic, RecipientKeyID: managerKeyID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	hostPrivate, hostPublic := deterministicX25519(t, 5)
	hostKeyID, _ := environmente2ee.KeyIDX25519(hostPublic)
	hostCertificate := endpointCertificate(t, rootPrivate, "acct_01", endpointidentity.RoleMachine, "machine_01", now, 6)
	hostBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: environmente2ee.SubjectHost, SubjectID: "machine_01", SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: hostCertificate, RecipientPublic: hostPublic, RecipientKeyID: hostKeyID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, recoveryPublic := deterministicX25519(t, 7)
	recoveryKeyID, _ := environmente2ee.KeyIDX25519(recoveryPublic)
	recoveryBinding, err := environmente2ee.SignKeyBinding(environmente2ee.KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: environmente2ee.SubjectRecovery, SubjectID: "environment_recovery", SubjectGeneration: 1, KeyGeneration: 1,
		RecipientPublic: recoveryPublic, RecipientKeyID: recoveryKeyID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authorityRaw, err := environmente2ee.SignAuthority(environmente2ee.AuthorityClaims{
		AccountID: "acct_01", Generation: 1, OperationID: [16]byte{1}, BindingBytes: [][]byte{managerBinding, hostBinding, recoveryBinding},
	}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := environmente2ee.ParseAuthority(authorityRaw, environmente2ee.RootKeys{rootID: rootPublic})
	if err != nil {
		t.Fatal(err)
	}
	globalRecipients, _ := authority.ExpectedRecipients(environmente2ee.ScopeGlobal, environmente2ee.ScopeActive, "")
	machineRecipients, _ := authority.ExpectedRecipients(environmente2ee.ScopeMachine, environmente2ee.ScopeActive, "machine_01")
	bootstrapGlobal := buildTestManifest(t, authority, environmente2ee.ManifestClaims{
		AccountID: "acct_01", AuthorityGeneration: 1, AuthorityID: authority.ID, Scope: environmente2ee.ScopeGlobal, State: environmente2ee.ScopeActive,
		Version: 1, KeyEpoch: 1, OperationID: [16]byte{8}, Mutation: environmente2ee.MutationInitialize,
	}, nil, bytes.Repeat([]byte{8}, 32), globalRecipients, managerSigningID, managerSigning, 8)
	bootstrapMachine := buildTestManifest(t, authority, environmente2ee.ManifestClaims{
		AccountID: "acct_01", AuthorityGeneration: 1, AuthorityID: authority.ID, Scope: environmente2ee.ScopeMachine, MachineID: "machine_01", State: environmente2ee.ScopeActive,
		Version: 1, KeyEpoch: 1, OperationID: [16]byte{9}, Mutation: environmente2ee.MutationInitialize,
	}, nil, bytes.Repeat([]byte{9}, 32), machineRecipients, managerSigningID, managerSigning, 9)
	latestClaims := bootstrapGlobal.ManifestClaims
	latestClaims.PreviousVersion, latestClaims.Version, latestClaims.OperationID, latestClaims.Mutation = 1, 2, [16]byte{10}, environmente2ee.MutationSet
	latestClaims.ChangedNames = []string{"APP_REGION"}
	latestGlobal := buildTestManifest(t, authority, latestClaims, map[string][]byte{"APP_REGION": []byte("value-unique-canary-9274")}, bytes.Repeat([]byte{8}, 32), globalRecipients, managerSigningID, managerSigning, 10)
	latestMachineClaims := bootstrapMachine.ManifestClaims
	latestMachineClaims.PreviousVersion, latestMachineClaims.Version, latestMachineClaims.OperationID, latestMachineClaims.Mutation = 1, 2, [16]byte{11}, environmente2ee.MutationSet
	latestMachineClaims.ChangedNames = []string{"EMPTY"}
	latestMachine := buildTestManifest(t, authority, latestMachineClaims, map[string][]byte{"EMPTY": {}}, bytes.Repeat([]byte{9}, 32), machineRecipients, managerSigningID, managerSigning, 11)
	var material environmentkey.Material
	material.Generation = 1
	copy(material.Private[:], hostPrivate)
	return processorFixture{rootID: rootID, rootPrivate: rootPrivate, rootPublic: rootPublic, hostKeyID: hostKeyID, source: staticHostKey{material: material}, authority: authority, bootstrapGlobal: bootstrapGlobal, bootstrapMachine: bootstrapMachine, latestGlobal: latestGlobal, latestMachine: latestMachine}
}

func endpointCertificate(t *testing.T, root ed25519.PrivateKey, account string, role endpointidentity.Role, id string, now time.Time, seed byte) []byte {
	t.Helper()
	certificate, err := endpointidentity.Sign(root, endpointidentity.Claims{AccountID: account, Role: role, EndpointID: id, NoisePublicKey: [32]byte{seed}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func deterministicX25519(t *testing.T, seed byte) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func buildTestManifest(t *testing.T, authority environmente2ee.Authority, claims environmente2ee.ManifestClaims, values map[string][]byte, scopeKey []byte, recipients []environmente2ee.Recipient, signerID string, signer ed25519.PrivateKey, random byte) environmente2ee.Manifest {
	t.Helper()
	raw, err := environmente2ee.BuildManifest(environmente2ee.BuildManifestInput{Claims: claims, Values: values, ScopeKey: scopeKey, Recipients: recipients, SignerKeyID: signerID, SignerPrivate: signer, Random: bytes.NewReader(bytes.Repeat([]byte{random}, 8192))})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := environmente2ee.ParseManifest(raw, authority)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func authorityCursor(authority environmente2ee.Authority) Cursor {
	return Cursor{Generation: authority.Generation, AuthorityID: authority.ID.String()}
}

func manifestEnvelope(manifest environmente2ee.Manifest) ManifestEnvelope {
	return ManifestEnvelope{Version: manifest.Version, KeyEpoch: manifest.KeyEpoch, ManifestID: manifest.ID.String(), Envelope: encodeEnvelope(manifest.Raw)}
}

func ptrManifestEnvelope(manifest environmente2ee.Manifest) *ManifestEnvelope {
	value := manifestEnvelope(manifest)
	return &value
}

func encodeEnvelope(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func mustCryptoProcessor(t *testing.T, source environmentkey.Source, rootID string, root ed25519.PublicKey, hostKeyID string) *CryptoProcessor {
	t.Helper()
	processor, err := NewCryptoProcessor(CryptoProcessorConfig{AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1, HostKeyGeneration: 1, HostRecipientKeyID: hostKeyID, RootKeyID: rootID, RootPublicKey: root, Keys: source})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func openCryptoStore(t *testing.T, path string, source environmentkey.Source, rootID string, root ed25519.PublicKey, hostKeyID string) *Store {
	t.Helper()
	config := Config{Path: path, HighWaterPath: path + ".high-water", IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true, AccountID: "acct_01", MachineID: "machine_01", InstallationGeneration: 1, HostKeyGeneration: 1, HostRecipientKeyID: hostKeyID, GenesisMarker: &testGenesisMarker{path: testGenesisMarkerPath(path)}, Processor: mustCryptoProcessor(t, source, rootID, root, hostKeyID)}
	prepareTestGenesisMarker(t, config.GenesisMarker.(*testGenesisMarker))
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
