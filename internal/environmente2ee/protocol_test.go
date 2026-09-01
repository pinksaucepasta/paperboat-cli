package environmente2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type testIdentity struct {
	rootPrivate             ed25519.PrivateKey
	rootID                  string
	rootKeys                RootKeys
	managerSign             ed25519.PrivateKey
	managerRecipientPrivate []byte
	hostRecipientPrivate    []byte
	recoveryPrivate         []byte
	authority               Authority
}

func fixture(t *testing.T) testIdentity {
	t.Helper()
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	rootSum := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootSum[:])
	roots := RootKeys{rootID: rootPublic}
	now := time.Unix(1788134400, 0).UTC()
	cert, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "acct_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01", NoisePublicKey: [32]byte{1}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certRaw, _ := cert.MarshalBinary()
	managerSign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	managerSigID, _ := KeyIDEd25519(managerSign.Public().(ed25519.PublicKey))
	managerPrivate, managerPublic := deterministicRecipient(t, 4)
	managerRecipientID, _ := KeyIDX25519(managerPublic)
	managerRaw, err := SignKeyBinding(KeyBindingClaims{AccountID: "acct_01", SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: certRaw, SigningPublic: managerSign.Public().(ed25519.PublicKey), SigningKeyID: managerSigID, RecipientPublic: managerPublic, RecipientKeyID: managerRecipientID, NotBefore: uint64(now.Unix()), Serial: 1}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	hostCert, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "acct_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", NoisePublicKey: [32]byte{2}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	hostCertRaw, _ := hostCert.MarshalBinary()
	hostPrivate, hostPublic := deterministicRecipient(t, 6)
	hostID, _ := KeyIDX25519(hostPublic)
	hostRaw, err := SignKeyBinding(KeyBindingClaims{AccountID: "acct_01", SubjectKind: SubjectHost, SubjectID: "machine_01", SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: hostCertRaw, RecipientPublic: hostPublic, RecipientKeyID: hostID, NotBefore: uint64(now.Unix()), Serial: 1}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPrivate, recoveryPublic := deterministicRecipient(t, 7)
	recoveryID, _ := KeyIDX25519(recoveryPublic)
	recoveryRaw, err := SignKeyBinding(KeyBindingClaims{AccountID: "acct_01", SubjectKind: SubjectRecovery, SubjectID: "environment_recovery", SubjectGeneration: 1, KeyGeneration: 1, RecipientPublic: recoveryPublic, RecipientKeyID: recoveryID, NotBefore: uint64(now.Unix()), Serial: 1}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authorityRaw, err := SignAuthority(AuthorityClaims{AccountID: "acct_01", Generation: 1, OperationID: [16]byte{1}, BindingBytes: [][]byte{managerRaw, hostRaw, recoveryRaw}}, rootID, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ParseAuthority(authorityRaw, roots)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{rootPrivate: rootPrivate, rootID: rootID, rootKeys: roots, managerSign: managerSign, managerRecipientPrivate: managerPrivate, hostRecipientPrivate: hostPrivate, recoveryPrivate: recoveryPrivate, authority: authority}
}

func deterministicRecipient(t *testing.T, seed byte) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func TestKeyBindingAllowsDifferentAuthorizedEndpointAndBindingRoots(t *testing.T) {
	now := time.Unix(1788134400, 0).UTC()
	endpointRoot := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	bindingRoot := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	endpointPublic := endpointRoot.Public().(ed25519.PublicKey)
	bindingPublic := bindingRoot.Public().(ed25519.PublicKey)
	endpointDigest := sha256.Sum256(endpointPublic)
	bindingDigest := sha256.Sum256(bindingPublic)
	endpointID := "aek_" + hex.EncodeToString(endpointDigest[:])
	bindingID := "aek_" + hex.EncodeToString(bindingDigest[:])

	certificate, err := endpointidentity.Sign(endpointRoot, endpointidentity.Claims{
		AccountID: "acct_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01",
		NoisePublicKey: [32]byte{1}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x23}, 32)).Public().(ed25519.PublicKey),
		Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateRaw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, 32))
	signingID, _ := KeyIDEd25519(signing.Public().(ed25519.PublicKey))
	_, recipientPublic := deterministicRecipient(t, 0x25)
	recipientID, _ := KeyIDX25519(recipientPublic)
	raw, err := SignKeyBinding(KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: certificateRaw, SigningPublic: signing.Public().(ed25519.PublicKey), SigningKeyID: signingID,
		RecipientPublic: recipientPublic, RecipientKeyID: recipientID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, bindingID, bindingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeyBinding(raw, RootKeys{bindingID: bindingPublic}); err == nil {
		t.Fatal("binding accepted without the endpoint certificate root")
	}
	if _, err := ParseKeyBinding(raw, RootKeys{bindingID: bindingPublic, endpointID: endpointPublic}); err != nil {
		t.Fatalf("binding rejected with both authorized roots: %v", err)
	}
}

func TestAuthorityAllowsEndpointRootDistinctFromBindingRoot(t *testing.T) {
	now := time.Unix(1788134400, 0).UTC()
	endpointRoot := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	bindingRoot := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	defer clear(endpointRoot)
	defer clear(bindingRoot)
	endpointPublic := append(ed25519.PublicKey(nil), endpointRoot.Public().(ed25519.PublicKey)...)
	bindingPublic := append(ed25519.PublicKey(nil), bindingRoot.Public().(ed25519.PublicKey)...)
	defer clear(endpointPublic)
	defer clear(bindingPublic)
	endpointDigest := sha256.Sum256(endpointPublic)
	bindingDigest := sha256.Sum256(bindingPublic)
	endpointID := "aek_" + hex.EncodeToString(endpointDigest[:])
	bindingID := "aek_" + hex.EncodeToString(bindingDigest[:])
	roots := RootKeys{endpointID: endpointPublic, bindingID: bindingPublic}

	certificate, err := endpointidentity.Sign(endpointRoot, endpointidentity.Claims{
		AccountID: "acct_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01",
		NoisePublicKey: [32]byte{0x41}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)).Public().(ed25519.PublicKey),
		Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateRaw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificateRaw)
	managerSigning := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	defer clear(managerSigning)
	managerSigningID, err := KeyIDEd25519(managerSigning.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	_, managerRecipientPublic := deterministicRecipient(t, 0x44)
	managerRecipientID, err := KeyIDX25519(managerRecipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	managerBinding, err := SignKeyBinding(KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: certificateRaw, SigningPublic: managerSigning.Public().(ed25519.PublicKey), SigningKeyID: managerSigningID,
		RecipientPublic: managerRecipientPublic, RecipientKeyID: managerRecipientID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, bindingID, bindingRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(managerBinding)

	_, recoveryRecipientPublic := deterministicRecipient(t, 0x45)
	recoveryRecipientID, err := KeyIDX25519(recoveryRecipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	recoveryBinding, err := SignKeyBinding(KeyBindingClaims{
		AccountID: "acct_01", SubjectKind: SubjectRecovery, SubjectID: "environment_recovery", SubjectGeneration: 1, KeyGeneration: 1,
		RecipientPublic: recoveryRecipientPublic, RecipientKeyID: recoveryRecipientID, NotBefore: uint64(now.Unix()), Serial: 1,
	}, bindingID, bindingRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recoveryBinding)

	authorityRaw, err := SignAuthority(AuthorityClaims{
		AccountID: "acct_01", Generation: 1, OperationID: [16]byte{0x46},
		BindingBytes: [][]byte{managerBinding, recoveryBinding},
	}, bindingID, bindingRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(authorityRaw)
	if _, err := ParseAuthority(authorityRaw, roots); err != nil {
		t.Fatalf("authority rejected when endpoint and binding roots are both authorized: %v", err)
	}
	if _, err := ParseAuthority(authorityRaw, RootKeys{bindingID: bindingPublic}); err == nil {
		t.Fatal("authority accepted when the endpoint certificate root was absent")
	}
}

func TestAuthorityManifestRoundTripAndTamper(t *testing.T) {
	f := fixture(t)
	recipients, err := f.authority.ExpectedRecipients(ScopeGlobal, ScopeActive, "")
	if err != nil {
		t.Fatal(err)
	}
	scopeKey := bytes.Repeat([]byte{9}, 32)
	claims := ManifestClaims{AccountID: "acct_01", AuthorityGeneration: f.authority.Generation, AuthorityID: f.authority.ID, Scope: ScopeGlobal, State: ScopeActive, PreviousVersion: 0, Version: 1, KeyEpoch: 1, OperationID: [16]byte{2}, Mutation: MutationInitialize}
	raw, err := BuildManifest(BuildManifestInput{Claims: claims, Values: map[string][]byte{}, ScopeKey: scopeKey, Recipients: recipients, SignerKeyID: mustSigningID(t, f.managerSign), SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 2048))})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(raw, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSuccessor(nil, manifest, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestTransition(nil, manifest, nil, f.authority); err != nil {
		t.Fatal(err)
	}
	machineRecipients, err := f.authority.ExpectedRecipients(ScopeMachine, ScopeActive, "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	machineRaw, err := BuildManifest(BuildManifestInput{Claims: ManifestClaims{AccountID: "acct_01", AuthorityGeneration: f.authority.Generation, AuthorityID: f.authority.ID, Scope: ScopeMachine, MachineID: "machine_01", State: ScopeActive, PreviousVersion: 0, Version: 1, KeyEpoch: 1, OperationID: [16]byte{15}, Mutation: MutationInitialize}, Values: map[string][]byte{}, ScopeKey: scopeKey, Recipients: machineRecipients, SignerKeyID: mustSigningID(t, f.managerSign), SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{15}, 4096))})
	if err != nil {
		t.Fatal(err)
	}
	machineManifest, err := ParseManifest(machineRaw, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	hostBindingForBootstrap := findBinding(t, f.authority, SubjectHost, "machine_01")
	bootstrapRecipient := RecipientPrivate{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: 1, KeyID: hostBindingForBootstrap.RecipientKeyID, PrivateKey: f.hostRecipientPrivate}
	delivery, err := ValidateFirstHostDelivery(nil, f.authority, manifest, machineManifest, bootstrapRecipient)
	if err != nil || len(delivery.Effective) != 0 {
		t.Fatalf("genesis first-host delivery rejected: %v", err)
	}
	clearValues(delivery.Global.Values)
	clear(delivery.Global.ScopeKey)
	clearValues(delivery.Machine.Values)
	clear(delivery.Machine.ScopeKey)
	clearValues(delivery.Effective)
	latest, err := ValidateLatestAfterFirstDelivery(manifest, machineManifest, manifest, machineManifest, f.authority, f.authority, bootstrapRecipient)
	if err != nil || len(latest.Effective) != 0 {
		t.Fatalf("identical latest bootstrap pair rejected: %v", err)
	}
	clearValues(latest.Global.Values)
	clear(latest.Global.ScopeKey)
	clearValues(latest.Machine.Values)
	clear(latest.Machine.ScopeKey)
	clearValues(latest.Effective)
	forkedMachine := machineManifest
	forkedMachine.ID[0] ^= 1
	if _, err := ValidateLatestAfterFirstDelivery(manifest, machineManifest, manifest, forkedMachine, f.authority, f.authority, bootstrapRecipient); err == nil {
		t.Fatal("equal-version different-ID latest machine accepted")
	}
	wrongBootstrap := bootstrapRecipient
	wrongBootstrap.PrivateKey = f.recoveryPrivate
	if _, err := ValidateFirstHostDelivery(nil, f.authority, manifest, machineManifest, wrongBootstrap); err == nil {
		t.Fatal("first-host delivery opened by wrong private key")
	}
	if ValidateManifestTransition(nil, machineManifest, &f.authority, f.authority) == nil {
		t.Fatal("machine initialization outside its authority transition accepted")
	}
	managerBinding := findBinding(t, f.authority, SubjectManagerCLI, "cli_01")
	decrypted, err := DecryptManifest(manifest, RecipientPrivate{Kind: RecipientManager, SubjectID: "cli_01", KeyGeneration: 1, KeyID: managerBinding.RecipientKeyID, PrivateKey: f.managerRecipientPrivate})
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted.Values) != 0 || !bytes.Equal(decrypted.ScopeKey, scopeKey) {
		t.Fatal("unexpected decrypted scope")
	}
	clear(decrypted.ScopeKey)
	hostBinding := findBinding(t, f.authority, SubjectHost, "machine_01")
	if _, err := DecryptManifest(manifest, RecipientPrivate{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: 1, KeyID: hostBinding.RecipientKeyID, PrivateKey: f.recoveryPrivate}); err == nil {
		t.Fatal("wrong recipient decrypted")
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 1
	if _, err := ParseManifest(tampered, f.authority); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	setClaims := manifest.ManifestClaims
	setClaims.PreviousVersion = 1
	setClaims.Version = 2
	setClaims.OperationID = [16]byte{3}
	setClaims.Mutation = MutationSet
	setClaims.ChangedNames = []string{"APP_TOKEN"}
	setRaw, err := BuildManifest(BuildManifestInput{Claims: setClaims, Values: map[string][]byte{"APP_TOKEN": []byte("canary-value")}, ScopeKey: scopeKey, Recipients: recipients, SignerKeyID: mustSigningID(t, f.managerSign), SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{10}, 4096))})
	if err != nil {
		t.Fatal(err)
	}
	setManifest, err := ParseManifest(setRaw, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSuccessor(&manifest, setManifest, false); err != nil {
		t.Fatal(err)
	}
	opened, err := DecryptManifest(setManifest, RecipientPrivate{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: 1, KeyID: hostBinding.RecipientKeyID, PrivateKey: f.hostRecipientPrivate})
	if err != nil {
		t.Fatal(err)
	}
	if string(opened.Values["APP_TOKEN"]) != "canary-value" {
		t.Fatal("value mismatch")
	}
	clearValues(opened.Values)
	clear(opened.ScopeKey)

	nextAuthority := authorityWithoutSubject(t, f, SubjectHost, "machine_01", nil)
	nextRecipients, err := nextAuthority.ExpectedRecipients(ScopeGlobal, ScopeActive, "")
	if err != nil {
		t.Fatal(err)
	}
	rotateClaims := setManifest.ManifestClaims
	rotateClaims.AuthorityGeneration = nextAuthority.Generation
	rotateClaims.AuthorityID = nextAuthority.ID
	rotateClaims.PreviousVersion = setManifest.Version
	rotateClaims.Version++
	rotateClaims.KeyEpoch++
	rotateClaims.OperationID = [16]byte{12}
	rotateClaims.Mutation = MutationRotate
	rotateClaims.ChangedNames = nil
	rotatedRaw, err := BuildManifest(BuildManifestInput{Claims: rotateClaims, Values: openedCopy(map[string][]byte{"APP_TOKEN": []byte("canary-value")}), ScopeKey: bytes.Repeat([]byte{12}, 32), Recipients: nextRecipients, SignerKeyID: mustSigningID(t, f.managerSign), SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{12}, 4096))})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := ParseManifest(rotatedRaw, nextAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestTransition(&setManifest, rotated, &f.authority, nextAuthority); err != nil {
		t.Fatalf("valid removal rotation rejected: %v", err)
	}
	reauthorizeClaims := rotateClaims
	reauthorizeClaims.KeyEpoch = setManifest.KeyEpoch
	reauthorizeClaims.Mutation = MutationReauthorize
	reauthorizeRaw, err := BuildManifest(BuildManifestInput{Claims: reauthorizeClaims, Values: map[string][]byte{"APP_TOKEN": []byte("canary-value")}, ScopeKey: scopeKey, Recipients: nextRecipients, SignerKeyID: mustSigningID(t, f.managerSign), SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{13}, 4096))})
	if err != nil {
		t.Fatal(err)
	}
	reauthorized, err := ParseManifest(reauthorizeRaw, nextAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateManifestTransition(&setManifest, reauthorized, &f.authority, nextAuthority) == nil {
		t.Fatal("recipient removal without scope-key rotation accepted")
	}
}

func TestRootAuthorizedResetForAbsentScope(t *testing.T) {
	f := fixture(t)
	resets := []ResetScope{{Scope: ScopeMachine, MachineID: "machine_01"}}
	nextAuthority := authorityWithoutSubject(t, f, 0, "", resets)
	manager := findBinding(t, nextAuthority, SubjectManagerCLI, "cli_01")
	recipients, err := nextAuthority.ExpectedRecipients(ScopeMachine, ScopeActive, "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildManifest(BuildManifestInput{
		Claims: ManifestClaims{AccountID: "acct_01", AuthorityGeneration: nextAuthority.Generation, AuthorityID: nextAuthority.ID, Scope: ScopeMachine, MachineID: "machine_01", State: ScopeActive, PreviousVersion: 0, Version: 1, KeyEpoch: 1, OperationID: [16]byte{14}, Mutation: MutationReset},
		Values: map[string][]byte{}, ScopeKey: bytes.Repeat([]byte{14}, 32), Recipients: recipients,
		SignerKeyID: manager.SigningKeyID, SignerPrivate: f.managerSign, Random: bytes.NewReader(bytes.Repeat([]byte{14}, 4096)),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(raw, nextAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestTransition(nil, manifest, &f.authority, nextAuthority); err != nil {
		t.Fatalf("root-authorized absent reset rejected: %v", err)
	}
	nextAuthority.ResetScopes = nil
	if ValidateManifestTransition(nil, manifest, &f.authority, nextAuthority) == nil {
		t.Fatal("unsigned reset scope accepted")
	}
}

func TestHostLatestDeliveryRequiresRootAuthorizedReset(t *testing.T) {
	f := fixture(t)
	nextAuthority := authorityWithoutSubject(t, f, 0, "", []ResetScope{{Scope: ScopeGlobal}, {Scope: ScopeMachine, MachineID: "machine_01"}})
	manager := findBinding(t, nextAuthority, SubjectManagerCLI, "cli_01")
	recipientBinding := findBinding(t, nextAuthority, SubjectHost, "machine_01")
	recipient := RecipientPrivate{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: recipientBinding.KeyGeneration, KeyID: recipientBinding.RecipientKeyID, PrivateKey: f.hostRecipientPrivate}

	baseGlobal := buildTestManifest(t, f.authority, ScopeGlobal, "", 0, 1, 1, MutationInitialize, nil, bytes.Repeat([]byte{0x21}, 32), f.managerSign, manager)
	baseMachine := buildTestManifest(t, f.authority, ScopeMachine, "machine_01", 0, 1, 1, MutationInitialize, nil, bytes.Repeat([]byte{0x22}, 32), f.managerSign, manager)
	resetGlobal := buildTestManifest(t, nextAuthority, ScopeGlobal, "", baseGlobal.Version, baseGlobal.Version+1, baseGlobal.KeyEpoch+1, MutationReset, baseGlobal.Names, bytes.Repeat([]byte{0x23}, 32), f.managerSign, manager)
	resetMachine := buildTestManifest(t, nextAuthority, ScopeMachine, "machine_01", baseMachine.Version, baseMachine.Version+1, baseMachine.KeyEpoch+1, MutationReset, baseMachine.Names, bytes.Repeat([]byte{0x24}, 32), f.managerSign, manager)
	if _, err := ValidateLatestAfterFirstDelivery(baseGlobal, baseMachine, resetGlobal, resetMachine, f.authority, nextAuthority, recipient); err != nil {
		t.Fatalf("root-authorized host reset rejected: %v", err)
	}

	// A reset authority may also be the bootstrap authority for a host binding
	// that first appears in that same transition. The pair validator must not
	// reject the exact bootstrap pair merely because its authority generations
	// are equal.
	prior := authorityWithoutSubject(t, f, SubjectHost, "machine_01", nil)
	previousID := prior.ID
	hostBinding := findBinding(t, f.authority, SubjectHost, "machine_01")
	currentRaw, err := SignAuthority(AuthorityClaims{
		AccountID: prior.AccountID, Generation: prior.Generation + 1, PreviousID: &previousID,
		OperationID: [16]byte{0x27}, BindingBytes: append(append([][]byte(nil), prior.BindingBytes...), hostBinding.Raw),
		ResetScopes: []ResetScope{{Scope: ScopeGlobal}, {Scope: ScopeMachine, MachineID: "machine_01"}},
	}, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ParseAuthority(currentRaw, f.rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	currentManager := findBinding(t, current, SubjectManagerCLI, "cli_01")
	bootstrapGlobal := buildTestManifest(t, current, ScopeGlobal, "", 1, 2, 2, MutationReset, nil, bytes.Repeat([]byte{0x28}, 32), f.managerSign, currentManager)
	bootstrapMachine := buildTestManifest(t, current, ScopeMachine, "machine_01", 1, 2, 2, MutationReset, nil, bytes.Repeat([]byte{0x29}, 32), f.managerSign, currentManager)
	if _, err := ValidateFirstHostDelivery(&prior, current, bootstrapGlobal, bootstrapMachine, recipient); err != nil {
		t.Fatalf("root-authorized reset bootstrap rejected: %v", err)
	}
	if _, err := ValidateLatestAfterFirstDelivery(bootstrapGlobal, bootstrapMachine, bootstrapGlobal, bootstrapMachine, current, current, recipient); err != nil {
		t.Fatalf("exact root-authorized reset bootstrap pair rejected: %v", err)
	}
	sameAuthorityGlobal := buildTestManifest(t, current, ScopeGlobal, "", bootstrapGlobal.Version, bootstrapGlobal.Version+1, bootstrapGlobal.KeyEpoch+1, MutationReset, bootstrapGlobal.Names, bytes.Repeat([]byte{0x2a}, 32), f.managerSign, currentManager)
	sameAuthorityMachine := buildTestManifest(t, current, ScopeMachine, "machine_01", bootstrapMachine.Version, bootstrapMachine.Version+1, bootstrapMachine.KeyEpoch+1, MutationReset, bootstrapMachine.Names, bytes.Repeat([]byte{0x2b}, 32), f.managerSign, currentManager)
	if _, err := ValidateLatestAfterFirstDelivery(bootstrapGlobal, bootstrapMachine, sameAuthorityGlobal, sameAuthorityMachine, current, current, recipient); err == nil {
		t.Fatal("host accepted a new reset under the same authority")
	}
	invalidGenesisGlobal := buildTestManifest(t, nextAuthority, ScopeGlobal, "", 0, 1, 1, MutationReset, nil, bytes.Repeat([]byte{0x2f}, 32), f.managerSign, manager)
	invalidGenesisMachine := buildTestManifest(t, nextAuthority, ScopeMachine, "machine_01", 0, 1, 1, MutationReset, nil, bytes.Repeat([]byte{0x30}, 32), f.managerSign, manager)
	if _, err := ValidateLatestAfterFirstDelivery(baseGlobal, baseMachine, invalidGenesisGlobal, invalidGenesisMachine, f.authority, nextAuthority, recipient); err == nil {
		t.Fatal("host accepted reset genesis after bootstrap authority changed")
	}
	invalidInitializeGlobal := buildTestManifest(t, nextAuthority, ScopeGlobal, "", 0, 1, 1, MutationInitialize, nil, bytes.Repeat([]byte{0x31}, 32), f.managerSign, manager)
	invalidInitializeMachine := buildTestManifest(t, nextAuthority, ScopeMachine, "machine_01", 0, 1, 1, MutationInitialize, nil, bytes.Repeat([]byte{0x32}, 32), f.managerSign, manager)
	if _, err := ValidateLatestAfterFirstDelivery(baseGlobal, baseMachine, invalidInitializeGlobal, invalidInitializeMachine, f.authority, nextAuthority, recipient); err == nil {
		t.Fatal("host accepted initialize after bootstrap authority changed")
	}
	unauthorizedCurrentRaw, err := SignAuthority(AuthorityClaims{
		AccountID: prior.AccountID, Generation: prior.Generation + 1, PreviousID: &previousID,
		OperationID: [16]byte{0x2c}, BindingBytes: append(append([][]byte(nil), prior.BindingBytes...), hostBinding.Raw),
	}, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedCurrent, err := ParseAuthority(unauthorizedCurrentRaw, f.rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedCurrentManager := findBinding(t, unauthorizedCurrent, SubjectManagerCLI, "cli_01")
	unauthorizedBootstrapGlobal := buildTestManifest(t, unauthorizedCurrent, ScopeGlobal, "", 1, 2, 2, MutationReset, nil, bytes.Repeat([]byte{0x2d}, 32), f.managerSign, unauthorizedCurrentManager)
	unauthorizedBootstrapMachine := buildTestManifest(t, unauthorizedCurrent, ScopeMachine, "machine_01", 1, 2, 2, MutationReset, nil, bytes.Repeat([]byte{0x2e}, 32), f.managerSign, unauthorizedCurrentManager)
	if _, err := ValidateFirstHostDelivery(&prior, unauthorizedCurrent, unauthorizedBootstrapGlobal, unauthorizedBootstrapMachine, recipient); err == nil {
		t.Fatal("first host delivery accepted reset without root reset authorization")
	}

	unauthorizedAuthority := authorityWithoutSubject(t, f, 0, "", nil)
	unauthorizedManager := findBinding(t, unauthorizedAuthority, SubjectManagerCLI, "cli_01")
	unauthorizedGlobal := buildTestManifest(t, unauthorizedAuthority, ScopeGlobal, "", baseGlobal.Version, baseGlobal.Version+1, baseGlobal.KeyEpoch+1, MutationReset, baseGlobal.Names, bytes.Repeat([]byte{0x25}, 32), f.managerSign, unauthorizedManager)
	unauthorizedMachine := buildTestManifest(t, unauthorizedAuthority, ScopeMachine, "machine_01", baseMachine.Version, baseMachine.Version+1, baseMachine.KeyEpoch+1, MutationReset, baseMachine.Names, bytes.Repeat([]byte{0x26}, 32), f.managerSign, unauthorizedManager)
	if _, err := ValidateLatestAfterFirstDelivery(baseGlobal, baseMachine, unauthorizedGlobal, unauthorizedMachine, f.authority, unauthorizedAuthority, recipient); err == nil {
		t.Fatal("host accepted reset manifest without root reset authorization")
	}
}

func TestFirstHostDeliveryAcceptsRootAuthorizedResetForAbsentMachineScope(t *testing.T) {
	f := fixture(t)
	prior := authorityWithoutSubject(t, f, SubjectHost, "machine_01", nil)
	hostBinding := findBinding(t, f.authority, SubjectHost, "machine_01")
	previousID := prior.ID
	currentRaw, err := SignAuthority(AuthorityClaims{
		AccountID: prior.AccountID, Generation: prior.Generation + 1, PreviousID: &previousID,
		OperationID: [16]byte{0x31}, BindingBytes: append(append([][]byte(nil), prior.BindingBytes...), hostBinding.Raw),
		ResetScopes: []ResetScope{{Scope: ScopeMachine, MachineID: "machine_01"}},
	}, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ParseAuthority(currentRaw, f.rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	manager := findBinding(t, current, SubjectManagerCLI, "cli_01")
	global := buildTestManifest(t, current, ScopeGlobal, "", 1, 2, 1, MutationReauthorize, nil, bytes.Repeat([]byte{0x32}, 32), f.managerSign, manager)
	machine := buildTestManifest(t, current, ScopeMachine, "machine_01", 0, 1, 1, MutationReset, nil, bytes.Repeat([]byte{0x33}, 32), f.managerSign, manager)
	recipient := RecipientPrivate{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: hostBinding.KeyGeneration, KeyID: hostBinding.RecipientKeyID, PrivateKey: f.hostRecipientPrivate}
	delivery, err := ValidateFirstHostDelivery(&prior, current, global, machine, recipient)
	if err != nil {
		t.Fatalf("root-authorized absent machine reset rejected: %v", err)
	}
	clearValues(delivery.Global.Values)
	clear(delivery.Global.ScopeKey)
	clearValues(delivery.Machine.Values)
	clear(delivery.Machine.ScopeKey)
	clearValues(delivery.Effective)
}

func buildTestManifest(t *testing.T, authority Authority, scope ScopeKind, machineID string, previousVersion, version, keyEpoch uint64, mutation MutationKind, changedNames []string, scopeKey []byte, signer ed25519.PrivateKey, manager KeyBinding) Manifest {
	t.Helper()
	recipients, err := authority.ExpectedRecipients(scope, ScopeActive, machineID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildManifest(BuildManifestInput{
		Claims: ManifestClaims{AccountID: authority.AccountID, AuthorityGeneration: authority.Generation, AuthorityID: authority.ID, Scope: scope, MachineID: machineID, State: ScopeActive, PreviousVersion: previousVersion, Version: version, KeyEpoch: keyEpoch, OperationID: [16]byte{0x61, byte(scope), byte(version)}, Mutation: mutation, ChangedNames: append([]string(nil), changedNames...)},
		Values: map[string][]byte{}, ScopeKey: scopeKey, Recipients: recipients, SignerKeyID: manager.SigningKeyID, SignerPrivate: signer, Random: bytes.NewReader(bytes.Repeat([]byte{0x62}, 8192)),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(raw, authority)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestProtocolBounds(t *testing.T) {
	plain := bytes.Repeat([]byte{1}, MaximumScopeBytes)
	padded, err := padPlaintext(bytes.NewReader(bytes.Repeat([]byte{2}, 512<<10)), plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 512<<10 {
		t.Fatalf("256 KiB plaintext framed into %d-byte bucket", len(padded))
	}
	opened, err := unpadPlaintext(padded)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("maximum scope framing did not round trip")
	}
	tooLarge := append(plain, 1)
	if _, err := padPlaintext(bytes.NewReader(nil), tooLarge); err == nil {
		t.Fatal("oversized scope accepted")
	}
	f := fixture(t)
	manager := findBinding(t, f.authority, SubjectManagerCLI, "cli_01")
	request := EnrollmentRequest{AccountID: "acct_01", OperationID: [16]byte{4}, SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: bytes.Repeat([]byte{1}, MaximumEnrollmentBytes), SigningPublic: manager.SigningPublic, SigningKeyID: manager.SigningKeyID, RecipientPublic: manager.RecipientPublic, RecipientKeyID: manager.RecipientKeyID, RequestExpiresAt: 1788134700}
	if _, err := CanonicalEnrollmentRequest(request); err == nil {
		t.Fatal("oversized enrollment request accepted")
	}
}

func TestMergeScopes(t *testing.T) {
	merged, err := MergeScopes(
		map[string][]byte{"APP_REGION": []byte("global"), "APP_TOKEN": []byte("global")},
		map[string][]byte{"APP_TOKEN": []byte("machine")},
	)
	if err != nil || string(merged["APP_REGION"]) != "global" || string(merged["APP_TOKEN"]) != "machine" {
		t.Fatalf("valid override failed: values=%v err=%v", merged, err)
	}
	clearValues(merged)
	if _, err := MergeScopes(map[string][]byte{"Foo": []byte("global")}, map[string][]byte{"FOO": []byte("machine")}); err == nil {
		t.Fatal("cross-scope case-fold collision accepted")
	}
}

// This is the first encryption from the RFC 9180 Base-mode vector for
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.
func TestRFC9180RecipientVector(t *testing.T) {
	private, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(mustHex(t, "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(
		mustHex(t, "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"),
		private,
		hpke.HKDFSHA256(),
		hpke.AES256GCM(),
		mustHex(t, "4f6465206f6e2061204772656369616e2055726e"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(
		mustHex(t, "436f756e742d30"),
		mustHex(t, "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"),
	)
	if err != nil || !bytes.Equal(plaintext, mustHex(t, "4265617574792069732074727574682c20747275746820626561757479")) {
		t.Fatalf("RFC 9180 vector rejected: %v", err)
	}
}

func TestEnrollmentChallengeRecoveryAndTamper(t *testing.T) {
	f := fixture(t)
	binding := findBinding(t, f.authority, SubjectManagerCLI, "cli_01")
	request := EnrollmentRequest{AccountID: "acct_01", OperationID: [16]byte{4}, SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: binding.EndpointCertificate, SigningPublic: binding.SigningPublic, SigningKeyID: binding.SigningKeyID, RecipientPublic: binding.RecipientPublic, RecipientKeyID: binding.RecipientKeyID, RequestExpiresAt: 1788134700}
	signature, err := SignEnrollmentRequest(request, f.managerSign)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyEnrollmentRequestSignature(request, signature); err != nil {
		t.Fatal(err)
	}
	requestRaw, err := CanonicalEnrollmentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	parsedRequest, err := ParseEnrollmentRequest(requestRaw)
	if err != nil || parsedRequest.RecipientKeyID != request.RecipientKeyID {
		t.Fatalf("canonical enrollment request rejected: %v", err)
	}
	verifiedRequest, recomputedSafety, err := VerifyPendingEnrollment(requestRaw, signature)
	if err != nil || verifiedRequest.SubjectID != request.SubjectID {
		t.Fatalf("pending enrollment rejected: %v", err)
	}
	expectedSafety, _ := EnrollmentSafetyCode(request)
	if recomputedSafety != expectedSafety {
		t.Fatal("pending enrollment safety code mismatch")
	}
	if _, _, err := VerifyPendingEnrollment(requestRaw, nil); err == nil {
		t.Fatal("manager pending enrollment without proof accepted")
	}
	noncanonicalRequest := append([]byte{0x98, 0x0f}, requestRaw[1:]...)
	if _, err := ParseEnrollmentRequest(noncanonicalRequest); err == nil {
		t.Fatal("noncanonical enrollment request accepted")
	}
	signature[0] ^= 1
	if VerifyEnrollmentRequestSignature(request, signature) == nil {
		t.Fatal("tampered proof accepted")
	}
	code, err := EnrollmentSafetyCode(request)
	if err != nil || len(code) != 19 {
		t.Fatalf("code=%q err=%v", code, err)
	}
	digest, _ := EnrollmentRequestDigest(request)
	context := EnrollmentChallengeContext{AccountID: "acct_01", RequestID: "envreq_01", OperationID: request.OperationID, RecipientKeyID: request.RecipientKeyID, RequestDigest: digest}
	sealed, challenge, err := SealEnrollmentChallenge(context, request.RecipientPublic, bytes.NewReader(bytes.Repeat([]byte{11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEnrollmentChallenge(context, f.managerRecipientPrivate, sealed)
	if err != nil || !bytes.Equal(opened, challenge) {
		t.Fatal("challenge mismatch")
	}
	proof1, _ := EnrollmentProof(context, challenge)
	proof2, _ := EnrollmentProof(context, opened)
	if proof1 != proof2 {
		t.Fatal("proof mismatch")
	}
	sealed[40] ^= 1
	if _, err := OpenEnrollmentChallenge(context, f.managerRecipientPrivate, sealed); err == nil {
		t.Fatal("tampered challenge accepted")
	}
	clear(challenge)
	clear(opened)
	recovery, err := EncodeRecovery(f.recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecovery(recovery)
	expectedRecovery, _ := canonicalPrivate(f.recoveryPrivate)
	if err != nil || !bytes.Equal(decoded, expectedRecovery) {
		t.Fatal("recovery mismatch")
	}
	replacement := "a"
	if recovery[len(recovery)-1:] == replacement {
		replacement = "b"
	}
	bad := recovery[:len(recovery)-1] + replacement
	if _, err := DecodeRecovery(bad); err == nil {
		t.Fatal("bad recovery accepted")
	}
	clear(decoded)
}

func TestAuthorityTransitionAbortRoundTripAndTamper(t *testing.T) {
	f := fixture(t)
	transitionDigest := sha256.Sum256([]byte("staged-transition"))
	claims := AuthorityTransitionAbortClaims{
		AccountID: "acct_01", ActiveAuthorityID: f.authority.ID,
		TransitionID: DocumentID(transitionDigest), OperationID: [16]byte{18},
	}
	raw, err := SignAuthorityTransitionAbort(claims, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	abort, err := ParseAuthorityTransitionAbort(raw, f.rootKeys)
	if err != nil || abort.AccountID != claims.AccountID || abort.ActiveAuthorityID != claims.ActiveAuthorityID || abort.TransitionID != claims.TransitionID || abort.OperationID != claims.OperationID {
		t.Fatalf("abort round trip failed: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ParseAuthorityTransitionAbort(tampered, f.rootKeys); err == nil {
		t.Fatal("tampered abort accepted")
	}
	wrongRoots := RootKeys{"aek_" + strings.Repeat("0", 64): bytes.Repeat([]byte{1}, 32)}
	if _, err := ParseAuthorityTransitionAbort(raw, wrongRoots); err == nil {
		t.Fatal("abort signed by an unpinned root accepted")
	}
}

func TestCanonicalAndAuthorityRollbackRejection(t *testing.T) {
	f := fixture(t)
	if err := ValidateAuthorityTransition(nil, f.authority); err != nil {
		t.Fatal(err)
	}
	nextClaims := f.authority.AuthorityClaims
	nextClaims.Generation = 2
	id := f.authority.ID
	nextClaims.PreviousID = &id
	nextClaims.OperationID = [16]byte{9}
	nextRaw, err := SignAuthority(nextClaims, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseAuthority(nextRaw, f.rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityTransition(&f.authority, next); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityTransition(&next, f.authority); err == nil {
		t.Fatal("rollback accepted")
	}
	noncanonical := append([]byte{0xd8, 0x12}, f.authority.Raw...)
	if _, err := ParseAuthority(noncanonical, f.rootKeys); err == nil {
		t.Fatal("nested/noncanonical tag accepted")
	}
}

func mustSigningID(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	id, err := KeyIDEd25519(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func findBinding(t *testing.T, a Authority, kind SubjectKind, id string) KeyBinding {
	t.Helper()
	for _, b := range a.Bindings {
		if b.SubjectKind == kind && b.SubjectID == id {
			return b
		}
	}
	t.Fatal("binding missing")
	return KeyBinding{}
}

func authorityWithoutSubject(t *testing.T, f testIdentity, kind SubjectKind, id string, resets []ResetScope) Authority {
	t.Helper()
	bindings := make([][]byte, 0, len(f.authority.BindingBytes))
	for _, binding := range f.authority.Bindings {
		if binding.SubjectKind != kind || binding.SubjectID != id {
			bindings = append(bindings, binding.Raw)
		}
	}
	previous := f.authority.ID
	raw, err := SignAuthority(AuthorityClaims{AccountID: f.authority.AccountID, Generation: f.authority.Generation + 1, PreviousID: &previous, OperationID: [16]byte{11}, BindingBytes: bindings, ResetScopes: resets}, f.rootID, f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ParseAuthority(raw, f.rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func openedCopy(values map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(values))
	for key, value := range values {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
