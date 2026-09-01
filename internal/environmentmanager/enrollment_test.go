package environmentmanager

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

func TestCancelUnactivatedGenesisDeletesOrphanAndAllowsFreshIdentity(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)

	const subjectID = "cli_genesis"
	manager := Manager{Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: subjectID}
	orphan, err := fixture.store.CreateEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, subjectID, true)
	if err != nil {
		t.Fatal(err)
	}
	defer orphan.Clear()
	originalSigningSeed := append([]byte(nil), orphan.SigningSeed[:]...)
	defer clear(originalSigningSeed)
	if err := storePendingGenesisEnrollment(t, manager, orphan); err != nil {
		t.Fatal(err)
	}

	if err := manager.CancelManagerEnrollment(); err != nil {
		t.Fatalf("cancel unactivated genesis: %v", err)
	}
	if _, err := fixture.store.LoadEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, subjectID); !errors.Is(err, config.ErrSecretNotFound) {
		t.Fatalf("orphan identity after cancellation: %v", err)
	}
	if _, found, err := manager.loadPendingEnrollment(); err != nil || found {
		t.Fatalf("pending genesis after cancellation: found=%v err=%v", found, err)
	}

	fresh, err := fixture.store.CreateEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, subjectID, true)
	if err != nil {
		t.Fatalf("create fresh genesis identity: %v", err)
	}
	defer fresh.Clear()
	if bytes.Equal(originalSigningSeed, fresh.SigningSeed[:]) {
		t.Fatal("fresh genesis identity reused the canceled identity")
	}
}

func TestCancelGenesisNeverDeletesIdentityWithAuthorityHighWater(t *testing.T) {
	fixture := newManagerFixture(t)
	defer fixture.identity.Clear()
	defer clearAuthority(&fixture.control.authority)
	defer clearManifest(&fixture.control.manifest)

	const subjectID = "cli_highwater"
	manager := Manager{Store: fixture.store, Issuer: fixture.issuer, AccountID: fixture.accountID, SubjectID: subjectID}
	identity, err := fixture.store.CreateEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, subjectID, true)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	originalSigningSeed := append([]byte(nil), identity.SigningSeed[:]...)
	defer clear(originalSigningSeed)
	if err := storePendingGenesisEnrollment(t, manager, identity); err != nil {
		t.Fatal(err)
	}
	const authorityID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := fixture.store.CommitEnvironmentAuthorityHighWater(fixture.issuer, fixture.accountID, subjectID, 1, authorityID); err != nil {
		t.Fatal(err)
	}

	if err := manager.CancelManagerEnrollment(); !errors.Is(err, ErrTransitionIncomplete) {
		t.Fatalf("cancel genesis with authority high-water: %v", err)
	}
	retained, err := fixture.store.LoadEnvironmentManagerIdentity(fixture.issuer, fixture.accountID, subjectID)
	if err != nil {
		t.Fatalf("load retained identity: %v", err)
	}
	defer retained.Clear()
	if retained.AuthorityGeneration != 1 || retained.AuthorityID != authorityID || !bytes.Equal(retained.SigningSeed[:], originalSigningSeed) {
		t.Fatalf("identity was changed or deleted: generation=%d authority=%q", retained.AuthorityGeneration, retained.AuthorityID)
	}
	if _, found, err := manager.loadPendingEnrollment(); err != nil || !found {
		t.Fatalf("pending genesis after protected cancellation: found=%v err=%v", found, err)
	}
}

func storePendingGenesisEnrollment(t *testing.T, manager Manager, identity config.EnvironmentManagerIdentity) error {
	t.Helper()
	now := time.Unix(1_780_000_000, 0).UTC()
	signing := ed25519.NewKeyFromSeed(identity.SigningSeed[:])
	defer clear(signing)
	signingID, err := environmente2ee.KeyIDEd25519(signing.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	recipient, err := ecdh.X25519().NewPrivateKey(identity.RecipientPrivate[:])
	if err != nil {
		return err
	}
	recipientPublic := recipient.PublicKey().Bytes()
	defer clear(recipientPublic)
	recipientID, err := environmente2ee.KeyIDX25519(recipientPublic)
	if err != nil {
		return err
	}
	request := environmente2ee.EnrollmentRequest{
		AccountID: manager.AccountID, OperationID: [16]byte{0x51},
		SubjectKind: environmente2ee.SubjectManagerCLI, SubjectID: manager.SubjectID,
		SubjectGeneration: 1, KeyGeneration: uint64(identity.KeyGeneration),
		EndpointCertificate: []byte("endpoint-certificate"), SigningPublic: signing.Public().(ed25519.PublicKey), SigningKeyID: signingID,
		RecipientPublic: recipientPublic, RecipientKeyID: recipientID, RequestExpiresAt: uint64(now.Add(5 * time.Minute).Unix()),
	}
	canonical, err := environmente2ee.CanonicalEnrollmentRequest(request)
	if err != nil {
		return err
	}
	defer clear(canonical)
	signature, err := environmente2ee.SignEnrollmentRequest(request, signing)
	if err != nil {
		return err
	}
	defer clear(signature)
	endpoint := base64.RawURLEncoding.EncodeToString(request.EndpointCertificate)
	signingPublic := base64.RawURLEncoding.EncodeToString(request.SigningPublic)
	signingProof := base64.RawURLEncoding.EncodeToString(signature)
	return manager.storePendingEnrollment(pendingEnrollment{
		Schema: pendingEnrollmentSchema, AccountID: manager.AccountID, SubjectID: manager.SubjectID, Genesis: true,
		Request: api.EnvironmentKeyEnrollmentRequest{
			Schema: api.EnvironmentKeyEnrollmentSchemaV1, OperationID: "envop_" + hex.EncodeToString(request.OperationID[:]),
			SubjectKind: "manager_cli", SubjectID: manager.SubjectID, SubjectGeneration: 1, KeyGeneration: identity.KeyGeneration,
			EndpointCertificate: &endpoint, SigningPublicKey: &signingPublic, SigningKeyID: &signingID, SigningProof: &signingProof,
			RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipientPublic), RecipientKeyID: recipientID,
			RequestExpiresAt: now.Add(5 * time.Minute),
		},
		Canonical: base64.RawURLEncoding.EncodeToString(canonical),
	})
}
