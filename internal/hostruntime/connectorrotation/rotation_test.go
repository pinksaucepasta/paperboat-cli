package connectorrotation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type testKeyStore struct {
	mu       sync.Mutex
	keys     map[string]ed25519.PrivateKey
	puts     int
	deletes  []string
	next     int
	signErrs map[string]error
}

func newTestKeyStore() *testKeyStore {
	return &testKeyStore{keys: make(map[string]ed25519.PrivateKey), signErrs: make(map[string]error)}
}

func (s *testKeyStore) Put(_ context.Context, private ed25519.PrivateKey) (KeyReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	keyID, err := connectorprotocol.IdentityKeyID(public)
	if err != nil {
		return KeyReference{}, err
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		return KeyReference{}, err
	}
	reference := "keychain://paperboat/connectors/connector_1/rotation-" + formatTestInt(s.next)
	s.keys[reference] = append(ed25519.PrivateKey(nil), private...)
	s.puts++
	return KeyReference{Reference: reference, KeyID: keyID, Thumbprint: thumbprint, PublicKey: public}, nil
}

func (s *testKeyStore) putExisting(reference string, private ed25519.PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[reference] = append(ed25519.PrivateKey(nil), private...)
	return nil
}

func (s *testKeyStore) Sign(_ context.Context, reference string, payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.signErrs[reference]; err != nil {
		return nil, err
	}
	private, ok := s.keys[reference]
	if !ok {
		return nil, ErrKeyUnavailable
	}
	return ed25519.Sign(private, payload), nil
}

func (s *testKeyStore) setSignError(reference string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.signErrs, reference)
		return
	}
	s.signErrs[reference] = err
}

func (s *testKeyStore) Delete(_ context.Context, reference string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[reference]; !ok {
		return nil
	}
	delete(s.keys, reference)
	s.deletes = append(s.deletes, reference)
	return nil
}

func (s *testKeyStore) has(reference string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[reference]
	return ok
}

func (s *testKeyStore) private(reference string) ed25519.PrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append(ed25519.PrivateKey(nil), s.keys[reference]...)
}

type testInstaller struct {
	mu          sync.Mutex
	installs    []connectorprotocol.CredentialRotationInstall
	revokes     []connectorprotocol.CredentialRotationRevoke
	installErr  error
	revokeErr   error
	installOnce bool
	revokeOnce  bool
}

func (i *testInstaller) Install(_ context.Context, install connectorprotocol.CredentialRotationInstall) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.installErr != nil {
		err := i.installErr
		if i.installOnce {
			i.installErr = nil
		}
		return err
	}
	i.installs = append(i.installs, install)
	return nil
}

func (i *testInstaller) Revoke(_ context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.revokeErr != nil {
		err := i.revokeErr
		if i.revokeOnce {
			i.revokeErr = nil
		}
		return err
	}
	i.revokes = append(i.revokes, revoke)
	return nil
}

func (i *testInstaller) setRevokeError(err error, once bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.revokeErr = err
	i.revokeOnce = once
}

func (i *testInstaller) counts() (int, int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.installs), len(i.revokes)
}

type failingJournal struct {
	mu       sync.Mutex
	delegate Journal
	saves    int
	failAt   int
	failErr  error
}

func (j *failingJournal) Load(ctx context.Context, operationID string) (Record, error) {
	return j.delegate.Load(ctx, operationID)
}

func (j *failingJournal) Save(ctx context.Context, record Record) error {
	j.mu.Lock()
	j.saves++
	fail := j.failAt > 0 && j.saves == j.failAt
	err := j.failErr
	j.mu.Unlock()
	if fail {
		return err
	}
	return j.delegate.Save(ctx, record)
}

func (j *failingJournal) setFailure(saveNumber int, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failAt = saveNumber
	j.failErr = err
}

func formatTestInt(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[index:])
}

func testRotationFixture(t *testing.T) (*Manager, *testKeyStore, *testInstaller, connectorprotocol.CredentialRotationChallenge, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := fixedClock{now: now}
	keys := newTestKeyStore()
	oldPrivate := deterministicPrivate(7)
	oldReference := "keychain://paperboat/connectors/connector_1/current"
	if err := keys.putExisting(oldReference, oldPrivate); err != nil {
		t.Fatal(err)
	}
	oldID, err := connectorprotocol.IdentityKeyID(oldPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	oldThumbprint, err := connectorprotocol.IdentityThumbprint(oldPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := connectorprotocol.NewRotationPlan("account_1", "tunnel_1", "operation_1", []connectorprotocol.RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := connectorprotocol.CredentialRotationChallenge{
		AccountID: "account_1", TunnelID: "tunnel_1", OperationID: plan.OperationID,
		ConnectorID: "connector_1", HostID: "host_1", SessionID: "session_old",
		ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0],
		OldCredentialGeneration: 1, NewCredentialGeneration: 2, OldIdentityKeyID: oldID,
		OldIdentityKeyThumbprint: oldThumbprint, ChallengeNonce: "rotation-challenge-1",
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		OverlapUntil: now.Add(10 * time.Minute), NewCredentialValidUntil: now.Add(time.Hour),
	}
	installer := &testInstaller{}
	manager, err := New(Config{
		AccountID: "account_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", HostID: "host_1",
		OldCredentialReference: oldReference, OldIdentityKeyID: oldID, OldIdentityThumbprint: oldThumbprint,
		OldCredentialGeneration: 1, KeyStore: keys, Journal: NewMemoryJournal(), Installer: installer,
		Clock: clock, Random: bytes.NewReader(bytes.Repeat([]byte{13}, ed25519.SeedSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, keys, installer, challenge, now
}

func deterministicPrivate(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func TestGenerateReplacementKeyStoresOnlyReferenceAndPublicIdentity(t *testing.T) {
	keys := newTestKeyStore()
	key, err := GenerateReplacementKey(context.Background(), keys, bytes.NewReader(bytes.Repeat([]byte{1}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	if key.Reference == "" || len(key.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("incomplete safe key reference: %+v", key)
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private", "seed", "bearer", "token"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("safe key metadata contains %q: %s", forbidden, encoded)
		}
	}
}

func TestRotationPutBeforeJournalSaveCleansOrphan(t *testing.T) {
	manager, keys, _, challenge, _ := testRotationFixture(t)
	saveErr := errors.New("simulated crash before rotation journal commit")
	manager.config.Journal = &failingJournal{
		delegate: NewMemoryJournal(),
		failAt:   1,
		failErr:  saveErr,
	}
	if _, err := manager.AcceptChallenge(context.Background(), challenge); !errors.Is(err, saveErr) {
		t.Fatalf("challenge error=%v, want journal failure", err)
	}
	if _, ok := manager.Record(); ok {
		t.Fatal("failed journal save left an in-memory rotation record")
	}
	if keys.puts != 1 || len(keys.deletes) != 1 {
		t.Fatalf("orphan cleanup counts: puts=%d deletes=%v", keys.puts, keys.deletes)
	}
	if !keys.has("keychain://paperboat/connectors/connector_1/current") {
		t.Fatal("orphan cleanup deleted the current credential")
	}
}

func TestRotationHostLifecycleDualSignsInstallsReadiesAndRevokesExactly(t *testing.T) {
	manager, keys, installer, challenge, now := testRotationFixture(t)
	proof, err := manager.AcceptChallenge(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Validate(now); err != nil {
		t.Fatal(err)
	}
	if proof.NewCredentialReference == challenge.OldIdentityKeyID || proof.NewCredentialReference == "" {
		t.Fatalf("proof did not carry a new write-only reference: %+v", proof)
	}
	oldPublic := deterministicPrivate(7).Public().(ed25519.PublicKey)
	newPublic, err := base64.RawURLEncoding.Strict().DecodeString(proof.NewPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := connectorprotocol.CredentialRotationProofPayload(proof)
	if err != nil {
		t.Fatal(err)
	}
	oldSignature, err := connectorprotocol.DecodeProof(proof.OldSignedProof)
	if err != nil || !ed25519.Verify(oldPublic, payload, oldSignature) {
		t.Fatalf("old proof did not verify: err=%v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(newPublic), payload, mustDecodeProof(t, proof.NewSignedProof)) {
		t.Fatal("new proof did not verify")
	}
	frame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationProof, "request_rotation_1", proof)
	if err != nil {
		t.Fatal(err)
	}
	frameBytes, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	newPrivate := keys.private(proof.NewCredentialReference)
	for _, forbidden := range []string{
		"private", "bearer", base64.RawStdEncoding.EncodeToString(oldPublic),
		base64.RawStdEncoding.EncodeToString(deterministicPrivate(7)),
		base64.RawStdEncoding.EncodeToString(newPrivate),
	} {
		if strings.Contains(strings.ToLower(string(frameBytes)), strings.ToLower(forbidden)) {
			t.Fatalf("rotation frame contains forbidden value %q: %s", forbidden, frameBytes)
		}
	}

	install := connectorprotocol.CredentialRotationInstall{
		AccountID: proof.AccountID, TunnelID: proof.TunnelID, OperationID: proof.OperationID,
		ConnectorID: proof.ConnectorID, HostID: proof.HostID, SessionID: proof.SessionID,
		ProcessGeneration: proof.ProcessGeneration, TargetSetHash: proof.TargetSetHash,
		OldCredentialGeneration: proof.OldCredentialGeneration, NewCredentialGeneration: proof.NewCredentialGeneration,
		NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint,
		NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference,
		ChallengeNonce: proof.ChallengeNonce, OverlapUntil: challenge.OverlapUntil,
		NewCredentialValidUntil: proof.NewCredentialValidUntil, ReplacementProcessGeneration: 2,
	}
	ack, err := manager.AcceptInstall(context.Background(), install)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != connectorprotocol.RotationAckInstalled || !keys.has(challengeOldReference(t, manager)) {
		t.Fatalf("install ack/state: ack=%+v", ack)
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 0 {
		t.Fatalf("installer counts after install: installs=%d revokes=%d", installs, revokes)
	}
	wrongInstall := install
	wrongInstall.OperationID = "operation_wrong"
	if _, err := manager.AcceptInstall(context.Background(), wrongInstall); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("wrong operation install error=%v", err)
	}
	wrongInstall = install
	wrongInstall.OverlapUntil = wrongInstall.OverlapUntil.Add(time.Second)
	if _, err := manager.AcceptInstall(context.Background(), wrongInstall); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("altered overlap install error=%v", err)
	}
	if installs, _ := installer.counts(); installs != 1 {
		t.Fatalf("wrong operation install reached runtime: installs=%d", installs)
	}

	if _, err := manager.MarkReady(context.Background(), install.SessionID, install.ReplacementProcessGeneration, 2, "sha256:"+strings.Repeat("a", 64), true, true, true); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("old session/process readiness error=%v", err)
	}
	ready, err := manager.MarkReady(context.Background(), "session_new", 2, 2, "sha256:"+strings.Repeat("a", 64), true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if ready.NewCredentialReference != proof.NewCredentialReference || ready.PreviousSessionID != install.SessionID || ready.ProcessGeneration != 2 {
		t.Fatalf("readiness lost replacement metadata: %+v", ready)
	}

	wrong := connectorprotocol.CredentialRotationRevoke{
		AccountID: ready.AccountID, TunnelID: ready.TunnelID, OperationID: "operation_wrong", ConnectorID: ready.ConnectorID,
		HostID: ready.HostID, SessionID: ready.SessionID, ProcessGeneration: ready.ProcessGeneration,
		TargetSetHash: ready.TargetSetHash, OldCredentialGeneration: ready.OldCredentialGeneration,
		NewCredentialGeneration: ready.NewCredentialGeneration, RevokeNonce: "rotation-revoke-1",
		IssuedAt: now, Deadline: now.Add(connectorprotocol.DefaultAbortTimeout),
	}
	if _, err := manager.AcceptRevoke(context.Background(), wrong); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("wrong revoke accepted: %v", err)
	}
	wrongSession := wrong
	wrongSession.OperationID = ready.OperationID
	wrongSession.SessionID = "session_stale"
	if _, err := manager.AcceptRevoke(context.Background(), wrongSession); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("stale revoke session accepted: %v", err)
	}
	wrongProcess := wrongSession
	wrongProcess.SessionID = ready.SessionID
	wrongProcess.ProcessGeneration++
	if _, err := manager.AcceptRevoke(context.Background(), wrongProcess); !errors.Is(err, connectorprotocol.ErrIdentityMismatch) {
		t.Fatalf("stale revoke process accepted: %v", err)
	}
	if len(keys.deletes) != 0 {
		t.Fatalf("wrong revoke deleted old key: %v", keys.deletes)
	}

	revoke := wrong
	revoke.OperationID = ready.OperationID
	installer.setRevokeError(errors.New("replacement did not acknowledge revoke"), true)
	if _, err := manager.AcceptRevoke(context.Background(), revoke); !errors.Is(err, ErrRevocationFailed) {
		t.Fatalf("unacknowledged revoke error=%v", err)
	}
	if len(keys.deletes) != 0 {
		t.Fatalf("old key deleted before revoke acknowledgement: %v", keys.deletes)
	}
	ack, err = manager.AcceptRevoke(context.Background(), revoke)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != connectorprotocol.RotationAckRevoked || len(keys.deletes) != 1 || !keys.has(proof.NewCredentialReference) {
		t.Fatalf("revoke outcome: ack=%+v deletes=%v", ack, keys.deletes)
	}
	if keys.has(challengeOldReference(t, manager)) {
		t.Fatal("old key remained after exact revoke")
	}
	if _, err := manager.AcceptRevoke(context.Background(), revoke); err != nil {
		t.Fatalf("idempotent revoke failed: %v", err)
	}
	if len(keys.deletes) != 1 {
		t.Fatalf("idempotent revoke deleted twice: %v", keys.deletes)
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 1 {
		t.Fatalf("installer counts after revoke: installs=%d revokes=%d", installs, revokes)
	}
}

func mustDecodeProof(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := connectorprotocol.DecodeProof(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func challengeOldReference(t *testing.T, manager *Manager) string {
	t.Helper()
	record, ok := manager.Record()
	if !ok {
		t.Fatal("rotation record missing")
	}
	return record.OldCredentialReference
}

func TestRotationRestartRecoveryDoesNotGenerateOrInstallAgain(t *testing.T) {
	manager, keys, installer, challenge, _ := testRotationFixture(t)
	proof, err := manager.AcceptChallenge(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	install := installForProof(challenge, proof)
	if _, err := manager.AcceptInstall(context.Background(), install); err != nil {
		t.Fatal(err)
	}
	ready, err := manager.MarkReady(context.Background(), "session_new", 2, 4, "sha256:"+strings.Repeat("b", 64), true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	firstRecord, ok := manager.Record()
	if !ok {
		t.Fatal("first record missing")
	}
	putsBefore := keys.puts
	manager2, err := New(Config{
		AccountID: "account_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", HostID: "host_1",
		OldCredentialReference: firstRecord.OldCredentialReference, OldIdentityKeyID: firstRecord.OldIdentityKeyID,
		OldIdentityThumbprint: firstRecord.OldIdentityThumbprint, OldCredentialGeneration: 1,
		KeyStore: keys, Journal: manager.config.Journal, Installer: installer, Clock: fixedClock{firstRecord.UpdatedAt},
		Random: bytes.NewReader(bytes.Repeat([]byte{99}, ed25519.SeedSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
		t.Fatal(err)
	}
	gotRecord, ok := manager2.Record()
	if !ok || gotRecord.Phase != PhaseReady || gotRecord.NewKey.Reference != firstRecord.NewKey.Reference {
		t.Fatalf("recovered record: ok=%v record=%+v", ok, gotRecord)
	}
	if keys.puts != putsBefore {
		t.Fatalf("recovery generated replacement key: before=%d after=%d", putsBefore, keys.puts)
	}
	if got, err := manager2.AcceptInstall(context.Background(), install); err != nil || got.Status != connectorprotocol.RotationAckInstalled {
		t.Fatalf("replayed install: ack=%+v err=%v", got, err)
	}
	if got, err := manager2.MarkReady(context.Background(), ready.SessionID, ready.ProcessGeneration, ready.ConfigGeneration, ready.ConfigContentHash, true, true, true); err != nil || got.SessionID != ready.SessionID {
		t.Fatalf("replayed readiness: ready=%+v err=%v", got, err)
	}
	if installs, _ := installer.counts(); installs != 1 {
		t.Fatalf("recovery reinstalled key: installs=%d", installs)
	}
}

func TestRotationRechallengeAfterExpiryReusesStagedKey(t *testing.T) {
	manager, keys, _, challenge, _ := testRotationFixture(t)
	if _, err := manager.AcceptChallenge(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	firstRecord, ok := manager.Record()
	if !ok {
		t.Fatal("initial rotation record missing")
	}
	putsBefore := keys.puts
	refreshedNow := challenge.ExpiresAt.Add(time.Second)
	manager2Config := manager.config
	manager2Config.Clock = fixedClock{now: refreshedNow}
	manager2, err := New(manager2Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
		t.Fatal(err)
	}
	refreshed := challenge
	refreshed.SessionID = "session_old_2"
	refreshed.ProcessGeneration = 2
	refreshed.ChallengeNonce = "rotation-challenge-2"
	refreshed.IssuedAt = refreshedNow.Add(-time.Second)
	refreshed.ExpiresAt = refreshedNow.Add(time.Minute)
	proof, err := manager2.AcceptChallenge(context.Background(), refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if keys.puts != putsBefore {
		t.Fatalf("rechallenge generated a second key: before=%d after=%d", putsBefore, keys.puts)
	}
	if proof.SessionID != refreshed.SessionID || proof.ChallengeNonce != refreshed.ChallengeNonce {
		t.Fatalf("proof did not use refreshed challenge: %+v", proof)
	}
	if err := proof.Validate(refreshedNow); err != nil {
		t.Fatalf("refreshed proof validation: %v", err)
	}
	if got, ok := manager2.Record(); !ok || got.NewKey.Reference != firstRecord.NewKey.Reference || got.Phase != PhaseProofAccepted {
		t.Fatalf("rechallenge changed staged key or phase: ok=%v record=%+v", ok, got)
	}
	alteredPolicy := refreshed
	alteredPolicy.OverlapUntil = alteredPolicy.OverlapUntil.Add(time.Second)
	if _, err := manager2.AcceptChallenge(context.Background(), alteredPolicy); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("altered overlap policy accepted: %v", err)
	}
}

func TestRotationRestartRecoveryAtEveryDurablePhase(t *testing.T) {
	t.Run("challenged", func(t *testing.T) {
		manager, keys, _, challenge, _ := testRotationFixture(t)
		oldReference := manager.config.OldCredentialReference
		keys.setSignError(oldReference, errors.New("crash while signing"))
		if _, err := manager.AcceptChallenge(context.Background(), challenge); err == nil {
			t.Fatal("challenge unexpectedly succeeded")
		}
		record, ok := manager.Record()
		if !ok || record.Phase != PhaseChallenged {
			t.Fatalf("crash did not leave challenged journal phase: ok=%v record=%+v", ok, record)
		}
		keys.setSignError(oldReference, nil)
		manager2Config := manager.config
		manager2, err := New(manager2Config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager2.AcceptChallenge(context.Background(), challenge); err != nil {
			t.Fatal(err)
		}
		if keys.puts != 1 {
			t.Fatalf("challenged recovery generated another key: puts=%d", keys.puts)
		}
	})

	t.Run("proof-accepted", func(t *testing.T) {
		manager, keys, _, challenge, _ := testRotationFixture(t)
		if _, err := manager.AcceptChallenge(context.Background(), challenge); err != nil {
			t.Fatal(err)
		}
		manager2, err := New(manager.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager2.AcceptChallenge(context.Background(), challenge); err != nil {
			t.Fatal(err)
		}
		if keys.puts != 1 {
			t.Fatalf("proof recovery generated another key: puts=%d", keys.puts)
		}
	})

	t.Run("installed", func(t *testing.T) {
		manager, _, installer, challenge, _ := testRotationFixture(t)
		proof, err := manager.AcceptChallenge(context.Background(), challenge)
		if err != nil {
			t.Fatal(err)
		}
		install := installForProof(challenge, proof)
		if _, err := manager.AcceptInstall(context.Background(), install); err != nil {
			t.Fatal(err)
		}
		manager2, err := New(manager.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager2.AcceptInstall(context.Background(), install); err != nil {
			t.Fatal(err)
		}
		if installs, _ := installer.counts(); installs != 1 {
			t.Fatalf("installed recovery reinstalled key: installs=%d", installs)
		}
	})

	t.Run("ready", func(t *testing.T) {
		manager, _, _, challenge, _ := testRotationFixture(t)
		proof, err := manager.AcceptChallenge(context.Background(), challenge)
		if err != nil {
			t.Fatal(err)
		}
		install := installForProof(challenge, proof)
		if _, err := manager.AcceptInstall(context.Background(), install); err != nil {
			t.Fatal(err)
		}
		ready, err := manager.MarkReady(context.Background(), "session_new", 2, 9, "sha256:"+strings.Repeat("d", 64), true, true, true)
		if err != nil {
			t.Fatal(err)
		}
		manager2, err := New(manager.config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		replayed, err := manager2.MarkReady(context.Background(), ready.SessionID, ready.ProcessGeneration, ready.ConfigGeneration, ready.ConfigContentHash, true, true, true)
		if err != nil || replayed.SessionID != ready.SessionID {
			t.Fatalf("ready recovery: ready=%+v err=%v", replayed, err)
		}
	})

	t.Run("revoking-and-revoked", func(t *testing.T) {
		manager, keys, installer, challenge, now := testRotationFixture(t)
		journal := &failingJournal{delegate: NewMemoryJournal(), failAt: 6, failErr: errors.New("crash after old-key deletion")}
		manager.config.Journal = journal
		proof, err := manager.AcceptChallenge(context.Background(), challenge)
		if err != nil {
			t.Fatal(err)
		}
		install := installForProof(challenge, proof)
		if _, err := manager.AcceptInstall(context.Background(), install); err != nil {
			t.Fatal(err)
		}
		ready, err := manager.MarkReady(context.Background(), "session_new", 2, 10, "sha256:"+strings.Repeat("e", 64), true, true, true)
		if err != nil {
			t.Fatal(err)
		}
		revoke := revokeForReady(ready, now)
		if _, err := manager.AcceptRevoke(context.Background(), revoke); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("revoke crash error=%v", err)
		}
		record, ok := manager.Record()
		if !ok || record.Phase != PhaseRevoking {
			t.Fatalf("crash did not leave revoking phase: ok=%v record=%+v", ok, record)
		}
		if keys.has(manager.config.OldCredentialReference) {
			t.Fatal("old key remained after successful revoke acknowledgement")
		}
		journal.setFailure(0, nil)
		manager2Config := manager.config
		manager2Config.Clock = fixedClock{now: now}
		manager2, err := New(manager2Config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager2.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		if ack, err := manager2.AcceptRevoke(context.Background(), revoke); err != nil || ack.Status != connectorprotocol.RotationAckRevoked {
			t.Fatalf("revoking recovery: ack=%+v err=%v", ack, err)
		}
		manager3, err := New(manager2Config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager3.Recover(context.Background(), challenge.OperationID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager3.AcceptRevoke(context.Background(), revoke); err != nil {
			t.Fatal(err)
		}
		if len(keys.deletes) != 1 {
			t.Fatalf("terminal recovery deleted old key more than once: %v", keys.deletes)
		}
		if _, revokes := installer.counts(); revokes != 2 {
			t.Fatalf("expected one retryable revoke after crash, got %d", revokes)
		}
	})
}

func TestFileJournalPersistsSafeMetadataAcrossOpen(t *testing.T) {
	path := secureJournalPath(t)
	journal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, keys, installer, challenge, _ := testRotationFixture(t)
	manager.config.Journal = journal
	proof, err := manager.AcceptChallenge(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AcceptInstall(context.Background(), installForProof(challenge, proof)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.MarkReady(context.Background(), "session_new", 2, 1, "sha256:"+strings.Repeat("c", 64), true, true, true); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Load(context.Background(), challenge.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Phase != PhaseReady || recovered.NewKey.Reference == "" || recovered.Install == nil || recovered.Ready == nil {
		t.Fatalf("reopened journal lost metadata: %+v", recovered)
	}
	encoded, err := osReadFileForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private_key", "private", "bearer", "enrollment_token", "old_signed_proof", "new_signed_proof"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("journal persisted forbidden %q: %s", forbidden, encoded)
		}
	}
	oldPrivate := deterministicPrivate(7)
	newPrivate := keys.private(recovered.NewKey.Reference)
	for _, secret := range []string{
		base64.RawStdEncoding.EncodeToString(oldPrivate),
		base64.RawURLEncoding.EncodeToString(oldPrivate),
		base64.RawStdEncoding.EncodeToString(newPrivate),
		base64.RawURLEncoding.EncodeToString(newPrivate),
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("journal persisted private key bytes: %q", secret)
		}
	}
	if !keys.has(recovered.NewKey.Reference) {
		t.Fatal("new private key was not retained by key store")
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 0 {
		t.Fatalf("unexpected installer state: installs=%d revokes=%d", installs, revokes)
	}
}

func TestFileJournalRejectsCorruptionAndUnsafePermissions(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{name: "duplicate-key", data: `{"version":1,"version":1,"records":[],"checksum":"sha256:` + strings.Repeat("0", 64) + `"}`},
		{name: "wrong-checksum", data: `{"version":1,"records":[],"checksum":"sha256:` + strings.Repeat("0", 64) + `"}`},
		{name: "trailing-json", data: `{"version":1,"records":[],"checksum":"sha256:` + strings.Repeat("0", 64) + `"}{}`},
		{name: "unknown-field", data: `{"version":1,"records":[],"checksum":"sha256:` + strings.Repeat("0", 64) + `","unexpected":true}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := secureJournalPath(t)
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileJournal(path); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("OpenFileJournal error=%v, want corruption", err)
			}
		})
	}

	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not enforced on Windows")
	}
	path := secureJournalPath(t)
	journal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, _, _, challenge, _ := testRotationFixture(t)
	manager.config.Journal = journal
	if _, err := manager.AcceptChallenge(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(path); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("permissive journal mode accepted: %v", err)
	}
}

func TestFileJournalRecoversLastKnownGoodAndRepairsAtomically(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission and rename semantics are platform-specific")
	}
	path := secureJournalPath(t)
	journal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, _, _, challenge, _ := testRotationFixture(t)
	manager.config.Journal = journal
	proof, err := manager.AcceptChallenge(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AcceptInstall(context.Background(), installForProof(challenge, proof)); err != nil {
		t.Fatal(err)
	}
	if record, ok := manager.Record(); !ok || record.Phase != PhaseInstalled {
		t.Fatalf("initial record: ok=%v record=%+v", ok, record)
	}
	// The install transition creates a last-known-good backup of proof acceptance.
	backupPath := path + ".bak"
	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode=%o, want 600", backupInfo.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoveredJournal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := recoveredJournal.Load(context.Background(), challenge.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Phase != PhaseProofAccepted {
		t.Fatalf("last-known-good phase=%s, want proof accepted", recovered.Phase)
	}
	if err := recoveredJournal.Save(context.Background(), recovered); err != nil {
		t.Fatal(err)
	}
	repaired, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repaired.Load(context.Background(), challenge.OperationID); err != nil || got.Phase != PhaseProofAccepted {
		t.Fatalf("repaired journal: record=%+v err=%v", got, err)
	}
}

func TestFileJournalSaveFailureDoesNotMutateMemoryOrDisk(t *testing.T) {
	path := secureJournalPath(t)
	journal, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, _, _, challenge, _ := testRotationFixture(t)
	manager.config.Journal = journal
	if _, err := manager.AcceptChallenge(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := manager.Record()
	if !ok {
		t.Fatal("record missing")
	}
	// A directory destination makes atomicfile fail before replacing the real
	// journal. The in-memory map must remain at the last committed phase.
	journal.path = t.TempDir()
	record.Phase = PhaseChallenged
	if err := journal.Save(context.Background(), record); !errors.Is(err, ErrJournalUncertain) {
		t.Fatalf("save failure=%v, want uncertain outcome", err)
	}
	if !okRecordPhase(journal, challenge.OperationID, PhaseProofAccepted) {
		t.Fatal("failed save changed in-memory record")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed save changed the committed journal bytes")
	}
}

func okRecordPhase(journal *FileJournal, operationID string, phase Phase) bool {
	record, err := journal.Load(context.Background(), operationID)
	return err == nil && record.Phase == phase
}

func installForProof(challenge connectorprotocol.CredentialRotationChallenge, proof connectorprotocol.CredentialRotationProof) connectorprotocol.CredentialRotationInstall {
	return connectorprotocol.CredentialRotationInstall{
		AccountID: proof.AccountID, TunnelID: proof.TunnelID, OperationID: proof.OperationID,
		ConnectorID: proof.ConnectorID, HostID: proof.HostID, SessionID: proof.SessionID,
		ProcessGeneration: proof.ProcessGeneration, TargetSetHash: proof.TargetSetHash,
		OldCredentialGeneration: proof.OldCredentialGeneration, NewCredentialGeneration: proof.NewCredentialGeneration,
		NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint,
		NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference,
		ChallengeNonce: proof.ChallengeNonce, OverlapUntil: challenge.OverlapUntil,
		NewCredentialValidUntil: proof.NewCredentialValidUntil, ReplacementProcessGeneration: proof.ProcessGeneration + 1,
	}
}

func revokeForReady(ready connectorprotocol.CredentialRotationReady, now time.Time) connectorprotocol.CredentialRotationRevoke {
	return connectorprotocol.CredentialRotationRevoke{
		AccountID: ready.AccountID, TunnelID: ready.TunnelID, OperationID: ready.OperationID,
		ConnectorID: ready.ConnectorID, HostID: ready.HostID, SessionID: ready.SessionID,
		ProcessGeneration: ready.ProcessGeneration, TargetSetHash: ready.TargetSetHash,
		OldCredentialGeneration: ready.OldCredentialGeneration, NewCredentialGeneration: ready.NewCredentialGeneration,
		RevokeNonce: "rotation-revoke-1", IssuedAt: now, Deadline: now.Add(connectorprotocol.DefaultAbortTimeout),
	}
}

func osReadFileForTest(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func secureJournalPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "connector-rotation.json")
}
