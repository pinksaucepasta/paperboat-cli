package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func rotationKey(seedByte byte) (ed25519.PrivateKey, string, string) {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seedByte}), ed25519.SeedSize)))
	public := private.Public().(ed25519.PublicKey)
	thumbprint, _ := IdentityThumbprint(public)
	return private, "ed25519:" + thumbprint, thumbprint
}

func rotationProofFor(t *testing.T, challenge CredentialRotationChallenge, oldPrivate, newPrivate ed25519.PrivateKey, reference string, issuedAt time.Time) CredentialRotationProof {
	t.Helper()
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	newKeyID, _ := IdentityKeyID(newPublic)
	newThumbprint, _ := IdentityThumbprint(newPublic)
	proof := CredentialRotationProof{
		AccountID: challenge.AccountID, TunnelID: challenge.TunnelID, OperationID: challenge.OperationID,
		ConnectorID: challenge.ConnectorID, HostID: challenge.HostID, SessionID: challenge.SessionID, ProcessGeneration: challenge.ProcessGeneration,
		TargetSetHash: challenge.TargetSetHash, OldCredentialGeneration: challenge.OldCredentialGeneration,
		NewCredentialGeneration: challenge.NewCredentialGeneration, OldIdentityKeyID: challenge.OldIdentityKeyID,
		OldIdentityKeyThumbprint: challenge.OldIdentityKeyThumbprint, NewIdentityKeyID: newKeyID,
		NewIdentityKeyThumbprint: newThumbprint, NewPublicKey: base64.RawURLEncoding.EncodeToString(newPublic),
		NewCredentialReference: reference, ChallengeNonce: challenge.ChallengeNonce, IssuedAt: issuedAt, NewCredentialValidUntil: challenge.NewCredentialValidUntil,
	}
	proof, err := SignCredentialRotationProof(proof, func(payload []byte) []byte { return ed25519.Sign(oldPrivate, payload) }, func(payload []byte) []byte { return ed25519.Sign(newPrivate, payload) })
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func rotationVerifier(keys map[string]ed25519.PrivateKey) RotationOldProofVerifier {
	return func(_ context.Context, proof CredentialRotationProof, payload, signature []byte) error {
		private, ok := keys[proof.OldIdentityKeyID]
		if !ok || !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
			return ErrAuthenticationFailed
		}
		return nil
	}
}

func TestCredentialRotationAggregateRequiresAllReplacementSessionsAndRevokes(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	oldOne, oldOneID, oldOneThumbprint := rotationKey(11)
	oldTwo, oldTwoID, oldTwoThumbprint := rotationKey(12)
	newOne, _, _ := rotationKey(21)
	newTwo, _, _ := rotationKey(22)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_1", []RotationTarget{
		{ConnectorID: "connector_2", HostID: "host_2", OldCredentialGeneration: 8, NewCredentialGeneration: 9},
		{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 3, NewCredentialGeneration: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: clock, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldOneID: oldOne, oldTwoID: oldTwo})})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	challengeOne, err := coordinator.Challenge(context.Background(), "connector_1", "sess_old_1", 7, oldOneID, oldOneThumbprint, "nonce-rotation-one", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	challengeTwo, err := coordinator.Challenge(context.Background(), "connector_2", "sess_old_2", 4, oldTwoID, oldTwoThumbprint, "nonce-rotation-two", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	proofOne := rotationProofFor(t, challengeOne, oldOne, newOne, "keychain://paperboat/rotation/connector_1", now.Add(time.Second))
	proofTwo := rotationProofFor(t, challengeTwo, oldTwo, newTwo, "keychain://paperboat/rotation/connector_2", now.Add(time.Second))
	installOne, ackOne, err := coordinator.AcceptProof(context.Background(), proofOne)
	if err != nil || ackOne.Status != RotationAckInstalled {
		t.Fatalf("connector one proof install=%+v err=%v", installOne, err)
	}
	if _, err := coordinator.HandleAck(context.Background(), ackOne); err != nil {
		t.Fatalf("connector one install acknowledgement err=%v", err)
	}
	installTwo, ackTwo, err := coordinator.AcceptProof(context.Background(), proofTwo)
	if err != nil || ackTwo.Status != RotationAckInstalled {
		t.Fatalf("connector two proof install=%+v err=%v", installTwo, err)
	}
	if _, err := coordinator.HandleAck(context.Background(), ackTwo); err != nil {
		t.Fatalf("connector two install acknowledgement err=%v", err)
	}
	readyOne := CredentialRotationReady{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: "sess_new_1", PreviousSessionID: installOne.SessionID, ProcessGeneration: installOne.ReplacementProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: installOne.OldCredentialGeneration, NewCredentialGeneration: installOne.NewCredentialGeneration, NewIdentityKeyID: installOne.NewIdentityKeyID, NewIdentityKeyThumbprint: installOne.NewIdentityKeyThumbprint, NewPublicKey: installOne.NewPublicKey, NewCredentialReference: installOne.NewCredentialReference, NewCredentialValidUntil: installOne.NewCredentialValidUntil, ConfigGeneration: 2, ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: now.Add(2 * time.Second)}
	readyTwo := readyOne
	readyTwo.ConnectorID = "connector_2"
	readyTwo.HostID = "host_2"
	readyTwo.SessionID = "sess_new_2"
	readyTwo.PreviousSessionID = installTwo.SessionID
	readyTwo.ProcessGeneration = installTwo.ReplacementProcessGeneration
	readyTwo.OldCredentialGeneration = installTwo.OldCredentialGeneration
	readyTwo.NewCredentialGeneration = installTwo.NewCredentialGeneration
	readyTwo.NewIdentityKeyID = installTwo.NewIdentityKeyID
	readyTwo.NewIdentityKeyThumbprint = installTwo.NewIdentityKeyThumbprint
	readyTwo.NewPublicKey = installTwo.NewPublicKey
	readyTwo.NewCredentialReference = installTwo.NewCredentialReference
	readyAckOne, err := coordinator.MarkReady(context.Background(), readyOne)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.HandleAck(context.Background(), readyAckOne); err != nil {
		t.Fatalf("connector one ready acknowledgement err=%v", err)
	}
	if _, err := coordinator.Revoke(context.Background(), "connector_1"); !errors.Is(err, ErrCredentialRotationNotReady) {
		t.Fatalf("early revoke error=%v", err)
	}
	readyAckTwo, err := coordinator.MarkReady(context.Background(), readyTwo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.HandleAck(context.Background(), readyAckTwo); err != nil {
		t.Fatalf("connector two ready acknowledgement err=%v", err)
	}
	revokeOne, err := coordinator.Revoke(context.Background(), "connector_1")
	if err != nil {
		t.Fatal(err)
	}
	revokeTwo, err := coordinator.Revoke(context.Background(), "connector_2")
	if err != nil {
		t.Fatal(err)
	}
	summary, err := coordinator.HandleAck(context.Background(), CredentialRotationAck{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: revokeOne.SessionID, ProcessGeneration: revokeOne.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: revokeOne.OldCredentialGeneration, NewCredentialGeneration: revokeOne.NewCredentialGeneration, Status: RotationAckRevoked})
	if err != nil || summary.Status != RotationAggregatePending {
		t.Fatalf("first revoke summary=%+v err=%v", summary, err)
	}
	summary, err = coordinator.HandleAck(context.Background(), CredentialRotationAck{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_2", HostID: "host_2", SessionID: revokeTwo.SessionID, ProcessGeneration: revokeTwo.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: revokeTwo.OldCredentialGeneration, NewCredentialGeneration: revokeTwo.NewCredentialGeneration, Status: RotationAckRevoked})
	if err != nil || summary.Status != RotationAggregateSucceeded || summary.CompletedAt.IsZero() {
		t.Fatalf("aggregate revoke summary=%+v err=%v", summary, err)
	}
	if len(store.Started) != 1 || len(store.Challenges) != 2 || len(store.Proofs) != 2 || len(store.Readiness) != 2 || len(store.Revocations) != 2 || len(store.Results) != 2 {
		t.Fatalf("durable rotation transitions started=%d challenges=%d proofs=%d ready=%d revoke=%d results=%d", len(store.Started), len(store.Challenges), len(store.Proofs), len(store.Readiness), len(store.Revocations), len(store.Results))
	}
}

func TestCredentialRotationRejectsReplayAndCrossSessionProofs(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(31)
	newPrivate, _, _ := rotationKey(32)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_2", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate})})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	challenge, err := coordinator.Challenge(context.Background(), "connector_1", "sess_old", 1, oldID, oldThumbprint, "nonce-replay-proof", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/connector_1", now.Add(time.Second))
	proof.SessionID = "sess_wrong"
	if _, _, err := coordinator.AcceptProof(context.Background(), proof); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("cross-session proof error=%v", err)
	}
	proof.SessionID = challenge.SessionID
	install, _, err := coordinator.AcceptProof(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.AcceptProof(context.Background(), proof); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("proof replay error=%v", err)
	}
	ready := CredentialRotationReady{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: "sess_new", PreviousSessionID: install.SessionID, ProcessGeneration: install.ReplacementProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: install.OldCredentialGeneration, NewCredentialGeneration: install.NewCredentialGeneration, NewIdentityKeyID: install.NewIdentityKeyID, NewIdentityKeyThumbprint: install.NewIdentityKeyThumbprint, NewPublicKey: install.NewPublicKey, NewCredentialReference: install.NewCredentialReference, NewCredentialValidUntil: install.NewCredentialValidUntil, ConfigGeneration: 1, ConfigContentHash: "sha256:" + strings.Repeat("b", 64), EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: now.Add(2 * time.Second)}
	if _, err := coordinator.MarkReady(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.MarkReady(context.Background(), ready); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("readiness replay error=%v", err)
	}
}

func TestCredentialRotationPersistenceFailureFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(41)
	newPrivate, _, _ := rotationKey(42)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_3", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate})})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	challenge, err := coordinator.Challenge(context.Background(), "connector_1", "sess_old", 1, oldID, oldThumbprint, "nonce-persistence", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	store.Failure = errors.New("database unavailable")
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/connector_1", now.Add(time.Second))
	if _, _, err := coordinator.AcceptProof(context.Background(), proof); !errors.Is(err, ErrCredentialRotationFailed) {
		t.Fatalf("persistence failure error=%v", err)
	}
	if got := coordinator.Summary().Targets[0].State; got != RotationTargetFailed {
		t.Fatalf("failed target state=%q", got)
	}
}

func TestCredentialRotationFramesUseStrictWireValidation(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(51)
	newPrivate, _, _ := rotationKey(52)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_frame", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := CredentialRotationChallenge{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: "sess_old", ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0], OldCredentialGeneration: 1, NewCredentialGeneration: 2, OldIdentityKeyID: oldID, OldIdentityKeyThumbprint: oldThumbprint, ChallengeNonce: "nonce-frame-rotation", IssuedAt: now, ExpiresAt: now.Add(time.Minute), OverlapUntil: now.Add(10 * time.Minute), NewCredentialValidUntil: now.Add(365 * 24 * time.Hour)}
	frame, err := NewFrame(MessageCredentialRotationChallenge, "req_rotation", challenge)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CredentialRotationChallenge
	if err := frame.DecodePayload(&decoded); err != nil || decoded.TargetSetHash != plan.TargetSetHash {
		t.Fatalf("decoded challenge=%+v err=%v", decoded, err)
	}
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/connector_1", now.Add(time.Second))
	if _, err := NewFrame(MessageCredentialRotationProof, "req_rotation_proof", proof); err != nil {
		t.Fatal(err)
	}
	bad := proof
	bad.NewIdentityKeyThumbprint = strings.Repeat("a", 43)
	if _, err := NewFrame(MessageCredentialRotationProof, "req_rotation_bad", bad); err == nil {
		t.Fatal("mismatched rotation key accepted")
	}
}

func TestCredentialRotationRecoveryRejectsDuplicateAndImpossiblePhases(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_recovery", []RotationTarget{
		{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2},
		{ConnectorID: "connector_2", HostID: "host_2", OldCredentialGeneration: 1, NewCredentialGeneration: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := &MemoryRotationPersistence{}
	loaded := RotationResume{Plan: plan, Started: true, Targets: []RotationResumeTarget{
		{Target: plan.Targets[0], State: RotationTargetPending},
		{Target: plan.Targets[0], State: RotationTargetPending},
	}}
	store := &recoveryRotationStore{MemoryRotationPersistence: base, loaded: loaded}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: func(context.Context, CredentialRotationProof, []byte, []byte) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("duplicate recovery error=%v", err)
	}
	loaded.Targets = []RotationResumeTarget{
		{Target: plan.Targets[0], State: RotationTargetReady, Challenge: CredentialRotationChallenge{SessionID: "sess_old"}},
		{Target: plan.Targets[1], State: RotationTargetPending},
	}
	store.loaded = loaded
	if err := coordinator.Resume(context.Background()); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("impossible recovery phase error=%v", err)
	}
}

func TestCredentialRotationRecoveryRejectsFinishedTimestampBeforeAllTargetsRevoke(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_finished", []RotationTarget{
		{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryRotationStore{
		MemoryRotationPersistence: &MemoryRotationPersistence{},
		loaded: RotationResume{
			Plan: plan, Started: true, FinishedAt: now,
			Targets: []RotationResumeTarget{{Target: plan.Targets[0], State: RotationTargetPending}},
		},
	}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: func(context.Context, CredentialRotationProof, []byte, []byte) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("inconsistent finished recovery error=%v", err)
	}
}

func TestCredentialRotationRecoveryAcceptsDurableFailedAggregate(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_failed_recovery", []RotationTarget{
		{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2},
		{ConnectorID: "connector_2", HostID: "host_2", OldCredentialGeneration: 1, NewCredentialGeneration: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryRotationStore{
		MemoryRotationPersistence: &MemoryRotationPersistence{},
		loaded: RotationResume{
			Plan: plan, Started: true, FinishedAt: now,
			Targets: []RotationResumeTarget{
				{Target: plan.Targets[0], State: RotationTargetFailed, Code: CodeCredentialRotationFailed},
				{Target: plan.Targets[1], State: RotationTargetPending},
			},
		},
	}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: func(context.Context, CredentialRotationProof, []byte, []byte) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); err != nil {
		t.Fatalf("failed aggregate recovery rejected: %v", err)
	}
	summary := coordinator.Summary()
	if summary.Status != RotationAggregateFailed || !summary.CompletedAt.IsZero() {
		t.Fatalf("failed recovery summary=%+v", summary)
	}
}

type recoveryRotationStore struct {
	*MemoryRotationPersistence
	loaded RotationResume
}

func (s *recoveryRotationStore) LoadCredentialRotation(context.Context, RotationPlan) (RotationResume, error) {
	return s.loaded, nil
}

func TestCredentialRotationNegativeAckBindsCurrentSessionAndPreservesTerminalState(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(61)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_negative", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: &testClock{now: now}, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate})})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	challenge, err := coordinator.Challenge(context.Background(), "connector_1", "sess_old", 3, oldID, oldThumbprint, "nonce-negative-rotation", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	bad := CredentialRotationAck{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: "other-session", ProcessGeneration: challenge.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: 1, NewCredentialGeneration: 2, Status: RotationAckRejected, Code: CodeCredentialRotationRejected}
	if _, err := coordinator.HandleAck(context.Background(), bad); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong-session negative ack error=%v", err)
	}
	good := bad
	good.SessionID = challenge.SessionID
	summary, err := coordinator.HandleAck(context.Background(), good)
	if !errors.Is(err, ErrCredentialRotationFailed) || summary.Status != RotationAggregateFailed {
		t.Fatalf("negative ack summary=%+v err=%v", summary, err)
	}
	if _, err := coordinator.Fail(context.Background(), "connector_1", CodeCredentialRotationFailed); !errors.Is(err, ErrCredentialRotationFailed) {
		t.Fatalf("terminal fail overwrite error=%v", err)
	}
}

func TestCredentialRotationExpiredChallengeCanBeReissuedForNewSession(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	_, oldID, oldThumbprint := rotationKey(65)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_rechallenge", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: store, Clock: clock, VerifyOldProof: func(context.Context, CredentialRotationProof, []byte, []byte) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Challenge(context.Background(), "connector_1", "old-session", 1, oldID, oldThumbprint, "nonce-rechallenge-one", now, now.Add(time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	second, err := coordinator.Challenge(context.Background(), "connector_1", "new-session", 2, oldID, oldThumbprint, "nonce-rechallenge-two", clock.Now(), clock.Now().Add(time.Minute), clock.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionID == first.SessionID || second.ChallengeNonce == first.ChallengeNonce || len(store.Challenges) != 2 {
		t.Fatalf("challenge was not renewed: first=%+v second=%+v count=%d", first, second, len(store.Challenges))
	}
}

func TestVerifyCredentialRotationProofAtRejectsStaleProof(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(71)
	newPrivate, _, _ := rotationKey(72)
	plan, err := NewRotationPlan("acct_1", "tunnel_1", "op_rotate_freshness", []RotationTarget{{ConnectorID: "connector_1", HostID: "host_1", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := CredentialRotationChallenge{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_1", HostID: "host_1", SessionID: "sess_old", ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0], OldCredentialGeneration: 1, NewCredentialGeneration: 2, OldIdentityKeyID: oldID, OldIdentityKeyThumbprint: oldThumbprint, ChallengeNonce: "nonce-freshness-rotation", IssuedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(-2 * time.Minute), OverlapUntil: now.Add(10 * time.Minute), NewCredentialValidUntil: now.Add(365 * 24 * time.Hour)}
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/freshness", challenge.IssuedAt)
	if err := VerifyCredentialRotationProofAt(context.Background(), proof, rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate}), now); !errors.Is(err, ErrCredentialExpired) && !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("stale proof error=%v", err)
	}
}

func TestCredentialRotationReadyRejectsStaleReadyAt(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	newPrivate, newID, newThumbprint := rotationKey(73)
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	ready := CredentialRotationReady{
		AccountID: "acct_1", TunnelID: "tunnel_1", OperationID: "op_rotate_ready_stale",
		ConnectorID: "connector_1", HostID: "host_1", SessionID: "sess_new",
		PreviousSessionID: "sess_old", ProcessGeneration: 2, TargetSetHash: "sha256:" + strings.Repeat("a", 64),
		OldCredentialGeneration: 1, NewCredentialGeneration: 2, NewIdentityKeyID: newID,
		NewIdentityKeyThumbprint: newThumbprint, NewPublicKey: base64.RawURLEncoding.EncodeToString(newPublic),
		NewCredentialReference: "keychain://paperboat/rotation/stale-ready", NewCredentialValidUntil: now.Add(time.Hour),
		ConfigGeneration: 2, ConfigContentHash: "sha256:" + strings.Repeat("b", 64),
		EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: now.Add(-MaxClockSkew - time.Second),
	}
	if err := ready.Validate(now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("stale readiness accepted: %v", err)
	}
}
