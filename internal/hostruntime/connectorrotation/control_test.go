package connectorrotation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

type controlReadiness struct {
	mu    sync.Mutex
	value ReplacementReadiness
	calls int
}

func (r *controlReadiness) WaitReplacementReady(_ context.Context, _ connectorprotocol.CredentialRotationInstall) (ReplacementReadiness, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.value, nil
}

type blockingControlReadiness struct {
	started chan struct{}
}

func (r *blockingControlReadiness) WaitReplacementReady(ctx context.Context, _ connectorprotocol.CredentialRotationInstall) (ReplacementReadiness, error) {
	select {
	case <-r.started:
	default:
		close(r.started)
	}
	<-ctx.Done()
	return ReplacementReadiness{}, ctx.Err()
}

type snapshotControlReadiness struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

type immediateSnapshotReadiness struct{}

func (immediateSnapshotReadiness) WaitReady(_ context.Context, snapshot connectorprotocol.Snapshot) (connectorprotocol.Readiness, error) {
	return connectorprotocol.Readiness{
		AccountID: snapshot.AccountID, TunnelID: snapshot.TunnelID, ConnectorID: snapshot.ConnectorID,
		SessionID: snapshot.SessionID, ProcessGeneration: snapshot.ProcessGeneration,
		Generation: snapshot.Generation, ContentHash: snapshot.ContentHash,
		EdgeReady: true, RouteReady: true, OriginReady: true,
	}, nil
}

type controlRevokeCommitter struct {
	mu         sync.Mutex
	prepares   int
	calls      int
	revoke     connectorprotocol.CredentialRotationRevoke
	rejoin     bool
	prepareErr error
	prepared   chan struct{}
	commits    chan struct{}
}

func (c *controlRevokeCommitter) PrepareRevoke(_ context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prepares++
	c.revoke = revoke
	if c.prepared != nil {
		select {
		case <-c.prepared:
		default:
			close(c.prepared)
		}
	}
	return c.prepareErr
}

func (c *controlRevokeCommitter) CommitRevoke(_ context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.revoke = revoke
	if c.commits != nil {
		select {
		case <-c.commits:
		default:
			close(c.commits)
		}
	}
	return nil
}

func (c *controlRevokeCommitter) RejoinAfterRevoke() bool { return c.rejoin }

func (r *snapshotControlReadiness) WaitReady(ctx context.Context, snapshot connectorprotocol.Snapshot) (connectorprotocol.Readiness, error) {
	r.once.Do(func() { close(r.started) })
	select {
	case <-r.release:
	case <-ctx.Done():
		return connectorprotocol.Readiness{}, ctx.Err()
	}
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return connectorprotocol.Readiness{
		AccountID: snapshot.AccountID, TunnelID: snapshot.TunnelID, ConnectorID: snapshot.ConnectorID,
		SessionID: snapshot.SessionID, ProcessGeneration: snapshot.ProcessGeneration,
		Generation: snapshot.Generation, ContentHash: snapshot.ContentHash,
		EdgeReady: true, RouteReady: true, OriginReady: true,
	}, nil
}

type controlPrepared struct{}

func (controlPrepared) Activate(context.Context) error { return nil }
func (controlPrepared) Abort(context.Context) error    { return nil }

type controlApplier struct{}

func (controlApplier) PrepareSnapshot(context.Context, connectorprotocol.Snapshot) (connectorprotocol.PreparedConfig, error) {
	return controlPrepared{}, nil
}

func (controlApplier) PrepareDelta(context.Context, connectorprotocol.Delta) (connectorprotocol.PreparedConfig, error) {
	return controlPrepared{}, nil
}

type controlDrainer struct{}

func (controlDrainer) StopNewStreams(context.Context) error          { return nil }
func (controlDrainer) ActiveStreams(context.Context) (uint32, error) { return 0, nil }
func (controlDrainer) ForceClose(context.Context) error              { return nil }

func controlCapabilities() []string {
	return []string{
		connectorprotocol.CapabilitySnapshot,
		connectorprotocol.CapabilityDelta,
		connectorprotocol.CapabilityAck,
		connectorprotocol.CapabilityHeartbeat,
		connectorprotocol.CapabilityRenewal,
		connectorprotocol.CapabilityCredentialRotation,
	}
}

func controlHello(challenge connectorprotocol.CredentialRotationChallenge, identityKeyID string, processGeneration, credentialGeneration uint64, nowClock fixedClock) connectorprotocol.Hello {
	return connectorprotocol.Hello{
		Protocol: connectorprotocol.ProtocolName, MinVersion: connectorprotocol.ProtocolVersion, MaxVersion: connectorprotocol.ProtocolVersion,
		AccountID: challenge.AccountID, TunnelID: challenge.TunnelID, ConnectorID: challenge.ConnectorID, HostID: challenge.HostID,
		ProcessGeneration: processGeneration, Capabilities: controlCapabilities(),
		Auth: connectorprotocol.AuthRequest{
			AccountID: challenge.AccountID, TunnelID: challenge.TunnelID, ConnectorID: challenge.ConnectorID, HostID: challenge.HostID,
			IdentityKeyID: identityKeyID, IdentityKeyThumbprint: identityKeyID[len("ed25519:"):], ProcessGeneration: processGeneration,
			CredentialGeneration: credentialGeneration, Nonce: "control-auth-nonce-1234", SignedProof: base64.RawURLEncoding.EncodeToString(make([]byte, 48)),
			IssuedAt: nowClock.Now(), ExpiresAt: nowClock.Now().Add(time.Minute),
		},
	}
}

func controlWelcome(now time.Time, sessionID string, capabilities []string) connectorprotocol.Welcome {
	return connectorprotocol.Welcome{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, SessionID: sessionID,
		Capabilities: capabilities, Lease: connectorprotocol.Lease{SessionID: sessionID, ExpiresAt: now.Add(time.Minute), HeartbeatIntervalMS: 10000},
		RequiresSnapshot: true, ServerTime: now,
	}
}

func controlSnapshot(t *testing.T, challenge connectorprotocol.CredentialRotationChallenge, sessionID string, processGeneration uint64) connectorprotocol.Snapshot {
	t.Helper()
	payload := []byte(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tunnel_1","generation":1,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-42d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"route_1","name":"default","protocol":"http","match_type":"exact","match_hostname":"preview.example.test","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`)
	snapshot, err := connectorprotocol.NewSnapshot(challenge.TunnelID, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID = challenge.AccountID
	snapshot.ConnectorID = challenge.ConnectorID
	snapshot.SessionID = sessionID
	snapshot.ProcessGeneration = processGeneration
	return snapshot
}

func readyControlSession(t *testing.T, challenge connectorprotocol.CredentialRotationChallenge, identityKeyID, sessionID string, processGeneration, credentialGeneration uint64, now time.Time) *connectorprotocol.ClientSession {
	t.Helper()
	hello := controlHello(challenge, identityKeyID, processGeneration, credentialGeneration, fixedClock{now: now})
	client, err := connectorprotocol.NewClientSession(connectorprotocol.ClientSessionConfig{Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptWelcome(controlWelcome(now, sessionID, hello.Capabilities)); err != nil {
		t.Fatal(err)
	}
	snapshot := controlSnapshot(t, challenge, sessionID, processGeneration)
	if _, err := client.ApplySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := client.MarkReady(true, true, true); err != nil {
		t.Fatal(err)
	}
	return client
}

func newControl(t *testing.T, manager *Manager, challenge connectorprotocol.CredentialRotationChallenge, identityKeyID, sessionID string, processGeneration, credentialGeneration uint64, now time.Time, readiness ReadinessSource) *ControlSession {
	t.Helper()
	hello := controlHello(challenge, identityKeyID, processGeneration, credentialGeneration, fixedClock{now: now})
	control, err := NewControlSession(ControlSessionConfig{Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager, Readiness: readiness, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	welcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req_welcome_"+sessionID, controlWelcome(now, sessionID, hello.Capabilities))
	if err != nil {
		t.Fatal(err)
	}
	if err := control.AcceptWelcomeFrame(welcomeFrame); err != nil {
		t.Fatal(err)
	}
	snapshot := controlSnapshot(t, challenge, sessionID, processGeneration)
	if _, err := control.Session().ApplySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Session().MarkReady(true, true, true); err != nil {
		t.Fatal(err)
	}
	return control
}

func TestControlSessionDispatchesRotationAndUsesExplicitReplacementReadyBoundary(t *testing.T) {
	manager, keys, installer, challenge, now := testRotationFixture(t)
	readiness := &controlReadiness{}
	control := newControl(t, manager, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, readiness)

	challengeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_rotation", challenge)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := control.HandleFrame(context.Background(), challengeFrame)
	if err != nil || len(responses) != 1 || responses[0].Type != connectorprotocol.MessageCredentialRotationProof || responses[0].RequestID != challengeFrame.RequestID {
		t.Fatalf("challenge responses=%+v err=%v", responses, err)
	}
	var proof connectorprotocol.CredentialRotationProof
	if err := responses[0].DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	if proof.SessionID != challenge.SessionID || proof.ProcessGeneration != challenge.ProcessGeneration || proof.OperationID != challenge.OperationID {
		t.Fatalf("proof lost binding: %+v", proof)
	}

	install := installForProof(challenge, proof)
	installFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationInstall, "req_install", install)
	if err != nil {
		t.Fatal(err)
	}
	responses, err = control.HandleFrame(context.Background(), installFrame)
	if err != nil || len(responses) != 1 || responses[0].Type != connectorprotocol.MessageCredentialRotationAck || responses[0].RequestID != installFrame.RequestID {
		t.Fatalf("install responses=%+v err=%v", responses, err)
	}
	var installAck connectorprotocol.CredentialRotationAck
	if err := responses[0].DecodePayload(&installAck); err != nil {
		t.Fatal(err)
	}
	if installAck.Status != connectorprotocol.RotationAckInstalled || readiness.calls != 0 {
		t.Fatalf("install ack/readiness calls: ack=%+v calls=%d", installAck, readiness.calls)
	}

	replacement := readyControlSession(t, challenge, proof.NewIdentityKeyID, "session_new", install.ReplacementProcessGeneration, challenge.NewCredentialGeneration, now)
	active, ok := replacement.Active()
	if !ok {
		t.Fatal("replacement has no active configuration")
	}
	readiness.value = ReplacementReadiness{
		Session: replacement, NegotiatedCapabilities: controlCapabilities(), SessionID: "session_new", ProcessGeneration: install.ReplacementProcessGeneration,
		ConfigGeneration: active.Generation, ConfigContentHash: active.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true,
	}
	readyFrame, err := control.ReplacementReadyFrame(context.Background(), "req_ready")
	if err != nil {
		t.Fatalf("replacement readiness: frame=%+v err=%v", readyFrame, err)
	}
	if readiness.calls != 1 || readyFrame.Type != connectorprotocol.MessageCredentialRotationReady || readyFrame.RequestID != "req_ready" {
		t.Fatalf("ready frame/calls: frame=%+v calls=%d", readyFrame, readiness.calls)
	}
	var ready connectorprotocol.CredentialRotationReady
	if err := readyFrame.DecodePayload(&ready); err != nil {
		t.Fatal(err)
	}
	if ready.SessionID != "session_new" || ready.PreviousSessionID != install.SessionID || ready.ProcessGeneration != install.ReplacementProcessGeneration || ready.ConfigGeneration != active.Generation {
		t.Fatalf("ready lost exact replacement binding: %+v", ready)
	}

	newControl := newControl(t, manager, challenge, proof.NewIdentityKeyID, ready.SessionID, ready.ProcessGeneration, challenge.NewCredentialGeneration, now, &controlReadiness{})
	revoke := revokeForReady(ready, now)
	revokeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationRevoke, "req_revoke", revoke)
	if err != nil {
		t.Fatal(err)
	}
	responses, err = newControl.HandleFrame(context.Background(), revokeFrame)
	if err != nil || len(responses) != 1 || responses[0].Type != connectorprotocol.MessageCredentialRotationAck || responses[0].RequestID != revokeFrame.RequestID {
		t.Fatalf("revoke responses=%+v err=%v", responses, err)
	}
	var revokeAck connectorprotocol.CredentialRotationAck
	if err := responses[0].DecodePayload(&revokeAck); err != nil {
		t.Fatal(err)
	}
	if revokeAck.Status != connectorprotocol.RotationAckRevoked {
		t.Fatalf("revoke ack=%+v", revokeAck)
	}
	if len(keys.deletes) != 1 || !keys.has(proof.NewCredentialReference) {
		t.Fatalf("credential lifecycle deletes=%v new-key=%t", keys.deletes, keys.has(proof.NewCredentialReference))
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 1 {
		t.Fatalf("installer counts=%d/%d", installs, revokes)
	}
}

func TestControlSessionInstallDoesNotWaitForReplacementReadiness(t *testing.T) {
	manager, _, _, challenge, now := testRotationFixture(t)
	readiness := &blockingControlReadiness{started: make(chan struct{})}
	control := newControl(t, manager, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, readiness)
	challengeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_rotation_async", challenge)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := control.HandleFrame(context.Background(), challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	var proof connectorprotocol.CredentialRotationProof
	if err := responses[0].DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	installFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationInstall, "req_install_async", installForProof(challenge, proof))
	if err != nil {
		t.Fatal(err)
	}
	installDone := make(chan struct{})
	var installResponses []connectorprotocol.Frame
	var installErr error
	go func() {
		installResponses, installErr = control.HandleFrame(context.Background(), installFrame)
		close(installDone)
	}()
	select {
	case <-installDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("install handling waited for replacement readiness")
	}
	if installErr != nil || len(installResponses) != 1 {
		t.Fatalf("install response=%+v err=%v", installResponses, installErr)
	}
	var ack connectorprotocol.CredentialRotationAck
	if err := installResponses[0].DecodePayload(&ack); err != nil || ack.Status != connectorprotocol.RotationAckInstalled {
		t.Fatalf("install ack=%+v err=%v", ack, err)
	}
	heartbeatAck := connectorprotocol.HeartbeatAck{
		AccountID: challenge.AccountID, TunnelID: challenge.TunnelID, ConnectorID: challenge.ConnectorID,
		SessionID: challenge.SessionID, ProcessGeneration: challenge.ProcessGeneration,
		LeaseExpiresAt: now.Add(2 * time.Minute), ServerTime: now,
	}
	heartbeatFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageHeartbeatAck, "req_heartbeat_between", heartbeatAck)
	if err != nil {
		t.Fatal(err)
	}
	if responses, err := control.HandleFrame(context.Background(), heartbeatFrame); err != nil || len(responses) != 0 {
		t.Fatalf("heartbeat handling after install responses=%+v err=%v", responses, err)
	}
	if _, err := control.HeartbeatFrame("req_heartbeat_out", now); err != nil {
		t.Fatalf("heartbeat send blocked after install: %v", err)
	}
	select {
	case <-readiness.started:
		t.Fatal("install handling invoked replacement readiness")
	default:
	}

	readyCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	readyFrame, readyErr := control.ReplacementReadyFrame(readyCtx, "req_ready_cancelled")
	if readyErr == nil || readyFrame.Type != connectorprotocol.MessageCredentialRotationAck {
		t.Fatalf("cancelled readiness frame=%+v err=%v", readyFrame, readyErr)
	}
	var failure connectorprotocol.CredentialRotationAck
	if err := readyFrame.DecodePayload(&failure); err != nil || failure.Status != connectorprotocol.RotationAckFailed {
		t.Fatalf("readiness failure=%+v err=%v", failure, err)
	}
}

func TestControlSessionFailsClosedWithoutRuntimeOrNegotiatedRotation(t *testing.T) {
	manager, _, _, challenge, now := testRotationFixture(t)
	hello := controlHello(challenge, challenge.OldIdentityKeyID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, fixedClock{now: now})
	if _, err := NewControlSession(ControlSessionConfig{Hello: hello, Rotation: manager, Readiness: &controlReadiness{}, Drainer: controlDrainer{}}); !errors.Is(err, ErrControlSessionInvalid) {
		t.Fatalf("nil applier accepted: %v", err)
	}
	if _, err := NewControlSession(ControlSessionConfig{Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}}); !errors.Is(err, connectorprotocol.ErrCapabilityMissing) {
		t.Fatalf("rotation runtime absence error=%v", err)
	}
	noRotationHello := hello
	noRotationHello.Capabilities = noRotationHello.Capabilities[:len(noRotationHello.Capabilities)-1]
	if _, err := NewControlSession(ControlSessionConfig{Hello: noRotationHello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager, Readiness: &controlReadiness{}, Clock: fixedClock{now: now}}); !errors.Is(err, connectorprotocol.ErrCapabilityMissing) {
		t.Fatalf("offered capability absence error=%v", err)
	}
	control, err := NewControlSession(ControlSessionConfig{Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager, Readiness: &controlReadiness{}, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	welcome := controlWelcome(now, challenge.SessionID, controlCapabilities()[:len(controlCapabilities())-1])
	frame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req_welcome_no_rotation", welcome)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.AcceptWelcomeFrame(frame); !errors.Is(err, connectorprotocol.ErrCapabilityMissing) {
		t.Fatalf("welcome without rotation accepted: %v", err)
	}
	pending, err := NewControlSession(ControlSessionConfig{
		Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager,
		Readiness: &controlReadiness{}, Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	validWelcome, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req_welcome_pending", controlWelcome(now, challenge.SessionID, hello.Capabilities))
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.AcceptWelcomeFrame(validWelcome); err != nil {
		t.Fatal(err)
	}
	challengeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_pending_rotation", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.HandleFrame(context.Background(), challengeFrame); !errors.Is(err, connectorprotocol.ErrCredentialRotationNotReady) {
		t.Fatalf("rotation accepted before active readiness: %v", err)
	}
}

func TestControlSessionRecoveryReusesDurableKeyAndInstall(t *testing.T) {
	manager, keys, installer, challenge, now := testRotationFixture(t)
	control := newControl(t, manager, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, &controlReadiness{})
	challengeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_rotation_recover", challenge)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := control.HandleFrame(context.Background(), challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	var proof connectorprotocol.CredentialRotationProof
	if err := responses[0].DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	putsBefore := keys.puts
	manager2, err := New(manager.config)
	if err != nil {
		t.Fatal(err)
	}
	control2 := newControl(t, manager2, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, &controlReadiness{})
	if err := control2.RecoverRotation(context.Background(), challenge.OperationID); err != nil {
		t.Fatal(err)
	}
	installFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationInstall, "req_install_recover", installForProof(challenge, proof))
	if err != nil {
		t.Fatal(err)
	}
	responses, err = control2.HandleFrame(context.Background(), installFrame)
	if err != nil || len(responses) != 1 {
		t.Fatalf("replayed install responses=%+v err=%v", responses, err)
	}
	if keys.puts != putsBefore {
		t.Fatalf("restart recovery generated another key: before=%d after=%d", putsBefore, keys.puts)
	}
	var ack connectorprotocol.CredentialRotationAck
	if err := responses[0].DecodePayload(&ack); err != nil || ack.Status != connectorprotocol.RotationAckInstalled {
		t.Fatalf("replayed install ack=%+v err=%v", ack, err)
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 0 {
		t.Fatalf("recovery installer counts=%d/%d", installs, revokes)
	}
}

func TestControlSessionRejectsWrongRotationBindingWithoutRuntimeSideEffects(t *testing.T) {
	manager, _, installer, challenge, now := testRotationFixture(t)
	control := newControl(t, manager, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, &controlReadiness{})
	validFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_valid_binding", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.HandleFrame(context.Background(), validFrame); err != nil {
		t.Fatal(err)
	}
	var lastResponse connectorprotocol.Frame
	for _, test := range []struct {
		name string
		edit func(*connectorprotocol.CredentialRotationChallenge)
	}{
		{name: "operation", edit: func(value *connectorprotocol.CredentialRotationChallenge) { value.OperationID = "operation_wrong" }},
		{name: "session", edit: func(value *connectorprotocol.CredentialRotationChallenge) { value.SessionID = "session_wrong" }},
		{name: "process", edit: func(value *connectorprotocol.CredentialRotationChallenge) { value.ProcessGeneration = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrong := challenge
			test.edit(&wrong)
			frame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req_wrong_"+test.name, wrong)
			if err != nil {
				t.Fatal(err)
			}
			responses, err := control.HandleFrame(context.Background(), frame)
			if err == nil || len(responses) != 1 {
				t.Fatalf("wrong binding responses=%+v err=%v", responses, err)
			}
			lastResponse = responses[0]
			var ack connectorprotocol.CredentialRotationAck
			if decodeErr := responses[0].DecodePayload(&ack); decodeErr != nil || ack.Status != connectorprotocol.RotationAckRejected {
				t.Fatalf("wrong binding ack=%+v err=%v", ack, decodeErr)
			}
		})
	}
	if installs, revokes := installer.counts(); installs != 0 || revokes != 0 {
		t.Fatalf("wrong binding reached installer=%d/%d", installs, revokes)
	}
	encoded, _ := json.Marshal(lastResponse)
	if strings.Contains(strings.ToLower(string(encoded)), "private") {
		t.Fatal("rotation failure frame disclosed secret marker")
	}
}

func TestControlSessionUsesExplicitHostStateApplierBoundary(t *testing.T) {
	var _ connectorprotocol.ConfigApplier = controlApplier{}
	var _ connectorprotocol.Drainer = controlDrainer{}
	var _ KeyStore = (*testKeyStore)(nil)
	var _ Installer = (*testInstaller)(nil)
}

func TestControlSessionServeKeepsOneLoopForReadinessRotationHeartbeatAndRenewal(t *testing.T) {
	manager, _, installer, challenge, now := testRotationFixture(t)
	readiness := &snapshotControlReadiness{started: make(chan struct{}), release: make(chan struct{})}
	hello := controlHello(challenge, challenge.OldIdentityKeyID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, fixedClock{now: now})
	hello.Auth.ExpiresAt = now.Add(100 * time.Millisecond)
	renewalPublic, renewalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotationReadiness := &controlReadiness{}
	control, err := NewControlSession(ControlSessionConfig{
		Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager,
		Readiness: rotationReadiness, SnapshotReadiness: readiness, AutomaticRotationReadiness: true,
		RenewalSigner: RenewalProofSignerFunc(func(_ context.Context, payload []byte) ([]byte, error) {
			return ed25519.Sign(renewalPrivate, payload), nil
		}),
		RenewalLead: 80 * time.Millisecond, Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("new control session: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controlSide, serverSide := net.Pipe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- control.Serve(ctx, controlSide, "req-live-hello") }()

	helloFrame := readServeFrame(t, serverSide)
	if helloFrame.Type != connectorprotocol.MessageHello || helloFrame.RequestID != "req-live-hello" {
		t.Fatalf("hello frame = %+v", helloFrame)
	}
	welcome := controlWelcome(now, challenge.SessionID, hello.Capabilities)
	welcome.Lease.HeartbeatIntervalMS = 20
	welcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req-live-welcome", welcome)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, welcomeFrame); err != nil {
		t.Fatalf("write welcome: %v", err)
	}
	var sawHeartbeat, sawRenewal bool
	handleProactive := func(frame connectorprotocol.Frame) bool {
		switch frame.Type {
		case connectorprotocol.MessageHeartbeat:
			var heartbeat connectorprotocol.Heartbeat
			if err := frame.DecodePayload(&heartbeat); err != nil {
				t.Fatal(err)
			}
			ack := connectorprotocol.HeartbeatAck{AccountID: heartbeat.AccountID, TunnelID: heartbeat.TunnelID, ConnectorID: heartbeat.ConnectorID, SessionID: heartbeat.SessionID, ProcessGeneration: heartbeat.ProcessGeneration, LeaseExpiresAt: now.Add(time.Minute), ServerTime: now}
			response, err := connectorprotocol.NewFrame(connectorprotocol.MessageHeartbeatAck, frame.RequestID, ack)
			if err != nil {
				t.Fatal(err)
			}
			if err := connectorprotocol.WriteFrame(serverSide, response); err != nil {
				t.Fatalf("write heartbeat ack: %v", err)
			}
			sawHeartbeat = true
			return true
		case connectorprotocol.MessageAuthRenew:
			var request connectorprotocol.RenewalRequest
			if err := frame.DecodePayload(&request); err != nil {
				t.Fatal(err)
			}
			if request.SessionID != challenge.SessionID || request.AccountID != challenge.AccountID || request.TunnelID != challenge.TunnelID || request.ConnectorID != challenge.ConnectorID || request.HostID != challenge.HostID || request.ProcessGeneration != challenge.ProcessGeneration || request.CredentialGeneration != challenge.OldCredentialGeneration {
				t.Fatalf("renewal binding = %+v", request)
			}
			if err := connectorprotocol.VerifyRenewalProof(request, func(payload, signature []byte) bool { return ed25519.Verify(renewalPublic, payload, signature) }); err != nil {
				t.Fatalf("renewal proof: %v", err)
			}
			result := connectorprotocol.AuthResult{AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, SessionID: request.SessionID, HostID: request.HostID, IdentityKeyID: request.IdentityKeyID, IdentityKeyThumbprint: request.IdentityKeyThumbprint, ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration + 1, CredentialExpiresAt: now.Add(3 * time.Minute), LeaseExpiresAt: now.Add(2 * time.Minute)}
			response, err := connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenewed, frame.RequestID, result)
			if err != nil {
				t.Fatal(err)
			}
			if err := connectorprotocol.WriteFrame(serverSide, response); err != nil {
				t.Fatalf("write renewal result: %v", err)
			}
			sawRenewal = true
			return true
		default:
			return false
		}
	}
	readUntil := func(wanted connectorprotocol.MessageType) connectorprotocol.Frame {
		for {
			if err := serverSide.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			frame, err := connectorprotocol.ReadFrame(serverSide)
			if err != nil {
				select {
				case serveErr := <-serveDone:
					t.Fatalf("control Serve ended while waiting for %s: %v (read: %v)", wanted, serveErr, err)
				default:
					t.Fatalf("read control frame while waiting for %s: %v", wanted, err)
				}
			}
			if frame.Type == wanted {
				return frame
			}
			if err := serverSide.SetReadDeadline(time.Time{}); err != nil {
				t.Fatalf("clear deadline after %s while waiting for %s: %v", frame.Type, wanted, err)
			}
			if !handleProactive(frame) {
				t.Fatalf("control frame=%+v, want %s", frame, wanted)
			}
		}
	}
	snapshot := controlSnapshot(t, challenge, challenge.SessionID, challenge.ProcessGeneration)
	snapshotFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageSnapshot, "req-live-snapshot", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, snapshotFrame); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	ackFrame := readUntil(connectorprotocol.MessageAck)
	var snapshotAck connectorprotocol.Ack
	if err := ackFrame.DecodePayload(&snapshotAck); err != nil || ackFrame.RequestID != snapshotFrame.RequestID || snapshotAck.Status != connectorprotocol.AckApplied {
		t.Fatalf("snapshot ack = %+v, err=%v", snapshotAck, err)
	}
	select {
	case <-readiness.started:
	case <-time.After(time.Second):
		t.Fatal("snapshot readiness did not start")
	}

	for !sawHeartbeat || !sawRenewal {
		frame := readServeFrame(t, serverSide)
		if !handleProactive(frame) {
			t.Fatalf("unexpected proactive frame: %+v", frame)
		}
	}
	close(readiness.release)
	readyFrame := readUntil(connectorprotocol.MessageReady)
	if readyFrame.Type != connectorprotocol.MessageReady || readyFrame.RequestID != snapshotFrame.RequestID {
		t.Fatalf("snapshot ready frame = %+v", readyFrame)
	}
	var ready connectorprotocol.Readiness
	if err := readyFrame.DecodePayload(&ready); err != nil || ready.Generation != snapshot.Generation || !ready.EdgeReady || !ready.RouteReady || !ready.OriginReady {
		t.Fatalf("snapshot readiness = %+v, err=%v", ready, err)
	}

	challengeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req-live-rotation", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, challengeFrame); err != nil {
		t.Fatalf("write rotation challenge: %v", err)
	}
	proofFrame := readUntil(connectorprotocol.MessageCredentialRotationProof)
	if proofFrame.Type != connectorprotocol.MessageCredentialRotationProof {
		t.Fatalf("rotation proof frame = %+v", proofFrame)
	}
	var proof connectorprotocol.CredentialRotationProof
	if err := proofFrame.DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	install := installForProof(challenge, proof)
	replacement := readyControlSession(t, challenge, proof.NewIdentityKeyID, "session_new", install.ReplacementProcessGeneration, challenge.NewCredentialGeneration, now)
	active, ok := replacement.Active()
	if !ok {
		t.Fatal("replacement has no active snapshot")
	}
	rotationReadiness.value = ReplacementReadiness{Session: replacement, NegotiatedCapabilities: controlCapabilities(), SessionID: "session_new", ProcessGeneration: install.ReplacementProcessGeneration, ConfigGeneration: active.Generation, ConfigContentHash: active.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	installFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationInstall, "req-live-install", install)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, installFrame); err != nil {
		t.Fatalf("write rotation install: %v", err)
	}
	installAckFrame := readUntil(connectorprotocol.MessageCredentialRotationAck)
	var installAck connectorprotocol.CredentialRotationAck
	if installAckFrame.Type != connectorprotocol.MessageCredentialRotationAck || installAckFrame.DecodePayload(&installAck) != nil || installAck.Status != connectorprotocol.RotationAckInstalled {
		t.Fatalf("rotation install response = %+v/%+v", installAckFrame, installAck)
	}

	wireReady := readUntil(connectorprotocol.MessageCredentialRotationReady)
	if wireReady.Type != connectorprotocol.MessageCredentialRotationReady {
		t.Fatalf("wire rotation ready = %+v", wireReady)
	}
	var decodedReady connectorprotocol.CredentialRotationReady
	if err := wireReady.DecodePayload(&decodedReady); err != nil {
		t.Fatal(err)
	}
	revoke := revokeForReady(decodedReady, now)
	revokeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationRevoke, "req-live-revoke", revoke)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, revokeFrame); err != nil {
		t.Fatalf("write rotation revoke: %v", err)
	}
	select {
	case serveErr := <-serveDone:
		t.Fatalf("control Serve ended before revoke response: %v", serveErr)
	default:
	}
	revokeAckFrame := readUntil(connectorprotocol.MessageCredentialRotationAck)
	var revokeAck connectorprotocol.CredentialRotationAck
	if revokeAckFrame.Type != connectorprotocol.MessageCredentialRotationAck || revokeAckFrame.DecodePayload(&revokeAck) != nil || revokeAck.Status != connectorprotocol.RotationAckRejected || revokeAck.Code != connectorprotocol.CodeIdentityMismatch {
		t.Fatalf("rotation revoke response = %+v/%+v", revokeAckFrame, revokeAck)
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 0 {
		t.Fatalf("live rotation counts = %d/%d, want 1/0 for old-session rejection", installs, revokes)
	}
	cancel()
	_ = serverSide.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("control Serve did not stop after cancellation")
	}
}

func TestControlSessionServeWaitsForAuthRenewedBeforeSchedulingAnotherRenewal(t *testing.T) {
	manager, _, _, challenge, now := testRotationFixture(t)
	hello := controlHello(challenge, challenge.OldIdentityKeyID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, fixedClock{now: now})
	hello.Auth.ExpiresAt = now.Add(100 * time.Millisecond)
	_, renewalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControlSession(ControlSessionConfig{
		Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager,
		Readiness: &controlReadiness{}, SnapshotReadiness: immediateSnapshotReadiness{},
		RenewalSigner: RenewalProofSignerFunc(func(_ context.Context, payload []byte) ([]byte, error) {
			return ed25519.Sign(renewalPrivate, payload), nil
		}),
		RenewalLead: 80 * time.Millisecond, Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	controlSide, serverSide := net.Pipe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- control.Serve(ctx, controlSide, "req-renewal-hello") }()

	helloFrame := readServeFrame(t, serverSide)
	welcome := controlWelcome(now, challenge.SessionID, hello.Capabilities)
	welcome.Lease.HeartbeatIntervalMS = 1000
	welcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, helloFrame.RequestID, welcome)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, welcomeFrame); err != nil {
		t.Fatal(err)
	}
	renewalFrame := readServeFrame(t, serverSide)
	if renewalFrame.Type != connectorprotocol.MessageAuthRenew {
		t.Fatalf("first proactive frame = %s, want %s", renewalFrame.Type, connectorprotocol.MessageAuthRenew)
	}
	var request connectorprotocol.RenewalRequest
	if err := renewalFrame.DecodePayload(&request); err != nil {
		t.Fatal(err)
	}

	assertNoControlFrame(t, serverSide, 80*time.Millisecond)
	result := connectorprotocol.AuthResult{
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
		SessionID: request.SessionID, HostID: request.HostID, IdentityKeyID: request.IdentityKeyID,
		IdentityKeyThumbprint: request.IdentityKeyThumbprint, ProcessGeneration: request.ProcessGeneration,
		CredentialGeneration: request.CredentialGeneration + 1, CredentialExpiresAt: now.Add(3 * time.Minute),
		LeaseExpiresAt: now.Add(2 * time.Minute),
	}
	response, err := connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenewed, renewalFrame.RequestID, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteFrame(serverSide, response); err != nil {
		t.Fatal(err)
	}
	assertNoControlFrame(t, serverSide, 80*time.Millisecond)

	cancel()
	_ = serverSide.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("control Serve did not stop")
	}
}

func assertNoControlFrame(t *testing.T, carrier net.Conn, wait time.Duration) {
	t.Helper()
	if err := carrier.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	if frame, err := connectorprotocol.ReadFrame(carrier); err == nil {
		t.Fatalf("unexpected control frame: %+v", frame)
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("wait for control frame: %v", err)
		}
	}
	if err := carrier.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestControlSessionRejectsWrongAndStaleAuthRenewed(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*testing.T, *ControlSession, connectorprotocol.AuthResult)
		edit  func(*connectorprotocol.AuthResult)
	}{
		{
			name: "wrong session",
			edit: func(result *connectorprotocol.AuthResult) { result.SessionID = "session_wrong" },
		},
		{
			name: "stale credential generation",
			apply: func(t *testing.T, control *ControlSession, result connectorprotocol.AuthResult) {
				t.Helper()
				result.CredentialGeneration = 2
				frame, err := connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenewed, "req-current-renewal", result)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := control.HandleFrame(context.Background(), frame); err != nil {
					t.Fatalf("apply current renewal: %v", err)
				}
			},
			edit: func(result *connectorprotocol.AuthResult) { result.CredentialGeneration = 1 },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, _, _, challenge, now := testRotationFixture(t)
			hello := controlHello(challenge, challenge.OldIdentityKeyID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, fixedClock{now: now})
			control, err := NewControlSession(ControlSessionConfig{
				Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager,
				Readiness: &controlReadiness{}, SnapshotReadiness: immediateSnapshotReadiness{}, Clock: fixedClock{now: now},
			})
			if err != nil {
				t.Fatal(err)
			}
			welcome := controlWelcome(now, challenge.SessionID, hello.Capabilities)
			welcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req-renewal-welcome", welcome)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := control.HandleFrame(context.Background(), welcomeFrame); err != nil {
				t.Fatal(err)
			}
			result := connectorprotocol.AuthResult{
				AccountID: hello.Auth.AccountID, TunnelID: hello.Auth.TunnelID, ConnectorID: hello.Auth.ConnectorID,
				SessionID: welcome.SessionID, HostID: hello.Auth.HostID, IdentityKeyID: hello.Auth.IdentityKeyID,
				IdentityKeyThumbprint: hello.Auth.IdentityKeyThumbprint, ProcessGeneration: hello.ProcessGeneration,
				CredentialGeneration: hello.Auth.CredentialGeneration + 1, CredentialExpiresAt: now.Add(3 * time.Minute),
				LeaseExpiresAt: now.Add(2 * time.Minute),
			}
			if test.apply != nil {
				test.apply(t, control, result)
			}
			test.edit(&result)
			frame, err := connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenewed, "req-invalid-renewal", result)
			if err != nil {
				t.Fatal(err)
			}
			responses, err := control.HandleFrame(context.Background(), frame)
			if !errors.Is(err, connectorprotocol.ErrIdentityMismatch) || len(responses) != 0 {
				t.Fatalf("invalid renewal responses=%+v err=%v", responses, err)
			}
		})
	}
}

func TestControlSessionWritesRevokeAckBeforeCommitAndRejoins(t *testing.T) {
	manager, installer, challenge, now, proof, install, readySource, ready := prepareRotationForRevoke(t)

	committer := &controlRevokeCommitter{rejoin: true, prepared: make(chan struct{}), commits: make(chan struct{})}
	hello := controlHello(challenge, proof.NewIdentityKeyID, install.ReplacementProcessGeneration, challenge.NewCredentialGeneration, fixedClock{now: now})
	control, err := NewControlSession(ControlSessionConfig{
		Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager,
		Readiness: readySource, SnapshotReadiness: immediateSnapshotReadiness{}, RotationRevokeCommitter: committer,
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientSide, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- control.Serve(ctx, clientSide, "req-rejoin-hello") }()
	_ = readServeFrame(t, serverSide)
	welcomeFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req-rejoin-welcome", controlWelcome(now, ready.SessionID, hello.Capabilities))
	if err := connectorprotocol.WriteFrame(serverSide, welcomeFrame); err != nil {
		t.Fatal(err)
	}
	snapshot := controlSnapshot(t, challenge, ready.SessionID, ready.ProcessGeneration)
	snapshotFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageSnapshot, "req-rejoin-snapshot", snapshot)
	if err := connectorprotocol.WriteFrame(serverSide, snapshotFrame); err != nil {
		t.Fatal(err)
	}
	if frame := readServeFrame(t, serverSide); frame.Type != connectorprotocol.MessageAck {
		t.Fatalf("snapshot response=%+v", frame)
	}
	if frame := readServeFrame(t, serverSide); frame.Type != connectorprotocol.MessageReady {
		t.Fatalf("snapshot ready=%+v", frame)
	}
	revoke := revokeForReady(ready, now)
	revokeFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationRevoke, "req-rejoin-revoke", revoke)
	if err := connectorprotocol.WriteFrame(serverSide, revokeFrame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-committer.prepared:
	case <-time.After(time.Second):
		t.Fatal("credential promotion did not complete before revoke acknowledgement")
	}
	if err := serverSide.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ackFrame, readErr := connectorprotocol.ReadFrame(serverSide)
	if readErr != nil {
		select {
		case serveErr := <-done:
			t.Fatalf("read revoke ack: %v; serve=%v", readErr, serveErr)
		default:
			t.Fatalf("read revoke ack: %v", readErr)
		}
	}
	var ack connectorprotocol.CredentialRotationAck
	if err := ackFrame.DecodePayload(&ack); err != nil || ack.Status != connectorprotocol.RotationAckRevoked {
		t.Fatalf("revoke ack=%+v err=%v", ack, err)
	}
	select {
	case <-committer.commits:
	case <-time.After(time.Second):
		t.Fatal("revoke commit did not run after acknowledgement")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rejoin serve error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control session did not rejoin after revoke")
	}
	if installs, revokes := installer.counts(); installs != 1 || revokes != 1 {
		t.Fatalf("rotation lifecycle=%d/%d", installs, revokes)
	}
}

func prepareRotationForRevoke(t *testing.T) (*Manager, *testInstaller, connectorprotocol.CredentialRotationChallenge, time.Time, connectorprotocol.CredentialRotationProof, connectorprotocol.CredentialRotationInstall, *controlReadiness, connectorprotocol.CredentialRotationReady) {
	t.Helper()
	manager, _, installer, challenge, now := testRotationFixture(t)
	readySource := &controlReadiness{}
	old := newControl(t, manager, challenge, challenge.OldIdentityKeyID, challenge.SessionID, challenge.ProcessGeneration, challenge.OldCredentialGeneration, now, readySource)
	challengeFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationChallenge, "req-rejoin-challenge", challenge)
	proofFrames, err := old.HandleFrame(context.Background(), challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	var proof connectorprotocol.CredentialRotationProof
	if err := proofFrames[0].DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	install := installForProof(challenge, proof)
	installFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationInstall, "req-rejoin-install", install)
	if _, err := old.HandleFrame(context.Background(), installFrame); err != nil {
		t.Fatal(err)
	}
	replacement := readyControlSession(t, challenge, proof.NewIdentityKeyID, "session_new", install.ReplacementProcessGeneration, challenge.NewCredentialGeneration, now)
	active, _ := replacement.Active()
	readySource.value = ReplacementReadiness{Session: replacement, NegotiatedCapabilities: controlCapabilities(), SessionID: "session_new", ProcessGeneration: install.ReplacementProcessGeneration, ConfigGeneration: active.Generation, ConfigContentHash: active.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	readyFrame, err := old.ReplacementReadyFrame(context.Background(), "req-rejoin-ready")
	if err != nil {
		t.Fatal(err)
	}
	var ready connectorprotocol.CredentialRotationReady
	if err := readyFrame.DecodePayload(&ready); err != nil {
		t.Fatal(err)
	}
	return manager, installer, challenge, now, proof, install, readySource, ready
}

func TestControlSessionFailsClosedAcrossRevokePromotionCrashWindows(t *testing.T) {
	t.Run("promotion failure writes no terminal ack", func(t *testing.T) {
		manager, _, challenge, now, proof, install, readySource, ready := prepareRotationForRevoke(t)
		promotionErr := errors.New("durable promotion unavailable")
		committer := &controlRevokeCommitter{prepareErr: promotionErr, prepared: make(chan struct{}), commits: make(chan struct{})}
		serverSide, done, cancel := startReplacementRevokeServe(t, manager, challenge, now, proof, install, readySource, ready, committer)
		defer cancel()
		revoke := revokeForReady(ready, now)
		frame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationRevoke, "req-failed-promotion", revoke)
		if err := connectorprotocol.WriteFrame(serverSide, frame); err != nil {
			t.Fatal(err)
		}
		<-committer.prepared
		if _, err := connectorprotocol.ReadFrame(serverSide); err == nil {
			t.Fatal("terminal revoke acknowledgement was written before durable promotion")
		}
		if err := <-done; !errors.Is(err, promotionErr) {
			t.Fatalf("serve error=%v", err)
		}
		if committer.calls != 0 {
			t.Fatal("post-ack shutdown ran without an acknowledgement")
		}
	})

	t.Run("ack write failure retains promoted replacement", func(t *testing.T) {
		manager, _, challenge, now, proof, install, readySource, ready := prepareRotationForRevoke(t)
		committer := &controlRevokeCommitter{prepared: make(chan struct{}), commits: make(chan struct{})}
		serverSide, done, cancel := startReplacementRevokeServe(t, manager, challenge, now, proof, install, readySource, ready, committer)
		defer cancel()
		revoke := revokeForReady(ready, now)
		frame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationRevoke, "req-failed-ack-write", revoke)
		if err := connectorprotocol.WriteFrame(serverSide, frame); err != nil {
			t.Fatal(err)
		}
		<-committer.prepared
		_ = serverSide.Close()
		if err := <-done; err == nil {
			t.Fatal("failed acknowledgement write was treated as success")
		}
		if committer.prepares != 1 || committer.calls != 0 {
			t.Fatalf("promotion/commit calls=%d/%d", committer.prepares, committer.calls)
		}
	})
}

func startReplacementRevokeServe(t *testing.T, manager *Manager, challenge connectorprotocol.CredentialRotationChallenge, now time.Time, proof connectorprotocol.CredentialRotationProof, install connectorprotocol.CredentialRotationInstall, readySource *controlReadiness, ready connectorprotocol.CredentialRotationReady, committer *controlRevokeCommitter) (net.Conn, <-chan error, context.CancelFunc) {
	t.Helper()
	hello := controlHello(challenge, proof.NewIdentityKeyID, install.ReplacementProcessGeneration, challenge.NewCredentialGeneration, fixedClock{now: now})
	control, err := NewControlSession(ControlSessionConfig{Hello: hello, Applier: controlApplier{}, Drainer: controlDrainer{}, Rotation: manager, Readiness: readySource, SnapshotReadiness: immediateSnapshotReadiness{}, RotationRevokeCommitter: committer, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	clientSide, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- control.Serve(ctx, clientSide, "req-crash-window-hello") }()
	_ = readServeFrame(t, serverSide)
	welcomeFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "req-crash-window-welcome", controlWelcome(now, ready.SessionID, hello.Capabilities))
	if err := connectorprotocol.WriteFrame(serverSide, welcomeFrame); err != nil {
		t.Fatal(err)
	}
	snapshot := controlSnapshot(t, challenge, ready.SessionID, ready.ProcessGeneration)
	snapshotFrame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageSnapshot, "req-crash-window-snapshot", snapshot)
	if err := connectorprotocol.WriteFrame(serverSide, snapshotFrame); err != nil {
		t.Fatal(err)
	}
	if frame := readServeFrame(t, serverSide); frame.Type != connectorprotocol.MessageAck {
		t.Fatalf("snapshot response=%+v", frame)
	}
	if frame := readServeFrame(t, serverSide); frame.Type != connectorprotocol.MessageReady {
		t.Fatalf("snapshot ready=%+v", frame)
	}
	return serverSide, done, cancel
}

func readServeFrame(t *testing.T, connection net.Conn) connectorprotocol.Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := connectorprotocol.ReadFrame(connection)
	if err != nil {
		t.Fatalf("read control frame: %v", err)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return frame
}
