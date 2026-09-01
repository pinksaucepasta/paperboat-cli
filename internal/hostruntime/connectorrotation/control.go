package connectorrotation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

var ErrControlSessionInvalid = errors.New("invalid connector control session")
var ErrControlSessionOutboundFull = errors.New("connector control outbound queue is full")

const (
	defaultControlOutboundQueue = 16
	maxControlOutboundQueue     = 1024
	defaultRenewalLead          = 30 * time.Second
	readinessCleanupTimeout     = 250 * time.Millisecond
)

// ReplacementReadiness is the host-side observation needed before a new
// credential can become authoritative. The provider must start or select the
// replacement process, wait for its connector, route, and origin readiness,
// and return the exact replacement session identity. It must not report a
// successful result based only on local configuration state.
type ReplacementReadiness struct {
	// Session is the replacement ClientSession that has accepted its Welcome,
	// applied the candidate through its ConfigApplier (normally
	// connectorprotocol.HostStateApplier), and reached SessionReady. It is
	// required. The metadata fields below are an observation from the process
	// supervisor and are checked against this session and its active snapshot.
	Session                *connectorprotocol.ClientSession
	NegotiatedCapabilities []string
	SessionID              string
	ProcessGeneration      uint64
	ConfigGeneration       uint64
	ConfigContentHash      string
	EdgeReady              bool
	RouteReady             bool
	OriginReady            bool
}

// ReadinessSource bridges the host process supervisor to the control
// protocol. The source owns process replacement and data-plane observation;
// this package only validates its result and emits the bound ready message.
type ReadinessSource interface {
	WaitReplacementReady(context.Context, connectorprotocol.CredentialRotationInstall) (ReplacementReadiness, error)
}

// SnapshotReadinessSource is the regular configuration cutover boundary. It
// must return only after the exact staged snapshot has an active edge carrier,
// admitted routes, and usable origins. A transport ping or durable state write
// is not sufficient to satisfy this contract.
type SnapshotReadinessSource interface {
	WaitReady(context.Context, connectorprotocol.Snapshot) (connectorprotocol.Readiness, error)
}

// CredentialRenewalSource supplies fresh proof material before the current
// credential expires. The control session owns when the request is framed and
// written; the source owns credential custody and signing.
type CredentialRenewalSource interface {
	Renew(context.Context, time.Time) (nonce, signedProof string, err error)
}

type CredentialRenewalSourceFunc func(context.Context, time.Time) (string, string, error)

func (f CredentialRenewalSourceFunc) Renew(ctx context.Context, now time.Time) (string, string, error) {
	return f(ctx, now)
}

// RenewalProofSigner keeps connector private bytes behind a reference-backed
// signing boundary. ControlSession constructs the complete renewal transcript
// only after Welcome has supplied the live SessionID, then passes the exact
// canonical payload here. A signer must return raw Ed25519 signature bytes.
type RenewalProofSigner interface {
	SignRenewalProof(context.Context, []byte) ([]byte, error)
}

type RenewalProofSignerFunc func(context.Context, []byte) ([]byte, error)

func (f RenewalProofSignerFunc) SignRenewalProof(ctx context.Context, payload []byte) ([]byte, error) {
	return f(ctx, payload)
}

// RotationRevokeCommitter retires the old process only after ControlSession
// has successfully written the server-authoritative revoked acknowledgement.
type RotationRevokeCommitter interface {
	CommitRevoke(context.Context, connectorprotocol.CredentialRotationRevoke) error
}

// RotationRevokePreparer durably commits the replacement credential after
// the server has instructed revoke but before the terminal revoked
// acknowledgement is written. A crash in that window must reconnect with the
// new credential rather than a server-revoked old reference.
type RotationRevokePreparer interface {
	PrepareRevoke(context.Context, connectorprotocol.CredentialRotationRevoke) error
}

// RotationRevokeRejoiner marks a successful revoke as a control-session
// identity boundary. Serve writes the revoked acknowledgement first, then
// exits cleanly so the production supervisor reconnects with the newly
// authoritative credential and a fresh rotation journal.
type RotationRevokeRejoiner interface {
	RejoinAfterRevoke() bool
}

// ControlSession is the host-side connector-v1 adapter. It combines the
// shared ClientSession state machine with the host credential-rotation Manager
// and exposes a framed Serve loop for the transport owner. The transport is
// deliberately an io.ReadWriteCloser so TRK-14 can supply QUIC/TCP/Unix
// carriers without moving credential custody into this package.
type ControlSession struct {
	mu                sync.RWMutex
	client            *connectorprotocol.ClientSession
	rotation          *Manager
	readiness         ReadinessSource
	snapshotReadiness SnapshotReadinessSource
	renewal           CredentialRenewalSource
	renewalSigner     RenewalProofSigner
	renewalLead       time.Duration
	outbound          chan connectorprotocol.Frame
	clock             connectorprotocol.Clock
	welcomed          bool
	welcome           connectorprotocol.Welcome
	requestSeq        uint64
	automaticRotation bool
	revokeCommitter   RotationRevokeCommitter
	rotationReadyOps  map[string]struct{}
}

type ControlSessionConfig struct {
	Hello                      connectorprotocol.Hello
	Applier                    connectorprotocol.ConfigApplier
	Drainer                    connectorprotocol.Drainer
	Rotation                   *Manager
	Readiness                  ReadinessSource
	SnapshotReadiness          SnapshotReadinessSource
	Renewal                    CredentialRenewalSource
	RenewalSigner              RenewalProofSigner
	AutomaticRotationReadiness bool
	RotationRevokeCommitter    RotationRevokeCommitter
	RenewalLead                time.Duration
	OutboundQueue              int
	Clock                      connectorprotocol.Clock
	ApplyTimeout               time.Duration
	AbortTimeout               time.Duration
}

func NewControlSession(config ControlSessionConfig) (*ControlSession, error) {
	if config.Applier == nil || config.Drainer == nil {
		// ClientSession supplies no-op defaults for unit-level protocol use, but
		// a live host adapter must never claim configuration or drain readiness
		// without the runtime-owned hooks.
		return nil, ErrControlSessionInvalid
	}
	if config.Rotation != nil && config.Readiness == nil {
		// Without an explicit readiness boundary the host could acknowledge an
		// install while no replacement session is serving traffic. Refuse that
		// silent downgrade.
		return nil, ErrControlSessionInvalid
	}
	if config.Rotation != nil && !hasControlCapability(config.Hello.Capabilities, connectorprotocol.CapabilityCredentialRotation) {
		return nil, rotationCapabilityError()
	}
	if hasControlCapability(config.Hello.Capabilities, connectorprotocol.CapabilityCredentialRotation) && config.Rotation == nil {
		return nil, rotationCapabilityError()
	}
	if config.OutboundQueue == 0 {
		config.OutboundQueue = defaultControlOutboundQueue
	}
	if config.OutboundQueue < 1 || config.OutboundQueue > maxControlOutboundQueue {
		return nil, ErrControlSessionInvalid
	}
	if config.RenewalLead == 0 {
		config.RenewalLead = defaultRenewalLead
	}
	if config.RenewalLead <= 0 || config.RenewalLead > connectorprotocol.MaxLease {
		return nil, ErrControlSessionInvalid
	}
	if config.Renewal != nil && config.RenewalSigner != nil {
		return nil, ErrControlSessionInvalid
	}
	if (config.Renewal != nil || config.RenewalSigner != nil) && !hasControlCapability(config.Hello.Capabilities, connectorprotocol.CapabilityRenewal) {
		return nil, &connectorprotocol.Error{Code: connectorprotocol.CodeCapabilityMissing, Reason: connectorprotocol.ReasonCapabilityMissing, Cause: errors.New("credential renewal capability is not negotiated")}
	}
	client, err := connectorprotocol.NewClientSession(connectorprotocol.ClientSessionConfig{
		Hello: config.Hello, Applier: config.Applier, Drainer: config.Drainer,
		Clock: config.Clock, ApplyTimeout: config.ApplyTimeout, AbortTimeout: config.AbortTimeout,
	})
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = controlRealClock{}
	}
	if config.AutomaticRotationReadiness && (config.Rotation == nil || config.Readiness == nil) {
		return nil, ErrControlSessionInvalid
	}
	if config.RotationRevokeCommitter != nil && config.Rotation == nil {
		return nil, ErrControlSessionInvalid
	}
	return &ControlSession{client: client, rotation: config.Rotation, readiness: config.Readiness, snapshotReadiness: config.SnapshotReadiness, renewal: config.Renewal, renewalSigner: config.RenewalSigner, renewalLead: config.RenewalLead, outbound: make(chan connectorprotocol.Frame, config.OutboundQueue), clock: clock, automaticRotation: config.AutomaticRotationReadiness, revokeCommitter: config.RotationRevokeCommitter, rotationReadyOps: make(map[string]struct{})}, nil
}

type controlRealClock struct{}

func (controlRealClock) Now() time.Time { return time.Now().UTC() }

func (s *ControlSession) Session() *connectorprotocol.ClientSession {
	if s == nil {
		return nil
	}
	return s.client
}

// Welcome returns a copy of the exact negotiated server session after
// authentication. It is safe for generation-bound replacement readiness.
func (s *ControlSession) Welcome() (connectorprotocol.Welcome, bool) {
	if s == nil {
		return connectorprotocol.Welcome{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.welcomed {
		return connectorprotocol.Welcome{}, false
	}
	value := s.welcome
	value.Capabilities = append([]string(nil), value.Capabilities...)
	return value, true
}

// HasSnapshotReadiness reports whether Serve can perform the regular staged
// snapshot cutover. HandleFrame remains available for protocol-level tests and
// rotation events, but a live carrier runner must require this boundary.
func (s *ControlSession) HasSnapshotReadiness() bool {
	return s != nil && s.snapshotReadiness != nil
}

// EnqueueFrame schedules one host-to-server control frame for the Serve loop.
// The queue is bounded and the caller retains ownership of the frame. No
// caller may write directly to the carrier while Serve is running.
func (s *ControlSession) EnqueueFrame(frame connectorprotocol.Frame) error {
	if s == nil || s.outbound == nil {
		return ErrControlSessionInvalid
	}
	if err := frame.Validate(); err != nil {
		return err
	}
	switch frame.Type {
	case connectorprotocol.MessageHeartbeat, connectorprotocol.MessageAuthRenew, connectorprotocol.MessageCredentialRotationReady, connectorprotocol.MessageDisconnect:
	default:
		return connectorprotocol.ErrUnsupportedMessage
	}
	select {
	case s.outbound <- frame:
		return nil
	default:
		return ErrControlSessionOutboundFull
	}
}

func (s *ControlSession) QueueHeartbeat(now time.Time) error {
	if s == nil {
		return ErrControlSessionInvalid
	}
	frame, err := s.HeartbeatFrame(s.nextRequestID("heartbeat"), now)
	if err != nil {
		return err
	}
	return s.EnqueueFrame(frame)
}

func (s *ControlSession) QueueRenewal(now time.Time, nonce, signedProof string) error {
	if s == nil {
		return ErrControlSessionInvalid
	}
	frame, err := s.RenewalFrame(s.nextRequestID("renewal"), now, nonce, signedProof)
	if err != nil {
		return err
	}
	return s.EnqueueFrame(frame)
}

func (s *ControlSession) nextRequestID(prefix string) string {
	s.mu.Lock()
	s.requestSeq++
	sequence := s.requestSeq
	s.mu.Unlock()
	if prefix == "" {
		prefix = "event"
	}
	return prefix + "-" + strconv.FormatUint(sequence, 10)
}

func (s *ControlSession) HelloFrame(requestID string) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	return connectorprotocol.NewFrame(connectorprotocol.MessageHello, requestID, s.client.Hello())
}

func (s *ControlSession) AcceptWelcomeFrame(frame connectorprotocol.Frame) error {
	if s == nil || s.client == nil || frame.Type != connectorprotocol.MessageWelcome {
		return ErrControlSessionInvalid
	}
	var welcome connectorprotocol.Welcome
	if err := frame.DecodePayload(&welcome); err != nil {
		return err
	}
	if s.rotation != nil && !hasControlCapability(welcome.Capabilities, connectorprotocol.CapabilityCredentialRotation) {
		return rotationCapabilityError()
	}
	if err := s.client.AcceptWelcome(welcome); err != nil {
		return err
	}
	s.mu.Lock()
	s.welcomed = true
	s.welcome = welcome
	s.mu.Unlock()
	return nil
}

// HandleFrame dispatches one server-to-host frame. Rotation install only
// acknowledges that the replacement credential was installed. Replacement
// readiness is an explicit event boundary through MarkRotationReadyFrame so a
// potentially slow process/data-plane wait can never block this receive loop.
func (s *ControlSession) HandleFrame(ctx context.Context, frame connectorprotocol.Frame) ([]connectorprotocol.Frame, error) {
	if s == nil || s.client == nil || ctx == nil {
		return nil, ErrControlSessionInvalid
	}
	if frame.Type == connectorprotocol.MessageWelcome {
		return nil, s.AcceptWelcomeFrame(frame)
	}
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	switch frame.Type {
	case connectorprotocol.MessageAck:
		var ack connectorprotocol.Ack
		if err := frame.DecodePayload(&ack); err != nil {
			return nil, err
		}
		if ack.Kind != connectorprotocol.AckReady {
			return nil, connectorprotocol.ErrUnsupportedMessage
		}
		hello := s.client.Hello()
		s.mu.RLock()
		welcome := s.welcome
		s.mu.RUnlock()
		active, ok := s.client.Active()
		if !ok || ack.AccountID != hello.AccountID || ack.TunnelID != hello.TunnelID || ack.ConnectorID != hello.ConnectorID || ack.SessionID != welcome.SessionID || ack.ProcessGeneration != hello.ProcessGeneration || ack.Generation != active.Generation || ack.ContentHash != active.ContentHash {
			return nil, connectorprotocol.ErrIdentityMismatch
		}
		if ack.Status != connectorprotocol.AckApplied && ack.Status != connectorprotocol.AckDuplicate {
			return nil, connectorprotocol.ErrSnapshotRequired
		}
		return nil, nil
	case connectorprotocol.MessageSnapshot:
		var snapshot connectorprotocol.Snapshot
		if err := frame.DecodePayload(&snapshot); err != nil {
			return nil, err
		}
		ack, applyErr := s.client.ApplySnapshot(ctx, snapshot)
		return s.applyAck(frame.RequestID, connectorprotocol.AckSnapshot, snapshot.Generation, snapshot.ContentHash, ack, applyErr)
	case connectorprotocol.MessageDelta:
		var delta connectorprotocol.Delta
		if err := frame.DecodePayload(&delta); err != nil {
			return nil, err
		}
		ack, applyErr := s.client.ApplyDelta(ctx, delta)
		return s.applyAck(frame.RequestID, connectorprotocol.AckDelta, delta.Generation, delta.ContentHash, ack, applyErr)
	case connectorprotocol.MessageHeartbeatAck:
		var ack connectorprotocol.HeartbeatAck
		if err := frame.DecodePayload(&ack); err != nil {
			return nil, err
		}
		return nil, s.client.AcceptHeartbeatAck(ack)
	case connectorprotocol.MessageAuthRenewed:
		var result connectorprotocol.AuthResult
		if err := frame.DecodePayload(&result); err != nil {
			return nil, err
		}
		return nil, s.client.ApplyRenewal(result)
	case connectorprotocol.MessageDrain:
		var request connectorprotocol.Drain
		if err := frame.DecodePayload(&request); err != nil {
			return nil, err
		}
		ack, drainErr := s.client.HandleDrain(ctx, request)
		response, frameErr := connectorprotocol.NewFrame(connectorprotocol.MessageDrainAck, frame.RequestID, ack)
		if frameErr != nil {
			return nil, errors.Join(drainErr, frameErr)
		}
		return []connectorprotocol.Frame{response}, drainErr
	case connectorprotocol.MessageCredentialRotationChallenge:
		return s.handleRotationChallenge(ctx, frame)
	case connectorprotocol.MessageCredentialRotationInstall:
		return s.handleRotationInstall(ctx, frame)
	case connectorprotocol.MessageCredentialRotationRevoke:
		return s.handleRotationRevoke(ctx, frame)
	case connectorprotocol.MessageCredentialRotationAck, connectorprotocol.MessageCredentialRotationReady:
		return nil, connectorprotocol.ErrUnsupportedMessage
	case connectorprotocol.MessageDisconnect:
		var disconnect connectorprotocol.Disconnect
		if err := frame.DecodePayload(&disconnect); err != nil {
			return nil, err
		}
		return nil, s.client.Close(disconnect.Reason)
	default:
		return nil, connectorprotocol.ErrUnsupportedMessage
	}
}

func (s *ControlSession) validateBoundRotation(identityAccount, tunnelID, connectorID, hostID, sessionID string, processGeneration uint64) error {
	s.mu.RLock()
	welcomed, welcome := s.welcomed, s.welcome
	s.mu.RUnlock()
	if !welcomed {
		return connectorprotocol.ErrSessionConflict
	}
	if err := s.requireRotationRuntime(); err != nil {
		return err
	}
	if err := s.client.CheckLease(s.clock.Now().UTC()); err != nil {
		return err
	}
	hello := s.client.Hello()
	if identityAccount != hello.AccountID || tunnelID != hello.TunnelID || connectorID != hello.ConnectorID || hostID != hello.HostID || sessionID != welcome.SessionID || processGeneration != hello.ProcessGeneration {
		return connectorprotocol.ErrIdentityMismatch
	}
	if s.client.State() != connectorprotocol.SessionReady {
		return &connectorprotocol.Error{
			Code:      connectorprotocol.CodeCredentialRotationNotReady,
			Reason:    connectorprotocol.ReasonSnapshotRejected,
			Retryable: true,
			Cause:     errors.New("active connector session is not ready for credential rotation"),
		}
	}
	return nil
}

func hasControlCapability(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func rotationCapabilityError() error {
	return &connectorprotocol.Error{
		Code:      connectorprotocol.CodeCapabilityMissing,
		Reason:    connectorprotocol.ReasonCapabilityMissing,
		Retryable: false,
		Cause:     errors.New("credential rotation capability is not negotiated"),
	}
}

func (s *ControlSession) requireRotationRuntime() error {
	if s == nil || s.client == nil || s.rotation == nil {
		return &connectorprotocol.Error{
			Code:      connectorprotocol.CodeCredentialRotationFailed,
			Reason:    connectorprotocol.ReasonCredentialRotation,
			Retryable: true,
			Cause:     errors.New("credential rotation runtime is unavailable"),
		}
	}
	s.mu.RLock()
	welcomed, welcome := s.welcomed, s.welcome
	s.mu.RUnlock()
	if !welcomed || !hasControlCapability(welcome.Capabilities, connectorprotocol.CapabilityCredentialRotation) || !hasControlCapability(s.client.Hello().Capabilities, connectorprotocol.CapabilityCredentialRotation) {
		return rotationCapabilityError()
	}
	return nil
}

func identitySessionID(session *connectorprotocol.ClientSession) string {
	if session == nil {
		return ""
	}
	return session.Disconnect().SessionID
}

func validateReplacementReadiness(observation ReplacementReadiness, install connectorprotocol.CredentialRotationInstall, oldSession *connectorprotocol.ClientSession, clock connectorprotocol.Clock) error {
	if observation.Session == nil || oldSession == nil {
		return &connectorprotocol.Error{Code: connectorprotocol.CodeCredentialRotationNotReady, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true, Cause: errors.New("replacement session is unavailable")}
	}
	if !hasControlCapability(observation.NegotiatedCapabilities, connectorprotocol.CapabilityCredentialRotation) || !hasControlCapability(observation.Session.Hello().Capabilities, connectorprotocol.CapabilityCredentialRotation) {
		return rotationCapabilityError()
	}
	if !observation.EdgeReady || !observation.RouteReady || !observation.OriginReady {
		return &connectorprotocol.Error{Code: connectorprotocol.CodeCredentialRotationNotReady, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true, Cause: errors.New("replacement readiness is incomplete")}
	}
	if connectorprotocol.ValidateIdentifier(observation.SessionID) != nil || observation.ProcessGeneration == 0 || observation.ConfigGeneration == 0 {
		return connectorprotocol.ErrInvalidInput
	}
	readiness := connectorprotocol.Readiness{
		AccountID: oldSession.Hello().AccountID, TunnelID: oldSession.Hello().TunnelID, ConnectorID: oldSession.Hello().ConnectorID,
		SessionID: observation.SessionID, ProcessGeneration: observation.ProcessGeneration,
		Generation: observation.ConfigGeneration, ContentHash: observation.ConfigContentHash,
		EdgeReady: observation.EdgeReady, RouteReady: observation.RouteReady, OriginReady: observation.OriginReady,
	}
	if err := readiness.Validate(); err != nil {
		return err
	}
	replacement := observation.Session
	if replacement.State() != connectorprotocol.SessionReady {
		return &connectorprotocol.Error{Code: connectorprotocol.CodeCredentialRotationNotReady, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true, Cause: errors.New("replacement session is not ready")}
	}
	if clock != nil {
		if err := replacement.CheckLease(clock.Now().UTC()); err != nil {
			return err
		}
	}
	identity := replacement.Hello()
	replacementID := identitySessionID(replacement)
	if replacementID != observation.SessionID || identity.ProcessGeneration != observation.ProcessGeneration || replacementID == install.SessionID || observation.ProcessGeneration < install.ReplacementProcessGeneration {
		return connectorprotocol.ErrIdentityMismatch
	}
	old := oldSession.Hello()
	if identity.AccountID != old.AccountID || identity.TunnelID != old.TunnelID || identity.ConnectorID != old.ConnectorID || identity.HostID != old.HostID {
		return connectorprotocol.ErrIdentityMismatch
	}
	active, ok := replacement.Active()
	if !ok || active.Generation != observation.ConfigGeneration || active.ContentHash != observation.ConfigContentHash {
		return &connectorprotocol.Error{Code: connectorprotocol.CodeContentHashMismatch, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true, Cause: errors.New("replacement active configuration does not match readiness")}
	}
	if active.AccountID != old.AccountID || active.TunnelID != old.TunnelID || active.ConnectorID != old.ConnectorID || active.SessionID != observation.SessionID || active.ProcessGeneration != observation.ProcessGeneration {
		return connectorprotocol.ErrIdentityMismatch
	}
	return nil
}

func (s *ControlSession) ensureRotationRecord(ctx context.Context, operationID string, allowNotFound bool) error {
	if s.rotation == nil {
		return connectorprotocol.ErrUnsupportedMessage
	}
	if record, ok := s.rotation.Record(); ok && record.OperationID == operationID {
		return nil
	}
	err := s.rotation.Recover(ctx, operationID)
	if allowNotFound && errors.Is(err, ErrOperationNotFound) {
		return nil
	}
	return err
}

func (s *ControlSession) handleRotationChallenge(ctx context.Context, frame connectorprotocol.Frame) ([]connectorprotocol.Frame, error) {
	var challenge connectorprotocol.CredentialRotationChallenge
	if err := frame.DecodePayload(&challenge); err != nil {
		return nil, err
	}
	if err := s.validateBoundRotation(challenge.AccountID, challenge.TunnelID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration); err != nil {
		return s.rotationError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
	}
	hello := s.client.Hello()
	if challenge.OldIdentityKeyID != hello.Auth.IdentityKeyID || challenge.OldIdentityKeyThumbprint != hello.Auth.IdentityKeyThumbprint {
		err := connectorprotocol.ErrIdentityMismatch
		return s.rotationError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
	}
	if err := s.ensureRotationRecord(ctx, challenge.OperationID, true); err != nil {
		return s.rotationError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
	}
	if s.rotation == nil {
		return s.rotationError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, connectorprotocol.ErrUnsupportedMessage)
	}
	proof, err := s.rotation.AcceptChallenge(ctx, challenge)
	if err != nil {
		return s.rotationError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
	}
	return oneFrame(connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationProof, frame.RequestID, proof))
}

func (s *ControlSession) handleRotationInstall(ctx context.Context, frame connectorprotocol.Frame) ([]connectorprotocol.Frame, error) {
	var install connectorprotocol.CredentialRotationInstall
	if err := frame.DecodePayload(&install); err != nil {
		return nil, err
	}
	if err := s.validateBoundRotation(install.AccountID, install.TunnelID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration); err != nil {
		return s.rotationError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, err)
	}
	if err := s.ensureRotationRecord(ctx, install.OperationID, false); err != nil {
		return s.rotationError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, err)
	}
	if s.rotation == nil {
		return s.rotationError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, connectorprotocol.ErrUnsupportedMessage)
	}
	ack, err := s.rotation.AcceptInstall(ctx, install)
	if err != nil {
		return s.rotationError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, err)
	}
	response, frameErr := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationAck, frame.RequestID, ack)
	if frameErr != nil {
		return nil, frameErr
	}
	return []connectorprotocol.Frame{response}, nil
}

func (s *ControlSession) handleRotationRevoke(ctx context.Context, frame connectorprotocol.Frame) ([]connectorprotocol.Frame, error) {
	var revoke connectorprotocol.CredentialRotationRevoke
	if err := frame.DecodePayload(&revoke); err != nil {
		return nil, err
	}
	if err := s.validateBoundRotation(revoke.AccountID, revoke.TunnelID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration); err != nil {
		return s.rotationError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
	}
	if s.client.State() != connectorprotocol.SessionReady {
		err := &connectorprotocol.Error{Code: connectorprotocol.CodeCredentialRotationNotReady, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true}
		return s.rotationError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
	}
	if err := s.ensureRotationRecord(ctx, revoke.OperationID, false); err != nil {
		return s.rotationError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
	}
	if s.rotation == nil {
		return s.rotationError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, connectorprotocol.ErrUnsupportedMessage)
	}
	ack, err := s.rotation.AcceptRevoke(ctx, revoke)
	if err != nil {
		return s.rotationError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
	}
	return oneFrame(connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationAck, frame.RequestID, ack))
}

func oneFrame(frame connectorprotocol.Frame, err error) ([]connectorprotocol.Frame, error) {
	if err != nil {
		return nil, err
	}
	return []connectorprotocol.Frame{frame}, nil
}

func rotationFailureAck(install connectorprotocol.CredentialRotationInstall, cause error) connectorprotocol.CredentialRotationAck {
	code := connectorprotocol.CodeOf(cause)
	if code == "" || code == connectorprotocol.CodeInvalidInput || code == connectorprotocol.CodeUnsupportedMessage {
		code = connectorprotocol.CodeCredentialRotationFailed
	}
	return connectorprotocol.CredentialRotationAck{
		AccountID: install.AccountID, TunnelID: install.TunnelID, OperationID: install.OperationID,
		ConnectorID: install.ConnectorID, HostID: install.HostID, SessionID: install.SessionID,
		ProcessGeneration: install.ProcessGeneration, TargetSetHash: install.TargetSetHash,
		OldCredentialGeneration: install.OldCredentialGeneration, NewCredentialGeneration: install.NewCredentialGeneration,
		Status: connectorprotocol.RotationAckFailed, Code: code,
	}
}

// rotationFailureFrame preserves a typed, correlated failure for an explicit
// readiness event. The error is returned as well so the supervisor can decide
// whether to retry or mark the operation uncertain; the frame is safe to send
// because it contains only the already-public operation identity and status.
func (s *ControlSession) rotationFailureFrame(requestID string, install connectorprotocol.CredentialRotationInstall, cause error) (connectorprotocol.Frame, error) {
	failure := rotationFailureAck(install, cause)
	frame, frameErr := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationAck, requestID, failure)
	if frameErr != nil {
		return connectorprotocol.Frame{}, errors.Join(cause, frameErr)
	}
	return frame, cause
}

func (s *ControlSession) rotationError(requestID, accountID, tunnelID, operationID, connectorID, hostID, sessionID string, processGeneration uint64, targetSetHash string, oldGeneration, newGeneration uint64, cause error) ([]connectorprotocol.Frame, error) {
	code := connectorprotocol.CodeOf(cause)
	if code == "" || code == connectorprotocol.CodeInvalidInput || code == connectorprotocol.CodeUnsupportedMessage {
		code = connectorprotocol.CodeCredentialRotationRejected
	}
	ack := connectorprotocol.CredentialRotationAck{
		AccountID: accountID, TunnelID: tunnelID, OperationID: operationID, ConnectorID: connectorID,
		HostID: hostID, SessionID: sessionID, ProcessGeneration: processGeneration, TargetSetHash: targetSetHash,
		OldCredentialGeneration: oldGeneration, NewCredentialGeneration: newGeneration,
		Status: connectorprotocol.RotationAckRejected, Code: code,
	}
	response, frameErr := connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationAck, requestID, ack)
	if frameErr != nil {
		return nil, errors.Join(cause, frameErr)
	}
	return []connectorprotocol.Frame{response}, cause
}

func (s *ControlSession) applyAck(requestID string, kind connectorprotocol.AckKind, generation uint64, contentHash string, ack connectorprotocol.Ack, applyErr error) ([]connectorprotocol.Frame, error) {
	if ack.Validate() != nil {
		code := connectorprotocol.CodeOf(applyErr)
		if code == "" {
			if kind == connectorprotocol.AckSnapshot {
				code = connectorprotocol.CodeSnapshotRejected
			} else {
				code = connectorprotocol.CodeDeltaRejected
			}
		}
		hello := s.client.Hello()
		s.mu.RLock()
		welcome := s.welcome
		s.mu.RUnlock()
		ack = connectorprotocol.Ack{AccountID: hello.AccountID, TunnelID: hello.TunnelID, ConnectorID: hello.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: hello.ProcessGeneration, Kind: kind, Status: connectorprotocol.AckRejected, Generation: generation, ContentHash: contentHash, Code: code}
	}
	response, frameErr := connectorprotocol.NewFrame(connectorprotocol.MessageAck, requestID, ack)
	if frameErr != nil {
		return nil, errors.Join(applyErr, frameErr)
	}
	return []connectorprotocol.Frame{response}, applyErr
}

// Serve sends hello and runs the one framed control loop until the peer closes
// or the session reaches a typed terminal state. Snapshot readiness is waited
// asynchronously so heartbeat, renewal, and rotation frames continue to be
// handled while origins are probed. Only this loop writes frames, which keeps
// wire ordering deterministic and bounds pending readiness to one result.
func (s *ControlSession) Serve(ctx context.Context, carrier io.ReadWriteCloser, helloRequestID string) error {
	if s == nil || carrier == nil || ctx == nil {
		return ErrControlSessionInvalid
	}
	hello, err := s.HelloFrame(helloRequestID)
	if err != nil {
		return err
	}
	if err := connectorprotocol.WriteFrame(carrier, hello); err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	defer carrier.Close()
	go func() {
		select {
		case <-runContext.Done():
			_ = carrier.Close()
		case <-stop:
		}
	}()
	frames := make(chan controlReadResult, 1)
	go readControlFrames(runContext, carrier, frames)
	readyResults := make(chan snapshotReadyResult, 1)
	rotationErrors := make(chan error, 1)
	var pending *snapshotReadyState
	var heartbeatTimer *time.Timer
	var heartbeatEvents <-chan time.Time
	var renewalTimer *time.Timer
	var renewalEvents <-chan time.Time
	renewalPending := false
	heartbeatInterval := time.Duration(0)
	resetHeartbeat := func() {
		if heartbeatInterval <= 0 {
			heartbeatEvents = nil
			return
		}
		if heartbeatTimer == nil {
			heartbeatTimer = time.NewTimer(heartbeatInterval)
		} else {
			resetControlTimer(heartbeatTimer)
			heartbeatTimer.Reset(heartbeatInterval)
		}
		heartbeatEvents = heartbeatTimer.C
	}
	resetRenewal := func() {
		if s.renewal == nil && s.renewalSigner == nil {
			renewalEvents = nil
			return
		}
		if renewalPending {
			renewalEvents = nil
			return
		}
		delay := credentialRenewalDelay(s.clock.Now().UTC(), s.client.Auth().ExpiresAt, s.renewalLead)
		if renewalTimer == nil {
			renewalTimer = time.NewTimer(delay)
		} else {
			resetControlTimer(renewalTimer)
			renewalTimer.Reset(delay)
		}
		renewalEvents = renewalTimer.C
	}
	defer func() {
		if heartbeatTimer != nil {
			heartbeatTimer.Stop()
		}
		if renewalTimer != nil {
			renewalTimer.Stop()
		}
		stopSnapshotReadiness(pending)
	}()
	for {
		select {
		case <-runContext.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return runContext.Err()
		case result := <-frames:
			if result.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return result.err
			}
			responses, handleErr := s.HandleFrame(runContext, result.frame)
			var revoke *connectorprotocol.CredentialRotationRevoke
			if result.frame.Type == connectorprotocol.MessageCredentialRotationRevoke && handleErr == nil && s.revokeCommitter != nil {
				var value connectorprotocol.CredentialRotationRevoke
				if err := result.frame.DecodePayload(&value); err != nil {
					return err
				}
				revoke = &value
				if preparer, ok := s.revokeCommitter.(RotationRevokePreparer); ok {
					if err := preparer.PrepareRevoke(runContext, value); err != nil {
						return err
					}
				}
			}
			for _, response := range responses {
				if err := connectorprotocol.WriteFrame(carrier, response); err != nil {
					return err
				}
			}
			if handleErr != nil {
				return handleErr
			}
			if result.frame.Type == connectorprotocol.MessageCredentialRotationInstall && s.automaticRotation {
				var install connectorprotocol.CredentialRotationInstall
				if err := result.frame.DecodePayload(&install); err != nil {
					return err
				}
				s.startAutomaticRotationReady(runContext, install, rotationErrors)
			}
			if revoke != nil {
				if err := s.revokeCommitter.CommitRevoke(runContext, *revoke); err != nil {
					return err
				}
				if rejoiner, ok := s.revokeCommitter.(RotationRevokeRejoiner); ok && rejoiner.RejoinAfterRevoke() {
					return nil
				}
			}
			if result.frame.Type == connectorprotocol.MessageWelcome {
				s.mu.RLock()
				welcome := s.welcome
				s.mu.RUnlock()
				heartbeatInterval = time.Duration(welcome.Lease.HeartbeatIntervalMS) * time.Millisecond
				renewalPending = false
				resetHeartbeat()
				resetRenewal()
			} else if result.frame.Type == connectorprotocol.MessageAuthRenewed {
				renewalPending = false
				resetRenewal()
			}
			if applied, ok := appliedSnapshot(result.frame, responses); ok {
				if s.snapshotReadiness == nil {
					return ErrControlSessionInvalid
				}
				candidate, candidateOK := s.client.Candidate()
				if !candidateOK || candidate.Generation != applied.Generation || candidate.ContentHash != applied.ContentHash {
					return ErrControlSessionInvalid
				}
				applied = candidate
				if pending != nil {
					pending.cancel()
				}
				readinessContext, readinessCancel := context.WithCancel(runContext)
				state := &snapshotReadyState{snapshot: applied, requestID: result.frame.RequestID, cancel: readinessCancel, done: make(chan struct{})}
				pending = state
				go s.waitSnapshotReady(readinessContext, state, readyResults)
			}
			if s.client.State() == connectorprotocol.SessionClosed {
				return nil
			}
		case outgoing := <-s.outbound:
			if err := connectorprotocol.WriteFrame(carrier, outgoing); err != nil {
				return err
			}
			if outgoing.Type == connectorprotocol.MessageAuthRenew {
				renewalPending = true
				if renewalTimer != nil {
					resetControlTimer(renewalTimer)
				}
				renewalEvents = nil
			}
		case <-heartbeatEvents:
			// Heartbeat uses the promoted generation when one exists, and the
			// exact staged candidate during bootstrap. The server accepts the
			// latter only as a lease renewal; it never promotes readiness from a
			// heartbeat. This keeps a slow carrier/origin probe from expiring the
			// session that is waiting to become ready.
			frame, err := s.HeartbeatFrame(s.nextRequestID("heartbeat"), s.clock.Now().UTC())
			if err != nil {
				if !errors.Is(err, connectorprotocol.ErrSnapshotRequired) && !errors.Is(err, connectorprotocol.ErrNotReady) {
					return err
				}
			} else if err := connectorprotocol.WriteFrame(carrier, frame); err != nil {
				return err
			}
			resetHeartbeat()
		case <-renewalEvents:
			if s.renewal == nil && s.renewalSigner == nil {
				renewalEvents = nil
				continue
			}
			now := s.clock.Now().UTC()
			var frame connectorprotocol.Frame
			var err error
			if s.renewalSigner != nil {
				frame, err = s.signedRenewalFrame(runContext, s.nextRequestID("renewal"), now)
			} else {
				nonce, signedProof, renewalErr := s.renewal.Renew(runContext, now)
				if renewalErr != nil {
					return renewalErr
				}
				frame, err = s.RenewalFrame(s.nextRequestID("renewal"), now, nonce, signedProof)
			}
			if err != nil {
				return err
			}
			if err := connectorprotocol.WriteFrame(carrier, frame); err != nil {
				return err
			}
			renewalPending = true
			renewalEvents = nil
		case result := <-readyResults:
			if pending == nil || !pending.matches(result) {
				// A canceled readiness worker may race with a newer candidate. The
				// key check fences its result without affecting session state.
				continue
			}
			pending.cancel()
			pending = nil
			if result.err != nil {
				return result.err
			}
			if err := validateSnapshotReadiness(result.snapshot, result.readiness); err != nil {
				return err
			}
			readiness, err := s.client.MarkReadyContext(runContext, true, true, true)
			if err != nil {
				return err
			}
			if err := validateSnapshotReadiness(result.snapshot, readiness); err != nil {
				return err
			}
			readyFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageReady, result.requestID, readiness)
			if err != nil {
				return err
			}
			if err := connectorprotocol.WriteFrame(carrier, readyFrame); err != nil {
				return err
			}
		case rotationErr := <-rotationErrors:
			if rotationErr != nil {
				return rotationErr
			}
		}
	}
}

func (s *ControlSession) startAutomaticRotationReady(ctx context.Context, install connectorprotocol.CredentialRotationInstall, results chan<- error) {
	if s == nil || ctx == nil || results == nil {
		return
	}
	s.mu.Lock()
	if _, exists := s.rotationReadyOps[install.OperationID]; exists {
		s.mu.Unlock()
		return
	}
	s.rotationReadyOps[install.OperationID] = struct{}{}
	s.mu.Unlock()
	go func() {
		frame, err := s.ReplacementReadyFrame(ctx, s.nextRequestID("rotation-ready"))
		if err == nil {
			err = s.EnqueueFrame(frame)
		}
		if err != nil {
			select {
			case results <- err:
			case <-ctx.Done():
			}
		}
	}()
}

type controlReadResult struct {
	frame connectorprotocol.Frame
	err   error
}

func readControlFrames(ctx context.Context, carrier io.Reader, results chan<- controlReadResult) {
	for {
		frame, err := connectorprotocol.ReadFrame(carrier)
		select {
		case results <- controlReadResult{frame: frame, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

type snapshotReadyState struct {
	snapshot  connectorprotocol.Snapshot
	requestID string
	cancel    context.CancelFunc
	done      chan struct{}
}

type snapshotReadyResult struct {
	snapshot  connectorprotocol.Snapshot
	requestID string
	readiness connectorprotocol.Readiness
	err       error
}

func (s *snapshotReadyState) matches(result snapshotReadyResult) bool {
	return s != nil && s.requestID == result.requestID && s.snapshot.AccountID == result.snapshot.AccountID && s.snapshot.TunnelID == result.snapshot.TunnelID && s.snapshot.ConnectorID == result.snapshot.ConnectorID && s.snapshot.SessionID == result.snapshot.SessionID && s.snapshot.ProcessGeneration == result.snapshot.ProcessGeneration && s.snapshot.Generation == result.snapshot.Generation && s.snapshot.ContentHash == result.snapshot.ContentHash
}

func (s *ControlSession) waitSnapshotReady(ctx context.Context, state *snapshotReadyState, results chan<- snapshotReadyResult) {
	defer close(state.done)
	readiness, err := s.snapshotReadiness.WaitReady(ctx, state.snapshot)
	result := snapshotReadyResult{snapshot: state.snapshot, requestID: state.requestID, readiness: readiness, err: err}
	select {
	case results <- result:
	case <-ctx.Done():
	}
}

// stopSnapshotReadiness cancels an in-flight readiness probe and waits only a
// bounded interval for a cooperative provider to release its resources. The
// Serve loop never waits for a replacement probe while it is live, so a
// provider that fails to honor context cancellation cannot block heartbeats or
// reconnect cleanup indefinitely.
func stopSnapshotReadiness(state *snapshotReadyState) {
	if state == nil {
		return
	}
	if state.cancel != nil {
		state.cancel()
	}
	if state.done == nil {
		return
	}
	timer := time.NewTimer(readinessCleanupTimeout)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-state.done:
	case <-timer.C:
	}
}

func resetControlTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func credentialRenewalDelay(now, expiresAt time.Time, lead time.Duration) time.Duration {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return time.Millisecond
	}
	delay := remaining - lead
	if delay <= 0 {
		delay = remaining / 2
	}
	if delay < time.Millisecond {
		return time.Millisecond
	}
	return delay
}

func appliedSnapshot(frame connectorprotocol.Frame, responses []connectorprotocol.Frame) (connectorprotocol.Snapshot, bool) {
	if frame.Type != connectorprotocol.MessageSnapshot && frame.Type != connectorprotocol.MessageDelta {
		return connectorprotocol.Snapshot{}, false
	}
	wantedKind := connectorprotocol.AckSnapshot
	if frame.Type == connectorprotocol.MessageDelta {
		wantedKind = connectorprotocol.AckDelta
	}
	for _, response := range responses {
		if response.Type != connectorprotocol.MessageAck {
			continue
		}
		var ack connectorprotocol.Ack
		if response.DecodePayload(&ack) != nil {
			return connectorprotocol.Snapshot{}, false
		}
		if ack.Kind != wantedKind || ack.Status != connectorprotocol.AckApplied {
			return connectorprotocol.Snapshot{}, false
		}
		if frame.Type == connectorprotocol.MessageSnapshot {
			var snapshot connectorprotocol.Snapshot
			if frame.DecodePayload(&snapshot) != nil {
				return connectorprotocol.Snapshot{}, false
			}
			return snapshot, true
		}
		var delta connectorprotocol.Delta
		if frame.DecodePayload(&delta) != nil {
			return connectorprotocol.Snapshot{}, false
		}
		return connectorprotocol.Snapshot{AccountID: delta.AccountID, TunnelID: delta.TunnelID, ConnectorID: delta.ConnectorID, SessionID: delta.SessionID, ProcessGeneration: delta.ProcessGeneration, Generation: delta.Generation, ContentHash: delta.ContentHash, Payload: append([]byte(nil), delta.Payload...)}, true
	}
	return connectorprotocol.Snapshot{}, false
}

func validateSnapshotReadiness(snapshot connectorprotocol.Snapshot, readiness connectorprotocol.Readiness) error {
	if err := readiness.Validate(); err != nil || !readiness.EdgeReady || !readiness.RouteReady || !readiness.OriginReady || readiness.AccountID != snapshot.AccountID || readiness.TunnelID != snapshot.TunnelID || readiness.ConnectorID != snapshot.ConnectorID || readiness.SessionID != snapshot.SessionID || readiness.ProcessGeneration != snapshot.ProcessGeneration || readiness.Generation != snapshot.Generation || readiness.ContentHash != snapshot.ContentHash {
		return &connectorprotocol.Error{Code: connectorprotocol.CodeNotReady, Reason: connectorprotocol.ReasonSnapshotRejected, Retryable: true, Cause: errors.New("snapshot readiness is not bound to the staged snapshot")}
	}
	return nil
}

func (s *ControlSession) HeartbeatFrame(requestID string, now time.Time) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	heartbeat, err := s.client.Heartbeat(now)
	if err != nil {
		return connectorprotocol.Frame{}, err
	}
	return connectorprotocol.NewFrame(connectorprotocol.MessageHeartbeat, requestID, heartbeat)
}

func (s *ControlSession) RenewalFrame(requestID string, now time.Time, nonce, signedProof string) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	request, err := s.client.RenewalRequest(now, nonce, signedProof)
	if err != nil {
		return connectorprotocol.Frame{}, err
	}
	return connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenew, requestID, request)
}

func (s *ControlSession) signedRenewalFrame(ctx context.Context, requestID string, now time.Time) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil || s.renewalSigner == nil || ctx == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	s.mu.RLock()
	welcome, welcomed := s.welcome, s.welcomed
	s.mu.RUnlock()
	if !welcomed {
		return connectorprotocol.Frame{}, connectorprotocol.ErrSessionConflict
	}
	var randomNonce [24]byte
	if _, err := rand.Read(randomNonce[:]); err != nil {
		return connectorprotocol.Frame{}, err
	}
	auth := s.client.Auth()
	request := connectorprotocol.RenewalRequest{
		SessionID: welcome.SessionID, AccountID: auth.AccountID, TunnelID: auth.TunnelID,
		ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID,
		IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: s.client.Hello().ProcessGeneration,
		CredentialGeneration: auth.CredentialGeneration, Nonce: base64.RawURLEncoding.EncodeToString(randomNonce[:]), RequestedAt: now,
	}
	payload, err := connectorprotocol.RenewalProofPayload(request)
	if err != nil {
		return connectorprotocol.Frame{}, err
	}
	signature, err := s.renewalSigner.SignRenewalProof(ctx, payload)
	if err != nil || len(signature) == 0 {
		return connectorprotocol.Frame{}, errors.Join(ErrControlSessionInvalid, err)
	}
	request.SignedProof = base64.RawURLEncoding.EncodeToString(signature)
	if err := request.ValidateAt(now); err != nil {
		return connectorprotocol.Frame{}, err
	}
	return connectorprotocol.NewFrame(connectorprotocol.MessageAuthRenew, requestID, request)
}

// ReplacementReadyFrame is the explicit asynchronous readiness boundary for
// a credential install. The caller invokes it from a supervisor/event worker,
// never from HandleFrame's receive loop. It may wait for process and
// data-plane readiness through ReadinessSource, then validates that observation
// against the replacement ClientSession and the active host configuration
// before emitting the credential-aware ready frame.
func (s *ControlSession) ReplacementReadyFrame(ctx context.Context, requestID string) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil || s.rotation == nil || s.readiness == nil || ctx == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	record, ok := s.rotation.Record()
	if !ok || record.Install == nil {
		return connectorprotocol.Frame{}, ErrOperationNotFound
	}
	if err := s.requireRotationRuntime(); err != nil {
		return connectorprotocol.Frame{}, err
	}
	observation, err := s.readiness.WaitReplacementReady(ctx, *record.Install)
	if err != nil {
		return s.rotationFailureFrame(requestID, *record.Install, err)
	}
	return s.MarkRotationReadyFrame(ctx, requestID, observation)
}

// MarkRotationReadyFrame consumes an already-observed replacement readiness
// event. Keeping this separate from ReplacementReadyFrame lets a process
// supervisor perform a bounded wait without holding the protocol receive loop.
func (s *ControlSession) MarkRotationReadyFrame(ctx context.Context, requestID string, observation ReplacementReadiness) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil || s.rotation == nil || ctx == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	if err := s.requireRotationRuntime(); err != nil {
		return connectorprotocol.Frame{}, err
	}
	record, ok := s.rotation.Record()
	if !ok || record.Install == nil {
		return connectorprotocol.Frame{}, ErrOperationNotFound
	}
	install := *record.Install
	if err := validateReplacementReadiness(observation, install, s.client, s.clock); err != nil {
		return s.rotationFailureFrame(requestID, install, err)
	}
	active, _ := observation.Session.Active()
	identity := observation.Session.Hello()
	ready, err := s.rotation.MarkReady(ctx, identitySessionID(observation.Session), identity.ProcessGeneration, active.Generation, active.ContentHash, observation.EdgeReady, observation.RouteReady, observation.OriginReady)
	if err != nil {
		return s.rotationFailureFrame(requestID, install, err)
	}
	return connectorprotocol.NewFrame(connectorprotocol.MessageCredentialRotationReady, requestID, ready)
}

// ObserveReplacementReady is a convenience for callers that want to own the
// wait and call MarkRotationReadyFrame after their own event scheduling. It
// does not mutate rotation state.
func (s *ControlSession) ObserveReplacementReady(ctx context.Context) (ReplacementReadiness, error) {
	if s == nil || s.rotation == nil || s.readiness == nil || ctx == nil {
		return ReplacementReadiness{}, ErrControlSessionInvalid
	}
	if err := s.requireRotationRuntime(); err != nil {
		return ReplacementReadiness{}, err
	}
	record, ok := s.rotation.Record()
	if !ok || record.Install == nil {
		return ReplacementReadiness{}, ErrOperationNotFound
	}
	return s.readiness.WaitReplacementReady(ctx, *record.Install)
}

// RecoverRotation explicitly restores a durable rotation after a process
// restart. It performs no key generation and emits no frame. Subsequent
// challenge/install/revoke handling remains bound to the newly authenticated
// session through validateBoundRotation.
func (s *ControlSession) RecoverRotation(ctx context.Context, operationID string) error {
	if s == nil || s.client == nil || s.rotation == nil || ctx == nil {
		return ErrControlSessionInvalid
	}
	if err := s.requireRotationRuntime(); err != nil {
		return err
	}
	return s.ensureRotationRecord(ctx, operationID, false)
}

func (s *ControlSession) CloseFrame(requestID string, reason connectorprotocol.DisconnectReason) (connectorprotocol.Frame, error) {
	if s == nil || s.client == nil {
		return connectorprotocol.Frame{}, ErrControlSessionInvalid
	}
	if err := s.client.Close(reason); err != nil {
		return connectorprotocol.Frame{}, err
	}
	disconnect := s.client.Disconnect()
	return connectorprotocol.NewFrame(connectorprotocol.MessageDisconnect, requestID, disconnect)
}
