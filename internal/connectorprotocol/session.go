package connectorprotocol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type SessionState string

const (
	SessionNew              SessionState = "new"
	SessionAwaitingSnapshot SessionState = "awaiting_snapshot"
	SessionAwaitingReady    SessionState = "awaiting_ready"
	SessionReady            SessionState = "ready"
	SessionDraining         SessionState = "draining"
	SessionClosed           SessionState = "closed"
)

type SessionRef struct {
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	SessionID         string `json:"session_id"`
	ProcessGeneration uint64 `json:"process_generation"`
}

func (r SessionRef) Validate() error {
	if ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.ConnectorID) != nil || ValidateIdentifier(r.SessionID) != nil || r.ProcessGeneration == 0 {
		return ErrInvalidInput
	}
	return nil
}

type AttachResult struct {
	Current  SessionRef
	Replaced *SessionRef
}

// SessionRegistry owns only live session identity. It intentionally does not
// own tunnel desired state or credential material. A stale close from an older
// process generation can never remove a newer session.
type SessionRegistry struct {
	mu      sync.RWMutex
	current map[string]SessionRef
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{current: make(map[string]SessionRef)}
}

func (r *SessionRegistry) Attach(ref SessionRef) (AttachResult, error) {
	if r == nil || ref.Validate() != nil {
		return AttachResult{}, ErrInvalidInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous, exists := r.current[ref.ConnectorID]
	if exists {
		if previous.TunnelID != ref.TunnelID {
			return AttachResult{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
		}
		if ref.ProcessGeneration <= previous.ProcessGeneration {
			return AttachResult{}, codeError(ErrSessionConflict, ReasonStaleGeneration, false, nil)
		}
	}
	r.current[ref.ConnectorID] = ref
	result := AttachResult{Current: ref}
	if exists {
		result.Replaced = &previous
	}
	return result, nil
}

func (r *SessionRegistry) Disconnect(ref SessionRef, reason DisconnectReason) error {
	if r == nil || ref.Validate() != nil || !validDisconnectReason(reason) {
		return ErrInvalidInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.current[ref.ConnectorID]
	if !exists {
		return nil
	}
	if current != ref {
		return codeError(ErrStaleSession, ReasonStaleGeneration, false, nil)
	}
	delete(r.current, ref.ConnectorID)
	return nil
}

func (r *SessionRegistry) Active(connectorID string) (SessionRef, bool) {
	if r == nil || ValidateIdentifier(connectorID) != nil {
		return SessionRef{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ref, ok := r.current[connectorID]
	return ref, ok
}

func (r *SessionRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.current)
}

type Authenticator interface {
	Authenticate(context.Context, AuthRequest) (AuthResult, error)
	Renew(context.Context, RenewalRequest) (AuthResult, error)
}

type AuthenticatorFuncs struct {
	AuthenticateFunc func(context.Context, AuthRequest) (AuthResult, error)
	RenewFunc        func(context.Context, RenewalRequest) (AuthResult, error)
}

func (f AuthenticatorFuncs) Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error) {
	if f.AuthenticateFunc == nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, errors.New("authentication is not configured"))
	}
	return f.AuthenticateFunc(ctx, request)
}

func (f AuthenticatorFuncs) Renew(ctx context.Context, request RenewalRequest) (AuthResult, error) {
	if f.RenewFunc == nil {
		return AuthResult{}, codeError(ErrCredentialExpired, ReasonCredentialExpired, true, errors.New("credential renewal is not configured"))
	}
	return f.RenewFunc(ctx, request)
}

type SnapshotSource interface {
	Snapshot(context.Context, string) (Snapshot, error)
}

type SnapshotSourceFunc func(context.Context, string) (Snapshot, error)

func (f SnapshotSourceFunc) Snapshot(ctx context.Context, tunnelID string) (Snapshot, error) {
	return f(ctx, tunnelID)
}

type SessionIDSource func() (string, error)

type ServerConfig struct {
	Authenticator     Authenticator
	Snapshots         SnapshotSource
	Capabilities      []string
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
	Clock             Clock
	SessionIDs        SessionIDSource
	Registry          *SessionRegistry
}

type Server struct {
	config ServerConfig
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Authenticator == nil || config.Snapshots == nil {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = DefaultLease
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = DefaultHeartbeat
	}
	if config.SessionIDs == nil {
		config.SessionIDs = func() (string, error) { return newOpaqueID("sess") }
	}
	if config.Registry == nil {
		config.Registry = NewSessionRegistry()
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration > MaxLease || config.HeartbeatInterval <= 0 || config.HeartbeatInterval*2 >= config.LeaseDuration || ValidateCapabilities(config.Capabilities) != nil {
		return nil, ErrInvalidInput
	}
	return &Server{config: config}, nil
}

type ServerSession struct {
	mu                  sync.RWMutex
	applyMu             sync.Mutex
	server              *Server
	ref                 SessionRef
	auth                AuthResult
	lease               Lease
	welcome             Welcome
	pendingSnapshot     *Snapshot
	pendingDelta        *Delta
	active              Snapshot
	hasActive           bool
	candidate           Snapshot
	hasCandidate        bool
	readyGeneration     uint64
	needsSnapshot       bool
	state               SessionState
	lastHeartbeat       time.Time
	lastHeartbeatSentAt time.Time
	drain               *Drain
	drainStatus         DrainStatus
	drainCode           Code
	drainCompleted      bool
	disconnectReason    DisconnectReason
}

// Accept authenticates a new process and returns the welcome plus the first
// complete snapshot. No delta can be emitted before the snapshot is acked.
func (s *Server) Accept(ctx context.Context, hello Hello) (*ServerSession, Welcome, Snapshot, error) {
	if s == nil || ctx == nil {
		return nil, Welcome{}, Snapshot{}, ErrInvalidInput
	}
	now := s.config.Clock.Now().UTC()
	if err := hello.Validate(now); err != nil {
		return nil, Welcome{}, Snapshot{}, err
	}
	version, err := NegotiateVersion(hello.MinVersion, hello.MaxVersion)
	if err != nil {
		return nil, Welcome{}, Snapshot{}, err
	}
	capabilities, err := NegotiateCapabilities(hello.Capabilities, s.config.Capabilities)
	if err != nil {
		return nil, Welcome{}, Snapshot{}, err
	}
	auth, err := s.config.Authenticator.Authenticate(ctx, hello.Auth)
	if err != nil {
		return nil, Welcome{}, Snapshot{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	if err := auth.Validate(now); err != nil || auth.AccountID != hello.AccountID || auth.TunnelID != hello.TunnelID || auth.ConnectorID != hello.ConnectorID || auth.HostID != hello.HostID || auth.IdentityKeyID != hello.Auth.IdentityKeyID || auth.IdentityKeyThumbprint != hello.Auth.IdentityKeyThumbprint || auth.ProcessGeneration != hello.ProcessGeneration {
		return nil, Welcome{}, Snapshot{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	snapshot, err := s.config.Snapshots.Snapshot(ctx, hello.TunnelID)
	if err != nil {
		return nil, Welcome{}, Snapshot{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, true, err)
	}
	if err := snapshot.Validate(); err != nil || snapshot.TunnelID != hello.TunnelID {
		return nil, Welcome{}, Snapshot{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	sessionID, err := s.config.SessionIDs()
	if err != nil || ValidateIdentifier(sessionID) != nil {
		return nil, Welcome{}, Snapshot{}, codeError(ErrSessionConflict, ReasonAuthentication, true, err)
	}
	leaseExpiry := auth.LeaseExpiresAt
	configuredExpiry := now.Add(s.config.LeaseDuration)
	if configuredExpiry.Before(leaseExpiry) {
		leaseExpiry = configuredExpiry
	}
	lease := Lease{SessionID: sessionID, ExpiresAt: leaseExpiry, HeartbeatIntervalMS: uint32(s.config.HeartbeatInterval / time.Millisecond)}
	if err := lease.Validate(now); err != nil {
		return nil, Welcome{}, Snapshot{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	ref := SessionRef{TunnelID: hello.TunnelID, ConnectorID: hello.ConnectorID, SessionID: sessionID, ProcessGeneration: hello.ProcessGeneration}
	if _, err := s.config.Registry.Attach(ref); err != nil {
		return nil, Welcome{}, Snapshot{}, err
	}
	welcome := Welcome{Protocol: ProtocolName, Version: version, SessionID: sessionID, Capabilities: capabilities, Lease: lease, RequiresSnapshot: true, ServerTime: now}
	snapshot = bindSnapshot(snapshot, hello.AccountID, hello.ConnectorID, sessionID, hello.ProcessGeneration)
	session := &ServerSession{server: s, ref: ref, auth: auth, lease: lease, welcome: welcome, pendingSnapshot: &snapshot, state: SessionAwaitingSnapshot, lastHeartbeat: now}
	return session, welcome, snapshot, nil
}

func bindSnapshot(snapshot Snapshot, accountID, connectorID, sessionID string, processGeneration uint64) Snapshot {
	snapshot.AccountID = accountID
	snapshot.ConnectorID = connectorID
	snapshot.SessionID = sessionID
	snapshot.ProcessGeneration = processGeneration
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	return snapshot
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	return snapshot
}

func (s *ServerSession) refAccountID() string {
	return s.auth.AccountID
}

func (s *ServerSession) matchesIdentity(accountID, tunnelID, connectorID, sessionID string, processGeneration uint64) bool {
	return accountID == s.auth.AccountID && tunnelID == s.ref.TunnelID && connectorID == s.ref.ConnectorID && sessionID == s.ref.SessionID && processGeneration == s.ref.ProcessGeneration
}

func (s *ServerSession) restoreStateLocked() {
	if s.hasActive && s.readyGeneration == s.active.Generation && !s.needsSnapshot {
		s.state = SessionReady
		return
	}
	if s.hasActive {
		s.state = SessionAwaitingSnapshot
		return
	}
	s.state = SessionAwaitingSnapshot
}

func (s *ServerSession) makeAckLocked(kind AckKind, status AckStatus, snapshot Snapshot) Ack {
	return Ack{AccountID: s.auth.AccountID, TunnelID: s.ref.TunnelID, ConnectorID: s.ref.ConnectorID, SessionID: s.ref.SessionID, ProcessGeneration: s.ref.ProcessGeneration, Kind: kind, Status: status, Generation: snapshot.Generation, ContentHash: snapshot.ContentHash}
}

func (s *ServerSession) Reference() SessionRef {
	if s == nil {
		return SessionRef{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ref
}

func (s *ServerSession) Welcome() Welcome {
	if s == nil {
		return Welcome{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.welcome
}

func (s *ServerSession) State() SessionState {
	if s == nil {
		return SessionClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *ServerSession) ensureActiveLocked(now time.Time) error {
	if s.state == SessionClosed {
		return codeError(ErrSessionClosed, s.disconnectReason, false, nil)
	}
	if s.server == nil || s.server.config.Registry == nil {
		return codeError(ErrSessionConflict, ReasonStaleGeneration, false, errors.New("session registry is not configured"))
	}
	if current, ok := s.server.config.Registry.Active(s.ref.ConnectorID); !ok || current != s.ref {
		s.closeLocked(ReasonSessionReplaced)
		return codeError(ErrStaleSession, ReasonSessionReplaced, false, nil)
	}
	if !s.auth.CredentialExpiresAt.After(now) {
		s.closeLocked(ReasonCredentialExpired)
		return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
	}
	if !s.lease.ExpiresAt.After(now) {
		s.closeLocked(ReasonLeaseExpired)
		return codeError(ErrLeaseExpired, ReasonLeaseExpired, true, nil)
	}
	if !s.lastHeartbeat.IsZero() && now.Sub(s.lastHeartbeat) > 2*time.Duration(s.lease.HeartbeatIntervalMS)*time.Millisecond {
		s.closeLocked(ReasonHeartbeatTimeout)
		return codeError(ErrHeartbeatTimeout, ReasonHeartbeatTimeout, true, nil)
	}
	return nil
}

func (s *ServerSession) closeLocked(reason DisconnectReason) {
	if s.state == SessionClosed {
		return
	}
	s.state = SessionClosed
	s.disconnectReason = reason
	// Registry is mandatory for server sessions. Disconnect is exact-match and
	// therefore safe even when a newer process generation has already replaced
	// this one.
	if s.server != nil && s.server.config.Registry != nil {
		_ = s.server.config.Registry.Disconnect(s.ref, reason)
	}
}

func (s *ServerSession) HandleAck(ctx context.Context, ack Ack) error {
	if s == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ack.Validate(); err != nil {
		return err
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return err
	}
	if !s.matchesIdentity(ack.AccountID, ack.TunnelID, ack.ConnectorID, ack.SessionID, ack.ProcessGeneration) {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if s.pendingSnapshot != nil {
		if ack.Kind != AckSnapshot || ack.Generation != s.pendingSnapshot.Generation || ack.ContentHash != s.pendingSnapshot.ContentHash {
			return codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, nil)
		}
		if ack.Status == AckSnapshotRequired || ack.Status == AckRejected {
			s.pendingSnapshot = nil
			s.needsSnapshot = true
			s.restoreStateLocked()
			if ack.Status == AckSnapshotRequired {
				return codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
			}
			return codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, nil)
		}
		s.candidate = cloneSnapshot(*s.pendingSnapshot)
		s.hasCandidate = true
		s.pendingSnapshot = nil
		s.needsSnapshot = false
		if !(s.hasActive && s.readyGeneration == s.active.Generation) {
			s.state = SessionAwaitingReady
		}
		return nil
	}
	if s.pendingDelta != nil {
		if ack.Kind != AckDelta || ack.Generation != s.pendingDelta.Generation || ack.ContentHash != s.pendingDelta.ContentHash {
			return codeError(ErrDeltaRejected, ReasonGenerationGap, false, nil)
		}
		pending := *s.pendingDelta
		s.pendingDelta = nil
		if ack.Status == AckSnapshotRequired {
			s.needsSnapshot = true
			s.restoreStateLocked()
			return codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
		}
		if ack.Status == AckRejected {
			s.needsSnapshot = true
			s.restoreStateLocked()
			return codeError(ErrDeltaRejected, ReasonSnapshotRejected, false, nil)
		}
		if s.hasActive && (pending.PreviousGeneration != s.active.Generation || pending.PreviousContentHash != s.active.ContentHash) {
			return codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
		}
		s.candidate = Snapshot{AccountID: s.refAccountID(), TunnelID: pending.TunnelID, ConnectorID: s.ref.ConnectorID, SessionID: s.ref.SessionID, ProcessGeneration: s.ref.ProcessGeneration, Generation: pending.Generation, ContentHash: pending.ContentHash, Payload: append([]byte(nil), pending.Payload...)}
		s.hasCandidate = true
		if !(s.hasActive && s.readyGeneration == s.active.Generation) {
			s.state = SessionAwaitingReady
		}
		return nil
	}
	if ack.Status == AckDuplicate {
		if !s.hasCandidate && !s.hasActive {
			return codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		current := s.active
		if s.hasCandidate {
			current = s.candidate
		}
		if ack.Generation != current.Generation || ack.ContentHash != current.ContentHash {
			return codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		return nil
	}
	return codeError(ErrInvalidInput, ReasonMalformed, false, nil)
}

// CanPersistNegativeAck is checked before HandleAck mutates pending state. A
// negative acknowledgement is durable recovery/failure metadata only when it
// addresses the exact snapshot or delta currently offered to this session.
// This prevents a malformed or stale peer from changing the operation state
// for an unrelated generation.
func (s *ServerSession) CanPersistNegativeAck(ack Ack) bool {
	if s == nil || (ack.Status != AckRejected && ack.Status != AckSnapshotRequired) {
		return false
	}
	if ack.Validate() != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.matchesIdentity(ack.AccountID, ack.TunnelID, ack.ConnectorID, ack.SessionID, ack.ProcessGeneration) {
		return false
	}
	if s.pendingSnapshot != nil {
		return ack.Kind == AckSnapshot && ack.Generation == s.pendingSnapshot.Generation && ack.ContentHash == s.pendingSnapshot.ContentHash
	}
	if s.pendingDelta != nil {
		return ack.Kind == AckDelta && ack.Generation == s.pendingDelta.Generation && ack.ContentHash == s.pendingDelta.ContentHash
	}
	return false
}

func (s *ServerSession) HandleReadiness(ctx context.Context, readiness Readiness) (Ack, error) {
	if s == nil || ctx == nil {
		return Ack{}, ErrInvalidInput
	}
	if err := readiness.Validate(); err != nil {
		return Ack{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return Ack{}, err
	}
	if !s.matchesIdentity(readiness.AccountID, readiness.TunnelID, readiness.ConnectorID, readiness.SessionID, readiness.ProcessGeneration) {
		return Ack{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if s.hasCandidate {
		if readiness.Generation != s.candidate.Generation || readiness.ContentHash != s.candidate.ContentHash {
			return Ack{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
	} else if !s.hasActive || readiness.Generation != s.active.Generation || readiness.ContentHash != s.active.ContentHash {
		return Ack{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	if !readiness.EdgeReady || !readiness.RouteReady || !readiness.OriginReady {
		return Ack{}, codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	if s.hasCandidate {
		s.active = cloneSnapshot(s.candidate)
		s.hasActive = true
		s.candidate = Snapshot{}
		s.hasCandidate = false
	}
	s.needsSnapshot = false
	s.readyGeneration = readiness.Generation
	s.state = SessionReady
	return s.makeAckLocked(AckReady, AckApplied, Snapshot{Generation: readiness.Generation, ContentHash: readiness.ContentHash}), nil
}

func (s *ServerSession) OfferSnapshot(ctx context.Context, snapshot Snapshot) error {
	if s == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := snapshot.Validate(); err != nil {
		return codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return err
	}
	if snapshot.TunnelID != s.ref.TunnelID {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if snapshot.AccountID != "" && snapshot.AccountID != s.refAccountID() || snapshot.ConnectorID != "" && snapshot.ConnectorID != s.ref.ConnectorID || snapshot.SessionID != "" && snapshot.SessionID != s.ref.SessionID || snapshot.ProcessGeneration != 0 && snapshot.ProcessGeneration != s.ref.ProcessGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if s.hasActive && snapshot.Generation < s.active.Generation {
		return codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	if s.hasCandidate && snapshot.Generation == s.candidate.Generation {
		if snapshot.ContentHash != s.candidate.ContentHash {
			return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
		return nil
	}
	if s.hasActive && snapshot.Generation == s.active.Generation {
		if snapshot.ContentHash != s.active.ContentHash {
			return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
		return nil
	}
	if s.pendingSnapshot != nil && snapshot.Generation == s.pendingSnapshot.Generation {
		if snapshot.ContentHash != s.pendingSnapshot.ContentHash {
			return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
		return nil
	}
	s.pendingDelta = nil
	bound := bindSnapshot(snapshot, s.refAccountID(), s.ref.ConnectorID, s.ref.SessionID, s.ref.ProcessGeneration)
	s.pendingSnapshot = &bound
	if !s.hasActive {
		s.state = SessionAwaitingSnapshot
	}
	return nil
}

func (s *ServerSession) OfferDelta(ctx context.Context, delta Delta) error {
	if s == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := delta.Validate(); err != nil {
		return codeError(ErrDeltaRejected, ReasonGenerationGap, false, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return err
	}
	if !s.hasActive || s.readyGeneration != s.active.Generation || s.needsSnapshot {
		return codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	if s.pendingSnapshot != nil || s.pendingDelta != nil || s.hasCandidate {
		return codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
	}
	if delta.TunnelID != s.ref.TunnelID || delta.AccountID != "" && delta.AccountID != s.refAccountID() || delta.ConnectorID != "" && delta.ConnectorID != s.ref.ConnectorID || delta.SessionID != "" && delta.SessionID != s.ref.SessionID || delta.ProcessGeneration != 0 && delta.ProcessGeneration != s.ref.ProcessGeneration || delta.PreviousGeneration != s.active.Generation || delta.PreviousContentHash != s.active.ContentHash {
		return codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
	}
	bound := delta
	bound.AccountID = s.refAccountID()
	bound.ConnectorID = s.ref.ConnectorID
	bound.SessionID = s.ref.SessionID
	bound.ProcessGeneration = s.ref.ProcessGeneration
	s.pendingDelta = &bound
	return nil
}

func (s *ServerSession) HandleHeartbeat(ctx context.Context, heartbeat Heartbeat) (HeartbeatAck, error) {
	if s == nil || ctx == nil {
		return HeartbeatAck{}, ErrInvalidInput
	}
	if err := heartbeat.Validate(); err != nil {
		return HeartbeatAck{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.server.config.Clock.Now().UTC()
	if err := s.ensureActiveLocked(now); err != nil {
		return HeartbeatAck{}, err
	}
	if !s.matchesIdentity(heartbeat.AccountID, heartbeat.TunnelID, heartbeat.ConnectorID, heartbeat.SessionID, heartbeat.ProcessGeneration) {
		return HeartbeatAck{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if heartbeat.SentAt.After(now.Add(MaxClockSkew)) {
		return HeartbeatAck{}, codeError(ErrInvalidInput, ReasonMalformed, false, nil)
	}
	if heartbeat.SentAt.Before(now.Add(-MaxClockSkew)) {
		return HeartbeatAck{}, codeError(ErrHeartbeatTimeout, ReasonHeartbeatTimeout, true, nil)
	}
	if !s.lastHeartbeatSentAt.IsZero() && !heartbeat.SentAt.After(s.lastHeartbeatSentAt) {
		return HeartbeatAck{}, codeError(ErrStaleSession, ReasonStaleGeneration, false, nil)
	}
	s.lastHeartbeatSentAt = heartbeat.SentAt
	if !s.hasActive {
		return HeartbeatAck{}, codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
	}
	if heartbeat.LastAppliedGeneration != s.active.Generation || heartbeat.LastAppliedHash != s.active.ContentHash {
		// Keep the last-known-good snapshot for rollback/traffic inspection, but
		// withdraw readiness until this process receives and promotes a matching
		// full snapshot.
		s.needsSnapshot = true
		s.readyGeneration = 0
		s.state = SessionAwaitingSnapshot
		return HeartbeatAck{}, codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
	}
	s.lastHeartbeat = now
	leaseExpiry := now.Add(s.server.config.LeaseDuration)
	if s.auth.CredentialExpiresAt.Before(leaseExpiry) {
		leaseExpiry = s.auth.CredentialExpiresAt
	}
	s.lease.ExpiresAt = leaseExpiry
	return HeartbeatAck{AccountID: s.refAccountID(), TunnelID: s.ref.TunnelID, ConnectorID: s.ref.ConnectorID, SessionID: s.ref.SessionID, ProcessGeneration: s.ref.ProcessGeneration, LeaseExpiresAt: leaseExpiry, ServerTime: now}, nil
}

// BeginDrain stops new streams for the currently ready generation. The
// returned request is idempotent for the same drain ID and target. A caller
// must provide a bounded deadline; the server never silently extends a drain
// after it has been sent.
func (s *ServerSession) BeginDrain(ctx context.Context, drainID string, deadline time.Time, forceAfterDeadline bool) (Drain, error) {
	if s == nil || ctx == nil {
		return Drain{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Drain{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return Drain{}, err
	}
	if !hasCapability(s.welcome.Capabilities, CapabilityDrain) {
		return Drain{}, codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, nil)
	}
	if s.drain != nil {
		if s.drain.DrainID == drainID {
			return *s.drain, nil
		}
		return Drain{}, codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
	}
	if !s.hasActive || s.needsSnapshot || s.readyGeneration != s.active.Generation || s.state != SessionReady {
		return Drain{}, codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	request := Drain{AccountID: s.refAccountID(), TunnelID: s.ref.TunnelID, ConnectorID: s.ref.ConnectorID, SessionID: s.ref.SessionID, ProcessGeneration: s.ref.ProcessGeneration, DrainID: drainID, Generation: s.active.Generation, ContentHash: s.active.ContentHash, Deadline: deadline, StopNewStreams: true, ForceAfterDeadline: forceAfterDeadline}
	if err := request.Validate(s.server.config.Clock.Now().UTC()); err != nil {
		return Drain{}, err
	}
	s.drain = &request
	s.drainStatus = DrainAccepted
	s.drainCode = ""
	s.drainCompleted = false
	s.state = SessionDraining
	return request, nil
}

// HandleDrainAck consumes connector progress or completion. A completion is
// retained so duplicate delivery is harmless; a stale session can never alter
// the registry or a newer drain because identity and drain ID are checked.
func (s *ServerSession) HandleDrainAck(ctx context.Context, ack DrainAck) error {
	if s == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	if err := ack.Validate(s.server.config.Clock.Now().UTC()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return err
	}
	if !s.matchesIdentity(ack.AccountID, ack.TunnelID, ack.ConnectorID, ack.SessionID, ack.ProcessGeneration) {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if s.drain == nil || ack.DrainID != s.drain.DrainID {
		return codeError(ErrStaleSession, ReasonStaleGeneration, false, nil)
	}
	if ack.Generation != s.drain.Generation || ack.ContentHash != s.drain.ContentHash {
		return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
	}
	if s.drainCompleted {
		if ack.Status == s.drainStatus && ack.Code == s.drainCode {
			return nil
		}
		return codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	}
	s.drainStatus = ack.Status
	s.drainCode = ack.Code
	switch ack.Status {
	case DrainAccepted, DrainProgress:
		return nil
	case DrainCompleted, DrainForced:
		s.drainCompleted = true
		return nil
	case DrainRejected:
		s.drainCompleted = true
		s.restoreStateLocked()
		return codeError(ErrDrainRejected, ReasonSnapshotRejected, false, nil)
	default:
		return ErrInvalidInput
	}
}

// CanPersistNegativeDrainAck is evaluated before HandleDrainAck mutates the
// drain state. Only a rejected acknowledgement for the exact outstanding
// request may fail the corresponding durable drain operation.
func (s *ServerSession) CanPersistNegativeDrainAck(ack DrainAck) bool {
	if s == nil || ack.Status != DrainRejected || ack.Validate(time.Time{}) != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.drain != nil && s.matchesIdentity(ack.AccountID, ack.TunnelID, ack.ConnectorID, ack.SessionID, ack.ProcessGeneration) && ack.DrainID == s.drain.DrainID && ack.Generation == s.drain.Generation && ack.ContentHash == s.drain.ContentHash
}

func hasCapability(values []string, capability string) bool {
	for _, value := range values {
		if value == capability {
			return true
		}
	}
	return false
}

func (s *ServerSession) Drain() (Drain, DrainStatus, bool) {
	if s == nil {
		return Drain{}, "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.drain == nil {
		return Drain{}, "", false
	}
	return *s.drain, s.drainStatus, s.drainCompleted
}

func (s *ServerSession) Renew(ctx context.Context, request RenewalRequest) (AuthResult, error) {
	if s == nil || ctx == nil {
		return AuthResult{}, ErrInvalidInput
	}
	s.mu.Lock()
	now := s.server.config.Clock.Now().UTC()
	if err := request.ValidateAt(now); err != nil {
		s.mu.Unlock()
		return AuthResult{}, err
	}
	if err := s.ensureActiveLocked(now); err != nil {
		s.mu.Unlock()
		return AuthResult{}, err
	}
	expected := s.auth
	ref := s.ref
	if request.SessionID != ref.SessionID || request.AccountID != expected.AccountID || request.TunnelID != ref.TunnelID || request.ConnectorID != ref.ConnectorID || request.HostID != expected.HostID || request.IdentityKeyID != expected.IdentityKeyID || request.IdentityKeyThumbprint != expected.IdentityKeyThumbprint || request.ProcessGeneration != ref.ProcessGeneration || request.CredentialGeneration != expected.CredentialGeneration {
		s.mu.Unlock()
		return AuthResult{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	s.mu.Unlock()
	result, err := s.server.config.Authenticator.Renew(ctx, request)
	if err != nil {
		return AuthResult{}, codeError(ErrCredentialExpired, ReasonCredentialExpired, true, err)
	}
	if err := result.Validate(now); err != nil || result.AccountID != expected.AccountID || result.TunnelID != ref.TunnelID || result.ConnectorID != ref.ConnectorID || result.SessionID != "" && result.SessionID != ref.SessionID || result.HostID != expected.HostID || result.IdentityKeyID != expected.IdentityKeyID || result.IdentityKeyThumbprint != expected.IdentityKeyThumbprint || result.ProcessGeneration != ref.ProcessGeneration || result.CredentialGeneration < expected.CredentialGeneration {
		if err == nil {
			err = ErrIdentityMismatch
		}
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureActiveLocked(s.server.config.Clock.Now().UTC()); err != nil {
		return AuthResult{}, err
	}
	if s.auth != expected || s.ref != ref {
		return AuthResult{}, codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
	}
	result.SessionID = ref.SessionID
	s.auth = result
	s.lease.ExpiresAt = result.LeaseExpiresAt
	configuredExpiry := now.Add(s.server.config.LeaseDuration)
	if configuredExpiry.Before(s.lease.ExpiresAt) {
		s.lease.ExpiresAt = configuredExpiry
	}
	s.lastHeartbeat = now
	return result, nil
}

func (s *ServerSession) Close(reason DisconnectReason) error {
	if s == nil || !validDisconnectReason(reason) {
		return ErrInvalidInput
	}
	s.mu.Lock()
	if s.state == SessionClosed {
		s.mu.Unlock()
		return nil
	}
	s.closeLocked(reason)
	s.mu.Unlock()
	return nil
}

func (s *ServerSession) Disconnect() Disconnect {
	if s == nil {
		return Disconnect{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	reason := s.disconnectReason
	if reason == "" {
		reason = ReasonProtocolClosed
	}
	return Disconnect{AccountID: s.auth.AccountID, TunnelID: s.ref.TunnelID, ConnectorID: s.ref.ConnectorID, SessionID: s.ref.SessionID, ProcessGeneration: s.ref.ProcessGeneration, Reason: reason, Retryable: reason == ReasonLeaseExpired || reason == ReasonHeartbeatTimeout || reason == ReasonCredentialExpired || reason == ReasonSessionReplaced}
}

type ClientSessionConfig struct {
	Hello        Hello
	Applier      ConfigApplier
	Drainer      Drainer
	Clock        Clock
	ApplyTimeout time.Duration
	AbortTimeout time.Duration
}

// Drainer is the narrow runtime hook needed by the control protocol. It must
// stop admitting new streams before returning, report a bounded active-stream
// count, and force-close only under the supplied cancellation/deadline. The
// control session never owns data-plane streams itself.
type Drainer interface {
	StopNewStreams(context.Context) error
	ActiveStreams(context.Context) (uint32, error)
	ForceClose(context.Context) error
}

type noopDrainer struct{}

func (noopDrainer) StopNewStreams(context.Context) error          { return nil }
func (noopDrainer) ActiveStreams(context.Context) (uint32, error) { return 0, nil }
func (noopDrainer) ForceClose(context.Context) error              { return nil }

type ClientSession struct {
	mu               sync.RWMutex
	applyMu          sync.Mutex
	config           ClientSessionConfig
	welcome          Welcome
	state            SessionState
	lease            Lease
	auth             AuthRequest
	active           Snapshot
	hasActive        bool
	candidate        Snapshot
	hasCandidate     bool
	prepared         PreparedConfig
	needsSnapshot    bool
	readyGeneration  uint64
	lastHeartbeatAck time.Time
	drain            *Drain
	drainStatus      DrainStatus
	drainCode        Code
	drainCompleted   bool
	activeStreams    uint32
	disconnectReason DisconnectReason
}

func NewClientSession(config ClientSessionConfig) (*ClientSession, error) {
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.Applier == nil {
		config.Applier = noopApplier{}
	}
	if config.Drainer == nil {
		config.Drainer = noopDrainer{}
	}
	if config.ApplyTimeout == 0 {
		config.ApplyTimeout = DefaultApplyTimeout
	}
	if config.AbortTimeout == 0 {
		config.AbortTimeout = DefaultAbortTimeout
	}
	if config.ApplyTimeout <= 0 || config.ApplyTimeout > MaxLease || config.AbortTimeout <= 0 || config.AbortTimeout > MaxLease {
		return nil, ErrInvalidInput
	}
	if err := config.Hello.Validate(config.Clock.Now().UTC()); err != nil {
		return nil, err
	}
	return &ClientSession{config: config, auth: config.Hello.Auth, state: SessionNew}, nil
}

func (c *ClientSession) Hello() Hello {
	if c == nil {
		return Hello{}
	}
	return c.config.Hello
}

// Auth returns the currently authenticated credential and expiry metadata.
// Control supervisors use this snapshot to schedule renewal without reaching
// into the session's state machine.
func (c *ClientSession) Auth() AuthRequest {
	if c == nil {
		return AuthRequest{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.auth
}

func (c *ClientSession) AcceptWelcome(welcome Welcome) error {
	if c == nil {
		return ErrInvalidInput
	}
	if err := welcome.Validate(c.config.Clock.Now().UTC()); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != SessionNew {
		return codeError(ErrSessionConflict, ReasonProtocolClosed, false, nil)
	}
	if welcome.Version != ProtocolVersion || welcome.Protocol != ProtocolName {
		return codeError(ErrProtocolIncompatible, ReasonProtocolMismatch, false, nil)
	}
	if _, err := NegotiateVersion(c.config.Hello.MinVersion, c.config.Hello.MaxVersion); err != nil {
		return err
	}
	if _, err := NegotiateCapabilities(c.config.Hello.Capabilities, welcome.Capabilities); err != nil {
		return err
	}
	c.welcome = welcome
	c.lease = welcome.Lease
	c.state = SessionAwaitingSnapshot
	c.lastHeartbeatAck = c.config.Clock.Now().UTC()
	return nil
}

func (c *ClientSession) ensureActiveLocked(now time.Time) error {
	if c.state == SessionClosed {
		return codeError(ErrSessionClosed, c.disconnectReason, false, nil)
	}
	if c.state == SessionNew {
		return codeError(ErrSessionConflict, ReasonProtocolClosed, false, nil)
	}
	if !c.lease.ExpiresAt.After(now) {
		c.state = SessionClosed
		c.disconnectReason = ReasonLeaseExpired
		return codeError(ErrLeaseExpired, ReasonLeaseExpired, true, nil)
	}
	if !c.lastHeartbeatAck.IsZero() && now.Sub(c.lastHeartbeatAck) > 2*time.Duration(c.lease.HeartbeatIntervalMS)*time.Millisecond {
		c.state = SessionClosed
		c.disconnectReason = ReasonHeartbeatTimeout
		return codeError(ErrHeartbeatTimeout, ReasonHeartbeatTimeout, true, nil)
	}
	return nil
}

func (c *ClientSession) ApplySnapshot(ctx context.Context, snapshot Snapshot) (Ack, error) {
	if c == nil || ctx == nil {
		return Ack{}, ErrInvalidInput
	}
	if err := snapshot.Validate(); err != nil {
		return Ack{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		c.mu.Unlock()
		return Ack{}, err
	}
	if snapshot.TunnelID != c.config.Hello.TunnelID {
		c.mu.Unlock()
		return Ack{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if err := snapshot.ValidateBound(); err != nil || snapshot.AccountID != c.config.Hello.AccountID || snapshot.ConnectorID != c.config.Hello.ConnectorID || snapshot.SessionID != c.welcome.SessionID || snapshot.ProcessGeneration != c.config.Hello.ProcessGeneration {
		c.mu.Unlock()
		return Ack{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	current := c.active
	if c.hasCandidate {
		current = c.candidate
	}
	hasCurrent := c.hasActive || c.hasCandidate
	if hasCurrent {
		if snapshot.Generation < current.Generation {
			c.mu.Unlock()
			return Ack{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		if snapshot.Generation == current.Generation {
			if snapshot.ContentHash == current.ContentHash {
				ack := c.makeAckLocked(AckSnapshot, AckDuplicate, snapshot)
				c.mu.Unlock()
				return ack, nil
			}
			c.mu.Unlock()
			return Ack{}, codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
	}
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	prepareCtx, cancelPrepare := context.WithTimeout(ctx, c.config.ApplyTimeout)
	prepared, err := c.config.Applier.PrepareSnapshot(prepareCtx, snapshot)
	prepareErr := prepareCtx.Err()
	cancelPrepare()
	if err != nil {
		abortErr := c.abortPrepared(prepared)
		if ctx.Err() != nil || prepareErr != nil {
			cause := ctx.Err()
			if cause == nil {
				cause = prepareErr
			}
			return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, joinCleanup(cause, abortErr))
		}
		return Ack{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, joinCleanup(err, abortErr))
	}
	if prepareErr != nil {
		abortErr := c.abortPrepared(prepared)
		return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, joinCleanup(prepareErr, abortErr))
	}
	if prepared == nil {
		return Ack{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, errors.New("applier returned nil prepared configuration"))
	}
	c.mu.Lock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		c.mu.Unlock()
		return Ack{}, c.abortAndJoin(err, prepared)
	}
	if c.hasCandidate && c.prepared != nil {
		c.mu.Unlock()
		return Ack{}, c.abortAndJoin(codeError(ErrGenerationGap, ReasonGenerationGap, true, nil), prepared)
	}
	snapshot = bindSnapshot(snapshot, c.config.Hello.AccountID, c.config.Hello.ConnectorID, c.welcome.SessionID, c.config.Hello.ProcessGeneration)
	c.candidate = snapshot
	c.hasCandidate = true
	c.prepared = prepared
	c.needsSnapshot = false
	c.readyGeneration = 0
	c.state = SessionAwaitingReady
	ack := c.makeAckLocked(AckSnapshot, AckApplied, snapshot)
	c.mu.Unlock()
	return ack, nil
}

func (c *ClientSession) ApplyDelta(ctx context.Context, delta Delta) (Ack, error) {
	if c == nil || ctx == nil {
		return Ack{}, ErrInvalidInput
	}
	if err := delta.Validate(); err != nil {
		return Ack{}, codeError(ErrDeltaRejected, ReasonGenerationGap, false, err)
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		c.mu.Unlock()
		return Ack{}, err
	}
	if err := delta.ValidateBound(); err != nil || delta.TunnelID != c.config.Hello.TunnelID || delta.AccountID != c.config.Hello.AccountID || delta.ConnectorID != c.config.Hello.ConnectorID || delta.SessionID != c.welcome.SessionID || delta.ProcessGeneration != c.config.Hello.ProcessGeneration {
		c.mu.Unlock()
		return Ack{}, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if !c.hasActive || c.needsSnapshot || c.hasCandidate {
		ack := c.makeAckLocked(AckDelta, AckSnapshotRequired, Snapshot{Generation: delta.Generation, ContentHash: delta.ContentHash})
		c.mu.Unlock()
		return ack, codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
	}
	if delta.PreviousGeneration == c.active.Generation && delta.PreviousContentHash == c.active.ContentHash {
		if delta.Generation != c.active.Generation+1 {
			c.needsSnapshot = true
			ack := c.makeAckLocked(AckDelta, AckSnapshotRequired, Snapshot{Generation: delta.Generation, ContentHash: delta.ContentHash})
			c.mu.Unlock()
			return ack, codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
		}
	} else if delta.Generation <= c.active.Generation {
		c.mu.Unlock()
		return Ack{}, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
	} else {
		c.needsSnapshot = true
		ack := c.makeAckLocked(AckDelta, AckSnapshotRequired, Snapshot{Generation: delta.Generation, ContentHash: delta.ContentHash})
		c.mu.Unlock()
		return ack, codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
	}
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	prepareCtx, cancelPrepare := context.WithTimeout(ctx, c.config.ApplyTimeout)
	prepared, err := c.config.Applier.PrepareDelta(prepareCtx, delta)
	prepareErr := prepareCtx.Err()
	cancelPrepare()
	if err != nil {
		abortErr := c.abortPrepared(prepared)
		if ctx.Err() != nil || prepareErr != nil {
			cause := ctx.Err()
			if cause == nil {
				cause = prepareErr
			}
			return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, joinCleanup(cause, abortErr))
		}
		return Ack{}, codeError(ErrDeltaRejected, ReasonSnapshotRejected, false, joinCleanup(err, abortErr))
	}
	if prepareErr != nil {
		abortErr := c.abortPrepared(prepared)
		return Ack{}, codeError(ErrCanceled, ReasonCanceled, true, joinCleanup(prepareErr, abortErr))
	}
	if prepared == nil {
		return Ack{}, codeError(ErrDeltaRejected, ReasonSnapshotRejected, false, errors.New("applier returned nil prepared configuration"))
	}
	c.mu.Lock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		c.mu.Unlock()
		return Ack{}, c.abortAndJoin(err, prepared)
	}
	if c.hasCandidate && c.prepared != nil {
		c.mu.Unlock()
		return Ack{}, c.abortAndJoin(codeError(ErrGenerationGap, ReasonGenerationGap, true, nil), prepared)
	}
	c.candidate = Snapshot{AccountID: c.config.Hello.AccountID, TunnelID: delta.TunnelID, ConnectorID: c.config.Hello.ConnectorID, Generation: delta.Generation, SessionID: c.welcome.SessionID, ProcessGeneration: c.config.Hello.ProcessGeneration, ContentHash: delta.ContentHash, Payload: append([]byte(nil), delta.Payload...)}
	c.hasCandidate = true
	c.prepared = prepared
	c.readyGeneration = 0
	c.state = SessionAwaitingReady
	ack := c.makeAckLocked(AckDelta, AckApplied, c.candidate)
	c.mu.Unlock()
	return ack, nil
}

// RejectionAck binds a negative apply result to the authenticated session.
// Callers use it only after the incoming payload has passed structural and
// bound validation, so the generation/hash remain useful to the peer even
// when preparation failed before ClientSession could create its candidate.
func (c *ClientSession) RejectionAck(kind AckKind, generation uint64, contentHash string, code Code) Ack {
	if c == nil {
		return Ack{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Ack{
		AccountID:         c.config.Hello.AccountID,
		TunnelID:          c.config.Hello.TunnelID,
		ConnectorID:       c.config.Hello.ConnectorID,
		SessionID:         c.welcome.SessionID,
		ProcessGeneration: c.config.Hello.ProcessGeneration,
		Kind:              kind,
		Status:            AckRejected,
		Generation:        generation,
		ContentHash:       contentHash,
		Code:              code,
	}
}

func (c *ClientSession) MarkReady(edgeReady, routeReady, originReady bool) (Readiness, error) {
	if c == nil {
		return Readiness{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.config.ApplyTimeout)
	defer cancel()
	return c.MarkReadyContext(ctx, edgeReady, routeReady, originReady)
}

// MarkReadyContext activates the staged candidate only after all readiness
// dimensions are true. The previous active snapshot remains untouched when
// activation or readiness fails.
func (c *ClientSession) MarkReadyContext(ctx context.Context, edgeReady, routeReady, originReady bool) (Readiness, error) {
	if c == nil {
		return Readiness{}, ErrInvalidInput
	}
	if ctx == nil {
		return Readiness{}, ErrInvalidInput
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		c.mu.Unlock()
		return Readiness{}, err
	}
	if !c.hasCandidate {
		c.mu.Unlock()
		return Readiness{}, codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
	}
	readiness := Readiness{AccountID: c.config.Hello.AccountID, SessionID: c.welcome.SessionID, TunnelID: c.config.Hello.TunnelID, ConnectorID: c.config.Hello.ConnectorID, ProcessGeneration: c.config.Hello.ProcessGeneration, Generation: c.candidate.Generation, ContentHash: c.candidate.ContentHash, EdgeReady: edgeReady, RouteReady: routeReady, OriginReady: originReady}
	if !edgeReady || !routeReady || !originReady {
		c.mu.Unlock()
		return readiness, codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	prepared := c.prepared
	candidate := cloneSnapshot(c.candidate)
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return readiness, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	if prepared == nil {
		return readiness, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, errors.New("missing prepared configuration"))
	}
	if err := prepared.Activate(ctx); err != nil {
		abortErr := c.abortPrepared(prepared)
		c.mu.Lock()
		if c.hasCandidate && c.candidate.Generation == candidate.Generation && c.candidate.ContentHash == candidate.ContentHash {
			c.candidate = Snapshot{}
			c.hasCandidate = false
			c.prepared = nil
			c.needsSnapshot = true
			c.restoreStateLocked()
		}
		c.mu.Unlock()
		if ctx.Err() != nil {
			return readiness, codeError(ErrCanceled, ReasonCanceled, true, joinCleanup(err, abortErr))
		}
		return readiness, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, joinCleanup(err, abortErr))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureActiveLocked(c.config.Clock.Now().UTC()); err != nil {
		return readiness, err
	}
	if !c.hasCandidate || c.candidate.Generation != candidate.Generation || c.candidate.ContentHash != candidate.ContentHash {
		return readiness, codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
	}
	c.active = cloneSnapshot(c.candidate)
	c.hasActive = true
	c.candidate = Snapshot{}
	c.hasCandidate = false
	c.prepared = nil
	c.needsSnapshot = false
	c.readyGeneration = c.active.Generation
	c.state = SessionReady
	return readiness, nil
}

func (c *ClientSession) Heartbeat(now time.Time) (Heartbeat, error) {
	if c == nil {
		return Heartbeat{}, ErrInvalidInput
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.IsZero() {
		now = c.config.Clock.Now().UTC()
	}
	if err := c.ensureActiveLocked(now); err != nil {
		return Heartbeat{}, err
	}
	current, ok := c.currentCandidateLocked()
	if !ok {
		return Heartbeat{}, codeError(ErrSnapshotRequired, ReasonGenerationGap, true, nil)
	}
	return Heartbeat{AccountID: c.config.Hello.AccountID, SessionID: c.welcome.SessionID, TunnelID: c.config.Hello.TunnelID, ConnectorID: c.config.Hello.ConnectorID, ProcessGeneration: c.config.Hello.ProcessGeneration, LastAppliedGeneration: current.Generation, LastAppliedHash: current.ContentHash, SentAt: now}, nil
}

func (c *ClientSession) AcceptHeartbeatAck(ack HeartbeatAck) error {
	if c == nil {
		return ErrInvalidInput
	}
	now := c.config.Clock.Now().UTC()
	if err := ack.Validate(now); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureActiveLocked(now); err != nil {
		return err
	}
	if ack.AccountID != c.config.Hello.AccountID || ack.TunnelID != c.config.Hello.TunnelID || ack.ConnectorID != c.config.Hello.ConnectorID || ack.SessionID != c.welcome.SessionID || ack.ProcessGeneration != c.config.Hello.ProcessGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	c.lease.ExpiresAt = ack.LeaseExpiresAt
	c.lastHeartbeatAck = now
	return nil
}

// HandleDrain accepts a generation-bound drain request and immediately stops
// new streams through the runtime adapter's drain hook. It returns an
// acknowledgement even when no streams are active; completion is sent through
// DrainProgress so the server can distinguish acceptance from completion.
func (c *ClientSession) HandleDrain(ctx context.Context, request Drain) (DrainAck, error) {
	if c == nil || ctx == nil {
		return DrainAck{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return DrainAck{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.config.Clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return DrainAck{}, err
	}
	c.mu.Lock()
	if err := c.ensureActiveLocked(now); err != nil {
		c.mu.Unlock()
		return DrainAck{}, err
	}
	if !hasCapability(c.welcome.Capabilities, CapabilityDrain) {
		c.mu.Unlock()
		return DrainAck{}, codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, nil)
	}
	if request.AccountID != c.config.Hello.AccountID || request.TunnelID != c.config.Hello.TunnelID || request.ConnectorID != c.config.Hello.ConnectorID || request.SessionID != c.welcome.SessionID || request.ProcessGeneration != c.config.Hello.ProcessGeneration {
		ack := c.makeDrainAckLocked(request, DrainRejected, 0, false, CodeDrainRejected)
		c.mu.Unlock()
		return ack, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if c.drain != nil {
		if request.DrainID != c.drain.DrainID {
			ack := c.makeDrainAckLocked(request, DrainRejected, c.activeStreams, false, CodeDrainRejected)
			c.mu.Unlock()
			return ack, codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
		}
		if request.Generation != c.drain.Generation || request.ContentHash != c.drain.ContentHash {
			ack := c.makeDrainAckLocked(request, DrainRejected, c.activeStreams, false, CodeDrainRejected)
			c.mu.Unlock()
			return ack, codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
		ack := c.makeDrainAckLocked(request, c.drainStatus, c.activeStreams, c.drainStatus == DrainForced, c.drainCode)
		c.mu.Unlock()
		return ack, nil
	}
	if !c.hasActive || c.needsSnapshot || c.readyGeneration != c.active.Generation {
		ack := c.makeDrainAckLocked(request, DrainRejected, 0, false, CodeDrainRejected)
		c.mu.Unlock()
		return ack, codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	if request.Generation != c.active.Generation || request.ContentHash != c.active.ContentHash {
		ack := c.makeDrainAckLocked(request, DrainRejected, 0, false, CodeDrainRejected)
		c.mu.Unlock()
		return ack, codeError(ErrStaleGeneration, ReasonStaleGeneration, true, nil)
	}
	c.drain = cloneDrain(request)
	c.drainStatus = DrainAccepted
	c.drainCode = ""
	c.drainCompleted = false
	c.activeStreams = 0
	c.state = SessionDraining
	c.mu.Unlock()

	// Stop admission before observing the stream count. A deadline-bound
	// context prevents an unhealthy runtime from holding the control loop.
	stopCtx, cancelStop := context.WithDeadline(ctx, request.Deadline)
	stopErr := c.config.Drainer.StopNewStreams(stopCtx)
	cancelStop()
	if stopErr != nil {
		c.mu.Lock()
		if c.drain != nil && c.drain.DrainID == request.DrainID {
			c.drainStatus = DrainRejected
			c.drainCode = CodeDrainRejected
			c.drainCompleted = true
			c.restoreStateLocked()
		}
		ack := c.makeDrainAckLocked(request, DrainRejected, c.activeStreams, false, CodeDrainRejected)
		c.mu.Unlock()
		return ack, codeError(ErrDrainRejected, ReasonSnapshotRejected, true, stopErr)
	}
	countCtx, cancelCount := context.WithTimeout(ctx, c.config.AbortTimeout)
	activeStreams, countErr := c.config.Drainer.ActiveStreams(countCtx)
	cancelCount()
	if countErr != nil || activeStreams > MaxActiveStreams {
		if countErr == nil {
			countErr = ErrInvalidInput
		}
		c.mu.Lock()
		if c.drain != nil && c.drain.DrainID == request.DrainID {
			c.drainStatus = DrainRejected
			c.drainCode = CodeDrainRejected
			c.drainCompleted = true
			c.restoreStateLocked()
		}
		ack := c.makeDrainAckLocked(request, DrainRejected, 0, false, CodeDrainRejected)
		c.mu.Unlock()
		return ack, codeError(ErrDrainRejected, ReasonSnapshotRejected, true, countErr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.drain == nil || c.drain.DrainID != request.DrainID {
		return c.makeDrainAckLocked(request, DrainRejected, activeStreams, false, CodeDrainRejected), codeError(ErrStaleSession, ReasonStaleGeneration, false, nil)
	}
	c.activeStreams = activeStreams
	return c.makeDrainAckLocked(request, DrainAccepted, activeStreams, false, ""), nil
}

// DrainProgress reports the number of streams that remain after the runtime
// has stopped admitting new streams. Completion and forced-close are distinct
// terminal outcomes and are idempotent for the active drain ID.
func (c *ClientSession) DrainProgress(ctx context.Context, activeStreams uint32, forcedClose bool) (DrainAck, error) {
	if c == nil || ctx == nil {
		return DrainAck{}, ErrInvalidInput
	}
	if activeStreams > MaxActiveStreams {
		return DrainAck{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return DrainAck{}, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	now := c.config.Clock.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureActiveLocked(now); err != nil {
		return DrainAck{}, err
	}
	if c.drain == nil {
		return DrainAck{}, codeError(ErrSessionConflict, ReasonStaleGeneration, false, nil)
	}
	c.activeStreams = activeStreams
	if c.drainCompleted {
		return c.makeDrainAckLocked(*c.drain, c.drainStatus, c.activeStreams, c.drainStatus == DrainForced, c.drainCode), nil
	}
	if forcedClose {
		if activeStreams != 0 {
			return DrainAck{}, codeError(ErrInvalidInput, ReasonSnapshotRejected, false, errors.New("forced drain must have zero active streams"))
		}
		c.drainStatus = DrainForced
		c.drainCode = CodeDrainTimeout
		c.drainCompleted = true
		return c.makeDrainAckLocked(*c.drain, DrainForced, 0, true, CodeDrainTimeout), nil
	}
	if activeStreams == 0 {
		c.drainStatus = DrainCompleted
		c.drainCode = ""
		c.drainCompleted = true
		return c.makeDrainAckLocked(*c.drain, DrainCompleted, 0, false, ""), nil
	}
	if !now.Before(c.drain.Deadline) {
		return c.makeDrainAckLocked(*c.drain, DrainProgress, activeStreams, false, ""), codeError(ErrDrainTimeout, ReasonHeartbeatTimeout, true, nil)
	}
	c.drainStatus = DrainProgress
	c.drainCode = ""
	return c.makeDrainAckLocked(*c.drain, DrainProgress, activeStreams, false, ""), nil
}

// CompleteDrain drives the runtime hook and emits one terminal acknowledgement.
// It is the preferred adapter entry point because stream counts and forced
// closure stay behind the bounded Drainer interface.
func (c *ClientSession) CompleteDrain(ctx context.Context, force bool) (DrainAck, error) {
	if c == nil || ctx == nil {
		return DrainAck{}, ErrInvalidInput
	}
	c.mu.RLock()
	request := c.drain
	completed := c.drainCompleted
	status := c.drainStatus
	code := c.drainCode
	active := c.activeStreams
	c.mu.RUnlock()
	if request == nil {
		return DrainAck{}, codeError(ErrSessionConflict, ReasonStaleGeneration, false, nil)
	}
	if completed {
		c.mu.RLock()
		ack := c.makeDrainAckLocked(*request, status, active, status == DrainForced, code)
		c.mu.RUnlock()
		return ack, nil
	}
	if force {
		forceCtx, cancel := context.WithTimeout(ctx, c.config.AbortTimeout)
		err := c.config.Drainer.ForceClose(forceCtx)
		cancel()
		if err != nil {
			return DrainAck{}, codeError(ErrDrainRejected, ReasonSnapshotRejected, true, err)
		}
		return c.DrainProgress(ctx, 0, true)
	}
	countCtx, cancel := context.WithTimeout(ctx, c.config.AbortTimeout)
	active, err := c.config.Drainer.ActiveStreams(countCtx)
	cancel()
	if err != nil {
		return DrainAck{}, codeError(ErrDrainRejected, ReasonSnapshotRejected, true, err)
	}
	return c.DrainProgress(ctx, active, false)
}

func (c *ClientSession) makeDrainAckLocked(request Drain, status DrainStatus, activeStreams uint32, forced bool, code Code) DrainAck {
	return DrainAck{AccountID: c.config.Hello.AccountID, TunnelID: c.config.Hello.TunnelID, ConnectorID: c.config.Hello.ConnectorID, SessionID: c.welcome.SessionID, ProcessGeneration: c.config.Hello.ProcessGeneration, DrainID: request.DrainID, Generation: request.Generation, ContentHash: request.ContentHash, Status: status, ActiveStreams: activeStreams, ForcedClose: forced, Code: code}
}

func cloneDrain(request Drain) *Drain {
	copy := request
	return &copy
}

func (c *ClientSession) Drain() (Drain, DrainStatus, uint32, bool) {
	if c == nil {
		return Drain{}, "", 0, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.drain == nil {
		return Drain{}, "", 0, false
	}
	return *c.drain, c.drainStatus, c.activeStreams, c.drainCompleted
}

func (c *ClientSession) RenewalRequest(now time.Time, nonce, signedProof string) (RenewalRequest, error) {
	if c == nil {
		return RenewalRequest{}, ErrInvalidInput
	}
	if now.IsZero() {
		now = c.config.Clock.Now().UTC()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if err := c.ensureActiveReadLocked(now); err != nil {
		return RenewalRequest{}, err
	}
	request := RenewalRequest{SessionID: c.welcome.SessionID, AccountID: c.auth.AccountID, TunnelID: c.auth.TunnelID, ConnectorID: c.auth.ConnectorID, HostID: c.auth.HostID, IdentityKeyID: c.auth.IdentityKeyID, IdentityKeyThumbprint: c.auth.IdentityKeyThumbprint, ProcessGeneration: c.config.Hello.ProcessGeneration, CredentialGeneration: c.auth.CredentialGeneration, Nonce: nonce, SignedProof: signedProof, RequestedAt: now}
	if err := request.Validate(); err != nil {
		return RenewalRequest{}, err
	}
	return request, nil
}

func (c *ClientSession) ensureActiveReadLocked(now time.Time) error {
	if c.state == SessionClosed {
		return codeError(ErrSessionClosed, c.disconnectReason, false, nil)
	}
	if c.state == SessionNew {
		return codeError(ErrSessionConflict, ReasonProtocolClosed, false, nil)
	}
	if !c.lease.ExpiresAt.After(now) {
		return codeError(ErrLeaseExpired, ReasonLeaseExpired, true, nil)
	}
	return nil
}

func (c *ClientSession) restoreStateLocked() {
	if c.hasActive && c.readyGeneration == c.active.Generation && !c.needsSnapshot {
		c.state = SessionReady
		return
	}
	if c.hasCandidate {
		c.state = SessionAwaitingReady
		return
	}
	c.state = SessionAwaitingSnapshot
}

func (c *ClientSession) abortPrepared(prepared PreparedConfig) error {
	if prepared == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.config.AbortTimeout)
	defer cancel()
	return prepared.Abort(ctx)
}

func joinCleanup(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	cleanup = fmt.Errorf("abort prepared configuration: %w", cleanup)
	if primary == nil {
		return cleanup
	}
	return errors.Join(primary, cleanup)
}

func (c *ClientSession) abortAndJoin(primary error, prepared PreparedConfig) error {
	return joinCleanup(primary, c.abortPrepared(prepared))
}

func (c *ClientSession) ApplyRenewal(result AuthResult) error {
	if c == nil {
		return ErrInvalidInput
	}
	now := c.config.Clock.Now().UTC()
	if err := result.ValidateBound(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureActiveLocked(now); err != nil {
		return err
	}
	if result.AccountID != c.auth.AccountID || result.TunnelID != c.auth.TunnelID || result.ConnectorID != c.auth.ConnectorID || result.SessionID != c.welcome.SessionID || result.HostID != c.auth.HostID || result.IdentityKeyID != c.auth.IdentityKeyID || result.IdentityKeyThumbprint != c.auth.IdentityKeyThumbprint || result.ProcessGeneration != c.config.Hello.ProcessGeneration || result.CredentialGeneration < c.auth.CredentialGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if result.CredentialExpiresAt.Before(c.auth.ExpiresAt) || result.LeaseExpiresAt.Before(c.lease.ExpiresAt) {
		return codeError(ErrSessionConflict, ReasonAuthentication, false, nil)
	}
	if result.CredentialGeneration == c.auth.CredentialGeneration && result.CredentialExpiresAt.Equal(c.auth.ExpiresAt) && result.LeaseExpiresAt.Equal(c.lease.ExpiresAt) {
		return nil
	}
	c.auth = AuthRequest{AccountID: result.AccountID, TunnelID: result.TunnelID, ConnectorID: result.ConnectorID, HostID: result.HostID, IdentityKeyID: result.IdentityKeyID, IdentityKeyThumbprint: result.IdentityKeyThumbprint, ProcessGeneration: result.ProcessGeneration, CredentialGeneration: result.CredentialGeneration, IssuedAt: now, ExpiresAt: result.CredentialExpiresAt}
	c.lease.ExpiresAt = result.LeaseExpiresAt
	c.lastHeartbeatAck = now
	return nil
}

func (c *ClientSession) Applied() (Snapshot, bool) {
	if c == nil {
		return Snapshot{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot, ok := c.currentCandidateLocked()
	if !ok {
		return Snapshot{}, false
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	return snapshot, true
}

// Candidate returns the snapshot staged by the most recent accepted apply but
// not yet promoted by MarkReadyContext. A control transport must use this
// exact value when asking the runtime to probe routes and origins; Applied may
// still refer to the previously active snapshot during a cutover.
func (c *ClientSession) Candidate() (Snapshot, bool) {
	if c == nil {
		return Snapshot{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasCandidate {
		return Snapshot{}, false
	}
	return cloneSnapshot(c.candidate), true
}

func (c *ClientSession) currentCandidateLocked() (Snapshot, bool) {
	if c.hasActive {
		return c.active, true
	}
	if c.hasCandidate {
		return c.candidate, true
	}
	return Snapshot{}, false
}

// Active returns the last promoted, ready configuration. A staged candidate
// is deliberately not returned as active until MarkReady succeeds.
func (c *ClientSession) Active() (Snapshot, bool) {
	if c == nil {
		return Snapshot{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasActive {
		return Snapshot{}, false
	}
	snapshot := cloneSnapshot(c.active)
	return snapshot, true
}

func (c *ClientSession) State() SessionState {
	if c == nil {
		return SessionClosed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *ClientSession) Close(reason DisconnectReason) error {
	if c == nil || !validDisconnectReason(reason) {
		return ErrInvalidInput
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if c.state == SessionClosed {
		c.mu.Unlock()
		return nil
	}
	c.state = SessionClosed
	c.disconnectReason = reason
	prepared := c.prepared
	c.prepared = nil
	c.candidate = Snapshot{}
	c.hasCandidate = false
	c.mu.Unlock()
	if err := c.abortPrepared(prepared); err != nil {
		return codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, joinCleanup(nil, err))
	}
	return nil
}

func (c *ClientSession) Disconnect() Disconnect {
	if c == nil {
		return Disconnect{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	reason := c.disconnectReason
	if reason == "" {
		reason = ReasonProtocolClosed
	}
	return Disconnect{AccountID: c.config.Hello.AccountID, TunnelID: c.config.Hello.TunnelID, ConnectorID: c.config.Hello.ConnectorID, SessionID: c.welcome.SessionID, ProcessGeneration: c.config.Hello.ProcessGeneration, Reason: reason, Retryable: reason == ReasonLeaseExpired || reason == ReasonHeartbeatTimeout || reason == ReasonCredentialExpired || reason == ReasonSessionReplaced}
}

func (s *ServerSession) Current() (Snapshot, bool, uint64) {
	if s == nil {
		return Snapshot{}, false, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.hasActive {
		return Snapshot{}, false, 0
	}
	snapshot := s.active
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	return snapshot, s.state == SessionReady && !s.needsSnapshot && s.readyGeneration == s.active.Generation, s.readyGeneration
}

func (s *ServerSession) Lease() Lease {
	if s == nil {
		return Lease{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lease
}

func (s *ServerSession) CheckLease(now time.Time) error {
	if s == nil {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureActiveLocked(now)
}

func (c *ClientSession) CheckLease(now time.Time) error {
	if c == nil {
		return ErrInvalidInput
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureActiveLocked(now)
}

func (c *ClientSession) makeAckLocked(kind AckKind, status AckStatus, snapshot Snapshot) Ack {
	return Ack{AccountID: c.config.Hello.AccountID, TunnelID: c.config.Hello.TunnelID, ConnectorID: c.config.Hello.ConnectorID, SessionID: c.welcome.SessionID, ProcessGeneration: c.config.Hello.ProcessGeneration, Kind: kind, Status: status, Generation: snapshot.Generation, ContentHash: snapshot.ContentHash}
}

type noopApplier struct{}

func (noopApplier) PrepareSnapshot(context.Context, Snapshot) (PreparedConfig, error) {
	return noopPrepared{}, nil
}
func (noopApplier) PrepareDelta(context.Context, Delta) (PreparedConfig, error) {
	return noopPrepared{}, nil
}

type noopPrepared struct{}

func (noopPrepared) Activate(context.Context) error { return nil }
func (noopPrepared) Abort(context.Context) error    { return nil }
