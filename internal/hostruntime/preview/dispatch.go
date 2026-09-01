package preview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const PreviewDispatchKind = "preview_dispatch"

var (
	ErrDispatchInvalid     = errors.New("invalid preview dispatch")
	ErrDispatchConflict    = errors.New("preview dispatch conflicts with an existing operation")
	ErrDispatchUnavailable = errors.New("preview dispatch carrier unavailable")
)

// DispatchRequest is the secret-free, operation-bound instruction delivered
// by paperboat-server to the selected online device. LeaseETag is transport
// metadata required for generation-safe renew and stop calls.
type DispatchRequest struct {
	Schema             string      `json:"schema"`
	Kind               string      `json:"kind"`
	PreviewID          string      `json:"preview_id"`
	OperationID        string      `json:"operation_id"`
	AccountID          string      `json:"account_id"`
	ActorID            string      `json:"actor_id"`
	OwnerDeviceID      string      `json:"owner_device_id"`
	OwnerSessionID     string      `json:"owner_session_id"`
	Target             LeaseTarget `json:"target"`
	AccessMode         string      `json:"access_mode"`
	Endpoint           string      `json:"endpoint"`
	LeaseDeadline      time.Time   `json:"lease_deadline"`
	UserDeadline       *time.Time  `json:"user_deadline,omitempty"`
	LeaseETag          string      `json:"lease_etag"`
	State              string      `json:"state"`
	AllocationState    string      `json:"allocation_state"`
	EdgeState          string      `json:"edge_state"`
	OriginState        string      `json:"origin_state"`
	CreatedAt          time.Time   `json:"created_at"`
	LastRenewedAt      time.Time   `json:"last_renewed_at"`
	ExpectedGeneration int64       `json:"expected_generation"`
	IdempotencyKey     string      `json:"idempotency_key"`
	RequestID          string      `json:"request_id"`
	CorrelationID      string      `json:"correlation_id"`
	RequestHash        string      `json:"request_hash"`
}

// DispatchOutcome is safe to return to the control plane. Readiness remains
// authoritative on paperboat-server and is never inferred from acceptance.
type DispatchOutcome struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	PreviewID   string `json:"preview_id"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Generation  int64  `json:"generation"`
}

// DispatchAuthorization is the verified, short-lived preview_launch claim
// projection. The HTTP boundary must construct it only after signature,
// expiry, scope, revocation, and single-use replay validation.
type DispatchAuthorization struct {
	AccountID          string
	ActorID            string
	MachineID          string
	OwnerSessionID     string
	PreviewID          string
	OperationID        string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestID          string
	CorrelationID      string
	RequestHash        string
	ExpiresAt          time.Time
}

// DispatchCarrierResolver attaches the exact already-created preview lease to
// an authenticated edge carrier. It must not allocate another lease or URL.
type DispatchCarrierResolver interface {
	ResolvePreviewCarrier(context.Context, DispatchRequest) (Carrier, error)
}

// DispatchReadinessObserver records real carrier and origin readiness using
// the current lease generation. The returned lease must be the server's new
// canonical projection and strong ETag.
type DispatchReadinessObserver interface {
	ObservePreviewReadiness(context.Context, DispatchReadiness, Lease, int64) (Lease, error)
}

// DispatchReadiness carries the stable operation and trace bindings required
// to sign and idempotently replay the device readiness observation. It has no
// reusable credential material.
type DispatchReadiness struct {
	OperationID    string
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
}

// DispatchOwnerSessions returns the lifetime of the selected device session.
// Closing the browser is unrelated; closing this channel means the device no
// longer owns the foreground preview and must trigger lease cleanup.
type DispatchOwnerSessions interface {
	OwnerSessionDone(accountID, machineID, ownerSessionID string) (<-chan struct{}, error)
}

// DispatchOwnerSessionTargetValidator is an optional stronger boundary used
// by hostd-minted local owner leases. It binds the local lease to the exact
// target before a delayed server dispatch can start forwarding traffic.
type DispatchOwnerSessionTargetValidator interface {
	OwnerSessionDoneForTarget(accountID, machineID, ownerSessionID string, target LeaseTarget) (<-chan struct{}, error)
}

// DispatchOwnerSessionReleaser is optional. A runtime owner registry may use
// it to release one reference when a foreground preview ends while keeping a
// shared owner_session_id alive for other concurrent previews.
type DispatchOwnerSessionReleaser interface {
	ReleaseOwnerSession(accountID, machineID, ownerSessionID string) error
}

type DispatchManagerConfig struct {
	MachineID  string
	Leases     LeaseClient
	Carriers   DispatchCarrierResolver
	Readiness  DispatchReadinessObserver
	Owners     DispatchOwnerSessions
	Sessions   *SessionManager
	Now        func() time.Time
	RunContext context.Context
}

// DispatchManager owns dashboard-created previews in memory for the lifetime
// of the stable host runtime. It deliberately has no persistence or recovery
// path, so a reboot can never restore a temporary preview.
type DispatchManager struct {
	config DispatchManagerConfig
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	operations map[string]dispatchOperation
	closed     bool
	inflight   sync.WaitGroup
}

type dispatchOperation struct {
	hash    string
	session *Session
	expires time.Time
	state   string
}

func NewDispatchManager(config DispatchManagerConfig) (*DispatchManager, error) {
	config.MachineID = strings.TrimSpace(config.MachineID)
	if config.MachineID == "" || config.Leases == nil || config.Carriers == nil || config.Readiness == nil || config.Owners == nil {
		return nil, ErrDispatchInvalid
	}
	if config.Sessions == nil {
		config.Sessions = NewSessionManager()
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	parent := config.RunContext
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &DispatchManager{config: config, ctx: ctx, cancel: cancel, operations: make(map[string]dispatchOperation)}, nil
}

// Dispatch validates and accepts one server-created lease. It returns before
// readiness; the wrapped carrier records readiness asynchronously and only
// then lets Session publish the lease as ready.
func (m *DispatchManager) Dispatch(ctx context.Context, authorization DispatchAuthorization, request DispatchRequest) (DispatchOutcome, error) {
	if m == nil || ctx == nil {
		return DispatchOutcome{}, ErrDispatchInvalid
	}
	hash, err := request.Validate(m.config.MachineID, m.config.Now())
	if err != nil {
		return DispatchOutcome{}, err
	}
	if err := authorization.validate(request, m.config.Now()); err != nil {
		return DispatchOutcome{}, err
	}
	lease := request.Lease()
	baseSessionConfig := SessionConfig{
		LeaseClient:        m.config.Leases,
		OwnerDeviceID:      lease.OwnerDeviceID,
		OwnerSessionID:     lease.OwnerSessionID,
		Target:             lease.Target,
		AccessMode:         lease.AccessMode,
		UserDeadline:       lease.UserDeadline,
		DisableParentWatch: true,
		Now:                m.config.Now,
	}
	if err := validateSessionLease(lease, baseSessionConfig, m.config.Now()); err != nil {
		return DispatchOutcome{}, err
	}

	m.mu.Lock()
	m.purgeExpiredLocked(m.config.Now())
	if m.closed {
		m.mu.Unlock()
		return DispatchOutcome{}, ErrSessionManagerStopped
	}
	if existing, ok := m.operations[request.OperationID]; ok {
		m.mu.Unlock()
		if existing.hash != hash {
			return DispatchOutcome{}, ErrDispatchConflict
		}
		return dispatchOutcome(request, existing), nil
	}
	// Reserve before resolving the carrier so concurrent identical deliveries
	// cannot start two foreground sessions. Failure removes the reservation.
	m.operations[request.OperationID] = dispatchOperation{hash: hash, expires: request.LeaseDeadline.UTC(), state: "accepted"}
	m.inflight.Add(1)
	m.mu.Unlock()
	defer m.inflight.Done()

	resolveCtx, cancelResolve := context.WithCancel(m.ctx)
	stopResolve := context.AfterFunc(ctx, cancelResolve)
	carrier, err := m.config.Carriers.ResolvePreviewCarrier(resolveCtx, request)
	stopResolve()
	cancelResolve()
	if err != nil || carrier == nil {
		m.releaseReservation(request.OperationID, hash)
		return DispatchOutcome{}, errors.Join(ErrDispatchUnavailable, err)
	}
	var ownerDone <-chan struct{}
	if targetValidator, ok := m.config.Owners.(DispatchOwnerSessionTargetValidator); ok {
		ownerDone, err = targetValidator.OwnerSessionDoneForTarget(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID, request.Target)
	} else {
		ownerDone, err = m.config.Owners.OwnerSessionDone(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID)
	}
	if err != nil || ownerDone == nil {
		m.releaseReservation(request.OperationID, hash)
		m.releaseOwnerSession(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID)
		closeCtx, cancel := context.WithTimeout(context.Background(), PreviewLeaseDefaultShutdown)
		_ = carrier.Close(closeCtx)
		cancel()
		return DispatchOutcome{}, errors.Join(ErrDispatchInvalid, err)
	}
	leaseSource := &dispatchSessionLease{admitted: lease}
	wrapped := &readinessCarrier{
		inner: carrier, observer: m.config.Readiness, admitted: lease, leaseSource: leaseSource,
		readiness: DispatchReadiness{OperationID: request.OperationID, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, CorrelationID: request.CorrelationID},
	}
	baseSessionConfig.Carrier = wrapped
	baseSessionConfig.OwnerDone = ownerDone
	session, err := StartExisting(m.ctx, baseSessionConfig, lease)
	if err != nil {
		m.releaseReservation(request.OperationID, hash)
		m.releaseOwnerSession(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID)
		closeCtx, cancel := context.WithTimeout(context.Background(), PreviewLeaseDefaultShutdown)
		_ = carrier.Close(closeCtx)
		cancel()
		return DispatchOutcome{}, err
	}
	leaseSource.setSession(session)
	if err := m.config.Sessions.Track(session); err != nil {
		m.releaseReservation(request.OperationID, hash)
		m.releaseOwnerSession(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID)
		stopCtx, cancel := context.WithTimeout(context.Background(), PreviewLeaseDefaultShutdown)
		_ = session.Stop(stopCtx)
		cancel()
		return DispatchOutcome{}, err
	}

	m.mu.Lock()
	current, ok := m.operations[request.OperationID]
	if !ok || current.hash != hash || m.closed {
		m.mu.Unlock()
		m.releaseOwnerSession(request.AccountID, request.OwnerDeviceID, request.OwnerSessionID)
		stopCtx, cancel := context.WithTimeout(context.Background(), PreviewLeaseDefaultShutdown)
		_ = session.Stop(stopCtx)
		cancel()
		return DispatchOutcome{}, ErrSessionManagerStopped
	}
	current.session = session
	m.operations[request.OperationID] = current
	m.mu.Unlock()
	go m.observeSession(request.OperationID, hash, session)
	return dispatchOutcome(request, current), nil
}

func (m *DispatchManager) releaseReservation(operationID, hash string) {
	m.mu.Lock()
	if current, ok := m.operations[operationID]; ok && current.hash == hash && current.session == nil {
		delete(m.operations, operationID)
	}
	m.mu.Unlock()
}

func dispatchOutcome(request DispatchRequest, operation dispatchOperation) DispatchOutcome {
	state := operation.state
	if state == "" {
		state = "accepted"
	}
	generation := request.ExpectedGeneration
	if operation.session != nil {
		operation.session.mu.RLock()
		if operation.session.readySet {
			state = "ready"
			generation = operation.session.ready.Generation
		}
		operation.session.mu.RUnlock()
	}
	return DispatchOutcome{Schema: PreviewTunnelSchemaV1, Kind: PreviewDispatchKind, PreviewID: request.PreviewID, OperationID: request.OperationID, State: state, Generation: generation}
}

func (m *DispatchManager) observeSession(operationID, hash string, session *Session) {
	<-session.done
	lease := session.currentLease()
	m.releaseOwnerSession(lease.AccountID, lease.OwnerDeviceID, lease.OwnerSessionID)
	m.mu.Lock()
	if current, ok := m.operations[operationID]; ok && current.hash == hash && current.session == session {
		current.session = nil
		current.state = "failed"
		m.operations[operationID] = current
	}
	m.mu.Unlock()
}

func (m *DispatchManager) releaseOwnerSession(accountID, machineID, ownerSessionID string) {
	releaser, ok := m.config.Owners.(DispatchOwnerSessionReleaser)
	if !ok || releaser == nil {
		return
	}
	_ = releaser.ReleaseOwnerSession(accountID, machineID, ownerSessionID)
}

func (m *DispatchManager) purgeExpiredLocked(now time.Time) {
	for operationID, operation := range m.operations {
		if !operation.expires.After(now.UTC()) && operation.session == nil {
			delete(m.operations, operationID)
		}
	}
}

func (m *DispatchManager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.operations = make(map[string]dispatchOperation)
	m.mu.Unlock()
	m.cancel()
	sessionErr := m.config.Sessions.Shutdown(ctx)
	waited := make(chan struct{})
	go func() {
		m.inflight.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		return sessionErr
	case <-ctx.Done():
		return errors.Join(sessionErr, ctx.Err())
	}
}

func (a DispatchAuthorization) validate(request DispatchRequest, now time.Time) error {
	if a.ExpiresAt.IsZero() || !a.ExpiresAt.After(now.UTC()) || a.AccountID != request.AccountID || a.ActorID != request.ActorID || a.MachineID != request.OwnerDeviceID || a.OwnerSessionID != request.OwnerSessionID || a.PreviewID != request.PreviewID || a.OperationID != request.OperationID || a.ExpectedGeneration != request.ExpectedGeneration || a.IdempotencyKey != request.IdempotencyKey || a.RequestID != request.RequestID || a.CorrelationID != request.CorrelationID || a.RequestHash != request.RequestHash {
		return fmt.Errorf("%w: verified authorization does not match request", ErrDispatchInvalid)
	}
	return nil
}

func (r DispatchRequest) Validate(machineID string, now time.Time) (string, error) {
	canonical, err := r.canonicalHashInput(machineID, now)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	want := hex.EncodeToString(digest[:])
	if len(r.RequestHash) != sha256.Size*2 || r.RequestHash != want {
		return "", fmt.Errorf("%w: request hash mismatch", ErrDispatchInvalid)
	}
	return want, nil
}

// ComputeRequestHash is shared by trusted dispatch senders and tests. It does
// not include RequestHash itself and uses a fixed struct for stable field order.
func (r DispatchRequest) ComputeRequestHash() (string, error) {
	canonical, err := r.canonicalHashInput(r.OwnerDeviceID, time.Time{})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (r DispatchRequest) canonicalHashInput(machineID string, now time.Time) ([]byte, error) {
	r.Schema = strings.TrimSpace(r.Schema)
	r.Kind = strings.TrimSpace(r.Kind)
	r.PreviewID = strings.TrimSpace(r.PreviewID)
	r.OperationID = strings.TrimSpace(r.OperationID)
	r.AccountID = strings.TrimSpace(r.AccountID)
	r.ActorID = strings.TrimSpace(r.ActorID)
	r.OwnerDeviceID = strings.TrimSpace(r.OwnerDeviceID)
	r.OwnerSessionID = strings.TrimSpace(r.OwnerSessionID)
	r.Target.Scheme = strings.ToLower(strings.TrimSpace(r.Target.Scheme))
	r.Target.Address = strings.TrimSpace(r.Target.Address)
	r.AccessMode = strings.ToLower(strings.TrimSpace(r.AccessMode))
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	r.LeaseETag = strings.TrimSpace(r.LeaseETag)
	r.IdempotencyKey = strings.TrimSpace(r.IdempotencyKey)
	r.RequestID = strings.TrimSpace(r.RequestID)
	r.CorrelationID = strings.TrimSpace(r.CorrelationID)
	if r.Schema != PreviewTunnelSchemaV1 || r.Kind != PreviewDispatchKind || !validLeaseID(r.PreviewID) || !validLeaseID(r.OperationID) || !validLeaseID(r.AccountID) || !validLeaseID(r.ActorID) || r.OwnerDeviceID != strings.TrimSpace(machineID) || !validLeaseID(r.OwnerSessionID) || r.ExpectedGeneration < 1 {
		return nil, ErrDispatchInvalid
	}
	if !validDispatchTrace(r.IdempotencyKey, 1, 256) || !validDispatchTrace(r.RequestID, 3, 128) || !validDispatchTrace(r.CorrelationID, 3, 128) {
		return nil, ErrDispatchInvalid
	}
	if err := validateLeaseTarget(r.Target); err != nil || r.AccessMode != "public" && r.AccessMode != "private" {
		return nil, ErrDispatchInvalid
	}
	if r.LeaseDeadline.IsZero() || !now.IsZero() && !r.LeaseDeadline.After(now.UTC()) || r.UserDeadline != nil && (r.UserDeadline.IsZero() || !now.IsZero() && !r.UserDeadline.After(now.UTC())) {
		return nil, ErrDispatchInvalid
	}
	if !validActiveLeaseState(r.State) || !validAllocationState(r.AllocationState) || !validEdgeState(r.EdgeState) || !validOriginState(r.OriginState) || r.CreatedAt.IsZero() || r.LastRenewedAt.IsZero() {
		return nil, ErrDispatchInvalid
	}
	lease := r.Lease()
	if generation := leaseGenerationForID(lease.ID, lease.ETag); generation != r.ExpectedGeneration {
		return nil, fmt.Errorf("%w: lease ETag generation mismatch", ErrDispatchInvalid)
	}
	return json.Marshal(struct {
		Schema             string      `json:"schema"`
		Kind               string      `json:"kind"`
		PreviewID          string      `json:"preview_id"`
		OperationID        string      `json:"operation_id"`
		AccountID          string      `json:"account_id"`
		ActorID            string      `json:"actor_id"`
		OwnerDeviceID      string      `json:"owner_device_id"`
		OwnerSessionID     string      `json:"owner_session_id"`
		Target             LeaseTarget `json:"target"`
		AccessMode         string      `json:"access_mode"`
		Endpoint           string      `json:"endpoint"`
		LeaseDeadline      time.Time   `json:"lease_deadline"`
		UserDeadline       *time.Time  `json:"user_deadline,omitempty"`
		LeaseETag          string      `json:"lease_etag"`
		State              string      `json:"state"`
		AllocationState    string      `json:"allocation_state"`
		EdgeState          string      `json:"edge_state"`
		OriginState        string      `json:"origin_state"`
		CreatedAt          time.Time   `json:"created_at"`
		LastRenewedAt      time.Time   `json:"last_renewed_at"`
		ExpectedGeneration int64       `json:"expected_generation"`
		IdempotencyKey     string      `json:"idempotency_key"`
		RequestID          string      `json:"request_id"`
		CorrelationID      string      `json:"correlation_id"`
	}{r.Schema, r.Kind, r.PreviewID, r.OperationID, r.AccountID, r.ActorID, r.OwnerDeviceID, r.OwnerSessionID, r.Target, r.AccessMode, r.Endpoint, r.LeaseDeadline.UTC(), utcTimePointer(r.UserDeadline), r.LeaseETag, r.State, r.AllocationState, r.EdgeState, r.OriginState, r.CreatedAt.UTC(), r.LastRenewedAt.UTC(), r.ExpectedGeneration, r.IdempotencyKey, r.RequestID, r.CorrelationID})
}

func validDispatchTrace(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func (r DispatchRequest) Lease() Lease {
	return Lease{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewLeaseKind, ID: r.PreviewID,
		AccountID: r.AccountID, ActorID: r.ActorID, OwnerDeviceID: r.OwnerDeviceID, OwnerSessionID: r.OwnerSessionID,
		Target: r.Target, AccessMode: r.AccessMode, Persistent: false, Endpoint: r.Endpoint,
		LeaseDeadline: r.LeaseDeadline.UTC(), UserDeadline: utcTimePointer(r.UserDeadline), State: r.State,
		AllocationState: r.AllocationState, EdgeState: r.EdgeState, OriginState: r.OriginState, CreatedAt: r.CreatedAt.UTC(),
		LastRenewedAt: r.LastRenewedAt.UTC(), CreateOperationID: r.OperationID, ETag: r.LeaseETag, Generation: r.ExpectedGeneration,
	}
}

type readinessCarrier struct {
	inner       Carrier
	observer    DispatchReadinessObserver
	admitted    Lease
	leaseSource *dispatchSessionLease
	readiness   DispatchReadiness
}

type dispatchSessionLease struct {
	mu       sync.RWMutex
	admitted Lease
	session  *Session
}

func (s *dispatchSessionLease) setSession(session *Session) {
	s.mu.Lock()
	s.session = session
	s.mu.Unlock()
}

func (s *dispatchSessionLease) current() Lease {
	s.mu.RLock()
	session, admitted := s.session, s.admitted
	s.mu.RUnlock()
	if session == nil {
		return admitted
	}
	return session.currentLease()
}

func (c *readinessCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	return c.inner.Run(ctx, lease, func(observed Lease) error {
		if err := validateReadyLeaseIdentity(c.admitted, observed); err != nil {
			return err
		}
		for attempt := 0; attempt < 4; attempt++ {
			current := c.leaseSource.current()
			if !sameLeaseIdentity(c.admitted, current) {
				return fmt.Errorf("%w: current lease changed identity", ErrDispatchInvalid)
			}
			expected := current.Generation
			if expected < 1 {
				expected = leaseGenerationForID(current.ID, current.ETag)
			}
			if observed.Generation > expected {
				return fmt.Errorf("%w: carrier reported a future lease generation", ErrDispatchInvalid)
			}
			candidate := current
			candidate.State, candidate.AllocationState, candidate.EdgeState, candidate.OriginState = "ready", "ready", "ready", "ready"
			updated, err := c.observer.ObservePreviewReadiness(ctx, c.readiness, candidate, expected)
			if err != nil {
				latest := c.leaseSource.current()
				latestGeneration := latest.Generation
				if latestGeneration < 1 {
					latestGeneration = leaseGenerationForID(latest.ID, latest.ETag)
				}
				if latestGeneration > expected {
					continue
				}
				return err
			}
			if err := validateReadyLeaseMutation(candidate, updated, expected); err != nil {
				return fmt.Errorf("%w: readiness response is stale or changed lease identity", ErrDispatchInvalid)
			}
			return ready(updated)
		}
		return fmt.Errorf("%w: readiness raced repeated lease renewals", ErrDispatchUnavailable)
	})
}

func (c *readinessCarrier) Close(ctx context.Context) error { return c.inner.Close(ctx) }

func validateReadyLeaseIdentity(expected, observed Lease) error {
	if !isReadyLease(observed) || !sameLeaseIdentity(expected, observed) || observed.Generation < expected.Generation || leaseGenerationForID(observed.ID, observed.ETag) != observed.Generation {
		return fmt.Errorf("%w: carrier readiness does not match admitted lease", ErrDispatchInvalid)
	}
	return nil
}

func validateReadyLeaseMutation(expected, updated Lease, previousGeneration int64) error {
	if !isReadyLease(updated) || !sameLeaseIdentity(expected, updated) || updated.Generation <= previousGeneration || leaseGenerationForID(updated.ID, updated.ETag) != updated.Generation {
		return ErrDispatchInvalid
	}
	return nil
}

func isReadyLease(lease Lease) bool {
	return lease.State == "ready" && lease.AllocationState == "ready" && lease.EdgeState == "ready" && lease.OriginState == "ready"
}

func sameLeaseIdentity(left, right Lease) bool {
	return right.Schema == left.Schema && right.Kind == left.Kind && right.ID == left.ID && right.AccountID == left.AccountID && right.ActorID == left.ActorID && right.OwnerDeviceID == left.OwnerDeviceID && right.OwnerSessionID == left.OwnerSessionID && right.Target == left.Target && right.AccessMode == left.AccessMode && right.Persistent == left.Persistent && right.Endpoint == left.Endpoint && right.CreatedAt.Equal(left.CreatedAt) && equalOptionalTime(right.UserDeadline, left.UserDeadline)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
