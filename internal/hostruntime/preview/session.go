package preview

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PreviewTunnelSchemaV1            = "paperboat.preview-tunnel/v1"
	PreviewLeaseKind                 = "preview_lease"
	PreviewLeaseDefaultRenewInterval = 10 * time.Second
	PreviewLeaseDefaultShutdown      = 10 * time.Second
	PreviewLeaseDefaultReconnect     = 250 * time.Millisecond
	PreviewLeaseMaxReconnect         = 5 * time.Second
	PreviewLeaseParentPoll           = 500 * time.Millisecond
)

var (
	ErrSessionInvalid     = errors.New("invalid preview session")
	ErrSessionStopped     = errors.New("preview session stopped before readiness")
	ErrLeaseLost          = errors.New("preview lease lost")
	ErrLeaseExpired       = errors.New("preview lease expired")
	ErrCarrierStopped     = errors.New("preview carrier stopped")
	ErrCarrierUnavailable = errors.New("preview carrier unavailable")
)

// LeaseTarget is the canonical v1 target. It intentionally does not reuse the
// retired host/port target used by the old preview registry.
type LeaseTarget struct {
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
}

// Lease is the in-memory, safe projection of a canonical preview lease. The
// endpoint is available to the carrier, but Session.URL only exposes it after
// readiness has been reported by an authenticated carrier.
type Lease struct {
	Schema          string      `json:"schema"`
	Kind            string      `json:"kind"`
	ID              string      `json:"id"`
	AccountID       string      `json:"account_id"`
	ActorID         string      `json:"actor_id"`
	OwnerDeviceID   string      `json:"owner_device_id"`
	OwnerSessionID  string      `json:"owner_session_id"`
	Target          LeaseTarget `json:"target"`
	AccessMode      string      `json:"access_mode"`
	Persistent      bool        `json:"persistent"`
	Endpoint        string      `json:"endpoint"`
	LeaseDeadline   time.Time   `json:"lease_deadline"`
	UserDeadline    *time.Time  `json:"user_deadline,omitempty"`
	State           string      `json:"state"`
	AllocationState string      `json:"allocation_state"`
	EdgeState       string      `json:"edge_state"`
	OriginState     string      `json:"origin_state"`
	CreatedAt       time.Time   `json:"created_at"`
	LastRenewedAt   time.Time   `json:"last_renewed_at"`
	// CreateOperationID is the durable server operation that allocated this
	// lease. It is transport-only metadata used by the authenticated carrier
	// attachment path and is never serialized in a preview resource.
	CreateOperationID string `json:"-"`
	ETag              string `json:"-"`
	Generation        int64  `json:"-"`
}

// LeaseRequest contains only create-time owner and target information. The
// server allocates the random endpoint and never accepts a requested hostname.
type LeaseRequest struct {
	OwnerDeviceID  string
	OwnerSessionID string
	Target         LeaseTarget
	AccessMode     string
	UserDeadline   *time.Time
	Duration       time.Duration
	IdempotencyKey string
}

// LeaseClient owns the control-plane calls for one foreground session. Stop
// must be idempotent at the implementation boundary.
type LeaseClient interface {
	// Every method must honor ctx. Renew and Stop receive a caller-owned
	// idempotency key so an uncertain HTTP result can be retried safely.
	Create(context.Context, LeaseRequest) (Lease, error)
	Renew(context.Context, Lease, string) (Lease, error)
	Stop(context.Context, Lease, string) error
}

// Carrier owns the authenticated data-plane attachment. Run must return when
// ctx is canceled. It may keep the same lease and invoke ready again after an
// edge reconnect, but it must never allocate a replacement endpoint.
type Carrier interface {
	Run(context.Context, Lease, func(Lease) error) error
	Close(context.Context) error
}

// LeaseLifecycleOwnership identifies which process is authoritative for
// renewing and stopping a lease. Foreground carriers own the lifecycle by
// default. The production CLI observer delegates it to stable hostd.
type LeaseLifecycleOwnership uint8

const (
	LeaseLifecycleOwned LeaseLifecycleOwnership = iota
	LeaseLifecycleObserved
)

// LeaseLifecycleCarrier lets a carrier explicitly delegate server lease
// mutations to another process while retaining readiness observation.
type LeaseLifecycleCarrier interface {
	LeaseLifecycleOwnership() LeaseLifecycleOwnership
}

// RetryableCarrierError lets a carrier request a bounded reconnect retry while
// preserving the existing lease and URL. Non-retryable setup errors fail fast.
type RetryableCarrierError struct {
	Err error
}

func (e *RetryableCarrierError) Error() string {
	if e == nil || e.Err == nil {
		return ErrCarrierUnavailable.Error()
	}
	return e.Err.Error()
}

func (e *RetryableCarrierError) Unwrap() error {
	if e == nil || e.Err == nil {
		return ErrCarrierUnavailable
	}
	return e.Err
}

// SessionConfig controls one non-persistent foreground preview. Set
// DisableParentWatch only for an embedding process that supplies an equivalent
// owner lifecycle through OwnerDone.
type SessionConfig struct {
	LeaseClient LeaseClient
	Carrier     Carrier

	OwnerDeviceID      string
	OwnerSessionID     string
	Target             LeaseTarget
	AccessMode         string
	UserDeadline       *time.Time
	Duration           time.Duration
	IdempotencyKey     string
	StopIdempotencyKey string
	OwnerDone          <-chan struct{}

	RenewInterval       time.Duration
	ShutdownTimeout     time.Duration
	ReconnectBackoff    time.Duration
	MaxReconnectBackoff time.Duration
	ParentPollInterval  time.Duration
	DisableParentWatch  bool
	LeaseLifecycle      LeaseLifecycleOwnership
	ParentPID           func() int
	Random              io.Reader
	Now                 func() time.Time
	OnRenew             func(Lease)
}

// Session owns the complete lifetime of one temporary preview lease. It has
// no durable descriptor and therefore has nothing to restore after reboot.
type Session struct {
	config             SessionConfig
	ctx                context.Context
	cancel             context.CancelFunc
	stopIdempotencyKey string

	mu       sync.RWMutex
	lease    Lease
	ready    Lease
	readySet bool
	readyErr error
	result   error

	readyDone chan struct{}
	done      chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeMu   sync.Mutex
	closeErr  error
	stopOnce  sync.Once
	managerMu sync.Mutex
	managers  map[*SessionManager]struct{}
}

// Start creates the server-owned lease, starts carrier and renewal loops, and
// returns before readiness. Call WaitReady before publishing the URL.
func Start(ctx context.Context, config SessionConfig) (*Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrSessionInvalid)
	}
	config, err := prepareSessionConfig(config)
	if err != nil {
		return nil, err
	}

	request := LeaseRequest{
		OwnerDeviceID: config.OwnerDeviceID, OwnerSessionID: config.OwnerSessionID,
		Target: config.Target, AccessMode: config.AccessMode,
		UserDeadline: config.UserDeadline, Duration: config.Duration,
		IdempotencyKey: config.IdempotencyKey,
	}
	if config.Duration > 0 {
		deadline := config.Now().UTC().Add(config.Duration)
		if request.UserDeadline == nil || deadline.Before(request.UserDeadline.UTC()) {
			request.UserDeadline = &deadline
		}
	}
	if request.UserDeadline != nil {
		deadline := request.UserDeadline.UTC()
		request.UserDeadline = &deadline
		config.UserDeadline = &deadline
	}
	lease, err := config.LeaseClient.Create(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := validateSessionLease(lease, config, config.Now()); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
		cleanupErr := stopLease(cleanupCtx, config.LeaseClient, lease, config.StopIdempotencyKey)
		cancel()
		return nil, errors.Join(err, cleanupErr)
	}
	lease.Generation = leaseGenerationForID(lease.ID, lease.ETag)
	return startSession(ctx, config, lease), nil
}

// StartExisting admits a lease that was already created by the control plane.
// It is the only entry point for dashboard-to-device dispatch. In particular,
// it never calls LeaseClient.Create, so a rejected or retried dispatch cannot
// mint a second endpoint.
func StartExisting(ctx context.Context, config SessionConfig, lease Lease) (*Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrSessionInvalid)
	}
	config, err := prepareSessionConfig(config)
	if err != nil {
		return nil, err
	}
	if err := validateSessionLease(lease, config, config.Now()); err != nil {
		return nil, err
	}
	lease.Generation = leaseGenerationForID(lease.ID, lease.ETag)
	return startSession(ctx, config, lease), nil
}

func prepareSessionConfig(config SessionConfig) (SessionConfig, error) {
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	config.OwnerDeviceID = strings.TrimSpace(config.OwnerDeviceID)
	config.OwnerSessionID = strings.TrimSpace(config.OwnerSessionID)
	config.Target.Scheme = strings.ToLower(strings.TrimSpace(config.Target.Scheme))
	config.Target.Address = strings.TrimSpace(config.Target.Address)
	config.IdempotencyKey = strings.TrimSpace(config.IdempotencyKey)
	config.StopIdempotencyKey = strings.TrimSpace(config.StopIdempotencyKey)
	if config.AccessMode == "" {
		config.AccessMode = "public"
	}
	config.AccessMode = strings.ToLower(strings.TrimSpace(config.AccessMode))
	if err := validateSessionConfig(config); err != nil {
		return SessionConfig{}, err
	}
	if config.RenewInterval <= 0 {
		config.RenewInterval = PreviewLeaseDefaultRenewInterval
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = PreviewLeaseDefaultShutdown
	}
	if config.ReconnectBackoff <= 0 {
		config.ReconnectBackoff = PreviewLeaseDefaultReconnect
	}
	if config.MaxReconnectBackoff <= 0 {
		config.MaxReconnectBackoff = PreviewLeaseMaxReconnect
	}
	if config.MaxReconnectBackoff < config.ReconnectBackoff {
		config.MaxReconnectBackoff = config.ReconnectBackoff
	}
	if config.ParentPollInterval <= 0 {
		config.ParentPollInterval = PreviewLeaseParentPoll
	}
	if config.IdempotencyKey == "" {
		key, keyErr := newSessionIdempotencyKey(config.Random)
		if keyErr != nil {
			return SessionConfig{}, fmt.Errorf("%w: generate idempotency key: %v", ErrSessionInvalid, keyErr)
		}
		config.IdempotencyKey = key
	}
	if config.StopIdempotencyKey == "" {
		key, keyErr := newSessionIdempotencyKey(config.Random)
		if keyErr != nil {
			return SessionConfig{}, fmt.Errorf("%w: generate stop idempotency key: %v", ErrSessionInvalid, keyErr)
		}
		config.StopIdempotencyKey = key
	}
	if config.StopIdempotencyKey == config.IdempotencyKey {
		return SessionConfig{}, fmt.Errorf("%w: create and stop idempotency keys must differ", ErrSessionInvalid)
	}
	return config, nil
}

func startSession(ctx context.Context, config SessionConfig, lease Lease) *Session {
	runCtx, cancel := context.WithCancel(ctx)
	session := &Session{
		config: config, ctx: runCtx, cancel: cancel, stopIdempotencyKey: config.StopIdempotencyKey, lease: lease,
		readyDone: make(chan struct{}), done: make(chan struct{}), closeDone: make(chan struct{}), managers: make(map[*SessionManager]struct{}),
	}
	if config.OwnerDone != nil {
		go session.watchOwner(config.OwnerDone)
	}
	if !config.DisableParentWatch {
		parentPID := os.Getppid
		if config.ParentPID != nil {
			parentPID = config.ParentPID
		}
		go session.watchParent(parentPID(), parentPID)
	}
	go session.run()
	return session
}

func validateSessionConfig(config SessionConfig) error {
	if config.LeaseClient == nil || config.Carrier == nil {
		return fmt.Errorf("%w: lease client and carrier are required", ErrSessionInvalid)
	}
	if strings.TrimSpace(config.OwnerDeviceID) == "" || strings.TrimSpace(config.OwnerSessionID) == "" {
		return fmt.Errorf("%w: owner device and session are required", ErrSessionInvalid)
	}
	if err := validateLeaseTarget(config.Target); err != nil {
		return err
	}
	if config.AccessMode != "" && config.AccessMode != "public" && config.AccessMode != "private" {
		return fmt.Errorf("%w: access mode must be public or private", ErrSessionInvalid)
	}
	if config.LeaseLifecycle != LeaseLifecycleOwned && config.LeaseLifecycle != LeaseLifecycleObserved {
		return fmt.Errorf("%w: lease lifecycle ownership is invalid", ErrSessionInvalid)
	}
	if config.Duration < 0 {
		return fmt.Errorf("%w: duration cannot be negative", ErrSessionInvalid)
	}
	if config.UserDeadline != nil && config.UserDeadline.IsZero() {
		return fmt.Errorf("%w: user deadline is invalid", ErrSessionInvalid)
	}
	return nil
}

func validateLeaseTarget(target LeaseTarget) error {
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme != "http" && scheme != "https" && scheme != "h2c" && scheme != "unix" && scheme != "tcp" {
		return fmt.Errorf("%w: target scheme %q is unsupported", ErrSessionInvalid, target.Scheme)
	}
	if strings.TrimSpace(target.Address) == "" || len(target.Address) > 512 || strings.ContainsAny(target.Address, "\r\n") {
		return fmt.Errorf("%w: target address is invalid", ErrSessionInvalid)
	}
	return nil
}

func validateSessionLease(lease Lease, config SessionConfig, now time.Time) error {
	if lease.Schema != PreviewTunnelSchemaV1 || lease.Kind != PreviewLeaseKind || !validLeaseID(lease.ID) || !validLeaseID(lease.AccountID) || !validLeaseID(lease.ActorID) {
		return fmt.Errorf("%w: server returned an invalid lease identity", ErrSessionInvalid)
	}
	if !validLeaseID(lease.OwnerDeviceID) || !validLeaseID(lease.OwnerSessionID) || lease.OwnerDeviceID != config.OwnerDeviceID || lease.OwnerSessionID != config.OwnerSessionID {
		return fmt.Errorf("%w: server returned a lease for a different owner", ErrSessionInvalid)
	}
	if lease.Target != config.Target {
		return fmt.Errorf("%w: server changed the lease target", ErrSessionInvalid)
	}
	if lease.AccessMode != config.AccessMode || lease.Persistent {
		return fmt.Errorf("%w: lease mode or persistence is invalid", ErrSessionInvalid)
	}
	endpoint, err := url.Parse(lease.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawPath != "" && endpoint.RawPath != "/" {
		return fmt.Errorf("%w: server returned an invalid HTTPS endpoint", ErrSessionInvalid)
	}
	if strings.TrimSpace(lease.ETag) == "" {
		return fmt.Errorf("%w: server returned no lease ETag", ErrSessionInvalid)
	}
	if leaseGenerationForID(lease.ID, lease.ETag) < 1 {
		return fmt.Errorf("%w: server returned an invalid lease ETag", ErrSessionInvalid)
	}
	if lease.LeaseDeadline.IsZero() || !lease.LeaseDeadline.After(now.UTC()) {
		return fmt.Errorf("%w: lease deadline has already passed", ErrSessionInvalid)
	}
	if lease.UserDeadline != nil && !lease.UserDeadline.After(now.UTC()) {
		return fmt.Errorf("%w: user deadline has already passed", ErrSessionInvalid)
	}
	if config.UserDeadline != nil {
		if lease.UserDeadline == nil || lease.UserDeadline.After(config.UserDeadline.UTC()) || lease.LeaseDeadline.After(config.UserDeadline.UTC()) {
			return fmt.Errorf("%w: lease exceeds the requested maximum duration", ErrSessionInvalid)
		}
	}
	if !validLeaseState(lease.State) || !validAllocationState(lease.AllocationState) || !validEdgeState(lease.EdgeState) || !validOriginState(lease.OriginState) {
		return fmt.Errorf("%w: server returned an invalid lease state", ErrSessionInvalid)
	}
	return nil
}

func validLeaseState(value string) bool {
	switch value {
	case "allocating", "connecting", "ready", "owner_disconnected", "expired", "stopped":
		return true
	default:
		return false
	}
}

func validLeaseID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validActiveLeaseState(value string) bool {
	return value == "allocating" || value == "connecting" || value == "ready"
}

func validAllocationState(value string) bool {
	switch value {
	case "pending", "ready", "failed", "released":
		return true
	default:
		return false
	}
}

func validEdgeState(value string) bool {
	switch value {
	case "pending", "ready", "degraded", "down":
		return true
	default:
		return false
	}
}

func validOriginState(value string) bool {
	switch value {
	case "unknown", "ready", "unavailable":
		return true
	default:
		return false
	}
}

func (s *Session) run() {
	defer close(s.done)

	renewDone := make(chan error, 1)
	if s.config.LeaseLifecycle == LeaseLifecycleObserved {
		renewDone <- nil
	} else {
		go func() {
			err := s.renewLoop(s.ctx)
			if err != nil {
				s.cancel()
			}
			renewDone <- err
		}()
	}

	carrierErr := s.runCarrier(s.ctx)
	s.cancel()
	renewErr := <-renewDone

	carrierCloseCtx, cancelCarrierClose := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	carrierCloseErr := s.closeCarrier(carrierCloseCtx)
	cancelCarrierClose()
	var leaseStopErr error
	if s.config.LeaseLifecycle == LeaseLifecycleOwned {
		leaseStopCtx, cancelLeaseStop := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		leaseStopErr = stopLease(leaseStopCtx, s.config.LeaseClient, s.currentLease(), s.stopIdempotencyKey)
		cancelLeaseStop()
	}

	primary := carrierErr
	if renewErr != nil {
		primary = errors.Join(primary, renewErr)
	}
	if errors.Is(primary, context.Canceled) {
		primary = nil
	}
	result := errors.Join(primary, carrierCloseErr, leaseStopErr)
	s.mu.Lock()
	s.result = result
	if !s.readySet {
		if result == nil {
			s.readyErr = ErrSessionStopped
		} else {
			s.readyErr = result
		}
	}
	s.mu.Unlock()
	s.readyOnce.Do(func() { close(s.readyDone) })
}

func (s *Session) runCarrier(ctx context.Context) error {
	attempt := 0
	for {
		err := s.runCarrierAttempt(ctx)
		if err == nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrCarrierStopped
		}
		if ctx.Err() != nil {
			return nil
		}
		if !retryableCarrier(err) {
			return err
		}
		if err := waitReconnect(ctx, reconnectDelay(s.config.ReconnectBackoff, s.config.MaxReconnectBackoff, attempt)); err != nil {
			return nil
		}
		attempt++
	}
}

func (s *Session) runCarrierAttempt(ctx context.Context) error {
	result := make(chan error, 1)
	lease := s.currentLease()
	go func() {
		result <- s.config.Carrier.Run(ctx, lease, s.markReady)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retryableCarrier(err error) bool {
	var retryable *RetryableCarrierError
	return errors.As(err, &retryable) || errors.Is(err, ErrCarrierUnavailable)
}

func retryableLeaseError(err error) bool {
	var retryable interface{ Retryable() bool }
	if errors.As(err, &retryable) {
		return retryable.Retryable()
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func reconnectDelay(initial, maximum time.Duration, attempt int) time.Duration {
	delay := initial
	for i := 0; i < attempt && delay < maximum; i++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) renewLoop(ctx context.Context) error {
	attempt := 0
	for {
		lease := s.currentLease()
		expiresAt := lease.LeaseDeadline
		if lease.UserDeadline != nil && lease.UserDeadline.Before(expiresAt) {
			expiresAt = *lease.UserDeadline
		}
		remaining := expiresAt.Sub(s.config.Now().UTC())
		if remaining <= 0 {
			return ErrLeaseExpired
		}
		next := s.config.RenewInterval
		if remaining/2 < next {
			next = remaining / 2
		}
		if next <= 0 {
			return ErrLeaseExpired
		}
		timer := time.NewTimer(next)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}

		if ctx.Err() != nil {
			return nil
		}
		// Readiness and other server observations can advance the lease while
		// this loop is waiting. Renew the latest authoritative generation, not
		// the snapshot captured before the timer started.
		lease = s.currentLease()
		expiresAt = lease.LeaseDeadline
		if lease.UserDeadline != nil && lease.UserDeadline.Before(expiresAt) {
			expiresAt = *lease.UserDeadline
		}
		if !expiresAt.After(s.config.Now().UTC()) {
			return ErrLeaseExpired
		}
		renewIdempotencyKey, keyErr := newSessionIdempotencyKey(s.config.Random)
		if keyErr != nil {
			return fmt.Errorf("%w: generate renew idempotency key: %v", ErrLeaseLost, keyErr)
		}
		for {
			renewCtx, cancelRenew := context.WithDeadline(ctx, expiresAt)
			renewed, err := s.renewLease(renewCtx, lease, renewIdempotencyKey)
			cancelRenew()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if errors.Is(err, context.DeadlineExceeded) && !expiresAt.After(s.config.Now().UTC()) {
					return ErrLeaseExpired
				}
				if !retryableLeaseError(err) {
					return errors.Join(ErrLeaseLost, err)
				}
				remaining = expiresAt.Sub(s.config.Now().UTC())
				if remaining <= 0 {
					return ErrLeaseExpired
				}
				delay := reconnectDelay(s.config.ReconnectBackoff, s.config.MaxReconnectBackoff, attempt)
				if delay > remaining {
					delay = remaining
				}
				if err := waitReconnect(ctx, delay); err != nil {
					return nil
				}
				if !expiresAt.After(s.config.Now().UTC()) {
					return ErrLeaseExpired
				}
				attempt++
				continue
			}
			if err := s.acceptRenewal(renewed, lease); err != nil {
				return errors.Join(ErrLeaseLost, err)
			}
			attempt = 0
			break
		}
	}
}

func (s *Session) renewLease(ctx context.Context, lease Lease, idempotencyKey string) (Lease, error) {
	type result struct {
		lease Lease
		err   error
	}
	completed := make(chan result, 1)
	go func() {
		renewed, err := s.config.LeaseClient.Renew(ctx, lease, idempotencyKey)
		completed <- result{lease: renewed, err: err}
	}()
	select {
	case outcome := <-completed:
		return outcome.lease, outcome.err
	case <-ctx.Done():
		return Lease{}, ctx.Err()
	}
}

func (s *Session) acceptRenewal(renewed, previous Lease) error {
	if renewed.ID != previous.ID || renewed.Endpoint != previous.Endpoint || renewed.OwnerDeviceID != previous.OwnerDeviceID || renewed.OwnerSessionID != previous.OwnerSessionID {
		return fmt.Errorf("%w: renewal changed lease identity, endpoint, or owner", ErrSessionInvalid)
	}
	if !validActiveLeaseState(renewed.State) {
		return fmt.Errorf("%w: server marked the lease %s", ErrLeaseLost, renewed.State)
	}
	previousGeneration := previous.Generation
	if previousGeneration < 1 {
		previousGeneration = leaseGenerationForID(previous.ID, previous.ETag)
	}
	newGeneration := leaseGenerationForID(renewed.ID, renewed.ETag)
	if renewed.ETag == previous.ETag || newGeneration <= previousGeneration {
		return fmt.Errorf("%w: renewal did not advance the lease generation", ErrSessionInvalid)
	}
	if err := validateSessionLease(renewed, s.config, s.config.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	renewed.Generation = newGeneration
	s.lease = renewed
	s.mu.Unlock()
	s.managerMu.Lock()
	managers := make([]*SessionManager, 0, len(s.managers))
	for manager := range s.managers {
		managers = append(managers, manager)
	}
	s.managerMu.Unlock()
	for _, manager := range managers {
		if err := manager.rekey(s, renewed); err != nil {
			s.cancel()
			return fmt.Errorf("%w: manager rejected renewed lease: %v", ErrLeaseLost, err)
		}
	}
	if s.config.OnRenew != nil {
		s.config.OnRenew(renewed)
	}
	return nil
}

func (s *Session) markReady(lease Lease) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	current := s.currentLease()
	if lease.ID != current.ID || lease.Endpoint != current.Endpoint {
		return fmt.Errorf("%w: carrier changed the lease endpoint", ErrSessionInvalid)
	}
	if lease.State != "ready" || lease.AllocationState != "ready" || lease.EdgeState != "ready" || lease.OriginState != "ready" {
		return fmt.Errorf("%w: carrier reported readiness before all dimensions were ready", ErrSessionInvalid)
	}
	if lease.ETag == "" {
		lease.ETag = current.ETag
	}
	lease.Generation = leaseGenerationForID(lease.ID, lease.ETag)
	if err := validateSessionLease(lease, s.config, s.config.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	if s.readySet {
		if s.ready.ID != lease.ID || s.ready.Endpoint != lease.Endpoint {
			s.mu.Unlock()
			return fmt.Errorf("%w: carrier reported a second lease", ErrSessionInvalid)
		}
		if lease.Generation < s.lease.Generation {
			s.mu.Unlock()
			return fmt.Errorf("%w: carrier regressed the lease generation", ErrSessionInvalid)
		}
		if lease.Generation == s.lease.Generation {
			s.mu.Unlock()
			return nil
		}
		s.lease = lease
		s.ready = lease
		s.mu.Unlock()
		return s.rekeyManagers(lease)
	}
	s.ready = lease
	// Readiness is a server mutation and therefore advances the strong ETag.
	// Adopt that authoritative lease before the next renewal; otherwise the
	// renewal loop would send the pre-ready generation and falsely lose a live
	// lease.
	s.lease = lease
	s.readySet = true
	s.mu.Unlock()

	if err := s.rekeyManagers(lease); err != nil {
		return err
	}
	s.readyOnce.Do(func() { close(s.readyDone) })
	return nil
}

func (s *Session) rekeyManagers(lease Lease) error {

	s.managerMu.Lock()
	managers := make([]*SessionManager, 0, len(s.managers))
	for manager := range s.managers {
		managers = append(managers, manager)
	}
	s.managerMu.Unlock()
	for _, manager := range managers {
		if err := manager.rekey(s, lease); err != nil {
			s.cancel()
			return fmt.Errorf("%w: manager rejected ready lease: %v", ErrLeaseLost, err)
		}
	}
	return nil
}

func (s *Session) watchOwner(ownerDone <-chan struct{}) {
	select {
	case <-ownerDone:
		s.cancel()
	case <-s.ctx.Done():
	}
}

func (s *Session) watchParent(parentPID int, currentParentPID func() int) {
	if parentPID <= 1 {
		return
	}
	if currentParentPID == nil {
		currentParentPID = os.Getppid
	}
	ticker := time.NewTicker(s.config.ParentPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if currentParentPID() != parentPID {
				s.cancel()
				return
			}
		}
	}
}

func (s *Session) closeCarrier(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.closeOnce.Do(func() {
		go func() {
			err := s.config.Carrier.Close(ctx)
			s.closeMu.Lock()
			s.closeErr = err
			s.closeMu.Unlock()
			close(s.closeDone)
		}()
	})
	select {
	case <-s.closeDone:
		s.closeMu.Lock()
		err := s.closeErr
		s.closeMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func stopLease(ctx context.Context, client LeaseClient, lease Lease, idempotencyKey string) error {
	completed := make(chan error, 1)
	go func() {
		completed <- client.Stop(ctx, lease, idempotencyKey)
	}()
	select {
	case err := <-completed:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) currentLease() Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lease
}

// Key returns the current manager identity. The generation is derived from
// the strong canonical ETag and changes on every successful renewal.
func (s *Session) Key() SessionKey {
	lease := s.currentLease()
	return SessionKey{LeaseID: lease.ID, OwnerSessionID: lease.OwnerSessionID, Generation: lease.Generation}
}

func (s *Session) attachManager(manager *SessionManager) {
	s.managerMu.Lock()
	s.managers[manager] = struct{}{}
	s.managerMu.Unlock()
}

func (s *Session) detachManager(manager *SessionManager) {
	s.managerMu.Lock()
	delete(s.managers, manager)
	s.managerMu.Unlock()
}

// WaitReady returns the lease only after all readiness dimensions have been
// confirmed by the carrier. This is the only URL publication boundary.
func (s *Session) WaitReady(ctx context.Context) (Lease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.readyDone:
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.readySet {
			return s.ready, nil
		}
		if s.readyErr != nil {
			return Lease{}, s.readyErr
		}
		return Lease{}, ErrSessionStopped
	case <-ctx.Done():
		return Lease{}, ctx.Err()
	}
}

// URL exposes no endpoint before readiness. A reconnect never changes the
// returned value while the owner lease remains valid.
func (s *Session) URL() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.readySet {
		return "", false
	}
	return s.ready.Endpoint, true
}

// Wait blocks until carrier and lease cleanup complete.
func (s *Session) Wait() error {
	<-s.done
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.result
}

// Stop cancels owner work and waits for bounded carrier and lease cleanup.
func (s *Session) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.stopOnce.Do(func() {
		s.cancel()
	})
	select {
	case <-s.done:
		return s.Wait()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newSessionIdempotencyKey(source io.Reader) (string, error) {
	if source == nil {
		source = cryptorand.Reader
	}
	var value [18]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", err
	}
	return "preview_" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func leaseGenerationForID(id, etag string) int64 {
	value := strings.TrimSpace(etag)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0
	}
	parts := strings.Split(strings.Trim(value, `"`), ":")
	if len(parts) != 4 || parts[0] != "ptv1" || parts[1] != PreviewLeaseKind {
		return 0
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || string(decoded) != id || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] {
		return 0
	}
	generation, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || generation < 1 {
		return 0
	}
	return generation
}

func formatLeaseETag(id string, generation int64) string {
	return fmt.Sprintf(`"ptv1:%s:%s:%d"`, PreviewLeaseKind, base64.RawURLEncoding.EncodeToString([]byte(id)), generation)
}
