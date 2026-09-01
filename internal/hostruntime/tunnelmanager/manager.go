// Package tunnelmanager owns durable tunnel reconciliation for the stable
// Paperboat host daemon. Preview leases are intentionally outside this package.
package tunnelmanager

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

var (
	ErrInvalidConfig        = errors.New("invalid tunnel manager configuration")
	ErrNotStarted           = errors.New("tunnel manager not started")
	ErrAlreadyStarted       = errors.New("tunnel manager already started")
	ErrGenerationConflict   = errors.New("tunnel generation conflict")
	ErrConnectorUnavailable = errors.New("tunnel connector unavailable")
	ErrOriginUnavailable    = errors.New("tunnel origin unavailable")
)

type networkGenerationContextKey struct{}

// networkGenerationContext identifies a pure network reattachment. Network
// generations are deliberately separate from config generations and are
// scoped to one durable tunnel so an event for one tunnel cannot fence an
// unrelated tunnel's replacement.
type networkGenerationContext struct {
	TunnelID   string
	Generation uint64
}

type networkRecoveryState struct {
	Observed uint64
	Applied  uint64
	InFlight uint64
}

const (
	CodeReady                = "ready"
	CodeReattached           = "reattached"
	CodeNetworkReattached    = "network_reattached"
	CodeOriginUnavailable    = "origin_unavailable"
	CodeControlUnavailable   = "control_unavailable"
	CodeConnectorUnavailable = "connector_unavailable"
	CodeApplyFailed          = "apply_failed"
	CodePersistenceConflict  = "persistence_conflict"
	CodePaused               = "paused"
	CodeStopped              = "stopped"
)

type StateStore interface {
	Snapshot() (hoststate.State, uint64, error)
	Commit(expectedRevision uint64, next hoststate.State) (uint64, error)
}

// Factory stages a connector/runtime generation without changing active
// traffic. The exact durable tunnel and connector identities are supplied on
// every call so a restart cannot allocate replacements implicitly.
type Factory interface {
	Prepare(context.Context, ApplyRequest) (Candidate, error)
}

type ApplyRequest struct {
	Tunnel    hoststate.Tunnel
	Connector hoststate.Connector
	Snapshot  hoststate.ConfigSnapshot
	Decoded   hoststate.TunnelConfigSnapshot
	Recovery  bool
}

type ProbeResult struct {
	Ready         bool
	FailureCode   string
	HealthyRoutes []string
	FailedRoutes  []string
}

// Candidate is fully isolated from the active generation until Activate.
// ProbeOrigins must be safe and non-mutating. Activate makes the prepared
// generation eligible while retaining the prior Active until the manager
// commits durable LKG state and explicitly drains it.
type Candidate interface {
	ProbeOrigins(context.Context) (ProbeResult, error)
	Activate(context.Context) (Active, error)
	Abort(context.Context) error
}

type Active interface {
	TunnelID() string
	ConnectorID() string
	Generation() uint64
	ContentHash() string
	Drain(context.Context) error
	Close(context.Context) error
}

// ActiveCarrierProvider exposes the authenticated data-carrier handle owned by
// one active runtime. It is intentionally optional so test and non-network
// candidates do not need to depend on connector transport details.
type ActiveCarrierProvider interface {
	ActiveDataCarrier() *connector.ActiveDataCarrier
}

// ActiveChange is emitted after the manager publishes a new active runtime or
// removes one. Previous and Current are immutable handles for the callback;
// the manager remains their lifecycle owner. A callback must not retain either
// handle after it receives a subsequent change without its own fencing.
type ActiveChange struct {
	TunnelID string
	Previous Active
	Current  Active
}

type Observation struct {
	TunnelID          string
	ConnectorID       string
	DesiredGeneration uint64
	AppliedGeneration uint64
	Code              string
	Retryable         bool
	NextRetryAt       time.Time
	ObservedAt        time.Time
	Err               error
}

type Config struct {
	Store   StateStore
	Factory Factory
	HostID  string
	// Refresh asks the control client to place newer authoritative desired
	// state in Store. A transient failure never removes cached desired/LKG.
	Refresh           func(context.Context) error
	Clock             func() time.Time
	ReconcileInterval time.Duration
	ApplyTimeout      time.Duration
	DrainTimeout      time.Duration
	// Report must return promptly. It runs on the serialized reconciliation
	// path so observation order matches durable generation order.
	Report         func(Observation)
	ActiveObserver func(ActiveChange)
}

type Manager struct {
	config Config

	lifecycleMu  sync.Mutex
	activationMu sync.Mutex
	opMu         sync.Mutex
	mu           sync.RWMutex
	ctx          context.Context
	stop         context.CancelFunc
	done         chan struct{}

	started bool
	closed  bool
	active  map[string]Active
	seen    map[string]uint64
	wake    chan struct{}
	// networkGeneration is the highest host-wide event observed for legacy
	// callers. networkStates is the authoritative per-tunnel fence. Keeping the
	// host-wide watermark preserves the old monitor API while allowing each
	// durable tunnel to apply the same event independently.
	networkGeneration uint64
	networkStates     map[string]networkRecoveryState

	shutdownDone chan struct{}
	shutdownErr  error
}

func New(config Config) (*Manager, error) {
	if config.Store == nil || config.Factory == nil || !validID(config.HostID) || config.Report == nil {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.ReconcileInterval == 0 {
		config.ReconcileInterval = 5 * time.Second
	}
	if config.ApplyTimeout == 0 {
		config.ApplyTimeout = 30 * time.Second
	}
	if config.DrainTimeout == 0 {
		config.DrainTimeout = 15 * time.Second
	}
	if config.ReconcileInterval <= 0 || config.ApplyTimeout <= 0 || config.DrainTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	return &Manager{config: config, active: make(map[string]Active), seen: make(map[string]uint64), networkStates: make(map[string]networkRecoveryState), wake: make(chan struct{}, 1)}, nil
}

// Start performs synchronous crash recovery before starting the reconciliation
// loop. A corrupt/unreadable durable store is fatal; per-tunnel origin or edge
// failures are reported and retried without discarding an existing LKG.
func (m *Manager) Start(ctx context.Context) error {
	return m.start(ctx, true)
}

// StartDeferred starts the manager lifecycle and reconciliation loop without
// running the initial reconciliation inline. It is for compositions whose
// inputs are established by another concurrently starting protocol, such as a
// connector control stream that must deliver Welcome before a carrier can be
// prepared. The caller must arrange a Notify after that protocol is ready.
// Ordinary users should call Start so crash recovery remains synchronous.
func (m *Manager) StartDeferred(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.start(ctx, false)
}

func (m *Manager) start(ctx context.Context, reconcile bool) error {
	if m == nil || ctx == nil {
		return ErrInvalidConfig
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ErrAlreadyStarted
	}
	if m.closed {
		m.mu.Unlock()
		return ErrNotStarted
	}
	m.ctx, m.stop = context.WithCancel(context.Background())
	m.done = make(chan struct{})
	m.started = true
	m.mu.Unlock()
	if reconcile {
		if err := m.ReconcileNow(ctx); err != nil {
			m.mu.Lock()
			m.stop()
			close(m.done)
			m.mu.Unlock()
			m.opMu.Lock()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), m.config.DrainTimeout)
			cleanupErr := m.closeAll(cleanupCtx)
			cancel()
			m.opMu.Unlock()
			m.mu.Lock()
			m.started = false
			m.mu.Unlock()
			return errors.Join(err, cleanupErr)
		}
	}
	go m.run()
	return nil
}

func (m *Manager) run() {
	defer close(m.done)
	ticker := time.NewTicker(m.config.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		ctx, cancel := context.WithTimeout(m.ctx, m.config.ApplyTimeout)
		_ = m.ReconcileNow(ctx)
		cancel()
	}
}

// Notify coalesces desired-state changes and never blocks the protocol reader.
func (m *Manager) Notify() {
	if m == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) ReconcileNow(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrInvalidConfig
	}
	m.mu.RLock()
	started := m.started && !m.closed
	m.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	managerCtx := m.ctx
	m.mu.RUnlock()
	linkedCtx, cancel := context.WithCancel(ctx)
	stopLink := context.AfterFunc(managerCtx, cancel)
	defer func() {
		stopLink()
		cancel()
	}()
	ctx = linkedCtx
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.RLock()
	started = m.started && !m.closed
	m.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	var refreshErr error
	if m.config.Refresh != nil {
		refreshErr = m.config.Refresh(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	state, _, err := m.config.Store.Snapshot()
	if err != nil {
		return err
	}
	tunnels := append([]hoststate.Tunnel(nil), state.Tunnels...)
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
	wanted := make(map[string]struct{}, len(tunnels))
	for _, tunnel := range tunnels {
		wanted[tunnel.ID] = struct{}{}
		if refreshErr != nil {
			m.report(tunnel, hoststate.Connector{}, CodeControlUnavailable, true, refreshErr)
		}
		connector, connectorErr := localConnector(state.Connectors, tunnel.ID, m.config.HostID)
		if connectorErr != nil {
			m.report(tunnel, hoststate.Connector{}, CodeConnectorUnavailable, true, connectorErr)
			continue
		}
		if err := m.reconcileTunnel(ctx, tunnel, connector); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Runtime, origin, and generation failures are already reported for
			// this tunnel. Untyped failures are global and must not be swallowed.
			if !errors.Is(err, ErrOriginUnavailable) && !errors.Is(err, ErrConnectorUnavailable) && !errors.Is(err, ErrGenerationConflict) {
				return err
			}
		}
	}
	for tunnelID, active := range m.snapshotActive() {
		if _, ok := wanted[tunnelID]; ok {
			continue
		}
		m.removeAndDrain(ctx, tunnelID, active)
		m.config.Report(Observation{TunnelID: tunnelID, ConnectorID: active.ConnectorID(), AppliedGeneration: active.Generation(), Code: CodeStopped, ObservedAt: m.now()})
	}
	return nil
}

func (m *Manager) reconcileTunnel(ctx context.Context, tunnel hoststate.Tunnel, connector hoststate.Connector) error {
	decoded, err := hoststate.ParseTunnelConfigSnapshot(tunnel.DesiredSnapshot.Payload, tunnel.ID, tunnel.DesiredGeneration)
	if err != nil || decoded.DesiredState != tunnel.DesiredState {
		if err == nil {
			err = ErrGenerationConflict
		}
		m.report(tunnel, connector, CodeApplyFailed, false, err)
		return err
	}
	if !m.acceptGeneration(tunnel.ID, tunnel.DesiredGeneration) {
		m.report(tunnel, connector, CodeApplyFailed, false, ErrGenerationConflict)
		return ErrGenerationConflict
	}
	if tunnel.DesiredState == "paused" {
		return m.pause(ctx, tunnel, connector)
	}
	current := m.activeFor(tunnel.ID)
	if current != nil && current.Generation() > tunnel.DesiredGeneration {
		m.report(tunnel, connector, CodeApplyFailed, false, ErrGenerationConflict)
		return ErrGenerationConflict
	}
	if current != nil && current.ConnectorID() == connector.ID && current.Generation() == tunnel.DesiredGeneration && current.ContentHash() == tunnel.DesiredSnapshot.ContentHash {
		return nil
	}
	if current == nil && tunnel.LastKnownGood != nil {
		lkg, err := hoststate.ParseTunnelConfigSnapshot(tunnel.LastKnownGood.Payload, tunnel.ID, tunnel.LastKnownGood.Generation)
		if err != nil {
			m.report(tunnel, connector, CodeApplyFailed, false, err)
			return err
		}
		// A paused LKG is durable evidence that traffic was intentionally
		// disabled. It must never be reattached during restart recovery.
		if lkg.DesiredState == "active" {
			if err := m.apply(ctx, tunnel, connector, *tunnel.LastKnownGood, true, false); err != nil {
				return err
			}
		}
		if lkg.DesiredState != "active" && lkg.DesiredState != "paused" {
			return ErrGenerationConflict
		}
		if lkg.DesiredState == "active" {
			current = m.activeFor(tunnel.ID)
		}
	}
	if current != nil && current.ConnectorID() == connector.ID && current.Generation() == tunnel.DesiredGeneration && current.ContentHash() == tunnel.DesiredSnapshot.ContentHash {
		return nil
	}
	return m.apply(ctx, tunnel, connector, tunnel.DesiredSnapshot, false, true)
}

func (m *Manager) pause(ctx context.Context, tunnel hoststate.Tunnel, connector hoststate.Connector) error {
	changed := false
	if current := m.activeFor(tunnel.ID); current != nil {
		m.removeAndDrain(ctx, tunnel.ID, current)
		changed = true
	}
	if tunnel.AppliedGeneration != tunnel.DesiredGeneration || tunnel.LastKnownGood == nil || tunnel.LastKnownGood.ContentHash != tunnel.DesiredSnapshot.ContentHash {
		if err := m.promote(ctx, tunnel, tunnel.DesiredSnapshot, connector); err != nil {
			m.report(tunnel, connector, CodePersistenceConflict, true, err)
			return err
		}
		changed = true
	}
	if changed {
		m.report(tunnel, connector, CodePaused, false, nil)
	}
	return nil
}

func (m *Manager) apply(ctx context.Context, tunnel hoststate.Tunnel, connector hoststate.Connector, snapshot hoststate.ConfigSnapshot, recovery, promote bool) error {
	decoded, err := hoststate.ParseTunnelConfigSnapshot(snapshot.Payload, tunnel.ID, snapshot.Generation)
	if err != nil {
		m.report(tunnel, connector, CodeApplyFailed, false, err)
		return err
	}
	candidate, err := m.config.Factory.Prepare(ctx, ApplyRequest{Tunnel: tunnel, Connector: connector, Snapshot: snapshot, Decoded: decoded, Recovery: recovery})
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, ErrConnectorUnavailable):
			m.report(tunnel, connector, CodeConnectorUnavailable, true, err)
		case errors.Is(err, ErrGenerationConflict):
			m.report(tunnel, connector, CodeApplyFailed, false, err)
		default:
			m.report(tunnel, connector, CodeApplyFailed, false, err)
		}
		return err
	}
	if candidate == nil {
		err = ErrConnectorUnavailable
		m.report(tunnel, connector, CodeConnectorUnavailable, true, err)
		return err
	}
	abort := func() {
		abortCtx, cancel := context.WithTimeout(context.Background(), m.config.DrainTimeout)
		defer cancel()
		_ = candidate.Abort(abortCtx)
	}
	probe, err := candidate.ProbeOrigins(ctx)
	if ctx.Err() != nil {
		abort()
		return ctx.Err()
	}
	if err != nil || !probe.Ready {
		if recovery {
			// A previously applied generation may reattach while the local
			// origin is down. This preserves endpoint and carrier identity while
			// accurately reporting degraded origin health.
			m.report(tunnel, connector, CodeOriginUnavailable, true, errors.Join(ErrOriginUnavailable, err))
		} else {
			abort()
			m.report(tunnel, connector, CodeOriginUnavailable, true, errors.Join(ErrOriginUnavailable, err))
			return errors.Join(ErrOriginUnavailable, err)
		}
	}
	// Shutdown cancels the manager context before waiting for this gate. Once
	// the gate is held, activation and optional durable promotion are one
	// lifecycle-linearized unit and cannot begin after stopped state publishes.
	m.activationMu.Lock()
	m.mu.RLock()
	running := m.started && !m.closed
	m.mu.RUnlock()
	if !running || ctx.Err() != nil {
		m.activationMu.Unlock()
		abort()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrNotStarted
	}
	active, err := candidate.Activate(ctx)
	if err != nil || active == nil || active.TunnelID() != tunnel.ID || active.ConnectorID() != connector.ID || active.Generation() != snapshot.Generation || active.ContentHash() != snapshot.ContentHash {
		m.activationMu.Unlock()
		if active != nil {
			_ = m.closeActive(context.Background(), active)
		}
		abort()
		if err == nil {
			err = ErrGenerationConflict
		}
		m.report(tunnel, connector, CodeApplyFailed, true, err)
		return err
	}
	if err := ctx.Err(); err != nil {
		m.activationMu.Unlock()
		_ = m.closeActive(context.Background(), active)
		return err
	}
	if expected, ok := ctx.Value(networkGenerationContextKey{}).(networkGenerationContext); ok && !m.networkGenerationCurrent(expected.TunnelID, expected.Generation) {
		m.activationMu.Unlock()
		_ = m.closeActive(context.Background(), active)
		return ErrGenerationConflict
	}
	if promote {
		if err := m.promote(ctx, tunnel, snapshot, connector); err != nil {
			m.activationMu.Unlock()
			_ = m.closeActive(context.Background(), active)
			m.report(tunnel, connector, CodePersistenceConflict, true, err)
			return err
		}
	}
	m.activationMu.Unlock()
	old, ok, swapErr := m.swapActiveIfRunning(tunnel.ID, active, ctx)
	if !ok {
		_ = m.closeActive(context.Background(), active)
		if swapErr != nil {
			return swapErr
		}
		return ErrNotStarted
	}
	if old != nil && old != active {
		m.drain(ctx, old)
		_ = m.closeActive(context.Background(), old)
	}
	code := CodeReady
	if recovery {
		code = CodeReattached
	} else if _, ok := ctx.Value(networkGenerationContextKey{}).(networkGenerationContext); ok {
		code = CodeNetworkReattached
	}
	m.report(tunnel, connector, code, false, nil)
	return nil
}

func (m *Manager) promote(ctx context.Context, expectedTunnel hoststate.Tunnel, snapshot hoststate.ConfigSnapshot, expectedConnector hoststate.Connector) error {
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, revision, err := m.config.Store.Snapshot()
		if err != nil {
			return err
		}
		found := false
		for index := range state.Tunnels {
			tunnel := &state.Tunnels[index]
			if tunnel.ID != snapshot.TunnelID {
				continue
			}
			found = true
			if tunnel.StableEndpointID != expectedTunnel.StableEndpointID || tunnel.DesiredState != expectedTunnel.DesiredState || tunnel.DesiredGeneration != snapshot.Generation || tunnel.DesiredSnapshot.ContentHash != snapshot.ContentHash {
				return ErrGenerationConflict
			}
			lkg := snapshot
			tunnel.AppliedGeneration = snapshot.Generation
			tunnel.LastKnownGood = &lkg
			tunnel.UpdatedAt = m.now()
		}
		if !found {
			return ErrGenerationConflict
		}
		connectorFound := false
		for index := range state.Connectors {
			if state.Connectors[index].ID == expectedConnector.ID && state.Connectors[index].TunnelID == snapshot.TunnelID && state.Connectors[index].HostID == expectedConnector.HostID {
				connectorFound = true
				state.Connectors[index].LastAppliedGeneration = snapshot.Generation
			}
		}
		if !connectorFound {
			return ErrGenerationConflict
		}
		// A crash-safe local commit is intentionally non-cancelable once its
		// fsync/rename sequence begins. Cancellation observed after it commits
		// prevents runtime publication; restart/reconcile safely reattaches the
		// newly durable LKG instead of attempting an unsafe rollback.
		if _, err := m.config.Store.Commit(revision, state); err == nil {
			return ctx.Err()
		} else if !errors.Is(err, hoststate.ErrConflict) {
			return err
		}
	}
	return ErrGenerationConflict
}

func (m *Manager) Shutdown(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrInvalidConfig
	}
	m.lifecycleMu.Lock()
	m.mu.Lock()
	shutdownDone := m.shutdownDone
	initiated := false
	if shutdownDone == nil && !m.started {
		m.mu.Unlock()
		m.lifecycleMu.Unlock()
		return nil
	}
	if shutdownDone == nil {
		stop, runDone := m.stop, m.done
		shutdownDone = make(chan struct{})
		m.shutdownDone = shutdownDone
		initiated = true
		m.mu.Unlock()
		stop()
		go m.finishShutdown(runDone, shutdownDone)
	} else {
		m.mu.Unlock()
	}
	m.lifecycleMu.Unlock()
	select {
	case <-shutdownDone:
		m.mu.RLock()
		err := m.shutdownErr
		m.mu.RUnlock()
		if err == nil {
			return nil
		}
		if initiated {
			return err
		}
		return m.retryShutdown(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) retryShutdown(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.opMu.Lock()
	err := m.closeAll(ctx)
	m.opMu.Unlock()
	m.mu.Lock()
	m.shutdownErr = err
	m.mu.Unlock()
	return err
}

func (m *Manager) finishShutdown(runDone, shutdownDone chan struct{}) {
	m.activationMu.Lock()
	m.mu.Lock()
	m.started = false
	m.closed = true
	m.mu.Unlock()
	m.activationMu.Unlock()
	<-runDone
	m.opMu.Lock()
	err := m.closeAll(context.Background())
	m.opMu.Unlock()
	m.mu.Lock()
	m.shutdownErr = err
	close(shutdownDone)
	m.mu.Unlock()
}

func (m *Manager) ResourceCounts() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]uint64{"tunnels": uint64(len(m.active))}
}

// WorkloadIdentities supplies stable identity and generation fencing to hostd.
// Counts alone cannot distinguish one tunnel being replaced by another.
func (m *Manager) WorkloadIdentities() []string {
	if m == nil {
		return nil
	}
	active := m.snapshotActive()
	result := make([]string, 0, len(active))
	for _, value := range active {
		result = append(result, fmt.Sprintf("%s\x00%s\x00%d\x00%s", value.TunnelID(), value.ConnectorID(), value.Generation(), value.ContentHash()))
	}
	sort.Strings(result)
	return result
}

func (m *Manager) activeFor(tunnelID string) Active {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active[tunnelID]
}

// ActiveForTunnel returns the exact currently published runtime. The boolean
// distinguishes an absent tunnel from a nil handle and allows adapters to
// apply generation fencing before attaching route-specific consumers.
func (m *Manager) ActiveForTunnel(tunnelID string) (Active, bool) {
	if m == nil || tunnelID == "" {
		return nil, false
	}
	m.mu.RLock()
	active, ok := m.active[tunnelID]
	m.mu.RUnlock()
	return active, ok && active != nil
}

// ActiveSnapshot returns a point-in-time copy of the manager's published
// runtimes. The returned map is owned by the caller.
func (m *Manager) ActiveSnapshot() map[string]Active {
	if m == nil {
		return nil
	}
	return m.snapshotActive()
}

func (m *Manager) snapshotActive() map[string]Active {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]Active, len(m.active))
	for key, value := range m.active {
		result[key] = value
	}
	return result
}

func (m *Manager) swapActiveIfRunning(tunnelID string, active Active, ctx context.Context) (Active, bool, error) {
	m.mu.Lock()
	if !m.started || m.closed {
		m.mu.Unlock()
		return nil, false, nil
	}
	if expected, ok := ctx.Value(networkGenerationContextKey{}).(networkGenerationContext); ok {
		if expected.TunnelID != tunnelID || !m.networkGenerationCurrentLocked(expected.TunnelID, expected.Generation) {
			m.mu.Unlock()
			return nil, false, ErrGenerationConflict
		}
		state := m.networkStates[expected.TunnelID]
		if state.InFlight != expected.Generation || state.Applied >= expected.Generation {
			m.mu.Unlock()
			return nil, false, ErrGenerationConflict
		}
	}
	old := m.active[tunnelID]
	m.active[tunnelID] = active
	if expected, ok := ctx.Value(networkGenerationContextKey{}).(networkGenerationContext); ok {
		state := m.networkStates[expected.TunnelID]
		// Mark the network generation only after the active pointer has been
		// published under the same lock. A retry after an ambiguous response can
		// therefore return this exact active without staging another carrier.
		state.Applied = expected.Generation
		state.InFlight = 0
		m.networkStates[expected.TunnelID] = state
	}
	observer := m.config.ActiveObserver
	m.mu.Unlock()
	if observer != nil {
		observer(ActiveChange{TunnelID: tunnelID, Previous: old, Current: active})
	}
	return old, true, nil
}

func (m *Manager) acceptGeneration(tunnelID string, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if previous := m.seen[tunnelID]; previous > generation {
		return false
	}
	if generation > m.seen[tunnelID] {
		m.seen[tunnelID] = generation
	}
	return true
}

func (m *Manager) removeAndDrain(ctx context.Context, tunnelID string, active Active) {
	m.mu.Lock()
	removed := m.active[tunnelID] == active
	if removed {
		delete(m.active, tunnelID)
	}
	observer := m.config.ActiveObserver
	m.mu.Unlock()
	if removed && observer != nil {
		observer(ActiveChange{TunnelID: tunnelID, Previous: active})
	}
	m.drain(ctx, active)
	_ = m.closeActive(context.Background(), active)
}

func (m *Manager) closeAll(ctx context.Context) error {
	var joined error
	for tunnelID, active := range m.snapshotActive() {
		m.drain(ctx, active)
		if err := m.closeActive(ctx, active); err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		m.mu.Lock()
		removed := m.active[tunnelID] == active
		if removed {
			delete(m.active, tunnelID)
		}
		observer := m.config.ActiveObserver
		m.mu.Unlock()
		if removed && observer != nil {
			observer(ActiveChange{TunnelID: tunnelID, Previous: active})
		}
	}
	return joined
}

func (m *Manager) closeActive(parent context.Context, active Active) error {
	ctx, cancel := context.WithTimeout(parent, m.config.DrainTimeout)
	defer cancel()
	return active.Close(ctx)
}

func (m *Manager) drain(parent context.Context, active Active) {
	ctx, cancel := context.WithTimeout(parent, m.config.DrainTimeout)
	defer cancel()
	_ = active.Drain(ctx)
}

func (m *Manager) report(tunnel hoststate.Tunnel, connector hoststate.Connector, code string, retryable bool, err error) {
	now := m.now()
	observation := Observation{TunnelID: tunnel.ID, ConnectorID: connector.ID, DesiredGeneration: tunnel.DesiredGeneration, AppliedGeneration: tunnel.AppliedGeneration, Code: code, Retryable: retryable, ObservedAt: now, Err: err}
	if retryable {
		observation.NextRetryAt = now.Add(m.config.ReconcileInterval)
	}
	m.config.Report(observation)
}

func (m *Manager) now() time.Time { return m.config.Clock().UTC() }

func localConnector(connectors []hoststate.Connector, tunnelID, hostID string) (hoststate.Connector, error) {
	var found hoststate.Connector
	for _, connector := range connectors {
		if connector.TunnelID != tunnelID || connector.HostID != hostID {
			continue
		}
		if found.ID != "" {
			return hoststate.Connector{}, fmt.Errorf("%w: duplicate connector identity", ErrConnectorUnavailable)
		}
		found = connector
	}
	if found.ID == "" {
		return hoststate.Connector{}, ErrConnectorUnavailable
	}
	return found, nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if index == 0 && !isAlphaNumeric(char) || index > 0 && !isAlphaNumeric(char) && char != '.' && char != '_' && char != ':' && char != '-' {
			return false
		}
	}
	return true
}

func isAlphaNumeric(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}
