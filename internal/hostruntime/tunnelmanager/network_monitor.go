package tunnelmanager

import (
	"context"
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

// NetworkRecoveryReplacerFactory resolves the authenticated, session-bound
// carrier replacer for one durable connector. The factory may refresh session
// identity or credentials, but it must never derive reusable credential bytes
// from host state. Returning an error leaves the existing active/LKG carrier
// untouched and is projected through the coordinator's health snapshot.
type NetworkRecoveryReplacerFactory func(context.Context, hoststate.Tunnel, hoststate.Connector) (networkrecovery.Identity, networkrecovery.CarrierReplacer, error)

// NetworkRecoveryCoordinator fans one typed monitor event to every currently
// active durable tunnel. Each tunnel gets one controller and one independent
// generation fence, so a replacement for one connector cannot block or
// invalidate another connector's same-generation replacement.
type NetworkRecoveryCoordinator struct {
	manager *Manager
	factory NetworkRecoveryReplacerFactory

	mu          sync.Mutex
	controllers map[string]*networkrecovery.Controller
	ctx         context.Context
	cancel      context.CancelFunc
	processMu   sync.Mutex
	wake        chan struct{}
	pending     *networkmonitor.Event
	workerDone  chan struct{}
	started     bool
	stopped     bool
}

type NetworkRecoveryCoordinatorConfig struct {
	Manager *Manager
	Factory NetworkRecoveryReplacerFactory
}

var (
	ErrNetworkRecoveryNotStarted = errors.New("network recovery coordinator not started")
	ErrNetworkRecoveryStopped    = errors.New("network recovery coordinator stopped")
)

func NewNetworkRecoveryCoordinator(config NetworkRecoveryCoordinatorConfig) (*NetworkRecoveryCoordinator, error) {
	if config.Manager == nil || config.Factory == nil {
		return nil, ErrInvalidConfig
	}
	return &NetworkRecoveryCoordinator{manager: config.Manager, factory: config.Factory, controllers: make(map[string]*networkrecovery.Controller)}, nil
}

func (c *NetworkRecoveryCoordinator) Start(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidConfig
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.stopped {
		return ErrNetworkRecoveryStopped
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.wake = make(chan struct{}, 1)
	c.workerDone = make(chan struct{})
	c.started = true
	go c.run(c.ctx, c.wake, c.workerDone)
	return nil
}

func (c *NetworkRecoveryCoordinator) run(ctx context.Context, wake <-chan struct{}, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			c.processMu.Lock()
			event, ok := c.takePending()
			if ok {
				c.processNetworkEvent(ctx, event)
			}
			c.processMu.Unlock()
		}
	}
}

// HandleNetworkEvent is the runtime adapter called by networkmonitor. It only
// queues debounced observations; a bounded coalescing worker performs the
// store snapshot and controller setup away from the netmon callback. The
// per-tunnel controllers own retry, cancellation, and stable-ready reset. No
// network endpoint or credential is copied into the event.
func (c *NetworkRecoveryCoordinator) HandleNetworkEvent(event networkmonitor.Event) {
	if c == nil || event.Generation == 0 {
		return
	}
	reasons := networkRecoveryReasons(event.Reasons)
	if reasons == 0 {
		return
	}
	c.mu.Lock()
	if !c.started || c.stopped || c.ctx == nil {
		c.mu.Unlock()
		return
	}
	if c.pending == nil || event.Generation > c.pending.Generation {
		copyEvent := event
		c.pending = &copyEvent
	} else if event.Generation == c.pending.Generation {
		c.pending.Reasons |= event.Reasons
		c.pending.Rebind = c.pending.Rebind || event.Rebind
		c.pending.Viable = event.Viable
	}
	wake := c.wake
	c.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (c *NetworkRecoveryCoordinator) takePending() (networkmonitor.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return networkmonitor.Event{}, false
	}
	event := *c.pending
	c.pending = nil
	return event, true
}

func (c *NetworkRecoveryCoordinator) processNetworkEvent(ctx context.Context, event networkmonitor.Event) {
	if ctx == nil || ctx.Err() != nil {
		return
	}
	durable, _, err := c.manager.config.Store.Snapshot()
	if err != nil {
		return
	}
	active := c.manager.ActiveSnapshot()
	reasons := networkRecoveryReasons(event.Reasons)
	for tunnelID, activeCarrier := range active {
		if activeCarrier == nil {
			continue
		}
		tunnel, connector, ok := c.activeBinding(durable, tunnelID, activeCarrier)
		if !ok {
			continue
		}
		// Record the observation before the controller can stage. This is the
		// manager-side atomic fence for an event that races replacement.
		if !c.manager.observeNetworkGenerationForTunnel(tunnelID, event.Generation) {
			continue
		}
		controller, err := c.controller(ctx, tunnel, connector)
		if err != nil {
			c.manager.report(tunnel, connector, CodeConnectorUnavailable, true, err)
			continue
		}
		_ = controller.Observe(networkrecovery.Observation{Generation: event.Generation, Reasons: reasons, Viable: event.Viable})
	}
}

// Flush synchronously processes each currently registered controller. The
// production monitor uses HandleNetworkEvent and the controller timers; this
// hook is for deterministic embedding/tests and for callers that already own
// an event loop.
func (c *NetworkRecoveryCoordinator) Flush(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalidConfig
	}
	c.processMu.Lock()
	defer c.processMu.Unlock()
	c.mu.Lock()
	if !c.started || c.stopped {
		c.mu.Unlock()
		return ErrNetworkRecoveryNotStarted
	}
	workerCtx := c.ctx
	event, hasEvent := c.takePendingLocked()
	if hasEvent {
		c.mu.Unlock()
		c.processNetworkEvent(workerCtx, event)
		c.mu.Lock()
	}
	controllers := make([]*networkrecovery.Controller, 0, len(c.controllers))
	for _, controller := range c.controllers {
		controllers = append(controllers, controller)
	}
	c.mu.Unlock()
	var joined error
	for _, controller := range controllers {
		err := controller.Flush(ctx)
		if errors.Is(err, networkrecovery.ErrNoPendingChange) {
			continue
		}
		joined = errors.Join(joined, err)
	}
	return joined
}

func (c *NetworkRecoveryCoordinator) takePendingLocked() (networkmonitor.Event, bool) {
	if c.pending == nil {
		return networkmonitor.Event{}, false
	}
	event := *c.pending
	c.pending = nil
	return event, true
}

func (c *NetworkRecoveryCoordinator) activeBinding(state hoststate.State, tunnelID string, active Active) (hoststate.Tunnel, hoststate.Connector, bool) {
	var tunnel hoststate.Tunnel
	foundTunnel := false
	for _, candidate := range state.Tunnels {
		if candidate.ID == tunnelID && candidate.DesiredState == "active" {
			tunnel = candidate
			foundTunnel = true
			break
		}
	}
	if !foundTunnel || active.TunnelID() != tunnelID {
		return hoststate.Tunnel{}, hoststate.Connector{}, false
	}
	connector, err := localConnector(state.Connectors, tunnelID, c.manager.config.HostID)
	if err != nil || connector.ID != active.ConnectorID() {
		return hoststate.Tunnel{}, hoststate.Connector{}, false
	}
	return tunnel, connector, true
}

func (c *NetworkRecoveryCoordinator) controller(ctx context.Context, tunnel hoststate.Tunnel, connector hoststate.Connector) (*networkrecovery.Controller, error) {
	c.mu.Lock()
	if existing := c.controllers[tunnel.ID]; existing != nil {
		c.mu.Unlock()
		return existing, nil
	}
	if !c.started || c.stopped || c.ctx == nil {
		c.mu.Unlock()
		return nil, ErrNetworkRecoveryNotStarted
	}
	controllerContext := c.ctx
	c.mu.Unlock()
	// Keep creation serialized so two monitor callbacks cannot create two
	// replacers for the same durable tunnel and race their active swaps.
	type factoryResult struct {
		identity networkrecovery.Identity
		replacer networkrecovery.CarrierReplacer
		err      error
	}
	result := make(chan factoryResult, 1)
	factoryContext, cancelFactory := context.WithCancel(controllerContext)
	go func() {
		identity, replacer, err := c.factory(factoryContext, tunnel, connector)
		result <- factoryResult{identity: identity, replacer: replacer, err: err}
	}()
	var factoryResultValue factoryResult
	select {
	case factoryResultValue = <-result:
	case <-controllerContext.Done():
		cancelFactory()
		return nil, controllerContext.Err()
	case <-ctx.Done():
		cancelFactory()
		return nil, ctx.Err()
	}
	cancelFactory()
	identity, replacer, err := factoryResultValue.identity, factoryResultValue.replacer, factoryResultValue.err
	if err != nil {
		return nil, err
	}
	controller, err := networkrecovery.New(networkrecovery.Config{Identity: identity, Replacer: replacer})
	if err != nil {
		return nil, err
	}
	if err := controller.Start(controllerContext); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if existing := c.controllers[tunnel.ID]; existing != nil {
		c.mu.Unlock()
		_ = controller.Stop(context.Background())
		return existing, nil
	}
	if c.stopped || c.ctx == nil {
		c.mu.Unlock()
		_ = controller.Stop(context.Background())
		return nil, ErrNetworkRecoveryStopped
	}
	c.controllers[tunnel.ID] = controller
	c.mu.Unlock()
	return controller, nil
}

func networkRecoveryReasons(reasons networkmonitor.Reason) networkrecovery.Reason {
	var result networkrecovery.Reason
	if reasons&networkmonitor.ReasonDefaultRoute != 0 {
		result |= networkrecovery.ReasonDefaultRoute
	}
	if reasons&networkmonitor.ReasonInterfaceAddress != 0 || reasons&networkmonitor.ReasonAddressFamily != 0 {
		result |= networkrecovery.ReasonInterfaceAddress
	}
	if reasons&networkmonitor.ReasonProxy != 0 {
		result |= networkrecovery.ReasonProxy
	}
	if reasons&networkmonitor.ReasonDNS != 0 {
		result |= networkrecovery.ReasonDNS
	}
	if reasons&networkmonitor.ReasonViability != 0 {
		result |= networkrecovery.ReasonPathViability
	}
	if reasons&networkmonitor.ReasonWake != 0 {
		result |= networkrecovery.ReasonSleepWake
	}
	// A network-cost change is still a path decision even though the recovery
	// controller intentionally does not expose the cost as a separate reason.
	if reasons&networkmonitor.ReasonNetworkCost != 0 {
		result |= networkrecovery.ReasonPathViability
	}
	return result
}

// Health returns a copy of one tunnel's typed network-recovery projection.
func (c *NetworkRecoveryCoordinator) Health(tunnelID string) (networkrecovery.HealthSnapshot, bool) {
	if c == nil || tunnelID == "" {
		return networkrecovery.HealthSnapshot{}, false
	}
	c.mu.Lock()
	controller := c.controllers[tunnelID]
	c.mu.Unlock()
	if controller == nil {
		return networkrecovery.HealthSnapshot{}, false
	}
	return controller.Snapshot(), true
}

// HealthSnapshots returns a bounded point-in-time map for health endpoints.
func (c *NetworkRecoveryCoordinator) HealthSnapshots() map[string]networkrecovery.HealthSnapshot {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	controllers := make(map[string]*networkrecovery.Controller, len(c.controllers))
	for tunnelID, controller := range c.controllers {
		controllers[tunnelID] = controller
	}
	c.mu.Unlock()
	result := make(map[string]networkrecovery.HealthSnapshot, len(controllers))
	for tunnelID, controller := range controllers {
		result[tunnelID] = controller.Snapshot()
	}
	return result
}

func (c *NetworkRecoveryCoordinator) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalidConfig
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil
	}
	c.stopped = true
	cancel := c.cancel
	workerDone := c.workerDone
	controllers := make([]*networkrecovery.Controller, 0, len(c.controllers))
	for _, controller := range c.controllers {
		controllers = append(controllers, controller)
	}
	c.cancel = nil
	c.workerDone = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var joined error
	if workerDone != nil {
		select {
		case <-workerDone:
		case <-ctx.Done():
			joined = errors.Join(joined, ctx.Err())
		}
	}
	for _, controller := range controllers {
		joined = errors.Join(joined, controller.Stop(ctx))
	}
	return joined
}

var _ interface {
	Start(context.Context) error
	Shutdown(context.Context) error
} = (*NetworkRecoveryCoordinator)(nil)
