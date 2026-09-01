package tunnelmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
)

// NetworkCarrierReplacer is the durable-manager adapter for network recovery.
// It uses the existing Factory stage/probe/activate path with promotion
// disabled: desired and LKG snapshots remain byte-for-byte unchanged, while a
// ready carrier is atomically published and the prior active carrier drains.
type NetworkCarrierReplacer struct {
	Manager  *Manager
	Identity networkrecovery.Identity
}

func NewNetworkCarrierReplacer(manager *Manager, identity networkrecovery.Identity) (*NetworkCarrierReplacer, error) {
	if manager == nil {
		return nil, ErrInvalidConfig
	}
	if err := identity.Validate(); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	return &NetworkCarrierReplacer{Manager: manager, Identity: identity}, nil
}

func (r *NetworkCarrierReplacer) Replace(ctx context.Context, request networkrecovery.ReplacementRequest) (networkrecovery.ReplacementResult, error) {
	if r == nil || r.Manager == nil || ctx == nil {
		return networkrecovery.ReplacementResult{}, ErrInvalidConfig
	}
	if request.Identity != r.Identity {
		return networkrecovery.ReplacementResult{}, errors.Join(ErrGenerationConflict, networkrecovery.ErrIdentityChanged)
	}
	active, err := r.Manager.ReplaceNetworkCarrier(ctx, request.Identity.TunnelID, request.Identity.ConnectorID, request.NetworkGeneration)
	if err != nil {
		return networkrecovery.ReplacementResult{}, err
	}
	if active == nil || active.TunnelID() != request.Identity.TunnelID || active.ConnectorID() != request.Identity.ConnectorID {
		return networkrecovery.ReplacementResult{}, fmt.Errorf("%w: replacement identity", ErrGenerationConflict)
	}
	return networkrecovery.ReplacementResult{
		Identity:          request.Identity,
		NetworkGeneration: request.NetworkGeneration,
		CarrierGeneration: active.Generation(),
		Ready:             true,
	}, nil
}

// ObserveNetworkGeneration records a host-wide network generation for legacy
// monitor callers. The per-tunnel state remains authoritative, but applying a
// host-wide event to every known tunnel ensures an in-flight replacement is
// fenced atomically when a newer event arrives.
func (m *Manager) ObserveNetworkGeneration(generation uint64) bool {
	if m == nil || generation == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || generation <= m.networkGeneration {
		return false
	}
	m.networkGeneration = generation
	for tunnelID, state := range m.networkStates {
		if generation > state.Observed {
			state.Observed = generation
			m.networkStates[tunnelID] = state
		}
	}
	return true
}

// ObserveTunnelNetworkGeneration records a network event for one durable
// tunnel. It is the preferred API for a monitor that already knows the
// affected tunnel. The network generation is independent from config
// generation and does not wake ordinary desired-state reconciliation.
func (m *Manager) ObserveTunnelNetworkGeneration(tunnelID string, generation uint64) bool {
	if m == nil || tunnelID == "" || generation == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || generation < m.networkGeneration || generation <= m.networkStates[tunnelID].Observed {
		return false
	}
	m.networkGeneration = generation
	state := m.networkStates[tunnelID]
	state.Observed = generation
	m.networkStates[tunnelID] = state
	return true
}

// observeNetworkGenerationForTunnel accepts a current or newer event for one
// tunnel and rejects only stale generations. Returning true for an equal
// generation lets the controller merge newly classified reasons without
// staging a second carrier; applied-generation replay is handled separately by
// ReplaceNetworkCarrier.
func (m *Manager) observeNetworkGenerationForTunnel(tunnelID string, generation uint64) bool {
	if m == nil || tunnelID == "" || generation == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || generation < m.networkGeneration {
		return false
	}
	state := m.networkStates[tunnelID]
	if generation < state.Observed {
		return false
	}
	if generation > state.Observed {
		state.Observed = generation
		m.networkStates[tunnelID] = state
	}
	if generation > m.networkGeneration {
		m.networkGeneration = generation
	}
	return true
}

// NetworkGeneration returns the highest host-wide network generation observed
// by either the legacy or per-tunnel monitor API. It is a diagnostic watermark;
// replacement fencing uses the tunnel-specific state below.
func (m *Manager) NetworkGeneration() uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networkGeneration
}

func (m *Manager) networkGenerationCurrent(tunnelID string, generation uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networkGenerationCurrentLocked(tunnelID, generation)
}

func (m *Manager) networkGenerationCurrentLocked(tunnelID string, generation uint64) bool {
	state, ok := m.networkStates[tunnelID]
	return !m.closed && ok && state.Observed == generation
}

func (m *Manager) clearNetworkInFlight(tunnelID string, generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.networkStates[tunnelID]
	if ok && state.InFlight == generation {
		state.InFlight = 0
		m.networkStates[tunnelID] = state
	}
}

// NetworkRecoveryState returns the current per-tunnel network fence. The
// boolean is false when no observation has been recorded for tunnelID.
func (m *Manager) NetworkRecoveryState(tunnelID string) (observed, applied, inFlight uint64, ok bool) {
	if m == nil || tunnelID == "" {
		return 0, 0, 0, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.networkStates[tunnelID]
	if !ok || state.Observed == 0 {
		return 0, 0, 0, false
	}
	return state.Observed, state.Applied, state.InFlight, true
}

// ReplaceNetworkCarrier forces a single active tunnel through the normal
// durable Factory path for a newer network generation. The operation is
// serialized with ReconcileNow and preserves the old Active until the new
// candidate has passed origin and carrier readiness.
func (m *Manager) ReplaceNetworkCarrier(ctx context.Context, tunnelID, connectorID string, networkGeneration uint64) (Active, error) {
	if m == nil || ctx == nil || tunnelID == "" || connectorID == "" || networkGeneration == 0 {
		return nil, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	started := m.started && !m.closed
	m.mu.RUnlock()
	if !started {
		return nil, ErrNotStarted
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	// A per-tunnel event may be delivered just before this call. If a legacy
	// host-wide event already established the same generation, initialize this
	// tunnel's state from that watermark without treating the call as a second
	// observation.
	m.mu.Lock()
	if m.closed || m.networkGeneration > networkGeneration {
		m.mu.Unlock()
		return nil, ErrGenerationConflict
	}
	state := m.networkStates[tunnelID]
	if state.Observed > networkGeneration {
		m.mu.Unlock()
		return nil, ErrGenerationConflict
	}
	if state.Observed < networkGeneration {
		state.Observed = networkGeneration
		m.networkStates[tunnelID] = state
		if networkGeneration > m.networkGeneration {
			m.networkGeneration = networkGeneration
		}
	}
	if state.Applied >= networkGeneration {
		active := m.active[tunnelID]
		m.mu.Unlock()
		if active == nil || active.ConnectorID() != connectorID {
			return nil, ErrGenerationConflict
		}
		return active, nil
	}
	state = m.networkStates[tunnelID]
	if state.InFlight != 0 && state.InFlight != networkGeneration {
		m.mu.Unlock()
		return nil, ErrGenerationConflict
	}
	state.InFlight = networkGeneration
	m.networkStates[tunnelID] = state
	m.mu.Unlock()
	completed := false
	defer func() {
		if !completed {
			m.clearNetworkInFlight(tunnelID, networkGeneration)
		}
	}()
	durableState, _, err := m.config.Store.Snapshot()
	if err != nil {
		return nil, err
	}
	var tunnel *hoststate.Tunnel
	for index := range durableState.Tunnels {
		if durableState.Tunnels[index].ID == tunnelID {
			tunnel = &durableState.Tunnels[index]
			break
		}
	}
	if tunnel == nil || tunnel.DesiredState != "active" {
		return nil, ErrGenerationConflict
	}
	connectorValue, err := localConnector(durableState.Connectors, tunnelID, m.config.HostID)
	if err != nil || connectorValue.ID != connectorID {
		if err == nil {
			err = ErrGenerationConflict
		}
		return nil, err
	}
	if active := m.activeFor(tunnelID); active == nil || active.ConnectorID() != connectorID {
		return nil, ErrConnectorUnavailable
	}
	replacementCtx := context.WithValue(ctx, networkGenerationContextKey{}, networkGenerationContext{TunnelID: tunnelID, Generation: networkGeneration})
	if err := m.apply(replacementCtx, *tunnel, connectorValue, tunnel.DesiredSnapshot, false, false); err != nil {
		return nil, err
	}
	active := m.activeFor(tunnelID)
	if active == nil || active.ConnectorID() != connectorID {
		return nil, ErrConnectorUnavailable
	}
	completed = true
	return active, nil
}

var _ networkrecovery.CarrierReplacer = (*NetworkCarrierReplacer)(nil)
