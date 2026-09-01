package connectorprotocol

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

// HostStateStore is the small durable-state boundary needed by the connector
// protocol. The concrete hoststate.Store provides the atomic revision check;
// tests and embedders may provide an equivalent implementation.
type HostStateStore interface {
	Snapshot() (hoststate.State, uint64, error)
	Commit(expectedRevision uint64, next hoststate.State) (uint64, error)
}

// HostStateApplier stages connector configuration in the durable host cache.
// Prepare only constructs a candidate in memory. Activate atomically promotes
// it to LastKnownGood, preserving the previous active snapshot until the
// protocol has observed edge, route, and origin readiness.
type HostStateApplier struct {
	Store            HostStateStore
	Clock            Clock
	StableEndpointID string
}

func (a *HostStateApplier) PrepareSnapshot(ctx context.Context, snapshot Snapshot) (PreparedConfig, error) {
	if a == nil || a.Store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	if err := snapshot.Validate(); err != nil {
		return nil, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock.Now().UTC()
	}
	state, revision, err := a.Store.Snapshot()
	if err != nil {
		return nil, err
	}
	candidate, deleted, err := stageSnapshot(state, snapshot, now, a.StableEndpointID)
	if err != nil {
		return nil, err
	}
	return &hostStatePrepared{store: a.Store, expectedRevision: revision, tunnelID: snapshot.TunnelID, connectorID: snapshot.ConnectorID, generation: snapshot.Generation, next: candidate, deleted: deleted}, nil
}

func (a *HostStateApplier) PrepareDelta(ctx context.Context, delta Delta) (PreparedConfig, error) {
	if a == nil || a.Store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	if err := delta.Validate(); err != nil {
		return nil, codeError(ErrDeltaRejected, ReasonGenerationGap, false, err)
	}
	state, revision, err := a.Store.Snapshot()
	if err != nil {
		return nil, err
	}
	tunnel, ok := findHostTunnel(state, delta.TunnelID)
	if !ok || tunnel.LastKnownGood == nil || tunnel.AppliedGeneration != delta.PreviousGeneration || tunnel.LastKnownGood.ContentHash != delta.PreviousContentHash {
		return nil, codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
	}
	snapshot := Snapshot{TunnelID: delta.TunnelID, Generation: delta.Generation, ContentHash: delta.ContentHash, Payload: append([]byte(nil), delta.Payload...)}
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock.Now().UTC()
	}
	candidate, deleted, err := stageSnapshot(state, snapshot, now, a.StableEndpointID)
	if err != nil {
		return nil, codeError(ErrDeltaRejected, ReasonSnapshotRejected, false, err)
	}
	return &hostStatePrepared{store: a.Store, expectedRevision: revision, tunnelID: delta.TunnelID, connectorID: delta.ConnectorID, generation: delta.Generation, next: candidate, deleted: deleted}, nil
}

func stageSnapshot(state hoststate.State, snapshot Snapshot, now time.Time, stableEndpointID string) (hoststate.State, bool, error) {
	if now.IsZero() {
		return hoststate.State{}, false, ErrInvalidInput
	}
	if err := hoststate.ValidateStableEndpointID(stableEndpointID); err != nil {
		return hoststate.State{}, false, err
	}
	decoded, err := hoststate.ParseTunnelConfigSnapshot(snapshot.Payload, snapshot.TunnelID, snapshot.Generation)
	if err != nil {
		return hoststate.State{}, false, err
	}
	endpointID, err := hoststate.StableEndpointIDForEndpoint(decoded.StableEndpoint)
	if err != nil {
		return hoststate.State{}, false, err
	}
	if endpointID != stableEndpointID {
		return hoststate.State{}, false, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, hoststate.ErrInvalidState)
	}
	converted, err := hoststate.NewConfigSnapshot(snapshot.TunnelID, snapshot.Generation, snapshot.Payload)
	if err != nil {
		return hoststate.State{}, false, err
	}
	if converted.ContentHash != snapshot.ContentHash {
		return hoststate.State{}, false, codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
	}
	next, err := cloneHostState(state)
	if err != nil {
		return hoststate.State{}, false, err
	}
	for index := range next.Tunnels {
		if next.Tunnels[index].ID != snapshot.TunnelID {
			continue
		}
		if next.Tunnels[index].AppliedGeneration > snapshot.Generation {
			return hoststate.State{}, false, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		if next.Tunnels[index].DesiredGeneration > snapshot.Generation {
			return hoststate.State{}, false, codeError(ErrStaleGeneration, ReasonStaleGeneration, false, nil)
		}
		if next.Tunnels[index].DesiredGeneration == snapshot.Generation && next.Tunnels[index].DesiredSnapshot.ContentHash != converted.ContentHash {
			return hoststate.State{}, false, codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
		}
		if next.Tunnels[index].StableEndpointID != stableEndpointID {
			return hoststate.State{}, false, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, hoststate.ErrInvalidState)
		}
		if decoded.DesiredState == "deleted" {
			next = removeTunnelState(next, snapshot.TunnelID)
			return next, true, nil
		}
		next.Tunnels[index].DesiredGeneration = snapshot.Generation
		next.Tunnels[index].DesiredSnapshot = converted
		next.Tunnels[index].DesiredState = decoded.DesiredState
		next.Tunnels[index].UpdatedAt = now
		return replaceRouteGenerations(next, snapshot.TunnelID, decoded.Routes, snapshot.Generation), false, nil
	}
	if decoded.DesiredState == "deleted" {
		return next, true, nil
	}
	newTunnel := hoststate.Tunnel{
		ID: snapshot.TunnelID, StableEndpointID: stableEndpointID, DesiredState: decoded.DesiredState,
		DesiredGeneration: snapshot.Generation, DesiredSnapshot: converted, UpdatedAt: now,
	}
	next.Tunnels = append(next.Tunnels, newTunnel)
	return replaceRouteGenerations(next, snapshot.TunnelID, decoded.Routes, snapshot.Generation), false, nil
}

func replaceRouteGenerations(state hoststate.State, tunnelID string, routes []hoststate.TunnelConfigRoute, generation uint64) hoststate.State {
	filtered := state.RouteGenerations[:0]
	for _, route := range state.RouteGenerations {
		if route.TunnelID != tunnelID {
			filtered = append(filtered, route)
		}
	}
	for _, route := range routes {
		filtered = append(filtered, hoststate.RouteGeneration{TunnelID: tunnelID, RouteID: route.ID, Generation: generation})
	}
	state.RouteGenerations = filtered
	return state
}

func removeTunnelState(state hoststate.State, tunnelID string) hoststate.State {
	tunnels := state.Tunnels[:0]
	for _, tunnel := range state.Tunnels {
		if tunnel.ID != tunnelID {
			tunnels = append(tunnels, tunnel)
		}
	}
	state.Tunnels = tunnels
	routes := state.RouteGenerations[:0]
	for _, route := range state.RouteGenerations {
		if route.TunnelID != tunnelID {
			routes = append(routes, route)
		}
	}
	state.RouteGenerations = routes
	connectors := state.Connectors[:0]
	for _, connector := range state.Connectors {
		if connector.TunnelID != tunnelID {
			connectors = append(connectors, connector)
		}
	}
	state.Connectors = connectors
	journal := state.UpdateJournal[:0]
	for _, entry := range state.UpdateJournal {
		if entry.TunnelID != tunnelID {
			journal = append(journal, entry)
		}
	}
	state.UpdateJournal = journal
	return state
}

func findHostTunnel(state hoststate.State, tunnelID string) (hoststate.Tunnel, bool) {
	for _, tunnel := range state.Tunnels {
		if tunnel.ID == tunnelID {
			return tunnel, true
		}
	}
	return hoststate.Tunnel{}, false
}

func cloneHostState(state hoststate.State) (hoststate.State, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return hoststate.State{}, err
	}
	var clone hoststate.State
	if err := json.Unmarshal(raw, &clone); err != nil {
		return hoststate.State{}, err
	}
	return clone, nil
}

type hostStatePrepared struct {
	mu               sync.Mutex
	store            HostStateStore
	expectedRevision uint64
	tunnelID         string
	connectorID      string
	generation       uint64
	next             hoststate.State
	deleted          bool
	staged           bool
}

// EnsureConnector seeds the server-owned connector reference into a newly
// staged tunnel.  The bootstrap control stream may deliver the first
// configuration before the connector has ever been persisted locally, so the
// applier needs one narrow, pre-Stage hook for that immutable identity.  It
// never accepts credential material and is intentionally idempotent only for
// the exact same connector record.
func (p *hostStatePrepared) EnsureConnector(value hoststate.Connector) error {
	if p == nil {
		return ErrInvalidInput
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deleted || p.staged {
		return ErrInvalidInput
	}
	if value.ID == "" || value.ID != p.connectorID || value.TunnelID != p.tunnelID {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	for _, existing := range p.next.Connectors {
		if existing.ID != value.ID {
			continue
		}
		if existing == value {
			return nil
		}
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	p.next.Connectors = append(p.next.Connectors, value)
	if err := p.next.Validate(); err != nil {
		p.next.Connectors = p.next.Connectors[:len(p.next.Connectors)-1]
		return err
	}
	return nil
}

// StagedState returns an isolated copy of the candidate desired state. It is
// intentionally read-only: a runtime coordinator may use it to stage carrier
// and origin readiness before Activate commits the generation, but cannot
// mutate the applier's crash-safe commit payload.
func (p *hostStatePrepared) StagedState() (hoststate.State, error) {
	if p == nil {
		return hoststate.State{}, ErrInvalidInput
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneHostState(p.next)
}

// Stage durably records desired state without promoting it to last-known-good.
// TunnelManager uses this boundary to discover and prepare the candidate while
// the previous active generation continues serving. A staged candidate remains
// desired after a failed readiness attempt so reconciliation can retry it.
func (p *hostStatePrepared) Stage(ctx context.Context) error {
	if p == nil || p.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.staged {
		return nil
	}
	next, err := cloneHostState(p.next)
	if err != nil {
		return err
	}
	revision, err := p.store.Commit(p.expectedRevision, next)
	if err != nil {
		return err
	}
	p.expectedRevision = revision
	p.staged = true
	return nil
}

func (p *hostStatePrepared) Activate(ctx context.Context) error {
	if p == nil || p.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return codeError(ErrCanceled, ReasonCanceled, true, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.staged {
		state, _, err := p.store.Snapshot()
		if err != nil {
			return err
		}
		if p.deleted {
			for _, tunnel := range state.Tunnels {
				if tunnel.ID == p.tunnelID {
					return codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
				}
			}
			return nil
		}
		for _, tunnel := range state.Tunnels {
			if tunnel.ID != p.tunnelID {
				continue
			}
			if tunnel.AppliedGeneration != p.generation || tunnel.LastKnownGood == nil || tunnel.LastKnownGood.Generation != p.generation || tunnel.LastKnownGood.ContentHash != tunnel.DesiredSnapshot.ContentHash {
				return codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
			}
			if p.connectorID == "" {
				return nil
			}
			for _, connector := range state.Connectors {
				if connector.ID == p.connectorID && connector.TunnelID == p.tunnelID && connector.LastAppliedGeneration == p.generation {
					return nil
				}
			}
			return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
		}
		return codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	next, err := cloneHostState(p.next)
	if err != nil {
		return err
	}
	if p.deleted {
		if _, err := p.store.Commit(p.expectedRevision, next); err != nil {
			return err
		}
		return nil
	}
	for index := range next.Tunnels {
		tunnel := &next.Tunnels[index]
		if tunnel.ID != p.tunnelID {
			continue
		}
		if tunnel.DesiredGeneration == 0 || tunnel.DesiredSnapshot.Generation != tunnel.DesiredGeneration {
			continue
		}
		lastKnownGood := tunnel.DesiredSnapshot
		tunnel.AppliedGeneration = tunnel.DesiredGeneration
		tunnel.LastKnownGood = &lastKnownGood
	}
	connectorFound := false
	for index := range next.Connectors {
		connector := &next.Connectors[index]
		if connector.ID != p.connectorID || connector.TunnelID != p.tunnelID {
			continue
		}
		connectorFound = true
		connector.LastAppliedGeneration = p.generation
	}
	if p.connectorID != "" && !connectorFound {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	if _, err := p.store.Commit(p.expectedRevision, next); err != nil {
		return err
	}
	return nil
}

func (p *hostStatePrepared) Abort(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

var _ ConfigApplier = (*HostStateApplier)(nil)
