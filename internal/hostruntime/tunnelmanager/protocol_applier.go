package tunnelmanager

import (
	"context"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

const protocolReadinessPollInterval = 10 * time.Millisecond

type stagedHostState interface {
	connectorprotocol.PreparedConfig
	Stage(context.Context) error
	StagedState() (hoststate.State, error)
}

type initialConnectorSeeder interface {
	EnsureConnector(hoststate.Connector) error
}

// CoordinatedConfigApplier durably records desired connector-v1 state, wakes
// TunnelManager, and exposes an exact readiness wait to the control-session
// runner. Desired state is durable before acknowledgement, while the prior
// last-known-good carrier stays active until TunnelManager promotes the new
// generation.
type CoordinatedConfigApplier struct {
	State            *connectorprotocol.HostStateApplier
	Manager          *Manager
	InitialConnector *hoststate.Connector
}

func (a *CoordinatedConfigApplier) PrepareSnapshot(ctx context.Context, snapshot connectorprotocol.Snapshot) (connectorprotocol.PreparedConfig, error) {
	if a == nil || a.State == nil || a.Manager == nil || ctx == nil || snapshot.ValidateBound() != nil {
		return nil, ErrInvalidConfig
	}
	prepared, err := a.State.PrepareSnapshot(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	decoded, err := hoststate.ParseTunnelConfigSnapshot(snapshot.Payload, snapshot.TunnelID, snapshot.Generation)
	if err != nil {
		return nil, errors.Join(err, prepared.Abort(context.Background()))
	}
	return a.stage(ctx, prepared, snapshot.AccountID, snapshot.TunnelID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration, snapshot.Generation, snapshot.ContentHash, decoded.DesiredState)
}

func (a *CoordinatedConfigApplier) PrepareDelta(ctx context.Context, delta connectorprotocol.Delta) (connectorprotocol.PreparedConfig, error) {
	if a == nil || a.State == nil || a.Manager == nil || ctx == nil || delta.ValidateBound() != nil {
		return nil, ErrInvalidConfig
	}
	prepared, err := a.State.PrepareDelta(ctx, delta)
	if err != nil {
		return nil, err
	}
	decoded, err := hoststate.ParseTunnelConfigSnapshot(delta.Payload, delta.TunnelID, delta.Generation)
	if err != nil {
		return nil, errors.Join(err, prepared.Abort(context.Background()))
	}
	return a.stage(ctx, prepared, delta.AccountID, delta.TunnelID, delta.ConnectorID, delta.SessionID, delta.ProcessGeneration, delta.Generation, delta.ContentHash, decoded.DesiredState)
}

func (a *CoordinatedConfigApplier) stage(ctx context.Context, prepared connectorprotocol.PreparedConfig, accountID, tunnelID, connectorID, sessionID string, processGeneration, generation uint64, contentHash, desiredState string) (connectorprotocol.PreparedConfig, error) {
	staged, ok := prepared.(stagedHostState)
	if !ok {
		return nil, errors.Join(ErrInvalidConfig, prepared.Abort(context.Background()))
	}
	state, err := staged.StagedState()
	if err != nil {
		return nil, errors.Join(err, prepared.Abort(context.Background()))
	}
	connectorState := state.Connectors
	if desiredState == "deleted" {
		current, _, snapshotErr := a.Manager.config.Store.Snapshot()
		if snapshotErr != nil {
			return nil, errors.Join(snapshotErr, prepared.Abort(context.Background()))
		}
		connectorState = current.Connectors
	}
	connector, err := exactProtocolConnector(connectorState, tunnelID, connectorID, a.Manager.config.HostID)
	if desiredState != "deleted" && (err != nil || connector.RotationGeneration == 0) && a.InitialConnector != nil {
		initial := *a.InitialConnector
		if initial.ID == connectorID && initial.TunnelID == tunnelID && initial.HostID == a.Manager.config.HostID {
			seeder, canSeed := staged.(initialConnectorSeeder)
			if canSeed {
				if seedErr := seeder.EnsureConnector(initial); seedErr != nil {
					return nil, errors.Join(seedErr, prepared.Abort(context.Background()))
				}
				state, err = staged.StagedState()
				if err != nil {
					return nil, errors.Join(err, prepared.Abort(context.Background()))
				}
				connector, err = exactProtocolConnector(state.Connectors, tunnelID, connectorID, a.Manager.config.HostID)
			}
		}
	}
	if err != nil || connector.RotationGeneration == 0 {
		return nil, errors.Join(ErrConnectorUnavailable, err, prepared.Abort(context.Background()))
	}
	tunnelFound := desiredState == "deleted"
	for _, tunnel := range state.Tunnels {
		if tunnel.ID == tunnelID && tunnel.DesiredGeneration == generation {
			tunnelFound = true
			break
		}
	}
	if !tunnelFound {
		return nil, errors.Join(ErrGenerationConflict, prepared.Abort(context.Background()))
	}
	if err := staged.Stage(ctx); err != nil {
		return nil, errors.Join(err, prepared.Abort(context.Background()))
	}
	// Keep the authenticated session binding alongside the staged desired
	// snapshot. This lets the manager distinguish a same-config reconnect from
	// an already healthy carrier and reattach the carrier without changing LKG.
	a.Manager.RecordControlSessionBinding(accountID, tunnelID, connectorID, sessionID, processGeneration, generation, contentHash)
	a.Manager.Notify()
	return prepared, nil
}

// WaitReady waits for the exact authenticated session generation to become
// the active, durable last-known-good runtime. It never treats a desired-state
// write or a transport ping as edge, route, and origin readiness.
func (a *CoordinatedConfigApplier) WaitReady(ctx context.Context, snapshot connectorprotocol.Snapshot) (connectorprotocol.Readiness, error) {
	if a == nil || a.Manager == nil || ctx == nil || snapshot.ValidateBound() != nil {
		return connectorprotocol.Readiness{}, ErrInvalidConfig
	}
	decoded, err := hoststate.ParseTunnelConfigSnapshot(snapshot.Payload, snapshot.TunnelID, snapshot.Generation)
	if err != nil {
		return connectorprotocol.Readiness{}, err
	}
	ticker := time.NewTicker(protocolReadinessPollInterval)
	defer ticker.Stop()
	for {
		ready, terminal, err := a.readiness(snapshot, decoded.DesiredState)
		if ready {
			return connectorprotocol.Readiness{
				AccountID: snapshot.AccountID, TunnelID: snapshot.TunnelID, ConnectorID: snapshot.ConnectorID,
				SessionID: snapshot.SessionID, ProcessGeneration: snapshot.ProcessGeneration,
				Generation: snapshot.Generation, ContentHash: snapshot.ContentHash,
				EdgeReady: true, RouteReady: true, OriginReady: true,
			}, nil
		}
		if terminal || err != nil {
			return connectorprotocol.Readiness{}, err
		}
		select {
		case <-ctx.Done():
			return connectorprotocol.Readiness{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *CoordinatedConfigApplier) readiness(snapshot connectorprotocol.Snapshot, desiredState string) (ready, terminal bool, err error) {
	state, _, err := a.Manager.config.Store.Snapshot()
	if err != nil {
		return false, false, err
	}
	var tunnel *hoststate.Tunnel
	for index := range state.Tunnels {
		if state.Tunnels[index].ID == snapshot.TunnelID {
			tunnel = &state.Tunnels[index]
			break
		}
	}
	if tunnel == nil {
		if desiredState == "deleted" {
			if a.Manager.activeFor(snapshot.TunnelID) == nil {
				return true, false, nil
			}
			// Deletion is staged by removing durable desired state first. The
			// manager may still be draining the previously active generation;
			// that bounded transition is pending readiness, not a conflict.
			return false, false, nil
		}
		return false, true, ErrGenerationConflict
	}
	if tunnel.DesiredGeneration > snapshot.Generation || tunnel.DesiredGeneration == snapshot.Generation && tunnel.DesiredSnapshot.ContentHash != snapshot.ContentHash {
		return false, true, ErrGenerationConflict
	}
	connector, connectorErr := exactProtocolConnector(state.Connectors, snapshot.TunnelID, snapshot.ConnectorID, a.Manager.config.HostID)
	if connectorErr != nil {
		return false, true, errors.Join(ErrConnectorUnavailable, connectorErr)
	}
	active := a.Manager.activeFor(snapshot.TunnelID)
	if desiredState == "paused" {
		if active != nil {
			return false, false, nil
		}
		if tunnel.AppliedGeneration == snapshot.Generation && tunnel.LastKnownGood != nil && tunnel.LastKnownGood.Generation == snapshot.Generation && tunnel.LastKnownGood.ContentHash == snapshot.ContentHash && connector.LastAppliedGeneration == snapshot.Generation {
			return true, false, nil
		}
		return false, false, nil
	}
	if active == nil || active.ConnectorID() != snapshot.ConnectorID || active.Generation() != snapshot.Generation || active.ContentHash() != snapshot.ContentHash {
		return false, false, nil
	}
	if tunnel.AppliedGeneration != snapshot.Generation || tunnel.LastKnownGood == nil || tunnel.LastKnownGood.Generation != snapshot.Generation || tunnel.LastKnownGood.ContentHash != snapshot.ContentHash || connector.LastAppliedGeneration != snapshot.Generation {
		return false, false, nil
	}
	return true, false, nil
}

func exactProtocolConnector(connectors []hoststate.Connector, tunnelID, connectorID, hostID string) (hoststate.Connector, error) {
	var found hoststate.Connector
	for _, connector := range connectors {
		if connector.ID != connectorID || connector.TunnelID != tunnelID || connector.HostID != hostID {
			continue
		}
		if found.ID != "" {
			return hoststate.Connector{}, ErrGenerationConflict
		}
		found = connector
	}
	if found.ID == "" {
		return hoststate.Connector{}, ErrConnectorUnavailable
	}
	return found, nil
}

var _ connectorprotocol.ConfigApplier = (*CoordinatedConfigApplier)(nil)
