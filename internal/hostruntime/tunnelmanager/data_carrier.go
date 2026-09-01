package tunnelmanager

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

// DataCarrierSessionSource resolves the live authenticated connector-v1
// session and its slot-bound dialer. The source must not mint identities from
// durable tunnel state; SessionID and ProcessGeneration come from the active
// control session.
type DataCarrierSessionSource interface {
	PrepareDataCarrier(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error)
}

type DataCarrierBuilder struct {
	Sessions DataCarrierSessionSource
}

func (b DataCarrierBuilder) PrepareCarrier(ctx context.Context, request ApplyRequest) (PreparedCarrier, error) {
	if ctx == nil || b.Sessions == nil {
		return nil, ErrInvalidConfig
	}
	preparedRequest, err := b.Sessions.PrepareDataCarrier(ctx, request)
	if err != nil {
		return nil, err
	}
	identity := preparedRequest.Identity
	if identity.TunnelID != request.Tunnel.ID || identity.ConnectorID != request.Connector.ID || identity.HostID != request.Connector.HostID || identity.Generation != request.Snapshot.Generation || identity.AccountID == "" || identity.SessionID == "" || identity.ProcessGeneration == 0 {
		return nil, ErrGenerationConflict
	}
	prepared, err := connector.PrepareDataCarrierRequest(ctx, preparedRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if errors.Is(err, connector.ErrInvalidDataCarrierConfig) {
			return nil, errors.Join(ErrInvalidConfig, err)
		}
		return nil, errors.Join(ErrConnectorUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		_ = prepared.Abort(context.Background())
		return nil, err
	}
	return dataCarrierPrepared{prepared: prepared}, nil
}

type dataCarrierPrepared struct {
	prepared *connector.PreparedDataCarrier
}

func (p dataCarrierPrepared) Activate(ctx context.Context) (RunningCarrier, error) {
	if p.prepared == nil {
		return nil, ErrConnectorUnavailable
	}
	active, err := p.prepared.Activate(ctx)
	if err != nil {
		return nil, errors.Join(ErrConnectorUnavailable, err)
	}
	return dataCarrierRunning{active: active}, nil
}

func (p dataCarrierPrepared) Abort(ctx context.Context) error {
	if p.prepared == nil {
		return nil
	}
	return p.prepared.Abort(ctx)
}

type dataCarrierRunning struct {
	active *connector.ActiveDataCarrier
}

// ActiveDataCarrier returns the exact authenticated transport handle
// published by this runtime. TunnelManager keeps ownership of its lifecycle;
// consumers must use ActiveObserver generation fencing before attaching.
func (r dataCarrierRunning) ActiveDataCarrier() *connector.ActiveDataCarrier {
	return r.active
}

func (r dataCarrierRunning) Drain(ctx context.Context) error {
	if r.active == nil {
		return nil
	}
	return r.active.Drain(ctx)
}

func (r dataCarrierRunning) Close(ctx context.Context) error {
	if r.active == nil {
		return nil
	}
	return r.active.Close(ctx)
}

var _ CarrierBuilder = DataCarrierBuilder{}
