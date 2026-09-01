package tunnelmanager

import (
	"context"
	"errors"
	"net"
	"time"

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
	var prepared *connector.PreparedDataCarrier
	for attempt := 0; ; attempt++ {
		prepared, err = connector.PrepareDataCarrierRequest(ctx, preparedRequest)
		if err == nil {
			break
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if errors.Is(err, connector.ErrInvalidDataCarrierConfig) {
			return nil, errors.Join(ErrInvalidConfig, err)
		}
		if !retryableDataCarrierPrepareError(err) {
			return nil, errors.Join(ErrConnectorUnavailable, err)
		}
		// Edge admission is published asynchronously after the authenticated
		// config ACK. A carrier can therefore reach the edge just before its
		// staged admission appears. Retry that transient window within the
		// manager's existing apply deadline instead of rejecting a valid
		// connector generation after one race-lost dial.
		delay := 100 * time.Millisecond * time.Duration(attempt+1)
		if delay > time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		_ = prepared.Abort(context.Background())
		return nil, err
	}
	return dataCarrierPrepared{prepared: prepared}, nil
}

// retryableDataCarrierPrepareError admits only failures which can change
// without changing the authenticated identity or configuration. Permanent
// admission, endpoint, and TLS failures must surface immediately; otherwise
// a bad credential or route binding would consume the entire manager apply
// deadline while obscuring the actionable cause. Transport/network errors
// remain retryable because the edge may be temporarily unavailable.
func retryableDataCarrierPrepareError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, connector.ErrDataCarrierAdmission) || errors.Is(err, connector.ErrInvalidDataCarrierEndpoint) || errors.Is(err, connector.ErrDataCarrierTLS) {
		return false
	}
	if errors.Is(err, connector.ErrDataCarrierClosed) || errors.Is(err, connector.ErrDataCarrierUnavailable) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr)
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
