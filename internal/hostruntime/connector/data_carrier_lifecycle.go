package connector

import (
	"context"
	"io"
	"sync"
)

// DataCarrierPrepareRequest is the narrow input boundary for a staged
// connector transport. Identity is supplied by the authenticated
// connector-v1 control session and is copied into the pool configuration
// before validation. The dialer receives a fresh, slot-bound
// DataCarrierDialRequest for every preferred or fallback attempt.
type DataCarrierPrepareRequest struct {
	Identity DataCarrierIdentity
	Config   DataCarrierPoolConfig
	Dialer   DataCarrierDialer
}

// PreparedDataCarrier owns a connected but not-yet-active pool. Connecting
// and pinging happen during Prepare so readiness is observable before the
// caller promotes a tunnel generation. Activation itself does not change any
// durable generation or tunnel-manager state.
type PreparedDataCarrier struct {
	pool *DataCarrierPool

	mu    sync.Mutex
	state DataCarrierLifecycleState
}

// DataCarrierLifecycleState is the explicit transport staging state. It is
// deliberately independent from tunnel-manager generation promotion.
type DataCarrierLifecycleState string

const (
	DataCarrierLifecyclePrepared DataCarrierLifecycleState = "prepared"
	DataCarrierLifecycleActive   DataCarrierLifecycleState = "active"
	DataCarrierLifecycleAborted  DataCarrierLifecycleState = "aborted"
	DataCarrierLifecycleClosed   DataCarrierLifecycleState = "closed"
)

// ActiveDataCarrier is the transport handle after an explicit activation.
// The pool remains the owner of stream admission, bounded queues, fallback,
// and carrier health; this handle only exposes the reusable lifecycle and
// authenticated stream boundaries needed by a runtime adapter.
type ActiveDataCarrier struct {
	prepared *PreparedDataCarrier
}

// PrepareDataCarrier stages and authenticates one bounded multi-carrier pool.
// The identity argument is authoritative. A non-zero Config.Session must
// match it exactly, preventing a caller from accidentally opening a carrier
// under another session or generation.
func PrepareDataCarrier(ctx context.Context, identity DataCarrierIdentity, config DataCarrierPoolConfig, dialer DataCarrierDialer) (*PreparedDataCarrier, error) {
	return PrepareDataCarrierRequest(ctx, DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: dialer})
}

// PrepareDataCarrierRequest is the request-shaped form of PrepareDataCarrier
// for adapters that already carry an explicit dial request boundary.
func PrepareDataCarrierRequest(ctx context.Context, request DataCarrierPrepareRequest) (*PreparedDataCarrier, error) {
	if ctx == nil || request.Dialer == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	if err := request.Identity.validate(); err != nil {
		return nil, err
	}
	if request.Config.Session != (DataCarrierIdentity{}) && request.Config.Session != request.Identity {
		return nil, ErrInvalidDataCarrierConfig
	}
	request.Config.Session = request.Identity
	// The context supplied to Prepare scopes the staging operation only. Once
	// the pool has been activated, its carrier session must outlive the
	// reconcile/apply call that staged it and remain owned by Prepared/Active
	// lifecycle handles until Abort or Close. Passing the operation context
	// directly here made DataCarrier.watch close an otherwise healthy session as
	// soon as the manager returned from reconciliation.
	lifetimeCtx := context.WithoutCancel(ctx)
	pool, err := NewDataCarrierPool(lifetimeCtx, request.Config, request.Dialer)
	if err != nil {
		return nil, err
	}
	if err := pool.Connect(ctx); err != nil {
		_ = pool.Close()
		return nil, err
	}
	return &PreparedDataCarrier{pool: pool, state: DataCarrierLifecyclePrepared}, nil
}

// Activate promotes a prepared pool to an active transport handle. Pool
// readiness is checked again at the boundary so a closed pool cannot be
// published as a live carrier.
func (p *PreparedDataCarrier) Activate(ctx context.Context) (*ActiveDataCarrier, error) {
	if p == nil || ctx == nil {
		return nil, ErrInvalidDataCarrierConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != DataCarrierLifecyclePrepared {
		return nil, ErrDataCarrierUnavailable
	}
	if p.pool == nil || p.pool.State() != DataCarrierPoolReady {
		return nil, ErrDataCarrierUnavailable
	}
	p.state = DataCarrierLifecycleActive
	return &ActiveDataCarrier{prepared: p}, nil
}

// Abort closes a prepared pool without making it active. It is safe to call
// more than once and is intentionally rejected after activation so ownership
// remains unambiguous between the prepared and active handles.
func (p *PreparedDataCarrier) Abort(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	if p.state == DataCarrierLifecycleActive {
		p.mu.Unlock()
		return ErrDataCarrierUnavailable
	}
	if p.state == DataCarrierLifecycleAborted || p.state == DataCarrierLifecycleClosed {
		p.mu.Unlock()
		return nil
	}
	p.state = DataCarrierLifecycleAborted
	pool := p.pool
	p.mu.Unlock()
	if pool != nil {
		return pool.Close()
	}
	return nil
}

// State reports the staged lifecycle, not tunnel-manager generation state.
func (p *PreparedDataCarrier) State() DataCarrierLifecycleState {
	if p == nil {
		return DataCarrierLifecycleClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.state {
	case DataCarrierLifecyclePrepared:
		return DataCarrierLifecyclePrepared
	case DataCarrierLifecycleActive:
		return DataCarrierLifecycleActive
	case DataCarrierLifecycleAborted:
		return DataCarrierLifecycleAborted
	default:
		return DataCarrierLifecycleClosed
	}
}

// Ready is the pool readiness signal. It is closed once at least one carrier
// has completed the authenticated control-session ping during Prepare.
func (p *PreparedDataCarrier) Ready() <-chan struct{} {
	if p == nil || p.pool == nil {
		return closedDataCarrierChannel()
	}
	return p.pool.Ready()
}

func (p *PreparedDataCarrier) SelectedTransport() (Transport, bool) {
	if p == nil || p.pool == nil {
		return "", false
	}
	return p.pool.SelectedTransport()
}

func (p *PreparedDataCarrier) Snapshot() []DataCarrierInfo {
	if p == nil || p.pool == nil {
		return nil
	}
	return p.pool.Snapshot()
}

// Pool returns the activated bounded pool for data and control stream use.
func (a *ActiveDataCarrier) Pool() *DataCarrierPool {
	if a == nil || a.prepared == nil {
		return nil
	}
	return a.prepared.pool
}

func (a *ActiveDataCarrier) Ready() <-chan struct{} {
	if a == nil || a.prepared == nil {
		return closedDataCarrierChannel()
	}
	return a.prepared.Ready()
}

func (a *ActiveDataCarrier) SelectedTransport() (Transport, bool) {
	if a == nil || a.prepared == nil {
		return "", false
	}
	return a.prepared.SelectedTransport()
}

func (a *ActiveDataCarrier) Snapshot() []DataCarrierInfo {
	if a == nil || a.prepared == nil {
		return nil
	}
	return a.prepared.Snapshot()
}

func (a *ActiveDataCarrier) Identity() (DataCarrierIdentity, bool) {
	if a == nil || a.Pool() == nil {
		return DataCarrierIdentity{}, false
	}
	return a.Pool().Identity()
}

func (a *ActiveDataCarrier) OpenControlStream(ctx context.Context) (io.ReadWriteCloser, error) {
	if a == nil || a.Pool() == nil {
		return nil, ErrDataCarrierUnavailable
	}
	return a.Pool().OpenControlStream(ctx)
}

func (a *ActiveDataCarrier) OpenStream(ctx context.Context, open StreamOpen) (io.ReadWriteCloser, error) {
	if a == nil || a.Pool() == nil {
		return nil, ErrDataCarrierUnavailable
	}
	return a.Pool().OpenStream(ctx, open)
}

func (a *ActiveDataCarrier) AcceptStream(ctx context.Context) (*DataCarrierStream, StreamOpen, error) {
	if a == nil || a.Pool() == nil {
		return nil, StreamOpen{}, ErrDataCarrierUnavailable
	}
	return a.Pool().AcceptStream(ctx)
}

// BeginDrain stops new stream admission for this carrier generation without
// waiting for sibling streams to finish.
func (a *ActiveDataCarrier) BeginDrain() error {
	if a == nil || a.Pool() == nil {
		return ErrInvalidDataCarrierConfig
	}
	return a.Pool().BeginDrain()
}

// ActiveStreams returns the aggregate stream count for this exact carrier
// generation.
func (a *ActiveDataCarrier) ActiveStreams() int {
	if a == nil || a.Pool() == nil {
		return 0
	}
	return a.Pool().ActiveStreams()
}

func (a *ActiveDataCarrier) Drain(ctx context.Context) error {
	if a == nil || a.Pool() == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	return a.Pool().Drain(ctx)
}

func (a *ActiveDataCarrier) Close(ctx context.Context) error {
	if a == nil || a.prepared == nil || ctx == nil {
		return ErrInvalidDataCarrierConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.prepared.mu.Lock()
	if a.prepared.state == DataCarrierLifecycleClosed || a.prepared.state == DataCarrierLifecycleAborted {
		a.prepared.mu.Unlock()
		return nil
	}
	a.prepared.state = DataCarrierLifecycleClosed
	pool := a.prepared.pool
	a.prepared.mu.Unlock()
	if pool == nil {
		return nil
	}
	return pool.Close()
}
