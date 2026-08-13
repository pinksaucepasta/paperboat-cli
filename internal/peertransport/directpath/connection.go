package directpath

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

// HealthConnection owns a nominated direct assembly and the native QUIC
// session established on its selected socket generation.
type HealthConnection struct {
	*peerquic.Session
	assembly *Assembly

	mu       sync.Mutex
	closed   bool
	closeErr error
	once     sync.Once
	state    atomic.Uint32
}

func NewHealthConnection(assembly *Assembly, session *peerquic.Session) (*HealthConnection, error) {
	if assembly == nil || session == nil || session.Connection == nil || assemblyClosed(assembly) {
		return nil, ErrInvalid
	}
	connection := &HealthConnection{Session: session, assembly: assembly}
	connection.state.Store(uint32(connectionmanager.StateReady))
	return connection, nil
}

func (c *HealthConnection) State() connectionmanager.State {
	if c == nil || c.Session == nil || c.Session.Connection == nil || c.isClosed() || assemblyClosed(c.assembly) {
		return connectionmanager.StateFailed
	}
	return connectionmanager.State(c.state.Load())
}

func (c *HealthConnection) ActiveHealthCapability() (connectionmanager.ActiveHealthCapability, error) {
	if c.State() != connectionmanager.StateTrusted {
		return connectionmanager.ActiveHealthCapability{}, ErrAssemblyClosed
	}
	return connectionmanager.ActiveHealthCapability{Path: connectionmanager.PathDirectQUIC, Transport: c}, nil
}

func (c *HealthConnection) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	if c == nil || c.Session == nil {
		return 0, ErrInvalid
	}
	ptos, err := c.Session.HealthExchange(ctx, nonce)
	return ptos, directHealthFailure(err)
}

func directHealthFailure(err error) error {
	if errors.Is(err, peerquic.ErrLifetimeProbeUnreachable) {
		return &connectionmanager.Failure{Class: connectionmanager.FailureTimeout, Path: connectionmanager.PathDirectQUIC, Cause: err}
	}
	return err
}

func (c *HealthConnection) AdmitInitialHealth(ctx context.Context, nonce [16]byte) error {
	if c == nil || ctx == nil || !c.state.CompareAndSwap(uint32(connectionmanager.StateReady), uint32(connectionmanager.StateProbing)) {
		return ErrInvalid
	}
	if _, err := c.HealthExchange(ctx, nonce); err != nil {
		c.state.Store(uint32(connectionmanager.StateFailed))
		_ = c.Close()
		return err
	}
	c.state.Store(uint32(connectionmanager.StateTrusted))
	return nil
}

// AdmitInitialHealthResponse transitions a responder connection to trusted
// only after its exact session router answers a valid initial health exchange.
func (c *HealthConnection) AdmitInitialHealthResponse(ctx context.Context, router *peerquic.StreamRouter) error {
	if c == nil || ctx == nil || router == nil || !router.Owns(c.Session) || !c.state.CompareAndSwap(uint32(connectionmanager.StateReady), uint32(connectionmanager.StateProbing)) {
		return ErrInvalid
	}
	if err := router.WaitInitialHealth(ctx); err != nil {
		c.state.Store(uint32(connectionmanager.StateFailed))
		_ = c.Close()
		return err
	}
	c.state.Store(uint32(connectionmanager.StateTrusted))
	return nil
}

func (c *HealthConnection) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.state.Store(uint32(connectionmanager.StateFailed))
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.closeErr = errors.Join(c.Session.Close(), c.assembly.Close())
	})
	return c.closeErr
}

func (c *HealthConnection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func assemblyClosed(assembly *Assembly) bool {
	if assembly == nil {
		return true
	}
	assembly.selectedMu.Lock()
	defer assembly.selectedMu.Unlock()
	return assembly.closed
}

var _ connectionmanager.ActiveHealthConnection = (*HealthConnection)(nil)
