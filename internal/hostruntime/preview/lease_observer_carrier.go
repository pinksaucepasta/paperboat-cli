package preview

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

var (
	ErrLeaseObserverInvalid        = errors.New("invalid preview lease observer")
	ErrLeaseObserverClosed         = errors.New("preview lease observer is closed")
	ErrLeaseObserverReaderRequired = errors.New("preview lease observer requires a read client")
	ErrLeaseObserverBinding        = errors.New("preview lease observer received a different lease")
	ErrLeaseObserverTerminal       = errors.New("preview lease reached a terminal state before readiness")
)

const (
	defaultLeaseObserverPoll = 250 * time.Millisecond
	maxLeaseObserverPoll     = 5 * time.Second
)

// LeaseReader is the read-only half of the preview control-plane client. It
// is deliberately separate from LeaseClient so a CLI can use its ordinary
// client-session bearer for reads while machine proofs are used for mutations.
type LeaseReader interface {
	Get(context.Context, string) (Lease, error)
}

// LeaseObserverCarrier is the production CLI carrier. It never opens a data
// connection: stable hostd receives the server dispatch and owns the one
// authenticated machine carrier. This object only observes the server lease
// until hostd has reported allocation, edge, and origin readiness.
type LeaseObserverCarrier struct {
	mu       sync.Mutex
	reader   LeaseReader
	auth     api.MachineAuthSource
	poll     time.Duration
	closed   bool
	cancel   context.CancelFunc
	done     chan struct{}
	closeErr error
}

type LeaseObserverCarrierConfig struct {
	Reader       LeaseReader
	MachineAuth  api.MachineAuthSource
	PollInterval time.Duration
}

func NewLeaseObserverCarrier(config LeaseObserverCarrierConfig) (*LeaseObserverCarrier, error) {
	if config.PollInterval == 0 {
		config.PollInterval = defaultLeaseObserverPoll
	}
	if config.PollInterval <= 0 || config.PollInterval > maxLeaseObserverPoll {
		return nil, ErrLeaseObserverInvalid
	}
	return &LeaseObserverCarrier{reader: config.Reader, auth: config.MachineAuth, poll: config.PollInterval}, nil
}

// SetLeaseReader completes composition after the API client is constructed.
// It is valid only before Run, which prevents a foreground session from
// changing the resource it is observing underneath an active readiness wait.
func (c *LeaseObserverCarrier) SetLeaseReader(reader LeaseReader) error {
	if c == nil || reader == nil {
		return ErrLeaseObserverReaderRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrLeaseObserverClosed
	}
	if c.done != nil {
		return ErrLeaseObserverInvalid
	}
	c.reader = reader
	return nil
}

// MachineAuthSource exposes the renewable machine identity used for create,
// renew, and stop mutations. Read requests still use the client bearer.
func (c *LeaseObserverCarrier) MachineAuthSource() (api.MachineAuthSource, error) {
	if c == nil {
		return nil, ErrLeaseObserverInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrLeaseObserverClosed
	}
	if c.auth == nil {
		return nil, ErrLeaseObserverInvalid
	}
	return c.auth, nil
}

// NeedsOwnerSessionLease marks the hostd-backed production carrier. The CLI
// must acquire a host-owned local lifetime before it asks the control plane
// to create the preview; injected carriers used by tests may omit this seam.
func (c *LeaseObserverCarrier) NeedsOwnerSessionLease() bool { return c != nil }

func (c *LeaseObserverCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	if c == nil || ctx == nil || ready == nil {
		return ErrLeaseObserverInvalid
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrLeaseObserverClosed
	}
	reader := c.reader
	if reader == nil {
		c.mu.Unlock()
		return ErrLeaseObserverReaderRequired
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.cancel, c.done = cancel, done
	poll := c.poll
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		if c.done == done {
			c.cancel = nil
			c.done = nil
		}
		close(done)
		c.mu.Unlock()
	}()

	for {
		observed, err := reader.Get(runCtx, lease.ID)
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return classifyLeaseObserverError(err)
		}
		if err := validateObservedLease(lease, observed); err != nil {
			return err
		}
		observed.CreateOperationID = lease.CreateOperationID
		switch {
		case isReadyLease(observed):
			if err := ready(observed); err != nil {
				return err
			}
			<-runCtx.Done()
			return nil
		case observed.State == "expired":
			return ErrLeaseExpired
		case observed.State == "stopped", observed.State == "owner_disconnected":
			return ErrLeaseObserverTerminal
		}
		timer := time.NewTimer(poll)
		select {
		case <-timer.C:
		case <-runCtx.Done():
			timer.Stop()
			return nil
		}
	}
}

func (c *LeaseObserverCarrier) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrLeaseObserverInvalid
	}
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.closed = true
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func validateObservedLease(expected, observed Lease) error {
	if !sameLeaseIdentity(expected, observed) {
		return fmt.Errorf("%w: lease identity changed", ErrLeaseObserverBinding)
	}
	if observed.Generation < expected.Generation || leaseGenerationForID(observed.ID, observed.ETag) != observed.Generation {
		return fmt.Errorf("%w: lease generation regressed", ErrLeaseObserverBinding)
	}
	return nil
}

func classifyLeaseObserverError(err error) error {
	if err == nil {
		return nil
	}
	var retryable interface{ Retryable() bool }
	if errors.As(err, &retryable) && retryable.Retryable() {
		return &RetryableCarrierError{Err: err}
	}
	return err
}

var _ Carrier = (*LeaseObserverCarrier)(nil)
var _ LeaseReader = (*APILeaseClient)(nil)
