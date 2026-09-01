package preview

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

var (
	ErrDataCarrierPreviewInvalid      = errors.New("invalid preview data-carrier attachment")
	ErrDataCarrierPreviewClosed       = errors.New("preview data-carrier attachment is closed")
	ErrDataCarrierPreviewRoute        = errors.New("preview data-carrier route is not admitted")
	ErrDataCarrierPreviewIdentity     = errors.New("preview data-carrier identity mismatch")
	ErrDataCarrierPreviewOrigin       = errors.New("preview data-carrier origin unavailable")
	ErrDataCarrierPreviewForward      = errors.New("preview data-carrier stream forwarding failed")
	ErrDataCarrierPreviewHubClosed    = errors.New("preview data-carrier hub is closed")
	ErrDataCarrierPreviewRegistration = errors.New("preview data-carrier route is already registered")
)

const (
	defaultDataCarrierPreviewQueue        = 16
	defaultDataCarrierPreviewStreams      = 64
	defaultDataCarrierPreviewDialTimeout  = 10 * time.Second
	defaultDataCarrierPreviewCloseTimeout = 5 * time.Second
)

// PreviewOriginDialer owns the local origin connection policy. The default
// dialer handles the canonical TCP, Unix, and HTTPS target forms. A caller
// that needs a write-only CA or mTLS reference must inject the dialer; this
// package never accepts reusable credential bytes.
type PreviewOriginDialer func(context.Context, LeaseTarget) (io.ReadWriteCloser, error)

// DataCarrierPreviewHub is the single accept loop for one active carrier.
// Multiple foreground previews must share a hub so an incoming stream cannot
// be consumed by the wrong preview while another adapter is waiting.
type DataCarrierPreviewHub struct {
	active   *connector.ActiveDataCarrier
	identity connector.DataCarrierIdentity
	queue    int

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	byRoute   map[string]*dataCarrierPreviewRegistration
}

type DataCarrierPreviewHubConfig struct {
	Active     *connector.ActiveDataCarrier
	Identity   connector.DataCarrierIdentity
	QueueDepth int
}

func NewDataCarrierPreviewHub(ctx context.Context, config DataCarrierPreviewHubConfig) (*DataCarrierPreviewHub, error) {
	if ctx == nil || config.Active == nil || config.Identity == (connector.DataCarrierIdentity{}) {
		return nil, ErrDataCarrierPreviewInvalid
	}
	if err := validatePreviewCarrierIdentity(config.Identity); err != nil {
		return nil, err
	}
	if config.QueueDepth == 0 {
		config.QueueDepth = defaultDataCarrierPreviewQueue
	}
	if config.QueueDepth < 1 || config.QueueDepth > 1024 {
		return nil, ErrDataCarrierPreviewInvalid
	}
	hubContext, cancel := context.WithCancel(ctx)
	hub := &DataCarrierPreviewHub{active: config.Active, identity: config.Identity, queue: config.QueueDepth, ctx: hubContext, cancel: cancel, done: make(chan struct{}), byRoute: make(map[string]*dataCarrierPreviewRegistration)}
	// Start exactly one accept loop at construction. This makes Close safe even
	// when a caller has not registered a preview yet and keeps ownership of
	// ActiveDataCarrier.AcceptStream centralized from the first stream onward.
	go hub.acceptLoop()
	return hub, nil
}

// Register reserves one exact preview route. The registration owns only its
// bounded stream queue; the hub continues serving other routes when it is
// closed.
func (h *DataCarrierPreviewHub) Register(routeID string) (*DataCarrierPreviewRegistration, error) {
	if h == nil || connectorprotocol.ValidateIdentifier(routeID) != nil {
		return nil, ErrDataCarrierPreviewInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrDataCarrierPreviewHubClosed
	}
	if _, exists := h.byRoute[routeID]; exists {
		return nil, ErrDataCarrierPreviewRegistration
	}
	registration := &dataCarrierPreviewRegistration{hub: h, routeID: routeID, queue: make(chan dataCarrierPreviewStream, h.queue), done: make(chan struct{})}
	h.byRoute[routeID] = registration
	return &DataCarrierPreviewRegistration{registration: registration}, nil
}

// DataCarrierPreviewRegistration is the route-scoped receive boundary used by
// DataCarrierPreviewCarrier. It exposes no carrier-wide accept operation.
type DataCarrierPreviewRegistration struct {
	registration *dataCarrierPreviewRegistration
	closeOnce    sync.Once
}

func (r *DataCarrierPreviewRegistration) Accept(ctx context.Context) (*connector.DataCarrierStream, connector.StreamOpen, error) {
	if r == nil || r.registration == nil || ctx == nil {
		return nil, connector.StreamOpen{}, ErrDataCarrierPreviewInvalid
	}
	select {
	case accepted := <-r.registration.queue:
		if accepted.stream == nil {
			return nil, connector.StreamOpen{}, accepted.err
		}
		return accepted.stream, accepted.open, nil
	case <-r.registration.done:
		return nil, connector.StreamOpen{}, r.registration.err()
	case <-ctx.Done():
		return nil, connector.StreamOpen{}, ctx.Err()
	}
}

func (r *DataCarrierPreviewRegistration) Close() error {
	if r == nil || r.registration == nil {
		return nil
	}
	r.closeOnce.Do(func() { r.registration.close() })
	return nil
}

func (h *DataCarrierPreviewHub) Identity() connector.DataCarrierIdentity {
	if h == nil {
		return connector.DataCarrierIdentity{}
	}
	return h.identity
}

func (h *DataCarrierPreviewHub) Done() <-chan struct{} {
	if h == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return h.done
}

// Close stops the one hub accept loop and releases queued streams. It does
// not close the active carrier because tunnel-manager remains its owner.
func (h *DataCarrierPreviewHub) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		registrations := make([]*dataCarrierPreviewRegistration, 0, len(h.byRoute))
		for _, registration := range h.byRoute {
			registrations = append(registrations, registration)
		}
		h.byRoute = make(map[string]*dataCarrierPreviewRegistration)
		h.mu.Unlock()
		h.cancel()
		for _, registration := range registrations {
			registration.closeWith(ErrDataCarrierPreviewHubClosed)
		}
		<-h.done
	})
	return nil
}

type dataCarrierPreviewRegistration struct {
	hub     *DataCarrierPreviewHub
	routeID string
	queue   chan dataCarrierPreviewStream
	done    chan struct{}

	mu        sync.Mutex
	closed    bool
	errValue  error
	closeOnce sync.Once
}

type dataCarrierPreviewStream struct {
	stream *connector.DataCarrierStream
	open   connector.StreamOpen
	err    error
}

func (r *dataCarrierPreviewRegistration) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errValue != nil {
		return r.errValue
	}
	return ErrDataCarrierPreviewClosed
}

func (r *dataCarrierPreviewRegistration) close() {
	r.closeWith(ErrDataCarrierPreviewClosed)
	if r.hub != nil {
		r.hub.mu.Lock()
		if current := r.hub.byRoute[r.routeID]; current == r {
			delete(r.hub.byRoute, r.routeID)
		}
		r.hub.mu.Unlock()
	}
}

func (r *dataCarrierPreviewRegistration) closeWith(err error) {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.errValue = err
		for {
			select {
			case accepted := <-r.queue:
				if accepted.stream != nil {
					_ = accepted.stream.Close()
				}
			default:
				close(r.done)
				r.mu.Unlock()
				return
			}
		}
	})
}

func (r *dataCarrierPreviewRegistration) enqueue(accepted dataCarrierPreviewStream) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	select {
	case r.queue <- accepted:
		return true
	default:
		return false
	}
}

func (h *DataCarrierPreviewHub) acceptLoop() {
	defer close(h.done)
	for {
		stream, open, err := h.active.AcceptStream(h.ctx)
		if err != nil {
			if h.ctx.Err() != nil {
				h.mu.Lock()
				h.closed = true
				h.mu.Unlock()
				h.closeRegistrations(ErrDataCarrierPreviewHubClosed)
				return
			}
			h.mu.Lock()
			h.closed = true
			h.mu.Unlock()
			h.closeRegistrations(errors.Join(ErrDataCarrierPreviewHubClosed, err))
			return
		}
		if stream == nil {
			continue
		}
		if open == (connector.StreamOpen{}) {
			open, err = connectorprotocol.ReadStreamOpen(stream)
		} else {
			err = open.Validate()
		}
		if err == nil && !previewIdentityMatches(h.identity, open) {
			err = ErrDataCarrierPreviewIdentity
		}
		if err != nil {
			_ = stream.Close()
			continue
		}
		h.mu.Lock()
		registration := h.byRoute[open.RouteID]
		h.mu.Unlock()
		if registration == nil {
			_ = stream.Close()
			continue
		}
		if !registration.enqueue(dataCarrierPreviewStream{stream: stream, open: open}) {
			_ = stream.Close()
		}
	}
}

func (h *DataCarrierPreviewHub) closeRegistrations(err error) {
	h.mu.Lock()
	registrations := make([]*dataCarrierPreviewRegistration, 0, len(h.byRoute))
	for _, registration := range h.byRoute {
		registrations = append(registrations, registration)
	}
	h.byRoute = make(map[string]*dataCarrierPreviewRegistration)
	h.mu.Unlock()
	for _, registration := range registrations {
		registration.closeWith(err)
	}
}

// DataCarrierPreviewCarrier adapts one route registration to preview.Carrier.
// It probes the local origin before reporting readiness and then forwards
// admitted streams without buffering application bytes.
type DataCarrierPreviewCarrier struct {
	hub       *DataCarrierPreviewHub
	active    *connector.ActiveDataCarrier
	identity  connector.DataCarrierIdentity
	routeID   string
	dialer    PreviewOriginDialer
	max       int
	dialWait  time.Duration
	closeWait time.Duration
	observe   func(error)
	ownHub    bool

	mu        sync.Mutex
	closed    bool
	register  *DataCarrierPreviewRegistration
	runCancel context.CancelFunc
	runDone   chan struct{}
}

type DataCarrierPreviewCarrierConfig struct {
	Hub      *DataCarrierPreviewHub
	Active   *connector.ActiveDataCarrier
	Identity connector.DataCarrierIdentity
	// RouteID is the server-authorized route admission key. It may differ
	// from the preview lease ID when a preview is attached to an ephemeral
	// route. An empty value keeps the direct carrier constructor compatible
	// with leases whose route and lease IDs are identical.
	RouteID            string
	DialOrigin         PreviewOriginDialer
	MaxStreams         int
	OriginDialTimeout  time.Duration
	OriginCloseTimeout time.Duration
	ObserveStreamError func(error)
}

func NewDataCarrierPreviewCarrier(config DataCarrierPreviewCarrierConfig) (*DataCarrierPreviewCarrier, error) {
	if config.Hub == nil && config.Active == nil || config.Hub != nil && config.Active != nil {
		return nil, ErrDataCarrierPreviewInvalid
	}
	ownHub := false
	if config.Hub == nil {
		if config.Identity == (connector.DataCarrierIdentity{}) {
			return nil, ErrDataCarrierPreviewInvalid
		}
		var err error
		config.Hub, err = NewDataCarrierPreviewHub(context.Background(), DataCarrierPreviewHubConfig{Active: config.Active, Identity: config.Identity})
		if err != nil {
			return nil, err
		}
		ownHub = true
	}
	if config.Identity == (connector.DataCarrierIdentity{}) {
		config.Identity = config.Hub.Identity()
	}
	if err := validatePreviewCarrierIdentity(config.Identity); err != nil || config.Hub.Identity() != config.Identity {
		return nil, ErrDataCarrierPreviewIdentity
	}
	if config.RouteID != "" && connectorprotocol.ValidateIdentifier(config.RouteID) != nil {
		return nil, ErrDataCarrierPreviewInvalid
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = defaultDataCarrierPreviewStreams
	}
	if config.MaxStreams < 1 || config.MaxStreams > 1024 {
		return nil, ErrDataCarrierPreviewInvalid
	}
	if config.OriginDialTimeout == 0 {
		config.OriginDialTimeout = defaultDataCarrierPreviewDialTimeout
	}
	if config.OriginCloseTimeout == 0 {
		config.OriginCloseTimeout = defaultDataCarrierPreviewCloseTimeout
	}
	if config.OriginDialTimeout <= 0 || config.OriginCloseTimeout <= 0 {
		return nil, ErrDataCarrierPreviewInvalid
	}
	return &DataCarrierPreviewCarrier{hub: config.Hub, active: config.Active, identity: config.Identity, routeID: config.RouteID, dialer: config.DialOrigin, max: config.MaxStreams, dialWait: config.OriginDialTimeout, closeWait: config.OriginCloseTimeout, observe: config.ObserveStreamError, ownHub: ownHub}, nil
}

func (c *DataCarrierPreviewCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	if c == nil || ctx == nil || ready == nil {
		return ErrDataCarrierPreviewInvalid
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrDataCarrierPreviewClosed
	}
	if c.register != nil {
		c.mu.Unlock()
		return ErrDataCarrierPreviewInvalid
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	runDone := make(chan struct{})
	routeID := c.routeID
	if routeID == "" {
		routeID = lease.ID
	}
	if connectorprotocol.ValidateIdentifier(routeID) != nil {
		cancelRun()
		c.mu.Unlock()
		return ErrDataCarrierPreviewInvalid
	}
	registration, err := c.hub.Register(routeID)
	if err != nil {
		cancelRun()
		c.mu.Unlock()
		return err
	}
	c.register = registration
	c.runCancel = cancelRun
	c.runDone = runDone
	c.mu.Unlock()
	defer func() {
		_ = registration.Close()
		cancelRun()
		close(runDone)
		c.mu.Lock()
		if c.register == registration {
			c.register = nil
		}
		if c.runDone == runDone {
			c.runDone = nil
			c.runCancel = nil
		}
		c.mu.Unlock()
	}()

	probeCtx, cancelProbe := context.WithTimeout(runCtx, c.dialWait)
	origin, err := c.dialOrigin(probeCtx, lease.Target)
	cancelProbe()
	if err != nil {
		return &RetryableCarrierError{Err: errors.Join(ErrDataCarrierPreviewOrigin, err)}
	}
	_ = closeWithTimeout(origin, c.closeWait)
	observed := lease
	observed.State, observed.AllocationState, observed.EdgeState, observed.OriginState = "ready", "ready", "ready", "ready"
	if err := ready(observed); err != nil {
		return err
	}

	permits := make(chan struct{}, c.max)
	var streams sync.WaitGroup
	for {
		stream, open, err := registration.Accept(runCtx)
		if err != nil {
			streams.Wait()
			if ctx.Err() != nil || c.isClosed() {
				return nil
			}
			if errors.Is(err, ErrDataCarrierPreviewHubClosed) || errors.Is(err, connector.ErrDataCarrierClosed) {
				return &RetryableCarrierError{Err: err}
			}
			return err
		}
		if open.RouteID != routeID || !previewIdentityMatches(c.identity, open) {
			_ = stream.Close()
			continue
		}
		select {
		case permits <- struct{}{}:
			streams.Add(1)
			go func(stream *connector.DataCarrierStream) {
				defer streams.Done()
				defer func() { <-permits }()
				if err := c.forward(runCtx, stream, lease.Target); err != nil && c.observe != nil {
					c.observe(err)
				}
			}(stream)
		default:
			_ = stream.Close()
		}
	}
}

func (c *DataCarrierPreviewCarrier) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrDataCarrierPreviewInvalid
	}
	c.mu.Lock()
	if c.closed {
		done := c.runDone
		c.mu.Unlock()
		if done == nil {
			return nil
		}
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.closed = true
	registration := c.register
	c.register = nil
	hub := c.hub
	ownHub := c.ownHub
	cancelRun := c.runCancel
	runDone := c.runDone
	c.mu.Unlock()
	if registration != nil {
		_ = registration.Close()
	}
	if cancelRun != nil {
		cancelRun()
	}
	if ownHub && hub != nil {
		if err := hub.Close(); err != nil {
			return err
		}
	}
	// The shared hub/manager owns the active pool and remains alive for other
	// preview routes. Closing one carrier only unregisters its route.
	if runDone != nil {
		select {
		case <-runDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *DataCarrierPreviewCarrier) isClosed() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	return closed
}

func (c *DataCarrierPreviewCarrier) dialOrigin(ctx context.Context, target LeaseTarget) (io.ReadWriteCloser, error) {
	if c.dialer != nil {
		return c.dialer(ctx, target)
	}
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if strings.TrimSpace(target.Address) == "" {
		return nil, ErrDataCarrierPreviewInvalid
	}
	dialer := &net.Dialer{}
	var (
		connection net.Conn
		err        error
	)
	if scheme == "unix" {
		connection, err = dialer.DialContext(ctx, "unix", target.Address)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", target.Address)
	}
	if err != nil {
		return nil, err
	}
	if scheme != "https" {
		return connection, nil
	}
	host := target.Address
	if parsed, _, splitErr := net.SplitHostPort(target.Address); splitErr == nil {
		host = strings.Trim(parsed, "[]")
	}
	tlsConnection := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func (c *DataCarrierPreviewCarrier) forward(ctx context.Context, stream *connector.DataCarrierStream, target LeaseTarget) error {
	if stream == nil {
		return ErrDataCarrierPreviewInvalid
	}
	originCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	origin, err := c.dialOrigin(originCtx, target)
	if err != nil {
		_ = stream.Close()
		return err
	}
	defer closeWithTimeout(origin, c.closeWait)
	stopClose := context.AfterFunc(originCtx, func() {
		_ = stream.Close()
		_ = origin.Close()
	})
	defer stopClose()
	copyDone := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(origin, stream)
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(stream, origin)
		copyDone <- copyErr
	}()
	var firstErr error
	select {
	case firstErr = <-copyDone:
	case <-originCtx.Done():
	}
	cancel()
	_ = stream.Close()
	_ = origin.Close()
	if firstErr != nil && !errors.Is(firstErr, io.EOF) && !errors.Is(firstErr, net.ErrClosed) && !errors.Is(firstErr, io.ErrClosedPipe) && !errors.Is(firstErr, context.Canceled) {
		return &RetryableCarrierError{Err: errors.Join(ErrDataCarrierPreviewForward, firstErr)}
	}
	return nil
}

func closeWithTimeout(stream io.Closer, timeout time.Duration) error {
	if stream == nil {
		return nil
	}
	if timeout <= 0 {
		return stream.Close()
	}
	result := make(chan error, 1)
	go func() { result <- stream.Close() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func validatePreviewCarrierIdentity(identity connector.DataCarrierIdentity) error {
	if connectorprotocol.ValidateIdentifier(identity.AccountID) != nil || connectorprotocol.ValidateIdentifier(identity.HostID) != nil || connectorprotocol.ValidateIdentifier(identity.TunnelID) != nil || connectorprotocol.ValidateIdentifier(identity.ConnectorID) != nil || connectorprotocol.ValidateIdentifier(identity.SessionID) != nil || identity.ProcessGeneration == 0 || identity.Generation == 0 {
		return ErrDataCarrierPreviewInvalid
	}
	return nil
}

func previewIdentityMatches(identity connector.DataCarrierIdentity, open connector.StreamOpen) bool {
	return open.AccountID == identity.AccountID && open.TunnelID == identity.TunnelID && open.ConnectorID == identity.ConnectorID && open.SessionID == identity.SessionID && open.ProcessGeneration == identity.ProcessGeneration && open.Generation == identity.Generation
}

func (c *DataCarrierPreviewCarrier) String() string {
	if c == nil {
		return "preview-data-carrier<nil>"
	}
	return fmt.Sprintf("preview-data-carrier<%s/%d>", c.identity.ConnectorID, c.identity.Generation)
}

var _ Carrier = (*DataCarrierPreviewCarrier)(nil)
