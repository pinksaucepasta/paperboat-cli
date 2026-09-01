package preview

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

var (
	ErrPreviewCarrierProviderInvalid     = errors.New("invalid preview carrier provider")
	ErrPreviewCarrierProviderUnavailable = errors.New("preview carrier provider unavailable")
	ErrPreviewCarrierProviderClosed      = errors.New("preview carrier provider is closed")
)

// AttachmentSessionSource acquires an already authenticated, ephemeral
// carrier for the exact server admission. It is deliberately injected: the
// source owns renewable machine credentials and endpoint dialing, while this
// package only consumes the resulting safe ActiveDataCarrier handle.
type AttachmentSessionSource interface {
	AcquirePreviewDataCarrier(context.Context, CarrierAdmission) (AttachmentSession, error)
}

// AttachmentSession is the source-owned authenticated carrier projection.
// Identity must be the identity proven by the live connector-v1 session, not
// one reconstructed from the preview request or durable lease.
type AttachmentSession struct {
	Active   *connector.ActiveDataCarrier
	Identity connector.DataCarrierIdentity
	// Release drops this acquisition's ownership reference. The source must
	// make it idempotent and close an ephemeral transport only after its own
	// references reach zero.
	Release func(context.Context) error
}

// AttachmentSessionSourceFunc adapts a function to
// AttachmentSessionSource without weakening the explicit admission boundary.
type AttachmentSessionSourceFunc func(context.Context, CarrierAdmission) (AttachmentSession, error)

func (f AttachmentSessionSourceFunc) AcquirePreviewDataCarrier(ctx context.Context, admission CarrierAdmission) (AttachmentSession, error) {
	if f == nil {
		return AttachmentSession{}, ErrPreviewCarrierProviderInvalid
	}
	return f(ctx, admission)
}

// PreviewCarrierProvider resolves a validated server attachment to a
// route-scoped preview carrier. One provider owns one hub per active carrier;
// individual previews never call ActiveDataCarrier.AcceptStream directly.
type PreviewCarrierProvider interface {
	CarrierForAttachment(context.Context, Lease, Attachment) (Carrier, error)
	Close(context.Context) error
}

type AttachmentPreviewCarrierProviderConfig struct {
	Sessions           AttachmentSessionSource
	PrivateAccess      *PrivateAccessSource
	RunContext         context.Context
	QueueDepth         int
	MaxStreams         int
	OriginDial         PreviewOriginDialer
	OriginDialTimeout  time.Duration
	OriginCloseTimeout time.Duration
	ObserveStreamError func(error)
}

// AttachmentPreviewCarrierProvider owns only hubs and route registrations.
// ActiveDataCarrier lifetime remains with the authenticated session source or
// tunnel manager, so replacing a carrier cannot accidentally close a shared
// transport used by other routes.
type AttachmentPreviewCarrierProvider struct {
	sessions  AttachmentSessionSource
	private   *PrivateAccessSource
	ctx       context.Context
	cancel    context.CancelFunc
	queue     int
	max       int
	dial      PreviewOriginDialer
	dialWait  time.Duration
	closeWait time.Duration
	observe   func(error)

	mu         sync.Mutex
	closed     bool
	hubs       map[attachmentHubKey]*attachmentHubEntry
	allEntries map[*attachmentHubEntry]struct{}
}

type attachmentHubKey struct {
	accountID   string
	hostID      string
	tunnelID    string
	connectorID string
}

type attachmentHubEntry struct {
	active   *connector.ActiveDataCarrier
	identity connector.DataCarrierIdentity
	// session is the provider's lifetime reference to the source-owned active
	// carrier. Route carriers only register/unregister with this hub; stopping
	// the last route must not tear down the stable host machine carrier.
	session  AttachmentSession
	hub      *DataCarrierPreviewHub
	refs     int
	carriers map[*attachmentPreviewCarrier]struct{}
}

func NewAttachmentPreviewCarrierProvider(config AttachmentPreviewCarrierProviderConfig) (*AttachmentPreviewCarrierProvider, error) {
	if config.Sessions == nil || config.RunContext == nil {
		return nil, ErrPreviewCarrierProviderInvalid
	}
	if config.QueueDepth == 0 {
		config.QueueDepth = defaultDataCarrierPreviewQueue
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = defaultDataCarrierPreviewStreams
	}
	if config.QueueDepth < 1 || config.QueueDepth > 1024 || config.MaxStreams < 1 || config.MaxStreams > 1024 {
		return nil, ErrPreviewCarrierProviderInvalid
	}
	if config.OriginDialTimeout == 0 {
		config.OriginDialTimeout = defaultDataCarrierPreviewDialTimeout
	}
	if config.OriginCloseTimeout == 0 {
		config.OriginCloseTimeout = defaultDataCarrierPreviewCloseTimeout
	}
	if config.OriginDialTimeout <= 0 || config.OriginCloseTimeout <= 0 {
		return nil, ErrPreviewCarrierProviderInvalid
	}
	ctx, cancel := context.WithCancel(config.RunContext)
	return &AttachmentPreviewCarrierProvider{
		sessions: config.Sessions, private: config.PrivateAccess, ctx: ctx, cancel: cancel,
		queue: config.QueueDepth, max: config.MaxStreams, dial: config.OriginDial,
		dialWait: config.OriginDialTimeout, closeWait: config.OriginCloseTimeout,
		observe: config.ObserveStreamError,
		hubs:    make(map[attachmentHubKey]*attachmentHubEntry), allEntries: make(map[*attachmentHubEntry]struct{}),
	}, nil
}

// CarrierForAttachment validates all lease and server binding fields before
// asking the injected source for a live carrier. The request context is used
// only for acquisition; the hub is owned by the provider runtime context and
// therefore cannot be killed by a browser/request cancellation.
func (p *AttachmentPreviewCarrierProvider) CarrierForAttachment(ctx context.Context, lease Lease, attachment Attachment) (Carrier, error) {
	if p == nil || ctx == nil {
		return nil, ErrPreviewCarrierProviderInvalid
	}
	now := time.Now().UTC()
	if err := validateAttachmentLease(lease, attachment, now); err != nil {
		return nil, err
	}
	admission, err := attachment.Admission()
	if err != nil {
		return nil, err
	}
	if err := admission.Validate(now); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPreviewCarrierProviderClosed
	}
	p.mu.Unlock()
	session, err := p.sessions.AcquirePreviewDataCarrier(ctx, admission)
	if err != nil {
		return nil, errors.Join(ErrPreviewCarrierProviderUnavailable, err)
	}
	if err := validateAttachmentSession(session, admission); err != nil {
		_ = releaseAttachmentSession(ctx, session)
		return nil, err
	}
	key := attachmentHubKey{accountID: admission.Binding.AccountID, hostID: admission.Binding.HostID, tunnelID: admission.Binding.TunnelID, connectorID: admission.Binding.ConnectorID}
	entry, reused, err := p.hubForSession(key, session)
	if err != nil {
		_ = releaseAttachmentSession(ctx, session)
		return nil, err
	}
	if reused {
		// hubForSession already has a provider-owned reference for this active
		// carrier. Balance this route's source acquisition without attaching
		// its release callback to the route lifetime.
		if err := releaseAttachmentSession(ctx, session); err != nil {
			return nil, err
		}
		session = AttachmentSession{}
	}
	carrier, err := NewDataCarrierPreviewCarrier(DataCarrierPreviewCarrierConfig{
		Hub: entry.hub, Identity: session.Identity, RouteID: admission.Binding.RouteID,
		DialOrigin: p.dial, MaxStreams: p.max, OriginDialTimeout: p.dialWait,
		OriginCloseTimeout: p.closeWait,
		ObserveStreamError: p.observe,
	})
	if err != nil {
		_ = releaseAttachmentSession(ctx, session)
		return nil, err
	}
	wrapped := &attachmentPreviewCarrier{inner: carrier, provider: p, entry: entry, session: session, key: key}
	if err := p.retainCarrier(wrapped); err != nil {
		_ = carrier.Close(ctx)
		_ = releaseAttachmentSession(ctx, session)
		return nil, err
	}
	if lease.AccessMode == "private" {
		if p.private == nil {
			_ = wrapped.Close(ctx)
			return nil, ErrPrivateAccessInvalid
		}
		host, hostErr := privateAccessEndpointHost(lease.Endpoint)
		if hostErr != nil {
			_ = wrapped.Close(ctx)
			return nil, hostErr
		}
		token, registerErr := p.private.register(lease, admission, entry.active, entry.identity)
		if registerErr != nil {
			_ = wrapped.Close(ctx)
			return nil, registerErr
		}
		wrapped.accessHost = host
		wrapped.accessToken = token
	}
	return wrapped, nil
}

func (p *AttachmentPreviewCarrierProvider) hubForSession(key attachmentHubKey, session AttachmentSession) (*attachmentHubEntry, bool, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, false, ErrPreviewCarrierProviderClosed
	}
	if existing := p.hubs[key]; existing != nil && existing.active == session.Active && existing.identity == session.Identity {
		p.mu.Unlock()
		return existing, true, nil
	}
	if err := validatePreviewCarrierIdentity(session.Identity); err != nil {
		p.mu.Unlock()
		return nil, false, err
	}
	hub, err := NewDataCarrierPreviewHub(p.ctx, DataCarrierPreviewHubConfig{Active: session.Active, Identity: session.Identity, QueueDepth: p.queue})
	if err != nil {
		p.mu.Unlock()
		return nil, false, err
	}
	previous := p.hubs[key]
	entry := &attachmentHubEntry{active: session.Active, identity: session.Identity, session: session, hub: hub, carriers: make(map[*attachmentPreviewCarrier]struct{})}
	p.hubs[key] = entry
	p.allEntries[entry] = struct{}{}
	p.mu.Unlock()
	if previous != nil {
		// Fence the previous generation after publishing the replacement. Close only
		// the old hub, never the active carrier owned by another component.
		_ = previous.hub.Close()
		_ = releaseAttachmentSession(context.WithoutCancel(p.ctx), previous.session)
	}
	return entry, false, nil
}

func (p *AttachmentPreviewCarrierProvider) retainCarrier(carrier *attachmentPreviewCarrier) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPreviewCarrierProviderClosed
	}
	if current := p.hubs[carrier.key]; current != carrier.entry {
		return fmt.Errorf("%w: carrier generation was replaced", ErrPreviewCarrierProviderUnavailable)
	}
	carrier.entry.refs++
	carrier.entry.carriers[carrier] = struct{}{}
	return nil
}

func (p *AttachmentPreviewCarrierProvider) releaseCarrier(carrier *attachmentPreviewCarrier, ctx context.Context) error {
	if carrier == nil {
		return nil
	}
	var closeHub *DataCarrierPreviewHub
	p.mu.Lock()
	if carrier.entry != nil {
		if _, exists := carrier.entry.carriers[carrier]; exists {
			delete(carrier.entry.carriers, carrier)
			if carrier.entry.refs > 0 {
				carrier.entry.refs--
			}
		}
		// The entry remains while the provider is alive, including when refs
		// reaches zero. This is the stable hostd carrier lifetime; a later
		// preview route can register on the same hub without dialing another
		// machine carrier. Replaced generations are removed once their final
		// route releases.
		if carrier.entry.refs == 0 && p.hubs[carrier.key] != carrier.entry {
			delete(p.allEntries, carrier.entry)
			closeHub = carrier.entry.hub
		}
	}
	p.mu.Unlock()
	if closeHub != nil {
		if err := closeHub.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Close fences every hub and releases route queues. The active transport
// handles are intentionally not closed here because their authenticated
// session source/tunnel manager owns that lifecycle.
func (p *AttachmentPreviewCarrierProvider) Close(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrPreviewCarrierProviderInvalid
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	entries := make([]*attachmentHubEntry, 0, len(p.allEntries))
	for entry := range p.allEntries {
		entries = append(entries, entry)
	}
	hubs := make([]*DataCarrierPreviewHub, 0, len(entries))
	carriers := make([]*attachmentPreviewCarrier, 0)
	sessions := make([]AttachmentSession, 0, len(entries))
	for _, entry := range entries {
		if entry != nil && entry.hub != nil {
			hubs = append(hubs, entry.hub)
		}
		if entry != nil && entry.session.Active != nil {
			sessions = append(sessions, entry.session)
		}
		for carrier := range entry.carriers {
			carriers = append(carriers, carrier)
		}
	}
	p.hubs = make(map[attachmentHubKey]*attachmentHubEntry)
	p.allEntries = make(map[*attachmentHubEntry]struct{})
	p.mu.Unlock()
	for _, hub := range hubs {
		closed := make(chan error, 1)
		go func(h *DataCarrierPreviewHub) { closed <- h.Close() }(hub)
		select {
		case err := <-closed:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, carrier := range carriers {
		if err := carrier.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	for _, session := range sessions {
		if err := releaseAttachmentSession(ctx, session); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

func (p *AttachmentPreviewCarrierProvider) Shutdown(ctx context.Context) error {
	return p.Close(ctx)
}

func validateAttachmentLease(lease Lease, attachment Attachment, now time.Time) error {
	if lease.Schema != PreviewTunnelSchemaV1 || lease.Kind != PreviewLeaseKind || !validLeaseID(lease.ID) || !validLeaseID(lease.AccountID) || !validLeaseID(lease.OwnerDeviceID) || !validLeaseID(lease.OwnerSessionID) {
		return fmt.Errorf("%w: lease identity is invalid", ErrAttachmentBinding)
	}
	if lease.Persistent || lease.LeaseDeadline.IsZero() || !lease.LeaseDeadline.After(now) || lease.Generation < 1 || !validLeaseID(lease.CreateOperationID) {
		return fmt.Errorf("%w: lease is not attachable", ErrAttachmentBinding)
	}
	if err := validateAttachmentEndpoint(lease.Endpoint, false); err != nil {
		return err
	}
	if err := attachment.Validate(now); err != nil {
		return err
	}
	if attachment.PreviewID != lease.ID || attachment.AccountID != lease.AccountID || attachment.OperationID != lease.CreateOperationID || attachment.OwnerDeviceID != lease.OwnerDeviceID || attachment.OwnerSessionID != lease.OwnerSessionID || attachment.Target != lease.Target || attachment.AccessMode != lease.AccessMode || attachment.Endpoint != lease.Endpoint || attachment.Binding.LeaseGeneration != uint64(lease.Generation) {
		return fmt.Errorf("%w: attachment does not match lease", ErrAttachmentBinding)
	}
	if attachment.ExpiresAt.After(lease.LeaseDeadline) {
		return fmt.Errorf("%w: attachment lifetime exceeds lease", ErrAttachmentBinding)
	}
	return nil
}

func validateAttachmentSession(session AttachmentSession, admission CarrierAdmission) error {
	if session.Active == nil || session.Release == nil {
		return fmt.Errorf("%w: source returned no active carrier", ErrAttachmentSessionInvalid)
	}
	if err := validatePreviewCarrierIdentity(session.Identity); err != nil {
		return fmt.Errorf("%w: source identity is invalid", ErrAttachmentSessionInvalid)
	}
	b := admission.Binding
	if session.Identity.AccountID != b.AccountID || session.Identity.HostID != b.HostID || session.Identity.TunnelID != b.TunnelID || session.Identity.ConnectorID != b.ConnectorID || session.Identity.SessionID != b.SessionID || session.Identity.ProcessGeneration != b.ProcessGeneration || session.Identity.Generation != b.ConfigGeneration {
		return fmt.Errorf("%w: source identity does not match admission", ErrAttachmentSessionInvalid)
	}
	for _, info := range session.Active.Snapshot() {
		if info.Identity == session.Identity && info.State == connector.DataCarrierReady {
			return nil
		}
	}
	return fmt.Errorf("%w: active carrier is not ready for admission identity", ErrAttachmentSessionInvalid)
}

func releaseAttachmentSession(ctx context.Context, session AttachmentSession) error {
	if session.Release == nil {
		return nil
	}
	return session.Release(ctx)
}

type attachmentPreviewCarrier struct {
	inner       *DataCarrierPreviewCarrier
	provider    *AttachmentPreviewCarrierProvider
	entry       *attachmentHubEntry
	session     AttachmentSession
	key         attachmentHubKey
	accessHost  string
	accessToken uint64
	once        sync.Once
	mu          sync.Mutex
	closeErr    error
}

func (c *attachmentPreviewCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	if c == nil || c.inner == nil {
		return ErrPreviewCarrierProviderInvalid
	}
	defer c.release(ctx)
	return c.inner.Run(ctx, lease, ready)
}

func (c *attachmentPreviewCarrier) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrPreviewCarrierProviderInvalid
	}
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	err := c.inner.Close(ctx)
	releaseErr := c.release(ctx)
	combined := errors.Join(err, releaseErr)
	c.mu.Lock()
	c.closeErr = combined
	c.mu.Unlock()
	return combined
}

func (c *attachmentPreviewCarrier) release(ctx context.Context) error {
	var err error
	c.once.Do(func() {
		if c.provider != nil && c.provider.private != nil && c.accessToken != 0 {
			c.provider.private.unregister(c.accessHost, c.accessToken)
		}
		if c.provider != nil {
			err = c.provider.releaseCarrier(c, ctx)
		} else {
			err = releaseAttachmentSession(ctx, c.session)
		}
	})
	return err
}

var _ PreviewCarrierProvider = (*AttachmentPreviewCarrierProvider)(nil)
var _ AttachmentSessionSource = AttachmentSessionSourceFunc(nil)
