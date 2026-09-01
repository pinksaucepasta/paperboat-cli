package preview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
)

var (
	ErrMachinePreviewRuntimeInvalid = errors.New("invalid machine preview runtime")
	ErrMachinePreviewRuntimeClosed  = errors.New("machine preview runtime is closed")
)

// MachinePreviewRuntimeConfig is the production composition boundary for a
// local CLI or host runtime. ControlURL and StateRoot are explicit because
// neither the edge endpoint nor the machine credential may be inferred from a
// preview target or owner-session nonce.
type MachinePreviewRuntimeConfig struct {
	ControlURL string
	StateRoot  string
	RunContext context.Context

	Transport       http.RoundTripper
	Carrier         connector.DataCarrierPoolConfig
	TLSLeafLifetime time.Duration
	SessionFactory  DataCarrierSessionSourceFactory

	QueueDepth         int
	MaxStreams         int
	OriginDial         PreviewOriginDialer
	OriginDialTimeout  time.Duration
	OriginCloseTimeout time.Duration
	ObserveStreamError func(error)
}

// MachinePreviewRuntime owns one authenticated machine carrier source and
// one route hub registry. Multiple preview routes created through the same
// runtime therefore share the machine identity/carrier safely; stopping one
// route only drops its own reference.
type MachinePreviewRuntime struct {
	attachments *AttachmentClient
	sessions    *MachineAttachmentSessionSource
	provider    *AttachmentPreviewCarrierProvider
	private     *PrivateAccessSource
	auth        *machinecontrol.Source
	machineID   string

	mu     sync.Mutex
	closed bool
	refs   int
}

// NewMachinePreviewRuntime validates the local registration before creating
// any network-facing client. A registration for another server is rejected so
// machine proofs and carrier admissions cannot cross environments.
func NewMachinePreviewRuntime(config MachinePreviewRuntimeConfig) (*MachinePreviewRuntime, error) {
	if config.RunContext == nil || !filepath.IsAbs(strings.TrimSpace(config.StateRoot)) {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	control, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || control.Scheme != "https" || control.Hostname() == "" || control.User != nil || control.RawQuery != "" || control.Fragment != "" || control.Path != "" && control.Path != "/" {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	store, err := identity.Open(identity.Config{StateRoot: config.StateRoot})
	if err != nil {
		return nil, fmt.Errorf("%w: open identity: %v", ErrMachinePreviewRuntimeInvalid, err)
	}
	registration, err := store.Registration()
	if err != nil || registration.MachineID == "" || registration.ServerURL != control.String() {
		return nil, fmt.Errorf("%w: local registration does not match control server", ErrMachinePreviewRuntimeInvalid)
	}
	auth, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: control.String(), StateRoot: config.StateRoot, Transport: config.Transport})
	if err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	grantClient, err := newPrivateAccessGrantClient(control.String(), auth, config.Transport)
	if err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	privateAccess, err := newPrivateAccessSource(grantClient)
	if err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	attachments, err := NewAttachmentClient(AttachmentClientConfig{
		ControlURL: control.String(), AllowedHosts: []string{control.Hostname()},
		Tokens: auth, Identities: auth, Proofs: auth, Transport: config.Transport,
	})
	if err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	sessions, err := NewMachineAttachmentSessionSource(MachineAttachmentSessionSourceConfig{
		StateRoot: config.StateRoot,
		Carrier:   config.Carrier, TLSLeafLifetime: config.TLSLeafLifetime, SessionFactory: config.SessionFactory,
	})
	if err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	discovery, err := newAccessorDiscoveryClient(control.String(), auth, config.Transport)
	if err != nil {
		_ = sessions.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	if err = privateAccess.configureAccessor(discovery, sessions); err != nil {
		_ = sessions.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	provider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{
		Sessions: sessions, PrivateAccess: privateAccess, RunContext: config.RunContext, QueueDepth: config.QueueDepth, MaxStreams: config.MaxStreams,
		OriginDial: config.OriginDial, OriginDialTimeout: config.OriginDialTimeout, OriginCloseTimeout: config.OriginCloseTimeout,
		ObserveStreamError: config.ObserveStreamError,
	})
	if err != nil {
		_ = sessions.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	return &MachinePreviewRuntime{attachments: attachments, sessions: sessions, provider: provider, private: privateAccess, auth: auth, machineID: registration.MachineID}, nil
}

// NewCarrier creates a route-scoped lazy attachment carrier. The target is
// checked at composition time for a useful typed error, while the server
// remains authoritative for the lease target and access mode.
func (r *MachinePreviewRuntime) NewCarrier(ctx context.Context, target LeaseTarget, machineID, ownerSessionID string) (Carrier, error) {
	if r == nil || ctx == nil || strings.TrimSpace(machineID) == "" || !validAttachmentID(strings.TrimSpace(ownerSessionID)) {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	if err := validateAttachmentTarget(target); err != nil {
		return nil, errors.Join(ErrMachinePreviewRuntimeInvalid, err)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrMachinePreviewRuntimeClosed
	}
	if machineID != r.machineID {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: machine identity differs from registration", ErrMachinePreviewRuntimeInvalid)
	}
	r.refs++
	r.mu.Unlock()
	carrier, err := NewAttachmentCarrier(AttachmentCarrierConfig{Attachments: r.attachments, Provider: r.provider})
	if err != nil {
		_ = r.release(ctx)
		return nil, err
	}
	return &machinePreviewCarrier{inner: carrier, runtime: r}, nil
}

// ResolvePreviewCarrier attaches a server-delivered dispatch to this stable
// host runtime. The dispatch already contains the authoritative lease target
// and owner binding; this method only creates the lazy attachment carrier.
// Actual carrier allocation remains deferred until Session.Run so a duplicate
// or canceled dispatch cannot create a second server-side attachment.
func (r *MachinePreviewRuntime) ResolvePreviewCarrier(ctx context.Context, request DispatchRequest) (Carrier, error) {
	if r == nil || ctx == nil {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	if _, err := request.Validate(r.machineID, time.Now().UTC()); err != nil {
		return nil, err
	}
	return r.NewCarrier(ctx, request.Target, request.OwnerDeviceID, request.OwnerSessionID)
}

// MachineAuthSource returns the same renewable source used by the attachment
// client. API callers can install it on api.Client for machine-proof preview
// create/renew/stop calls without taking ownership of its secret material.
func (r *MachinePreviewRuntime) MachineAuthSource() (api.MachineAuthSource, error) {
	if r == nil {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrMachinePreviewRuntimeClosed
	}
	return r.auth, nil
}

// PrivateAccessSource returns the stable runtime's narrow PAC and CONNECT
// source. Callers do not receive the renewable machine credential or carrier
// ownership; every Open reauthorizes through this runtime.
func (r *MachinePreviewRuntime) PrivateAccessSource() (*PrivateAccessSource, error) {
	if r == nil {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.private == nil {
		return nil, ErrMachinePreviewRuntimeClosed
	}
	return r.private, nil
}

// Close fences route hubs and closes the source-owned authenticated carrier.
// It is safe to call after all route carriers have released themselves.
func (r *MachinePreviewRuntime) Close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrMachinePreviewRuntimeInvalid
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	if r.private != nil {
		r.private.Close()
	}
	return errors.Join(r.provider.Close(ctx), r.sessions.Close(ctx))
}

func (r *MachinePreviewRuntime) release(ctx context.Context) error {
	r.mu.Lock()
	if r.refs > 0 {
		r.refs--
	}
	r.mu.Unlock()
	// The runtime is owned by stable hostd, not by an individual preview
	// route. A route release only drops its reference; closing the shared
	// machine carrier here would make the next server dispatch fail. Hostd's
	// production assembly calls Close exactly once during shutdown.
	_ = ctx
	return nil
}

type machinePreviewCarrier struct {
	inner   *AttachmentCarrier
	runtime *MachinePreviewRuntime
	once    sync.Once
	mu      sync.Mutex
	err     error
}

func (c *machinePreviewCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	if c == nil || c.inner == nil {
		return ErrMachinePreviewRuntimeInvalid
	}
	return c.inner.Run(ctx, lease, ready)
}

// MachineAuthSource exposes the same renewable source used by this carrier's
// attachment client. The CLI installs it on its API client before creating the
// lease, so the owner-session nonce can never become the machine identity.
func (c *machinePreviewCarrier) MachineAuthSource() (api.MachineAuthSource, error) {
	if c == nil || c.runtime == nil {
		return nil, ErrMachinePreviewRuntimeInvalid
	}
	return c.runtime.MachineAuthSource()
}

func (c *machinePreviewCarrier) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrMachinePreviewRuntimeInvalid
	}
	c.once.Do(func() {
		c.err = errors.Join(c.inner.Close(ctx), c.runtime.release(ctx))
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

var _ Carrier = (*machinePreviewCarrier)(nil)
var _ api.MachineAuthSource = (*machinecontrol.Source)(nil)
