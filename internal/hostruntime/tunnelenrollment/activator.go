package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// CredentialSigner is a reference-backed signing boundary. Implementations
// must not expose the Ed25519 private key to the assembly source.
type CredentialSigner func(context.Context, []byte) ([]byte, error)

// ProductionAssemblySource resolves the server-authoritative connector-v1
// bootstrap composition. The returned config must contain an authenticated
// ControlStream and a CarrierDescriptorSource. The latter is invoked only
// after Welcome supplies the server-owned SessionID.
//
// The source owns HTTP/WebSocket transport and server response validation.
// It must bind the returned Hello, connector, process generation, credential
// generation, endpoints, and TLS peer authority to request. The signer uses
// request.CredentialReference without releasing private bytes.
type ProductionAssemblySource interface {
	ResolveProductionAssembly(context.Context, ActivationRequest, CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error)
}

// ProductionAssemblyBinder lets a source attach runtime-owned drain,
// replacement, and readiness adapters before the control stream starts.
type ProductionAssemblyBinder interface {
	BindProductionAssembly(ActivationRequest, *tunnelmanager.ProductionAssembly) error
}

type ProductionAssemblySourceLifecycle interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

type ProductionAssemblyActivatorConfig struct {
	Credentials CredentialStore
	Source      ProductionAssemblySource
	Clock       func() time.Time
}

// ProductionAssemblyActivator starts and retains one canonical stable-hostd
// assembly for each tunnel. It reports ready only after tunnelmanager has
// published the exact connector runtime; opening the control stream alone is
// never treated as activation success.
type ProductionAssemblyActivator struct {
	credentials CredentialStore
	source      ProductionAssemblySource
	clock       func() time.Time

	mu         sync.Mutex
	assemblies map[string]*activatedAssembly
	started    bool
	closed     bool
	lifetime   context.Context
	cancel     context.CancelFunc
}

type activatedAssembly struct {
	request    ActivationRequest
	assembly   *tunnelmanager.ProductionAssembly
	projection Projection
	ready      chan struct{}
	err        error
}

func NewProductionAssemblyActivator(config ProductionAssemblyActivatorConfig) (*ProductionAssemblyActivator, error) {
	if config.Credentials == nil || config.Source == nil {
		return nil, ErrActivation
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &ProductionAssemblyActivator{
		credentials: config.Credentials,
		source:      config.Source,
		clock:       config.Clock,
		assemblies:  make(map[string]*activatedAssembly),
	}, nil
}

func (a *ProductionAssemblyActivator) Activate(ctx context.Context, request ActivationRequest) (Projection, error) {
	if a == nil || ctx == nil || !validActivationRequest(request) {
		return Projection{}, ErrActivation
	}
	key := request.HostID + "\x00" + request.TunnelID
	a.mu.Lock()
	if !a.started || a.closed || a.lifetime == nil {
		a.mu.Unlock()
		return Projection{}, &ActivationDiagnostic{Code: ActivationDiagnosticLifecycleUnavailable, Cause: ErrUnavailable}
	}
	if current := a.assemblies[key]; current != nil {
		if !sameActivation(current.request, request) {
			a.mu.Unlock()
			return Projection{}, ErrConflict
		}
		ready := current.ready
		a.mu.Unlock()
		select {
		case <-ready:
			return current.projection, current.err
		case <-ctx.Done():
			return Projection{}, ctx.Err()
		}
	}
	current := &activatedAssembly{request: request, ready: make(chan struct{})}
	a.assemblies[key] = current
	a.mu.Unlock()

	projection, assembly, err := a.activate(ctx, request)
	a.mu.Lock()
	closed := a.closed
	if closed && err == nil {
		err = ErrUnavailable
	}
	current.assembly = assembly
	current.projection = projection
	current.err = err
	close(current.ready)
	if err != nil {
		delete(a.assemblies, key)
	}
	a.mu.Unlock()
	if closed && assembly != nil {
		_ = assembly.Shutdown(context.Background())
	}
	return projection, err
}

func (a *ProductionAssemblyActivator) activate(ctx context.Context, request ActivationRequest) (Projection, *tunnelmanager.ProductionAssembly, error) {
	signer := func(signCtx context.Context, payload []byte) ([]byte, error) {
		return a.credentials.Sign(signCtx, request.CredentialReference, payload)
	}
	config, err := a.source.ResolveProductionAssembly(ctx, request, signer)
	if err != nil {
		return Projection{}, nil, activationFailure(err)
	}
	if err := validateResolvedAssembly(request, config); err != nil {
		return Projection{}, nil, activationFailure(err)
	}

	ready := make(chan tunnelmanager.ActiveChange, 1)
	previousObserver := config.Production.ActiveObserver
	config.Production.ActiveObserver = func(change tunnelmanager.ActiveChange) {
		if previousObserver != nil {
			previousObserver(change)
		}
		if change.TunnelID == request.TunnelID && change.Current != nil && change.Current.ConnectorID() == request.ConnectorID {
			select {
			case ready <- change:
			default:
			}
		}
	}
	assembly, _, err := tunnelmanager.OpenProductionAssembly(config)
	if err != nil {
		return Projection{}, nil, activationFailure(err)
	}
	if binder, ok := a.source.(ProductionAssemblyBinder); ok {
		if err := binder.BindProductionAssembly(request, assembly); err != nil {
			_ = assembly.Shutdown(context.Background())
			return Projection{}, nil, activationFailure(err)
		}
	}
	a.mu.Lock()
	lifetime := a.lifetime
	a.mu.Unlock()
	if lifetime == nil {
		_ = assembly.Shutdown(context.Background())
		return Projection{}, nil, &ActivationDiagnostic{Code: ActivationDiagnosticLifecycleUnavailable, Cause: ErrUnavailable}
	}
	if err := assembly.Start(lifetime); err != nil {
		_ = assembly.Shutdown(context.Background())
		return Projection{}, nil, activationFailure(err)
	}
	if active, ok := assembly.Manager.ActiveForTunnel(request.TunnelID); ok && active != nil && active.ConnectorID() == request.ConnectorID {
		return a.readyProjection(request, config), assembly, nil
	}
	select {
	case change := <-ready:
		if change.Current.Generation() == 0 || change.Current.ContentHash() == "" {
			_ = assembly.Shutdown(context.Background())
			return Projection{}, nil, ErrActivation
		}
		return a.readyProjection(request, config), assembly, nil
	case <-ctx.Done():
		_ = assembly.Shutdown(context.Background())
		return Projection{}, nil, ctx.Err()
	}
}

func activationFailure(err error) error {
	if err == nil {
		return nil
	}
	var diagnostic *ActivationDiagnostic
	if errors.As(err, &diagnostic) {
		return err
	}
	var code ActivationDiagnosticCode
	switch {
	case errors.Is(err, tunnelmanager.ErrProductionIdentityMissing),
		errors.Is(err, tunnelmanager.ErrProductionControlMissing):
		code = ActivationDiagnosticLifecycleUnavailable
	case connectorprotocol.CodeOf(err) != "",
		errors.Is(err, connectorrotation.ErrControlSessionInvalid),
		errors.Is(err, tunnelmanager.ErrProductionAssemblyInvalid),
		errors.Is(err, tunnelmanager.ErrProductionControlRestartRequired):
		code = ActivationDiagnosticInvalidSessionConfig
	}
	if code == "" {
		return errors.Join(ErrActivation, err)
	}
	return &ActivationDiagnostic{Code: code, Cause: errors.Join(ErrActivation, err)}
}

func (a *ProductionAssemblyActivator) readyProjection(request ActivationRequest, config tunnelmanager.ProductionAssemblyConfig) Projection {
	readyAt := a.clock().UTC()
	return Projection{
		Schema:               Schema,
		Kind:                 "tunnel_connector",
		TunnelID:             request.TunnelID,
		HostID:               request.HostID,
		ConnectorID:          request.ConnectorID,
		OperationID:          request.OperationID,
		State:                "ready",
		CredentialReference:  request.CredentialReference,
		CredentialGeneration: config.Control.Hello.Auth.CredentialGeneration,
		ReadyAt:              &readyAt,
	}
}

// Start establishes the stable-hostd lifetime used by every connector
// control session. Request contexts are used only to bound enrollment and
// readiness; a successful CLI request ending must not cancel a live tunnel.
func (a *ProductionAssemblyActivator) Start(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrActivation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrUnavailable
	}
	if a.started {
		return nil
	}
	if lifecycle, ok := a.source.(ProductionAssemblySourceLifecycle); ok {
		if err := lifecycle.Start(ctx); err != nil {
			return err
		}
	}
	a.lifetime, a.cancel = context.WithCancel(context.Background())
	a.started = true
	return nil
}

// Shutdown releases all retained assemblies. It is idempotent at the
// activator boundary and bounded by ctx.
func (a *ProductionAssemblyActivator) Shutdown(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrActivation
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	if a.cancel != nil {
		a.cancel()
	}
	assemblies := make([]*tunnelmanager.ProductionAssembly, 0, len(a.assemblies))
	for _, current := range a.assemblies {
		if current.assembly != nil {
			assemblies = append(assemblies, current.assembly)
		}
	}
	a.assemblies = make(map[string]*activatedAssembly)
	a.mu.Unlock()
	var result error
	for _, assembly := range assemblies {
		result = errors.Join(result, assembly.Shutdown(ctx))
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
	}
	if lifecycle, ok := a.source.(ProductionAssemblySourceLifecycle); ok {
		result = errors.Join(result, lifecycle.Shutdown(ctx))
	}
	return result
}

func (a *ProductionAssemblyActivator) ResourceCounts() map[string]uint64 {
	result := map[string]uint64{"tunnels": 0, "connectors": 0, "active": 0}
	if a == nil {
		return result
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, current := range a.assemblies {
		if current.assembly == nil {
			continue
		}
		for key, value := range current.assembly.ResourceCounts() {
			result[key] += value
		}
	}
	return result
}

func validActivationRequest(request ActivationRequest) bool {
	return request.AccountID != "" && request.TunnelID != "" && request.HostID != "" && request.ConnectorID != "" && request.OperationID != "" && hoststate.ValidateStableEndpointID(request.StableEndpointID) == nil && request.CredentialReference != "" && request.CredentialKeyID != "" && request.CredentialKeyID == "ed25519:"+request.CredentialThumbprint && len(request.CredentialPublicKey) == ed25519.PublicKeySize && request.CredentialGeneration > 0 && request.ProcessGeneration > 0
}

func sameActivation(left, right ActivationRequest) bool {
	return left.AccountID == right.AccountID && left.TunnelID == right.TunnelID && left.HostID == right.HostID && left.ConnectorID == right.ConnectorID && left.OperationID == right.OperationID && left.StableEndpointID == right.StableEndpointID && left.CredentialReference == right.CredentialReference && left.CredentialKeyID == right.CredentialKeyID && left.CredentialThumbprint == right.CredentialThumbprint && bytes.Equal(left.CredentialPublicKey, right.CredentialPublicKey) && left.CredentialGeneration == right.CredentialGeneration && left.ProcessGeneration == right.ProcessGeneration
}

func validateResolvedAssembly(request ActivationRequest, config tunnelmanager.ProductionAssemblyConfig) error {
	hello := config.Control.Hello
	if config.ControlStream == nil || config.CarrierDescriptorSource == nil || config.SessionSource.Dialer != nil || config.InitialConnector == nil || hoststate.ValidateStableEndpointID(request.StableEndpointID) != nil || config.StableEndpointID != request.StableEndpointID || hello.AccountID != request.AccountID || hello.Auth.AccountID != request.AccountID || hello.TunnelID != request.TunnelID || hello.HostID != request.HostID || hello.ConnectorID != request.ConnectorID || hello.ProcessGeneration != request.ProcessGeneration || hello.Auth.IdentityKeyID != request.CredentialKeyID || hello.Auth.IdentityKeyThumbprint != request.CredentialThumbprint || hello.Auth.CredentialGeneration != request.CredentialGeneration || config.InitialConnector.ID != request.ConnectorID || config.InitialConnector.TunnelID != request.TunnelID || config.InitialConnector.HostID != request.HostID || config.InitialConnector.Credential.Reference != request.CredentialReference || config.InitialConnector.Credential.Generation != hello.Auth.CredentialGeneration || config.InitialConnector.RotationGeneration != hello.Auth.CredentialGeneration {
		return errors.Join(ErrActivation, ErrConflict)
	}
	return nil
}

var _ Activator = (*ProductionAssemblyActivator)(nil)

var _ interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	ResourceCounts() map[string]uint64
} = (*ProductionAssemblyActivator)(nil)
