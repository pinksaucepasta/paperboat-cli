//go:build darwin || linux || windows

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"

	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// newProductionTunnelEnrollmentService composes the connector-add local RPC,
// reference-backed key custody, signed WSS control, TLS/QUIC carrier bootstrap,
// durable tunnel manager, rotation, renewal, drain, and origin readiness under
// the one stable hostd lifecycle.
func newProductionTunnelEnrollmentService(controlURL, stateRoot, hostID, localControlToken string, transport http.RoundTripper) (*ProductionTunnelEnrollment, error) {
	identityStore, err := runtimeidentity.Open(runtimeidentity.Config{StateRoot: stateRoot})
	if err != nil {
		return nil, err
	}
	auth, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL, StateRoot: stateRoot, Transport: transport})
	if err != nil {
		return nil, err
	}
	origins, originStreams, err := tunnelmanager.NewOriginRuntime(
		tunnelmanager.CredentialStoreOriginSecretResolver{Store: clientconfig.FileSecretStore{Dir: filepath.Join(stateRoot, "origin-credentials")}},
		false,
		nil,
	)
	if err != nil {
		return nil, err
	}
	source, err := tunnelenrollment.NewHTTPSProductionAssemblySource(tunnelenrollment.HTTPSProductionAssemblySourceConfig{
		ControlURL: controlURL, StateRoot: stateRoot, HostID: hostID, Transport: transport,
		Auth: auth, Clock: productionClock{}, Origins: origins, OriginStreams: originStreams,
		MachineTLSCertificate: identityStore.CurrentTLSCertificateWithURIs,
		Report: func(observation tunnelmanager.Observation) {
			if observation.Err != nil {
				diagnostic := tunnelenrollment.ActivationDiagnosticCodeOf(observation.Err)
				if diagnostic == "" {
					diagnostic = observation.Code
				}
				slog.Warn("durable tunnel reconciliation failed", "tunnel_id", observation.TunnelID, "connector_id", observation.ConnectorID, "code", observation.Code, "diagnostic", diagnostic, "retryable", observation.Retryable)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		ControlURL: controlURL, StateRoot: stateRoot, HostID: hostID, ControlToken: localControlToken,
		Transport: transport, Auth: auth, AssemblySource: newReconnectSafeProductionAssemblySource(source),
	})
}

// reconnectSafeProductionAssemblySource adds the one boundary that a
// long-lived production assembly cannot provide itself: a reconnect must
// reserve a strictly higher process epoch in the durable enrollment journal
// before the replacement Hello is allowed onto the wire. The inner source
// remains responsible for endpoint/authentication construction; this wrapper
// refreshes that complete binding for each claimed epoch.
type reconnectSafeProductionAssemblySource struct {
	inner tunnelenrollment.ProductionAssemblySource

	mu          sync.Mutex
	credentials processGenerationClaimer
}

type processGenerationClaimer interface {
	ClaimProcessGeneration(context.Context, tunnelenrollment.ActivationRequest) (tunnelenrollment.ActivationRequest, error)
}

type reconnectSafeAssemblyBinding struct {
	source  *reconnectSafeProductionAssemblySource
	request tunnelenrollment.ActivationRequest
	config  tunnelmanager.ProductionAssemblyConfig
	signer  tunnelenrollment.CredentialSigner
	mu      sync.RWMutex
}

func newReconnectSafeProductionAssemblySource(inner tunnelenrollment.ProductionAssemblySource) tunnelenrollment.ProductionAssemblySource {
	if inner == nil {
		return nil
	}
	return &reconnectSafeProductionAssemblySource{inner: inner}
}

func (s *reconnectSafeProductionAssemblySource) BindCredentialStore(store *tunnelenrollment.FileCredentialStore) error {
	if s == nil || store == nil {
		return tunnelenrollment.ErrInvalid
	}
	binder, ok := s.inner.(interface {
		BindCredentialStore(*tunnelenrollment.FileCredentialStore) error
	})
	if !ok {
		return tunnelenrollment.ErrActivation
	}
	if err := binder.BindCredentialStore(store); err != nil {
		return err
	}
	s.mu.Lock()
	s.credentials = store
	s.mu.Unlock()
	return nil
}

func (s *reconnectSafeProductionAssemblySource) ResolveProductionAssembly(ctx context.Context, request tunnelenrollment.ActivationRequest, signer tunnelenrollment.CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error) {
	if s == nil || s.inner == nil || ctx == nil || signer == nil {
		return tunnelmanager.ProductionAssemblyConfig{}, tunnelenrollment.ErrInvalid
	}
	config, err := s.inner.ResolveProductionAssembly(ctx, request, signer)
	if err != nil {
		return tunnelmanager.ProductionAssemblyConfig{}, err
	}
	if config.ControlSessionFactory == nil || config.CarrierDescriptorSource == nil {
		return tunnelmanager.ProductionAssemblyConfig{}, tunnelenrollment.ErrActivation
	}
	binding := &reconnectSafeAssemblyBinding{source: s, request: request, config: config, signer: signer}
	config.CarrierDescriptorSource = binding.carrierDescriptor
	config.ControlSessionFactory = binding.controlSessionFactory
	return config, nil
}

func (s *reconnectSafeProductionAssemblySource) BindProductionAssembly(request tunnelenrollment.ActivationRequest, assembly *tunnelmanager.ProductionAssembly) error {
	if s == nil || s.inner == nil {
		return tunnelenrollment.ErrActivation
	}
	binder, ok := s.inner.(tunnelenrollment.ProductionAssemblyBinder)
	if !ok {
		return tunnelenrollment.ErrActivation
	}
	return binder.BindProductionAssembly(request, assembly)
}

func (s *reconnectSafeProductionAssemblySource) Start(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return tunnelenrollment.ErrActivation
	}
	if lifecycle, ok := s.inner.(tunnelenrollment.ProductionAssemblySourceLifecycle); ok {
		return lifecycle.Start(ctx)
	}
	return nil
}

func (s *reconnectSafeProductionAssemblySource) Shutdown(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return tunnelenrollment.ErrActivation
	}
	if lifecycle, ok := s.inner.(tunnelenrollment.ProductionAssemblySourceLifecycle); ok {
		return lifecycle.Shutdown(ctx)
	}
	return nil
}

func (b *reconnectSafeAssemblyBinding) carrierDescriptor(ctx context.Context, welcome connectorprotocol.Welcome, apply tunnelmanager.ApplyRequest) (connector.DataCarrierSessionSource, error) {
	if b == nil || ctx == nil {
		return connector.DataCarrierSessionSource{}, tunnelenrollment.ErrInvalid
	}
	b.mu.RLock()
	config := b.config
	b.mu.RUnlock()
	if config.CarrierDescriptorSource == nil {
		return connector.DataCarrierSessionSource{}, tunnelenrollment.ErrActivation
	}
	return config.CarrierDescriptorSource(ctx, welcome, apply)
}

func (b *reconnectSafeAssemblyBinding) controlSessionFactory(ctx context.Context, applier *tunnelmanager.CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
	if b == nil || b.source == nil || ctx == nil || applier == nil {
		return connectorrotation.ControlSessionConfig{}, tunnelenrollment.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.config.ControlSessionFactory == nil || b.signer == nil {
		return connectorrotation.ControlSessionConfig{}, tunnelenrollment.ErrActivation
	}
	b.source.mu.Lock()
	store := b.source.credentials
	b.source.mu.Unlock()
	if store == nil {
		return connectorrotation.ControlSessionConfig{}, tunnelenrollment.ErrSecretStore
	}
	candidate := b.request
	if candidate.ProcessGeneration == ^uint64(0) {
		return connectorrotation.ControlSessionConfig{}, errors.Join(tunnelenrollment.ErrConflict, tunnelenrollment.ErrEnrollmentRetryable)
	}
	candidate.ProcessGeneration++
	// Build and sign the fresh Hello against the candidate first. No network
	// operation is possible until the exact candidate is durably claimed below.
	refreshed, err := b.source.inner.ResolveProductionAssembly(ctx, candidate, b.signer)
	if err != nil {
		return connectorrotation.ControlSessionConfig{}, err
	}
	if refreshed.ControlSessionFactory == nil || refreshed.CarrierDescriptorSource == nil {
		return connectorrotation.ControlSessionConfig{}, tunnelenrollment.ErrActivation
	}
	fresh, err := refreshed.ControlSessionFactory(ctx, applier)
	if err != nil {
		return connectorrotation.ControlSessionConfig{}, err
	}
	if fresh.Hello.ProcessGeneration != candidate.ProcessGeneration || fresh.Hello.Auth.ProcessGeneration != candidate.ProcessGeneration {
		return connectorrotation.ControlSessionConfig{}, errors.Join(tunnelenrollment.ErrConflict, tunnelenrollment.ErrActivation)
	}
	claimed, err := store.ClaimProcessGeneration(ctx, b.request)
	if err != nil {
		return connectorrotation.ControlSessionConfig{}, err
	}
	if claimed.ProcessGeneration != candidate.ProcessGeneration {
		return connectorrotation.ControlSessionConfig{}, errors.Join(tunnelenrollment.ErrConflict, tunnelenrollment.ErrActivation)
	}
	b.request = claimed
	b.config = refreshed
	return fresh, nil
}

var _ tunnelenrollment.ProductionAssemblySource = (*reconnectSafeProductionAssemblySource)(nil)
var _ tunnelenrollment.ProductionAssemblyBinder = (*reconnectSafeProductionAssemblySource)(nil)
var _ tunnelenrollment.ProductionAssemblySourceLifecycle = (*reconnectSafeProductionAssemblySource)(nil)
