package runtime

import (
	"context"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

var (
	ErrProductionTunnelAssemblyRequired    = errors.New("production tunnel assembly provider is required")
	ErrProductionTunnelAssemblyUnavailable = errors.New("production tunnel assembly is unavailable")
)

// ProductionTunnelAssemblyInputs contains only non-secret composition inputs
// discovered by the production host. The provider remains responsible for
// obtaining the server-owned connector identity, renewable credential
// reference, authenticated data-carrier dialer, route authorizer, and control
// stream source. No bearer or private-key bytes cross this boundary.
type ProductionTunnelAssemblyInputs struct {
	StateRoot              string
	ControlURL             string
	ControlTransport       http.RoundTripper
	EnvironmentID          string
	MachineID              string
	InstallationGeneration uint64
	Metrics                *observability.Registry
}

type ProductionTunnelEnrollmentConfig struct {
	ControlURL     string
	StateRoot      string
	HostID         string
	ControlToken   string
	Transport      http.RoundTripper
	Auth           tunnelenrollment.MachineAuth
	Activator      tunnelenrollment.Activator
	AssemblySource tunnelenrollment.ProductionAssemblySource
}

type ProductionTunnelEnrollment struct {
	manager   *tunnelenrollment.Manager
	lifecycle interface {
		Start(context.Context) error
		Shutdown(context.Context) error
		ResourceCounts() map[string]uint64
	}
}

// NewProductionTunnelEnrollmentHandler composes the stable-hostd enrollment
// endpoint. Activator is mandatory: without the server bootstrap/session
// source, the endpoint must fail closed instead of reporting a connector as
// installed.
func NewProductionTunnelEnrollmentHandler(config ProductionTunnelEnrollmentConfig) (http.Handler, error) {
	service, err := NewProductionTunnelEnrollment(config)
	if err != nil {
		return nil, err
	}
	return service, nil
}

// NewProductionTunnelEnrollment builds the one stable-hostd service that owns
// the local RPC and all connector assemblies created through it. When an
// AssemblySource is supplied, the reference-backed credential store is shared
// by enrollment and signed-Hello activation and is closed through the stable
// workload lifecycle.
func NewProductionTunnelEnrollment(config ProductionTunnelEnrollmentConfig) (*ProductionTunnelEnrollment, error) {
	credentials, err := tunnelenrollment.NewFileCredentialStore(config.StateRoot)
	if err != nil {
		return nil, err
	}
	activator := config.Activator
	var lifecycle interface {
		Start(context.Context) error
		Shutdown(context.Context) error
		ResourceCounts() map[string]uint64
	}
	if activator == nil && config.AssemblySource != nil {
		if binder, ok := config.AssemblySource.(interface {
			BindCredentialStore(*tunnelenrollment.FileCredentialStore) error
		}); ok {
			if bindErr := binder.BindCredentialStore(credentials); bindErr != nil {
				return nil, bindErr
			}
		}
		productionActivator, activationErr := tunnelenrollment.NewProductionAssemblyActivator(tunnelenrollment.ProductionAssemblyActivatorConfig{Credentials: credentials, Source: config.AssemblySource})
		if activationErr != nil {
			return nil, activationErr
		}
		activator = productionActivator
		lifecycle = productionActivator
	}
	if activator == nil {
		return nil, tunnelenrollment.ErrActivation
	}
	if lifecycle == nil {
		lifecycle, _ = activator.(interface {
			Start(context.Context) error
			Shutdown(context.Context) error
			ResourceCounts() map[string]uint64
		})
	}
	manager, err := tunnelenrollment.NewManager(tunnelenrollment.ManagerConfig{ControlURL: config.ControlURL, HostID: config.HostID, Auth: config.Auth, Transport: config.Transport, Credentials: credentials, Activator: activator, ControlToken: config.ControlToken})
	if err != nil {
		return nil, err
	}
	return &ProductionTunnelEnrollment{manager: manager, lifecycle: lifecycle}, nil
}

func (s *ProductionTunnelEnrollment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.manager == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.manager.ServeHTTP(w, r)
}

func (s *ProductionTunnelEnrollment) Start(ctx context.Context) error {
	if s == nil || s.manager == nil || ctx == nil {
		return tunnelenrollment.ErrActivation
	}
	if s.lifecycle != nil {
		if err := s.lifecycle.Start(ctx); err != nil {
			return err
		}
	}
	return s.manager.Resume(ctx)
}

func (s *ProductionTunnelEnrollment) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return tunnelenrollment.ErrActivation
	}
	if s.lifecycle != nil {
		return s.lifecycle.Shutdown(ctx)
	}
	return nil
}

func (s *ProductionTunnelEnrollment) ResourceCounts() map[string]uint64 {
	if s == nil || s.lifecycle == nil {
		return map[string]uint64{"tunnels": 0, "connectors": 0, "active": 0}
	}
	return s.lifecycle.ResourceCounts()
}

var _ http.Handler = (*ProductionTunnelEnrollment)(nil)

var _ interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	ResourceCounts() map[string]uint64
} = (*ProductionTunnelEnrollment)(nil)

// ProductionTunnelAssemblyProvider is the explicit production integration
// seam for stable hostd. NewProductionHost keeps the legacy connector path
// when this provider is nil; callers that opt into connector-v1 must provide
// the complete server-backed assembly and therefore cannot silently receive a
// partial or fake tunnel runtime.
type ProductionTunnelAssemblyProvider func(context.Context, ProductionTunnelAssemblyInputs) (*tunnelmanager.ProductionAssembly, error)

func productionTunnelAssembly(ctx context.Context, provider ProductionTunnelAssemblyProvider, inputs ProductionTunnelAssemblyInputs) (*tunnelmanager.ProductionAssembly, error) {
	if provider == nil {
		return nil, ErrProductionTunnelAssemblyRequired
	}
	assembly, err := provider(ctx, inputs)
	if err != nil {
		return nil, err
	}
	if assembly == nil {
		return nil, ErrProductionTunnelAssemblyUnavailable
	}
	return assembly, nil
}
