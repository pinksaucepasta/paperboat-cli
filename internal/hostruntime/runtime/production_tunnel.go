package runtime

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
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

	mu             sync.Mutex
	started        bool
	closed         bool
	recoveryCancel context.CancelFunc
	recoveryDone   chan struct{}
	recoveryErr    error
	recoveryHealth ProductionTunnelRecoveryHealth
}

// ProductionTunnelRecoveryHealth is the bounded, secret-free status of the
// asynchronous durable connector recovery worker. The worker can fail while
// hostd and its local HTTP control plane remain healthy; callers should use
// this snapshot to decide whether a connector needs repair or retry.
type ProductionTunnelRecoveryHealth struct {
	State          string `json:"state"`
	WorkerRunning  bool   `json:"worker_running"`
	LastErrorCode  string `json:"last_error_code,omitempty"`
	Retryable      bool   `json:"retryable,omitempty"`
	LastErrorKnown bool   `json:"last_error_known,omitempty"`
}

const (
	productionTunnelRecoveryStarting = "starting"
	productionTunnelRecoveryRunning  = "recovering"
	productionTunnelRecoveryReady    = "ready"
	productionTunnelRecoveryDegraded = "degraded"
	productionTunnelRecoveryStopped  = "stopped"
)

var (
	ErrProductionTunnelEnrollmentStarted = errors.New("production tunnel enrollment already started")
	ErrProductionTunnelEnrollmentStopped = errors.New("production tunnel enrollment already stopped")
)

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
	if err := ctx.Err(); err != nil {
		return err
	}

	// Hold the service lock while the lifecycle is initialized so Shutdown
	// cannot race a half-started activator. Production lifecycle Start only
	// installs cancellation/state; it must not wait for connector readiness.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrProductionTunnelEnrollmentStopped
	}
	if s.started {
		s.mu.Unlock()
		return ErrProductionTunnelEnrollmentStarted
	}
	s.recoveryErr = nil
	s.recoveryHealth = ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryStarting}
	if s.lifecycle != nil {
		if err := s.lifecycle.Start(ctx); err != nil {
			s.recoveryErr = err
			s.recoveryHealth = productionTunnelRecoveryHealthForError(err, false)
			s.mu.Unlock()
			return err
		}
	}
	recoveryCtx, cancel := context.WithCancel(context.Background())
	s.recoveryCancel = cancel
	s.recoveryDone = make(chan struct{})
	s.started = true
	s.recoveryHealth = ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryRunning, WorkerRunning: true}
	recoveryDone := s.recoveryDone
	s.mu.Unlock()

	// Resume is deliberately detached from the request context. A local
	// enrollment request or host startup deadline must not cancel durable
	// connector recovery. Shutdown owns recoveryCtx and waits on recoveryDone.
	go s.runRecovery(recoveryCtx, recoveryDone)
	return nil
}

func (s *ProductionTunnelEnrollment) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return tunnelenrollment.ErrActivation
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.started = false
	cancel := s.recoveryCancel
	done := s.recoveryDone
	lifecycle := s.lifecycle
	s.recoveryHealth = ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryStopped}
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var result error
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if lifecycle != nil {
		result = errors.Join(result, lifecycle.Shutdown(ctx))
	}
	s.mu.Lock()
	s.recoveryCancel = nil
	s.recoveryDone = nil
	s.mu.Unlock()
	return result
}

// runRecovery performs the durable activation once. A failed connector is a
// workload health failure, not a stable-hostd process failure. The error is
// retained as a typed, redacted health projection until a later successful
// lifecycle replaces it or Shutdown marks the service stopped.
func (s *ProductionTunnelEnrollment) runRecovery(ctx context.Context, done chan struct{}) {
	err := s.manager.Resume(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	defer close(done)
	s.recoveryCancel = nil
	if s.closed {
		s.recoveryHealth = ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryStopped}
		return
	}
	if err != nil {
		s.recoveryErr = err
		s.recoveryHealth = productionTunnelRecoveryHealthForError(err, false)
		return
	}
	s.recoveryErr = nil
	s.recoveryHealth = ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryReady}
}

// RecoveryHealth returns a copy-isolated, secret-free status projection.
func (s *ProductionTunnelEnrollment) RecoveryHealth() ProductionTunnelRecoveryHealth {
	if s == nil {
		return ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryStopped}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryHealth
}

// Health is the concise compatibility name used by local diagnostics
// adapters. It is equivalent to RecoveryHealth and never exposes secrets.
func (s *ProductionTunnelEnrollment) Health() ProductionTunnelRecoveryHealth {
	return s.RecoveryHealth()
}

// RecoveryError returns the last activation error for programmatic typed
// branching. It intentionally does not serialize the error through HTTP.
func (s *ProductionTunnelEnrollment) RecoveryError() error {
	if s == nil {
		return ErrProductionTunnelEnrollmentStopped
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryErr
}

// LastError is an alias for RecoveryError for lifecycle consumers that expose
// the most recent typed failure separately from the safe health projection.
func (s *ProductionTunnelEnrollment) LastError() error {
	return s.RecoveryError()
}

func productionTunnelRecoveryHealthForError(err error, workerRunning bool) ProductionTunnelRecoveryHealth {
	if err == nil {
		return ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryReady, WorkerRunning: workerRunning}
	}
	health := ProductionTunnelRecoveryHealth{State: productionTunnelRecoveryDegraded, WorkerRunning: workerRunning, LastErrorKnown: true}
	var protocolErr *connectorprotocol.Error
	if errors.As(err, &protocolErr) && protocolErr != nil {
		health.LastErrorCode = string(protocolErr.Code)
		health.Retryable = protocolErr.Retryable
		return health
	}
	switch {
	case errors.Is(err, tunnelenrollment.ErrUnavailable):
		health.LastErrorCode = "unavailable"
		health.Retryable = true
	case errors.Is(err, tunnelenrollment.ErrEnrollmentRetryable):
		health.LastErrorCode = "enrollment_retryable"
		health.Retryable = true
	case errors.Is(err, context.DeadlineExceeded):
		health.LastErrorCode = "deadline_exceeded"
		health.Retryable = true
	case errors.Is(err, context.Canceled):
		health.LastErrorCode = "canceled"
		health.Retryable = true
	case errors.Is(err, tunnelenrollment.ErrActivation):
		health.LastErrorCode = "activation_unavailable"
	default:
		health.LastErrorCode = "recovery_failed"
	}
	return health
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
