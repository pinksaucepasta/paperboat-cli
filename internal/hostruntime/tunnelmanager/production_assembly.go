package tunnelmanager

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/networkrecovery"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

var (
	// ErrProductionAssemblyInvalid means that a caller omitted one of the
	// server-owned identity, readiness, or transport boundaries. It is kept
	// separate from ErrInvalidConfig so production startup can report the
	// missing authority without silently falling back to the legacy connector.
	ErrProductionAssemblyInvalid        = errors.New("invalid production tunnel assembly")
	ErrProductionIdentityMissing        = errors.New("production tunnel identity source is unavailable")
	ErrProductionCredentialMissing      = errors.New("production tunnel credential renewal source is unavailable")
	ErrProductionControlMissing         = errors.New("production tunnel control stream source is unavailable")
	ErrProductionControlStarted         = errors.New("production tunnel control loop is already started")
	ErrProductionControlDisconnected    = errors.New("production tunnel control stream disconnected")
	ErrProductionControlRestartRequired = errors.New("production tunnel control requires a fresh authenticated session")
)

// ProductionAssemblyConfig is the complete host-side connector-v1 assembly
// boundary. The server-owned identity and renewable credential sources are
// deliberately injected. This package must never derive a connector session
// or mint a credential from durable tunnel state.
//
// InitialConnector is the server-owned, write-only connector record used to
// seed a brand-new host-state store when the first snapshot arrives. It is
// never a credential or bearer token; the reference is resolved by the
// platform credential store at carrier setup time.
//
// ControlStream is an optional, already-authenticated connector-v1 bootstrap
// stream provider. It receives Hello/Welcome and the first snapshot before
// the data carrier exists. The protocol has no control migration message, so
// the stream remains the canonical control stream after activation.
type ProductionAssemblyConfig struct {
	Production ProductionConfig

	StableEndpointID string
	Clock            connectorprotocol.Clock
	SessionSource    connector.DataCarrierSessionSource
	// CarrierDescriptorSource resolves the carrier transport only after the
	// server-authenticated Welcome has supplied the live SessionID. It is the
	// production path for new enrollments. SessionSource remains supported for
	// already-running/recovered sessions; exactly one source is required.
	CarrierDescriptorSource CarrierDescriptorSource
	Origins                 OriginProber
	OriginStreams           *OriginStreamForwarder

	Control connectorrotation.ControlSessionConfig

	InitialConnector *hoststate.Connector

	// ControlSessionFactory creates a fresh ControlSession for each bootstrap
	// reconnect. ControlSession contains ClientSession state and cannot be
	// reused after a peer disconnects. The factory must obtain a new
	// server-authenticated Hello/Auth identity with a strictly higher
	// ProcessGeneration and re-sign the Auth transcript; a new Welcome session
	// ID alone is not sufficient for the server's durable stale-process fence.
	// This assembly only injects the durable applier and readiness boundary.
	ControlSessionFactory func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error)
	// ControlStream is intentionally a one-shot, already-authenticated stream
	// provider. A replacement connector process must create a new assembly and
	// ControlSession with its new session/process identity.
	ControlStream  func(context.Context) (io.ReadWriteCloser, error)
	ObserveWelcome func(connectorprotocol.Welcome) error
	HelloRequestID string

	// NetworkReplacerFactory resolves an authenticated replacer for each
	// active durable connector. When omitted, this assembly supplies the one
	// connector represented by Control and rejects unrelated connectors rather
	// than inventing session or credential material for them.
	NetworkReplacerFactory NetworkRecoveryReplacerFactory
}

type CarrierDescriptorSource func(context.Context, connectorprotocol.Welcome, ApplyRequest) (connector.DataCarrierSessionSource, error)

// ProductionAssembly owns one ProductionManager, its coordinated applier,
// and one canonical connectorrotation.ControlSession. It implements the
// stable hostd tunnel workload boundary by delegating lifecycle and workload
// identity to the manager.
type ProductionAssembly struct {
	Manager *ProductionManager
	Factory *RuntimeFactory
	Applier *CoordinatedConfigApplier
	Control *connectorrotation.ControlSession

	controlRunner   *connector.DataCarrierControlRunner
	controlStream   func(context.Context) (io.ReadWriteCloser, error)
	observeWelcome  func(connectorprotocol.Welcome) error
	helloRequestID  string
	controlFactory  func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error)
	accountID       string
	tunnelID        string
	connectorID     string
	hostID          string
	controlMu       sync.Mutex
	controlStarted  bool
	controlCancel   context.CancelFunc
	controlDone     chan struct{}
	controlErr      error
	networkRecovery *NetworkRecoveryCoordinator
}

// OpenProductionAssembly builds the complete durable host-side composition.
// It does not open a second state store, create a second reconciliation loop,
// or activate a carrier. Activation remains the Manager's readiness-gated
// responsibility after the exact live connector identity has been supplied.
func OpenProductionAssembly(config ProductionAssemblyConfig) (*ProductionAssembly, hoststate.StartupStatus, error) {
	if err := validateProductionAssemblyConfig(config); err != nil {
		return nil, hoststate.StartupStatus{}, err
	}

	var sessionSource DataCarrierSessionSource
	var deferred *welcomeDataCarrierSessionSource
	if config.CarrierDescriptorSource != nil {
		deferred = &welcomeDataCarrierSessionSource{factory: config.CarrierDescriptorSource, hello: config.Control.Hello}
		sessionSource = deferred
	} else {
		sessionSource = liveDataCarrierSessionSource{source: config.SessionSource, expectedAccountID: config.Control.Hello.AccountID}
	}
	factory, err := NewRuntimeFactory(RuntimeFactoryConfig{Builder: DataCarrierBuilder{Sessions: sessionSource}, Origins: config.Origins, OriginStreams: config.OriginStreams})
	if err != nil {
		return nil, hoststate.StartupStatus{}, errors.Join(ErrProductionAssemblyInvalid, err)
	}
	production := config.Production
	production.Factory = factory
	if config.Clock != nil {
		production.Clock = config.Clock.Now
	}
	manager, status, err := OpenProduction(production)
	if err != nil {
		return nil, status, err
	}
	applier, err := manager.ConfigApplier(config.Clock, config.StableEndpointID)
	if err != nil {
		_ = manager.Shutdown(context.Background())
		return nil, status, errors.Join(ErrProductionAssemblyInvalid, err)
	}
	applier.InitialConnector = cloneInitialConnector(config.InitialConnector)
	networkFactory := config.NetworkReplacerFactory
	if networkFactory == nil {
		networkFactory = func(ctx context.Context, tunnel hoststate.Tunnel, connectorValue hoststate.Connector) (networkrecovery.Identity, networkrecovery.CarrierReplacer, error) {
			if ctx == nil || tunnel.ID != config.Control.Hello.TunnelID || connectorValue.ID != config.Control.Hello.ConnectorID || connectorValue.HostID != config.Control.Hello.HostID {
				return networkrecovery.Identity{}, nil, errors.Join(ErrProductionIdentityMissing, connectorprotocol.ErrIdentityMismatch)
			}
			identity := networkrecovery.Identity{EnvironmentID: config.Control.Hello.AccountID, MachineID: config.Control.Hello.HostID, TunnelID: tunnel.ID, ConnectorID: connectorValue.ID}
			replacer, replacerErr := NewNetworkCarrierReplacer(manager.Manager, identity)
			return identity, replacer, replacerErr
		}
	}
	networkRecovery, err := NewNetworkRecoveryCoordinator(NetworkRecoveryCoordinatorConfig{Manager: manager.Manager, Factory: networkFactory})
	if err != nil {
		_ = manager.Shutdown(context.Background())
		return nil, status, errors.Join(ErrProductionAssemblyInvalid, err)
	}

	controlConfig := config.Control
	controlConfig.Applier = applier
	controlConfig.SnapshotReadiness = applier
	control, err := connectorrotation.NewControlSession(controlConfig)
	if err != nil {
		_ = manager.Shutdown(context.Background())
		return nil, status, errors.Join(ErrProductionAssemblyInvalid, err)
	}
	runner, err := connector.NewDataCarrierControlRunner(connector.DataCarrierControlRunnerConfig{Control: control})
	if err != nil {
		_ = manager.Shutdown(context.Background())
		return nil, status, errors.Join(ErrProductionAssemblyInvalid, err)
	}
	observeWelcome := config.ObserveWelcome
	if deferred != nil {
		observeWelcome = func(welcome connectorprotocol.Welcome) error {
			if err := deferred.ObserveWelcome(welcome); err != nil {
				return err
			}
			if config.ObserveWelcome != nil {
				return config.ObserveWelcome(welcome)
			}
			return nil
		}
	}
	return &ProductionAssembly{
		Manager:         manager,
		Factory:         factory,
		Applier:         applier,
		Control:         control,
		controlRunner:   runner,
		controlStream:   config.ControlStream,
		observeWelcome:  observeWelcome,
		helloRequestID:  config.HelloRequestID,
		controlFactory:  config.ControlSessionFactory,
		accountID:       config.Control.Hello.AccountID,
		tunnelID:        config.Control.Hello.TunnelID,
		connectorID:     config.Control.Hello.ConnectorID,
		hostID:          config.Control.Hello.HostID,
		networkRecovery: networkRecovery,
	}, status, nil
}

func validateProductionAssemblyConfig(config ProductionAssemblyConfig) error {
	if config.Production.Factory != nil || config.Production.StateRoot == "" || config.Production.HostID == "" || config.Production.Report == nil {
		return errors.Join(ErrProductionAssemblyInvalid, ErrInvalidConfig)
	}
	if err := hoststate.ValidateStableEndpointID(config.StableEndpointID); err != nil {
		return errors.Join(ErrProductionIdentityMissing, ErrProductionAssemblyInvalid, err)
	}
	if config.Clock == nil || config.Origins == nil {
		return errors.Join(ErrProductionAssemblyInvalid, ErrInvalidConfig)
	}
	if config.InitialConnector == nil {
		return errors.Join(ErrProductionIdentityMissing, ErrProductionAssemblyInvalid)
	}
	if (config.CarrierDescriptorSource == nil) == (config.SessionSource.Dialer == nil) {
		return errors.Join(ErrProductionIdentityMissing, ErrProductionAssemblyInvalid)
	}
	if config.CarrierDescriptorSource == nil {
		if err := validateConnectorSessionIdentity(config.SessionSource.Identity); err != nil {
			return errors.Join(ErrProductionIdentityMissing, err)
		}
		if config.SessionSource.Identity.HostID != config.Production.HostID {
			return errors.Join(ErrProductionIdentityMissing, ErrGenerationConflict)
		}
	}
	initial := *config.InitialConnector
	if initial.ID != config.Control.Hello.ConnectorID || initial.TunnelID != config.Control.Hello.TunnelID || initial.HostID != config.Control.Hello.HostID || initial.RotationGeneration == 0 || initial.RotationGeneration != config.Control.Hello.Auth.CredentialGeneration || initial.Credential.Generation != initial.RotationGeneration {
		return errors.Join(ErrProductionIdentityMissing, connectorprotocol.ErrIdentityMismatch)
	}
	if config.Control.Renewal == nil && config.Control.RenewalSigner == nil {
		return ErrProductionCredentialMissing
	}
	if config.ControlStream != nil && config.ControlSessionFactory == nil {
		return errors.Join(ErrProductionControlMissing, ErrProductionAssemblyInvalid)
	}
	if config.Control.Drainer == nil {
		return errors.Join(ErrProductionControlMissing, ErrProductionAssemblyInvalid)
	}
	if config.CarrierDescriptorSource == nil {
		if config.Control.Hello.AccountID != config.SessionSource.Identity.AccountID || config.Control.Hello.TunnelID != config.SessionSource.Identity.TunnelID || config.Control.Hello.ConnectorID != config.SessionSource.Identity.ConnectorID || config.Control.Hello.HostID != config.SessionSource.Identity.HostID || config.Control.Hello.ProcessGeneration != config.SessionSource.Identity.ProcessGeneration {
			return errors.Join(ErrProductionIdentityMissing, connectorprotocol.ErrIdentityMismatch)
		}
	} else if config.Control.Hello.HostID != config.Production.HostID {
		return errors.Join(ErrProductionIdentityMissing, connectorprotocol.ErrIdentityMismatch)
	}
	if err := config.Control.Hello.Validate(time.Time{}); err != nil {
		return errors.Join(ErrProductionControlMissing, err)
	}
	return nil
}

func cloneInitialConnector(value *hoststate.Connector) *hoststate.Connector {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validateConnectorSessionIdentity(identity connector.DataCarrierIdentity) error {
	if identity.AccountID == "" || identity.HostID == "" || identity.TunnelID == "" || identity.ConnectorID == "" || identity.SessionID == "" || identity.ProcessGeneration == 0 || identity.Generation == 0 {
		return ErrProductionAssemblyInvalid
	}
	return nil
}

// Start starts the one serialized durable reconciliation loop and, when a
// control stream provider is configured, synchronously acquires the first
// authenticated bootstrap stream before returning. The stream itself is then
// owned by a bounded control goroutine, so hostd never needs an out-of-band
// RunControl call.
func (a *ProductionAssembly) Start(ctx context.Context) error {
	if a == nil || a.Manager == nil || ctx == nil {
		return ErrProductionAssemblyInvalid
	}
	// A descriptor source bound to Welcome cannot prepare a carrier until the
	// control stream has delivered that frame. Start the manager lifecycle first
	// without its synchronous initial reconcile, then acquire control; the
	// manager's wake-up below reconciles once Welcome and the authoritative
	// snapshot are available. Assemblies without a control stream retain the
	// ordinary synchronous crash-recovery contract.
	startManager := a.Manager.Start
	if a.controlStream != nil {
		startManager = a.Manager.StartDeferred
	}
	if err := startManager(ctx); err != nil {
		return err
	}
	if a.networkRecovery != nil {
		if err := a.networkRecovery.Start(ctx); err != nil {
			return errors.Join(err, a.Manager.Shutdown(context.Background()))
		}
	}
	if a.controlStream == nil {
		return nil
	}
	controlCtx, done, err := a.claimControl(ctx)
	if err != nil {
		return err
	}
	stream, err := a.controlStream(controlCtx)
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		if err == nil {
			err = ErrProductionControlMissing
		}
		finalErr := errors.Join(ErrProductionControlMissing, err)
		a.finishControl(done, finalErr)
		return errors.Join(finalErr, a.Shutdown(context.Background()))
	}
	go a.runControlLoop(controlCtx, done, a.Control, a.controlRunner, stream, a.helloRequestID)
	// StartDeferred intentionally skips inline reconciliation. Wake the loop
	// after control ownership is established so Welcome can release the
	// session-bound carrier prepare gate without waiting for the interval tick.
	a.Manager.Notify()
	return nil
}

// RunControl is the explicit test/embedding hook for one already-authenticated
// connector-v1 bootstrap stream. Production callers should use Start with a
// ControlStream provider, which owns acquisition and reconnects.
func (a *ProductionAssembly) RunControl(ctx context.Context, stream io.ReadWriteCloser, helloRequestID string) error {
	if a == nil || a.controlRunner == nil || ctx == nil {
		return ErrProductionAssemblyInvalid
	}
	if helloRequestID == "" {
		helloRequestID = a.helloRequestID
	}
	if helloRequestID == "" {
		return errors.Join(ErrProductionControlMissing, ErrProductionAssemblyInvalid)
	}
	controlCtx, done, err := a.claimControl(ctx)
	if err != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return err
	}
	if stream == nil {
		if a.controlStream == nil {
			err = ErrProductionControlMissing
		} else {
			stream, err = a.controlStream(controlCtx)
		}
		if err != nil || stream == nil {
			if stream != nil {
				_ = stream.Close()
			}
			if err == nil {
				err = ErrProductionControlMissing
			}
			finalErr := errors.Join(ErrProductionControlMissing, err)
			a.finishControl(done, finalErr)
			return finalErr
		}
	}
	return a.runControlLoop(controlCtx, done, a.Control, a.controlRunner, stream, helloRequestID)
}

func (a *ProductionAssembly) claimControl(parent context.Context) (context.Context, chan struct{}, error) {
	if a == nil || parent == nil {
		return nil, nil, ErrProductionAssemblyInvalid
	}
	a.controlMu.Lock()
	defer a.controlMu.Unlock()
	if a.controlStarted {
		return nil, nil, ErrProductionControlStarted
	}
	controlCtx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	a.controlStarted = true
	a.controlCancel = cancel
	a.controlDone = done
	a.controlErr = nil
	return controlCtx, done, nil
}

func (a *ProductionAssembly) finishControl(done chan struct{}, err error) {
	if a == nil || done == nil {
		return
	}
	a.controlMu.Lock()
	if a.controlDone == done {
		a.controlErr = err
		close(done)
	}
	a.controlMu.Unlock()
}

func (a *ProductionAssembly) runControlLoop(ctx context.Context, done chan struct{}, control *connectorrotation.ControlSession, runner *connector.DataCarrierControlRunner, stream io.ReadWriteCloser, helloRequestID string) error {
	if a == nil || ctx == nil || done == nil || control == nil || runner == nil || stream == nil || helloRequestID == "" {
		err := ErrProductionAssemblyInvalid
		if stream != nil {
			_ = stream.Close()
		}
		a.finishControl(done, err)
		return err
	}
	if err := a.runControlAttempt(ctx, runner, stream, helloRequestID); err == nil && ctx.Err() == nil {
		return a.reconnectControl(ctx, done, ErrProductionControlDisconnected)
	} else if ctx.Err() != nil {
		a.finishControl(done, ctx.Err())
		return ctx.Err()
	} else {
		return a.reconnectControl(ctx, done, err)
	}
}

func (a *ProductionAssembly) runControlAttempt(ctx context.Context, runner *connector.DataCarrierControlRunner, stream io.ReadWriteCloser, helloRequestID string) error {
	if a.observeWelcome != nil {
		stream = &welcomeObservingControlStream{ReadWriteCloser: stream, onWelcome: a.observeWelcome}
	}
	err := runner.Run(ctx, stream, helloRequestID)
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (a *ProductionAssembly) reconnectControl(ctx context.Context, done chan struct{}, cause error) error {
	if cause == nil {
		cause = ErrProductionControlDisconnected
	}
	if ctx.Err() != nil {
		a.finishControl(done, ctx.Err())
		return ctx.Err()
	}
	a.reportControlFailure(cause, 1)
	if a.controlFactory == nil || a.controlStream == nil {
		finalErr := errors.Join(ErrProductionControlRestartRequired, cause)
		a.finishControl(done, finalErr)
		return finalErr
	}
	for attempt := 1; ; attempt++ {
		delay := productionControlReconnectDelay(attempt, a.connectorID)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			a.finishControl(done, ctx.Err())
			return ctx.Err()
		case <-timer.C:
		}
		controlConfig, err := a.controlFactory(ctx, a.Applier)
		if err != nil {
			if errors.Is(err, ErrProductionControlRestartRequired) {
				finalErr := errors.Join(ErrProductionControlRestartRequired, err)
				a.finishControl(done, finalErr)
				return finalErr
			}
			a.reportControlFailure(err, attempt+1)
			continue
		}
		control, runner, err := a.newControl(controlConfig)
		if err != nil {
			if errors.Is(err, ErrProductionControlRestartRequired) {
				finalErr := errors.Join(ErrProductionControlRestartRequired, err)
				a.finishControl(done, finalErr)
				return finalErr
			}
			a.reportControlFailure(err, attempt+1)
			continue
		}
		stream, err := a.controlStream(ctx)
		if err != nil || stream == nil {
			if stream != nil {
				_ = stream.Close()
			}
			if err == nil {
				err = ErrProductionControlMissing
			}
			a.reportControlFailure(errors.Join(ErrProductionControlMissing, err), attempt+1)
			continue
		}
		a.controlMu.Lock()
		a.Control = control
		a.controlRunner = runner
		a.controlMu.Unlock()
		if err := a.runControlAttempt(ctx, runner, stream, a.helloRequestID); err == nil && ctx.Err() == nil {
			cause = ErrProductionControlDisconnected
		} else if ctx.Err() != nil {
			a.finishControl(done, ctx.Err())
			return ctx.Err()
		} else {
			cause = err
		}
		a.reportControlFailure(cause, attempt+1)
	}
}

func (a *ProductionAssembly) newControl(config connectorrotation.ControlSessionConfig) (*connectorrotation.ControlSession, *connector.DataCarrierControlRunner, error) {
	if a == nil || a.Applier == nil {
		return nil, nil, ErrProductionAssemblyInvalid
	}
	if config.Hello.AccountID != a.accountID || config.Hello.TunnelID != a.tunnelID || config.Hello.ConnectorID != a.connectorID || config.Hello.HostID != a.hostID {
		return nil, nil, connectorprotocol.ErrIdentityMismatch
	}
	// The server persists the highest process generation ever accepted for a
	// connector and rejects a later session that reuses it. A reconnect must
	// therefore be a fresh authenticated process epoch, not merely a new
	// websocket/session ID. Keep the durable connector identity unchanged, but
	// fail closed when the injected factory hands us a stale Hello. The factory
	// owns the process-generation claim and must also re-sign Auth for it.
	a.controlMu.Lock()
	current := a.Control
	a.controlMu.Unlock()
	if current == nil || current.Session() == nil {
		return nil, nil, ErrProductionControlRestartRequired
	}
	currentGeneration := current.Session().Hello().ProcessGeneration
	if config.Hello.ProcessGeneration <= currentGeneration || config.Hello.Auth.ProcessGeneration != config.Hello.ProcessGeneration {
		return nil, nil, errors.Join(ErrProductionControlRestartRequired, ErrGenerationConflict)
	}
	config.Applier = a.Applier
	config.SnapshotReadiness = a.Applier
	control, err := connectorrotation.NewControlSession(config)
	if err != nil {
		return nil, nil, err
	}
	runner, err := connector.NewDataCarrierControlRunner(connector.DataCarrierControlRunnerConfig{Control: control})
	if err != nil {
		return nil, nil, err
	}
	return control, runner, nil
}

func (a *ProductionAssembly) reportControlFailure(err error, nextAttempt int) {
	if a == nil || a.Manager == nil || err == nil {
		return
	}
	var tunnelID, connectorID string
	a.controlMu.Lock()
	control := a.Control
	a.controlMu.Unlock()
	if control != nil && control.Session() != nil {
		hello := control.Session().Hello()
		tunnelID, connectorID = hello.TunnelID, hello.ConnectorID
	}
	now := a.Manager.now()
	a.Manager.config.Report(Observation{TunnelID: tunnelID, ConnectorID: connectorID, Code: CodeControlUnavailable, Retryable: true, NextRetryAt: now.Add(productionControlReconnectDelay(nextAttempt, connectorID)), ObservedAt: now, Err: err})
}

func productionControlReconnectDelay(attempt int, identity string) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		attempt = 6
	}
	base := 100 * time.Millisecond * time.Duration(1<<(attempt-1))
	// Derive a stable per-connector spread so independent connectors do not all
	// reconnect on the same tick while lifecycle tests remain reproducible.
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(identity))
	spreadPercent := (hash.Sum32() + uint32(attempt*37)) % 50
	spread := time.Duration(spreadPercent) * base / 100
	if base+spread > 5*time.Second {
		return 5 * time.Second
	}
	return base + spread
}

func (a *ProductionAssembly) Shutdown(ctx context.Context) error {
	if a == nil || a.Manager == nil || ctx == nil {
		return ErrProductionAssemblyInvalid
	}
	a.controlMu.Lock()
	cancel, done := a.controlCancel, a.controlDone
	a.controlMu.Unlock()
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
	var recoveryErr error
	if a.networkRecovery != nil {
		recoveryErr = a.networkRecovery.Shutdown(ctx)
	}
	return errors.Join(recoveryErr, a.Manager.Shutdown(ctx))
}

// HandleNetworkEvent connects the platform network monitor to the durable
// tunnel recovery coordinator. It is intentionally a no-op before Start or
// after Shutdown, so a late monitor callback cannot stage a carrier during
// lifecycle teardown.
func (a *ProductionAssembly) HandleNetworkEvent(event networkmonitor.Event) {
	if a == nil || a.networkRecovery == nil {
		return
	}
	a.networkRecovery.HandleNetworkEvent(event)
}

func (a *ProductionAssembly) NetworkHealth(tunnelID string) (networkrecovery.HealthSnapshot, bool) {
	if a == nil || a.networkRecovery == nil {
		return networkrecovery.HealthSnapshot{}, false
	}
	return a.networkRecovery.Health(tunnelID)
}

func (a *ProductionAssembly) NetworkHealthSnapshots() map[string]networkrecovery.HealthSnapshot {
	if a == nil || a.networkRecovery == nil {
		return nil
	}
	return a.networkRecovery.HealthSnapshots()
}

func (a *ProductionAssembly) ResourceCounts() map[string]uint64 {
	if a == nil || a.Manager == nil {
		return nil
	}
	return a.Manager.ResourceCounts()
}

func (a *ProductionAssembly) WorkloadIdentities() []string {
	if a == nil || a.Manager == nil {
		return nil
	}
	return a.Manager.WorkloadIdentities()
}

type liveDataCarrierSessionSource struct {
	source            connector.DataCarrierSessionSource
	expectedAccountID string
}

type welcomeDataCarrierSessionSource struct {
	factory CarrierDescriptorSource
	hello   connectorprotocol.Hello
	mu      sync.RWMutex
	welcome connectorprotocol.Welcome
	ready   chan struct{}
	once    sync.Once
}

func (s *welcomeDataCarrierSessionSource) ObserveWelcome(welcome connectorprotocol.Welcome) error {
	if s == nil || s.factory == nil || welcome.SessionID == "" {
		return ErrProductionIdentityMissing
	}
	s.mu.Lock()
	s.welcome = welcome
	if s.ready == nil {
		s.ready = make(chan struct{})
	}
	ready := s.ready
	s.mu.Unlock()
	s.once.Do(func() { close(ready) })
	return nil
}

func (s *welcomeDataCarrierSessionSource) PrepareDataCarrier(ctx context.Context, request ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
	if s == nil || ctx == nil || s.factory == nil {
		return connector.DataCarrierPrepareRequest{}, ErrProductionAssemblyInvalid
	}
	s.mu.Lock()
	if s.ready == nil {
		s.ready = make(chan struct{})
	}
	ready := s.ready
	s.mu.Unlock()
	select {
	case <-ready:
	case <-ctx.Done():
		return connector.DataCarrierPrepareRequest{}, ctx.Err()
	}
	s.mu.RLock()
	welcome := s.welcome
	hello := s.hello
	s.mu.RUnlock()
	source, err := s.factory(ctx, welcome, request)
	if err != nil {
		return connector.DataCarrierPrepareRequest{}, err
	}
	prepared, err := source.PrepareDataCarrier(ctx)
	if err != nil {
		return connector.DataCarrierPrepareRequest{}, err
	}
	identity := prepared.Identity
	if identity.AccountID != hello.AccountID || identity.TunnelID != hello.TunnelID || identity.ConnectorID != hello.ConnectorID || identity.HostID != hello.HostID || identity.SessionID != welcome.SessionID || identity.ProcessGeneration != hello.ProcessGeneration || identity.Generation != request.Snapshot.Generation {
		return connector.DataCarrierPrepareRequest{}, errors.Join(ErrGenerationConflict, ErrProductionIdentityMissing)
	}
	return prepared, nil
}

// welcomeObservingControlStream keeps the bootstrap transport opaque to the
// control state machine while exposing the authenticated Welcome identity to
// the carrier session source. It observes complete connector-v1 frames only;
// all validation and dispatch remain owned by ControlSession.Serve.
type welcomeObservingControlStream struct {
	io.ReadWriteCloser
	onWelcome func(connectorprotocol.Welcome) error

	mu       sync.Mutex
	pending  []byte
	observed bool
	err      error
}

func (s *welcomeObservingControlStream) Read(p []byte) (int, error) {
	if s == nil || s.ReadWriteCloser == nil {
		return 0, ErrProductionControlMissing
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return 0, err
	}
	s.mu.Unlock()
	n, err := s.ReadWriteCloser.Read(p)
	if n <= 0 {
		return n, err
	}
	s.mu.Lock()
	s.pending = append(s.pending, p[:n]...)
	callbackErr := s.observeLocked()
	if callbackErr != nil {
		s.err = callbackErr
	}
	s.mu.Unlock()
	// Return bytes already read so ControlSession can process a valid Welcome;
	// surface an observer failure on the next read without losing the frame.
	if callbackErr != nil && err == nil && n == 0 {
		err = callbackErr
	}
	return n, err
}

func (s *welcomeObservingControlStream) observeLocked() error {
	if s.observed || s.onWelcome == nil {
		return nil
	}
	for {
		if len(s.pending) < 4 {
			return nil
		}
		length := int(binary.BigEndian.Uint32(s.pending[:4]))
		if length <= 0 || length > connectorprotocol.MaxFrameBytes {
			// Leave malformed-frame handling to ReadFrame and stop buffering so a
			// peer cannot grow this observer beyond one bounded frame.
			s.pending = nil
			return nil
		}
		total := 4 + length
		if len(s.pending) < total {
			return nil
		}
		frame, err := connectorprotocol.ReadFrame(bytes.NewReader(s.pending[:total]))
		if err != nil {
			return nil
		}
		s.pending = append([]byte(nil), s.pending[total:]...)
		if frame.Type != connectorprotocol.MessageWelcome {
			continue
		}
		var welcome connectorprotocol.Welcome
		if err := frame.DecodePayload(&welcome); err != nil {
			return err
		}
		if err := s.onWelcome(welcome); err != nil {
			return err
		}
		s.observed = true
		return nil
	}
}

func (s *welcomeObservingControlStream) SetDeadline(deadline time.Time) error {
	if setter, ok := s.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return setter.SetDeadline(deadline)
	}
	return nil
}

func (s *welcomeObservingControlStream) SetReadDeadline(deadline time.Time) error {
	if setter, ok := s.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return setter.SetReadDeadline(deadline)
	}
	return nil
}

func (s *welcomeObservingControlStream) SetWriteDeadline(deadline time.Time) error {
	if setter, ok := s.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return setter.SetWriteDeadline(deadline)
	}
	return nil
}

func (s liveDataCarrierSessionSource) PrepareDataCarrier(ctx context.Context, request ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
	if ctx == nil {
		return connector.DataCarrierPrepareRequest{}, ErrProductionAssemblyInvalid
	}
	prepared, err := s.source.PrepareDataCarrier(ctx)
	if err != nil {
		return connector.DataCarrierPrepareRequest{}, err
	}
	identity := prepared.Identity
	if identity.AccountID != s.expectedAccountID || identity.TunnelID != request.Tunnel.ID || identity.ConnectorID != request.Connector.ID || identity.HostID != request.Connector.HostID || identity.Generation != request.Snapshot.Generation {
		return connector.DataCarrierPrepareRequest{}, errors.Join(ErrGenerationConflict, ErrProductionIdentityMissing)
	}
	return prepared, nil
}

var _ interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	ResourceCounts() map[string]uint64
} = (*ProductionAssembly)(nil)
