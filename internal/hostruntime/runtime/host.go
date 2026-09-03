//go:build darwin || linux || windows

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configapply"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/envinject"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	stablehostd "github.com/pinksaucepasta/paperboat/internal/hostruntime/hostd"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

var ErrHostInvalid = errors.New("invalid host runtime composition")

type HostConfig struct {
	Runtime            runtimeconfig.Config
	ListenAddress      string
	WorkspaceRoot      string
	ShellPath          string
	AgentEnvironment   []string
	OriginPatterns     []string
	EnvironmentID      string
	MachineID          string
	InboxPath          string
	AgentTokenFile     string
	ShutdownTimeout    time.Duration
	RecoveryExitSignal string
	FileTransferPolicy *filetransfer.PolicyStore
}

type HostDependencies struct {
	Authorizer                server.AuthorizerFactory
	AuthorizationService      Service
	Listener                  ListenerFactory
	Connector                 Service
	Previews                  *preview.Registry
	PreviewRoutesChanged      func()
	PreviewDispatcher         server.PreviewDispatcher
	PreviewRecovery           Service
	PreviewOwnerSessions      *preview.OwnerSessionLeaseManager
	RuntimeObservationService Service
	ManagedEnvironment        envinject.EnvironmentSource
	ConfigApply               configapply.Handler
	ConfigApplyProof          bool
	ConfigSync                Service
	Random                    io.Reader
	HostedLifecycle           HostedLifecycle
	SessionLauncherFactory    func(*session.Manager) (server.SessionLauncher, error)
	HealthTracker             *health.HealthTracker
	Metrics                   *observability.Registry
	EventLog                  *observability.EventLog
	CodexSessions             *codexsession.Manager
	LocalControlToken         string
	TunnelEnrollment          http.Handler
	TunnelEnrollmentLifecycle Service
	ManagedSSH                *managedssh.Host
	ManagedSSHService         Service
	TunnelManager             stablehostd.TunnelWorkloads
	UpdateGate                hostdproto.UpdateGateHandler
	NativePeerFactory         func(func(net.Conn) error, http.Handler, http.Handler) (Service, error)
	TransferKeys              *transfercrypto.KeyVault
}

func previewPrivateTCPAccessHandler(value any) http.Handler {
	provider, ok := value.(interface{ PrivateTCPAccess() http.Handler })
	if !ok {
		return nil
	}
	return provider.PrivateTCPAccess()
}

func transferKeyEraser(vault *transfercrypto.KeyVault) func(string) error {
	if vault == nil {
		return nil
	}
	return vault.Delete
}

type HostedLifecycle interface {
	Service
	protocol.CapabilityProvider
}

type Host struct {
	workerMu            sync.RWMutex
	runtime             *Runtime
	hostd               *stablehostd.Daemon
	workers             *stablehostd.WorkerController
	http                *HTTPService
	handler             http.Handler
	sessions            *session.Manager
	executions          *execprocess.Manager
	health              *runtimeHealthSource
	transferRoot        string
	cleanupUnstarted    func() error
	workloadMu          sync.Mutex
	workloadGeneration  uint64
	workloadFingerprint string
	updateGate          hostdproto.UpdateGateHandler
}

func (h *Host) UpdateGate() hostdproto.UpdateGateHandler {
	if h == nil {
		return nil
	}
	return h.updateGate
}

func NewClientCoordinator(ctx context.Context, config HostConfig, dependencies HostDependencies) (_ *Host, resultErr error) {
	if err := config.Runtime.Validate(); err != nil || !LoopbackAddress(config.ListenAddress) || !filepath.IsAbs(config.WorkspaceRoot) || config.MachineID == "" || dependencies.Authorizer == nil || dependencies.Connector == nil || dependencies.RuntimeObservationService == nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.FileTransferPolicy == nil {
		config.FileTransferPolicy = filetransfer.NewPolicyStore(filetransfer.DefaultPolicy)
	}
	durable, err := store.Open(ctx, store.Config{Root: config.Runtime.StateRoot})
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, durable.Close())
		}
	}()
	resources := config.Runtime.Resources
	if resources == (runtimeconfig.ResourceLimits{}) {
		resources = runtimeconfig.DefaultResources
	}
	journal, err := operation.NewPersistentJournal(ctx, resources.MaxConcurrentOps*32, durable, time.Hour, nil)
	if err != nil {
		return nil, err
	}
	transferService, err := filetransfer.New(filetransfer.Config{Root: filepath.Join(config.Runtime.StateRoot, "file-transfers"), LocalMachineID: config.MachineID, Store: durable, PublishRoot: config.InboxPath, Random: rand.Reader, Policy: config.FileTransferPolicy, EraseTransferKey: transferKeyEraser(dependencies.TransferKeys)})
	if err != nil {
		return nil, err
	}
	transferHandler, err := server.NewFileTransferHandler(server.FileTransferHandlerConfig{
		Service: transferService, Journal: journal, Authorizer: dependencies.Authorizer, TransferKeys: dependencies.TransferKeys,
		AuthorizeCreate: func(authorization server.Authorization, request server.CreateFileTransferRequest) bool {
			return authorization.MachineID == config.MachineID && authorization.UserID != "" && request.SourceMachineID == authorization.SourceMachineID && request.InitiatingUserID == authorization.UserID && request.DestinationMachineID == config.MachineID && request.SessionID == ""
		},
	})
	if err != nil {
		return nil, err
	}
	var nativePeerService Service
	if dependencies.NativePeerFactory != nil {
		nativePeerService, err = dependencies.NativePeerFactory(func(net.Conn) error { return ErrHostInvalid }, transferHandler, nil)
		if err != nil || nativePeerService == nil {
			return nil, errors.Join(ErrHostInvalid, err)
		}
	}
	mux := http.NewServeMux()
	if dependencies.PreviewOwnerSessions != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/preview-owner-sessions", dependencies.PreviewOwnerSessions)
		mux.Handle("/v1/preview-owner-sessions/", dependencies.PreviewOwnerSessions)
	}
	if dependencies.TunnelEnrollment != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/tunnel-connectors/enroll", dependencies.TunnelEnrollment)
	}
	if handler := previewPrivateTCPAccessHandler(dependencies.PreviewDispatcher); handler != nil {
		mux.Handle("/v1/private-tcp-access", handler)
		mux.Handle("/v1/private-tcp-access/", handler)
	}
	mux.Handle("/v1/file-transfers", transferHandler)
	mux.Handle("/v1/file-transfers/", transferHandler)
	if dependencies.PreviewDispatcher != nil {
		handler, dispatchErr := server.NewPreviewDispatchHandler(server.PreviewDispatchHandlerConfig{Authorizer: dependencies.Authorizer, Dispatcher: dependencies.PreviewDispatcher, MachineID: config.MachineID})
		if dispatchErr != nil {
			return nil, dispatchErr
		}
		mux.Handle("/v1/preview-launches", handler)
	}
	healthSource := &runtimeHealthSource{}
	registerHostLivenessAndDiagnostics(mux, healthSource, dependencies.HealthTracker, dependencies.Metrics, dependencies.EventLog)
	if dependencies.Metrics != nil {
		mux.Handle("/metrics", dependencies.Metrics.Handler())
	}
	httpService, err := NewHTTPService(HTTPConfig{Address: config.ListenAddress, Handler: mux, Listener: dependencies.Listener})
	if err != nil {
		return nil, err
	}
	components := []stablehostd.Component{
		{Name: "storage", Required: true, Service: shutdownService{shutdown: func(context.Context) error { return durable.Close() }}},
		{Name: "file_transfer_cleanup", Required: true, Service: &filetransfer.CleanupWorker{Service: transferService}},
	}
	if dependencies.AuthorizationService != nil {
		components = append(components, stablehostd.Component{Name: "authorization", Required: false, Service: dependencies.AuthorizationService})
	}
	if dependencies.PreviewRecovery != nil {
		components = append(components, stablehostd.Component{Name: "preview_recovery", Required: false, Service: dependencies.PreviewRecovery})
	}
	if dependencies.TunnelEnrollmentLifecycle != nil {
		components = append(components, stablehostd.Component{Name: "tunnel_enrollment", Required: true, Service: dependencies.TunnelEnrollmentLifecycle})
	}
	if nativePeerService != nil {
		components = append(components, stablehostd.Component{Name: "peer_transport", Required: true, Service: nativePeerService})
	}
	components = append(components,
		stablehostd.Component{Name: "runtime_observation", Required: true, Service: dependencies.RuntimeObservationService},
		stablehostd.Component{Name: "edge", Required: true, Service: dependencies.Connector},
		stablehostd.Component{Name: "control_plane", Required: true, Service: httpService},
	)
	// Client mode still participates in the same stable-hostd update fence as
	// host mode. Transfers, previews, connector state, and the local control
	// plane belong to the stable daemon; the replaceable worker is only the
	// versioned coordination lifecycle. Without this composition, the Windows
	// SCM owner calls StartStable on a coordinator with no stable daemon and
	// fails every Client installation with ErrHostInvalid.
	daemon, err := stablehostd.New(stablehostd.Config{
		Workloads:       stablehostd.Workloads{Transfers: transferService},
		Components:      components,
		ShutdownTimeout: config.ShutdownTimeout,
	})
	if err != nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	workerComponents := []Component{{Capability: "worker_lifecycle", Required: true, Service: workerLifecycleService{}}}
	runtime, err := NewRuntime(Config{
		Version: config.Runtime.Version, Components: workerComponents, ShutdownTimeout: config.ShutdownTimeout,
		HealthTracker: dependencies.HealthTracker, Metrics: dependencies.Metrics, EventLog: dependencies.EventLog,
	})
	if err != nil {
		return nil, err
	}
	workers, err := stablehostd.NewWorkerController(daemon)
	if err != nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	healthSource.set(runtime, workerComponents)
	host := &Host{runtime: runtime, hostd: daemon, workers: workers, http: httpService, handler: mux, health: healthSource, transferRoot: filepath.Join(config.Runtime.StateRoot, "file-transfers"), cleanupUnstarted: durable.Close, updateGate: dependencies.UpdateGate}
	if host.updateGate == nil {
		host.updateGate, err = newStandaloneUpdateGate(standaloneUpdateGateConfig{MachineID: config.MachineID, StatePath: filepath.Join(config.Runtime.StateRoot, "updates", "standalone-deployment-gate.json"), Health: mux, Workloads: host.WorkloadStatus})
		if err != nil {
			return nil, errors.Join(ErrHostInvalid, err)
		}
	}
	return host, nil
}

func transferWorkloadCount(root string) uint64 {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return 0
	}
	var count uint64
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".content" {
			count++
		}
	}
	return count
}

func NewHost(ctx context.Context, config HostConfig, dependencies HostDependencies) (_ *Host, resultErr error) {
	if err := config.Runtime.Validate(); err != nil || !LoopbackAddress(config.ListenAddress) || !filepath.IsAbs(config.WorkspaceRoot) || config.MachineID == "" || dependencies.Authorizer == nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	if dependencies.SessionLauncherFactory == nil && config.ShellPath == "" {
		return nil, ErrHostInvalid
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.ShutdownTimeout <= 0 {
		return nil, ErrHostInvalid
	}
	if config.AgentTokenFile == "" {
		config.AgentTokenFile = filepath.Join(config.Runtime.StateRoot, "agent", "token")
	}
	if config.FileTransferPolicy == nil {
		config.FileTransferPolicy = filetransfer.NewPolicyStore(filetransfer.DefaultPolicy)
	}
	if !filepath.IsAbs(config.AgentTokenFile) {
		return nil, ErrHostInvalid
	}
	config.AgentEnvironment = append(config.AgentEnvironment,
		"PAPERBOAT_FILE_TRANSFER_ENDPOINT=http://"+config.ListenAddress+"/v1/file-transfers",
		"PAPERBOAT_FILE_TRANSFER_STAGING_ENDPOINT=http://"+config.ListenAddress+"/v1/local-file-transfers",
		"PAPERBOAT_RUNTIME_AGENT_TOKEN_FILE="+config.AgentTokenFile,
		"PAPERBOAT_WORKSPACE_ROOT="+config.WorkspaceRoot,
	)
	invalidConfigApply := dependencies.ConfigApplyProof && dependencies.ConfigApply == nil
	invalidHosted := config.Runtime.Profile == runtimeconfig.Hosted && dependencies.HostedLifecycle == nil ||
		config.Runtime.Profile == runtimeconfig.BYOD && dependencies.HostedLifecycle != nil
	if invalidConfigApply {
		return nil, errors.Join(ErrHostInvalid, errors.New("invalid config-apply dependencies"))
	}
	if invalidHosted {
		return nil, errors.Join(ErrHostInvalid, errors.New("invalid hosted lifecycle dependencies"))
	}
	adapter, err := pty.NewAdapter(config.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	resources := config.Runtime.Resources
	if resources == (runtimeconfig.ResourceLimits{}) {
		resources = runtimeconfig.DefaultResources
	}
	random := dependencies.Random
	if random == nil {
		random = rand.Reader
	}
	random = &lockedReader{reader: random}
	agentToken, err := writeAgentToken(config.AgentTokenFile, random)
	if err != nil {
		return nil, err
	}

	durable, err := store.Open(ctx, store.Config{Root: config.Runtime.StateRoot})
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, durable.Close())
		}
	}()
	sessions, err := session.NewManager(session.ManagerConfig{
		Launch: func(command pty.Command) (session.PTYProcess, error) {
			command, environmentErr := commandWithManagedEnvironment(command, dependencies.ManagedEnvironment)
			if environmentErr != nil {
				return nil, environmentErr
			}
			return adapter.Start(command)
		},
		Random: random, HistoryBytes: resources.HistoryBytes,
		AttachmentBytes: config.Runtime.Limits.PendingOutputBytes,
		MaxSessions:     resources.MaxSessions, MaxAttachments: resources.MaxAttachments,
		MaxInputDecisions:  resources.MaxInputDecisions,
		TerminationTimeout: 10 * time.Second, TerminationGrace: 2 * time.Second,
		Store:              durable,
		RecoveryExitSignal: config.RecoveryExitSignal,
	})
	if err != nil {
		return nil, err
	}
	var sessionLauncher server.SessionLauncher
	if dependencies.SessionLauncherFactory != nil {
		sessionLauncher, err = dependencies.SessionLauncherFactory(sessions)
	} else {
		sessionLauncher, err = process.NewShellLauncher(config.ShellPath, config.AgentEnvironment, sessions)
	}
	if err != nil || sessionLauncher == nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	journal, err := operation.NewPersistentJournal(ctx, resources.MaxConcurrentOps*32, durable, time.Hour, nil)
	if err != nil {
		return nil, err
	}

	healthSource := &runtimeHealthSource{}
	writers := filetransfer.NewWriterRegistry()
	executionConfig := execprocess.Config{
		WorkspaceRoot: config.WorkspaceRoot, BaseEnvironment: config.AgentEnvironment,
		MaximumActive: resources.MaxConcurrentOps, MaximumOperations: resources.MaxConcurrentOps * 32,
		ReplayBytes: int(config.Runtime.Limits.PendingOutputBytes), CancelGrace: 2 * time.Second, Store: durable,
	}
	if dependencies.ManagedEnvironment != nil {
		// Resolve at process creation so updates affect only new executions and
		// secret values never enter the durable operation journal.
		executionConfig.ManagedEnvironment = dependencies.ManagedEnvironment.Environment
	}
	executions, err := execprocess.NewPersistent(ctx, executionConfig)
	if err != nil {
		return nil, err
	}
	dispatcher, err := server.NewDispatcher(server.DispatcherConfig{
		Sessions: sessions, Health: healthSource, SessionLauncher: sessionLauncher,
		WorkspaceRoot: config.WorkspaceRoot, Random: random,
		ConfigApply: dependencies.ConfigApply,
		Writers:     writers, Exec: executions,
	})
	if err != nil {
		return nil, err
	}
	transferService, err := filetransfer.New(filetransfer.Config{
		Root: filepath.Join(config.Runtime.StateRoot, "file-transfers"), LocalMachineID: config.MachineID, Store: durable,
		PublishRoot: config.InboxPath, Random: random, Policy: config.FileTransferPolicy, EraseTransferKey: transferKeyEraser(dependencies.TransferKeys),
	})
	if err != nil {
		return nil, err
	}
	transferHandler, err := server.NewFileTransferHandler(server.FileTransferHandlerConfig{
		Service: transferService, Journal: journal, Authorizer: dependencies.Authorizer, TransferKeys: dependencies.TransferKeys,
		AuthorizeCreate: func(authorization server.Authorization, request server.CreateFileTransferRequest) bool {
			return authorization.MachineID == config.MachineID && authorization.UserID != "" &&
				request.SourceMachineID == authorization.SourceMachineID && request.InitiatingUserID == authorization.UserID &&
				(request.DestinationMachineID == config.MachineID || request.SessionID != "" && authorization.SessionID == request.SessionID)
		},
		ResolveDeliveryClient: func(_ server.Authorization, request server.CreateFileTransferRequest) (string, error) {
			if request.DestinationMachineID == config.MachineID {
				return "", nil
			}
			return writers.Recipient(request.SessionID, request.DestinationMachineID)
		},
	})
	if err != nil {
		return nil, err
	}
	providers := []protocol.CapabilityProvider{dispatcher}
	if dependencies.HostedLifecycle != nil {
		providers = append(providers, dependencies.HostedLifecycle)
	}
	available, err := protocol.AvailableCapabilities(providers...)
	if err != nil {
		return nil, err
	}
	var protocolMetrics server.MetricRecorder
	if dependencies.Metrics != nil {
		protocolMetrics = dependencies.Metrics
	}
	protocolServer, err := server.New(server.Config{
		Negotiator: protocol.Negotiator{Profile: config.Runtime.Profile, Available: available, ConfigApplyProof: dependencies.ConfigApplyProof},
		Journal:    journal, Authorizer: nil, Handler: dispatcher,
		MaxConcurrent:     resources.MaxConcurrentOps,
		HeartbeatInterval: config.Runtime.Limits.HeartbeatInterval,
		MutationDeadline:  config.Runtime.Limits.MutationDeadline,
		Metrics:           protocolMetrics,
	})
	if err != nil {
		return nil, err
	}
	connectionLimiter, err := server.NewConnectionLimiter(resources.MaxAttachments * resources.MaxSessions)
	if err != nil {
		return nil, err
	}
	nativeManager, err := server.NewNativeAssociationManager(server.NativeAssociationConfig{
		Server: protocolServer, Authorizer: dependencies.Authorizer, Limiter: connectionLimiter, Random: random,
	})
	if err != nil {
		return nil, err
	}
	codexHTTPHandler, err := hostCodexHTTPHandler(dependencies.CodexSessions, dependencies.Authorizer)
	if err != nil {
		return nil, err
	}
	var nativePeerService Service
	if dependencies.NativePeerFactory != nil {
		nativePeerService, err = dependencies.NativePeerFactory(nativeManager.Serve, transferHandler, codexHTTPHandler)
		if err != nil || nativePeerService == nil {
			return nil, errors.Join(ErrHostInvalid, err)
		}
	}
	websocketHandler, err := server.NewWebSocketHandler(server.WebSocketHandlerConfig{
		Server: protocolServer, Authorizer: dependencies.Authorizer,
		OriginPatterns: append([]string(nil), config.OriginPatterns...),
		MaxConnections: resources.MaxAttachments * resources.MaxSessions,
		Limiter:        connectionLimiter,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if dependencies.PreviewOwnerSessions != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/preview-owner-sessions", dependencies.PreviewOwnerSessions)
		mux.Handle("/v1/preview-owner-sessions/", dependencies.PreviewOwnerSessions)
	}
	if dependencies.TunnelEnrollment != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/tunnel-connectors/enroll", dependencies.TunnelEnrollment)
	}
	if handler := previewPrivateTCPAccessHandler(dependencies.PreviewDispatcher); handler != nil {
		mux.Handle("/v1/private-tcp-access", handler)
		mux.Handle("/v1/private-tcp-access/", handler)
	}
	mux.Handle("/v1/runtime", websocketHandler)
	if codexHTTPHandler != nil {
		mux.Handle("/v1/codex-sessions/", codexHTTPHandler)
	}
	mux.Handle("/v1/file-transfers", transferHandler)
	mux.Handle("/v1/file-transfers/", transferHandler)
	if dependencies.TransferKeys != nil {
		localTransferHandler, localTransferErr := server.NewLocalFileTransferHandler(server.LocalFileTransferConfig{Token: agentToken, MachineID: config.MachineID, Service: transferService, TransferKeys: dependencies.TransferKeys, ResolveRecipient: writers.Recipient})
		if localTransferErr != nil {
			return nil, localTransferErr
		}
		mux.Handle("/v1/local-file-transfers", localTransferHandler)
		mux.Handle("/v1/local-file-transfers/", localTransferHandler)
	}
	if dependencies.PreviewDispatcher != nil {
		previewDispatchHandler, dispatchErr := server.NewPreviewDispatchHandler(server.PreviewDispatchHandlerConfig{Authorizer: dependencies.Authorizer, Dispatcher: dependencies.PreviewDispatcher, MachineID: config.MachineID})
		if dispatchErr != nil {
			return nil, dispatchErr
		}
		mux.Handle("/v1/preview-launches", previewDispatchHandler)
	}
	registerHostLivenessAndDiagnostics(mux, healthSource, dependencies.HealthTracker, dependencies.Metrics, dependencies.EventLog)
	if dependencies.Metrics != nil {
		mux.Handle("/metrics", dependencies.Metrics.Handler())
	}
	httpService, err := NewHTTPService(HTTPConfig{Address: config.ListenAddress, Handler: mux, Listener: dependencies.Listener, NativeHandler: func(conn net.Conn) { _ = nativeManager.Serve(conn) }})
	if err != nil {
		return nil, err
	}
	// The stable daemon owns every component which terminates or routes a live
	// workload. A replaceable worker only coordinates policy and the control
	// plane. This is the update boundary: stopping a worker must never call
	// ShutdownForRecovery or close a connection accepted by hostd.
	stableComponents := make([]stablehostd.Component, 0, 12)
	transferCleanup := &filetransfer.CleanupWorker{Service: transferService}
	stableComponents = append(stableComponents,
		stablehostd.Component{Name: "storage", Required: true, Service: shutdownService{shutdown: func(context.Context) error { return durable.Close() }}},
		stablehostd.Component{Name: "sessions", Required: true, Service: shutdownService{shutdown: sessions.Shutdown}},
		stablehostd.Component{Name: "file_transfer_cleanup", Required: true, Service: transferCleanup},
	)
	if dependencies.CodexSessions != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "codex.v1", Required: false, Service: &codexSessionService{manager: dependencies.CodexSessions}})
	}
	workerComponents := []Component{{Capability: "worker_lifecycle", Required: true, Service: workerLifecycleService{}}}
	if dependencies.AuthorizationService != nil {
		workerComponents = append(workerComponents, Component{Capability: "authorization", Required: false, Service: dependencies.AuthorizationService})
	}
	if dependencies.ConfigSync != nil {
		if stableHostOwnsCoordination() {
			stableComponents = append(stableComponents, stablehostd.Component{Name: "config_sync", Required: config.Runtime.Profile == runtimeconfig.BYOD, Service: dependencies.ConfigSync})
		} else {
			workerComponents = append(workerComponents, Component{Capability: "config_sync", Required: config.Runtime.Profile == runtimeconfig.BYOD, Service: dependencies.ConfigSync})
		}
	}
	stableComponents = append(stableComponents, stablehostd.Component{Name: "protocol", Required: true, Service: protocolServer})
	if nativePeerService != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "peer_transport", Required: false, Service: nativePeerService})
	}
	if dependencies.PreviewRecovery != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "preview_recovery", Required: false, Service: dependencies.PreviewRecovery})
	}
	if dependencies.TunnelEnrollmentLifecycle != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "tunnel_enrollment", Required: true, Service: dependencies.TunnelEnrollmentLifecycle})
	}
	if dependencies.RuntimeObservationService != nil {
		// Presence is a stable host responsibility. The replaceable worker
		// negotiates lifecycle only and is not guaranteed to run on every
		// platform, so placing this service in workerComponents silently stops
		// heartbeats after an update (and on hostd-only startup). Keep the
		// observation loop alive with the same daemon that owns the machine
		// identity and local control plane.
		stableComponents = append(stableComponents, stablehostd.Component{Name: "runtime_observation", Required: false, Service: dependencies.RuntimeObservationService})
	}
	if dependencies.ManagedSSHService != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "managed_ssh_authority", Required: true, Service: dependencies.ManagedSSHService})
	}
	if dependencies.TunnelManager != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "tunnel_manager", Required: true, Service: dependencies.TunnelManager})
	}
	if dependencies.Connector != nil {
		stableComponents = append(stableComponents, stablehostd.Component{Name: "edge", Required: true, Service: dependencies.Connector})
	}
	// Start hosted preparation after transport dependencies. Reverse shutdown then
	// flushes hosted state before connector drain and the final runtime observation.
	if dependencies.HostedLifecycle != nil {
		if stableHostOwnsCoordination() {
			stableComponents = append(stableComponents, stablehostd.Component{Name: "hosted_lifecycle", Required: true, Service: dependencies.HostedLifecycle})
		} else {
			workerComponents = append(workerComponents, Component{Capability: "hosted_lifecycle", Required: true, Service: dependencies.HostedLifecycle})
		}
	}
	stableComponents = append(stableComponents, stablehostd.Component{Name: "control_plane", Required: true, Service: httpService})
	daemon, err := stablehostd.New(stablehostd.Config{
		Workloads:  stablehostd.Workloads{Sessions: sessions, Executions: executions, Transfers: transferService, Previews: dependencies.Previews, Codex: dependencies.CodexSessions, ManagedSSH: dependencies.ManagedSSH, Tunnels: dependencies.TunnelManager},
		Components: stableComponents, ShutdownTimeout: config.ShutdownTimeout,
	})
	if err != nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	runtime, err := NewRuntime(Config{
		Version: config.Runtime.Version, Components: workerComponents, ShutdownTimeout: config.ShutdownTimeout,
		HealthTracker: dependencies.HealthTracker, Metrics: dependencies.Metrics, EventLog: dependencies.EventLog,
	})
	if err != nil {
		return nil, err
	}
	workers, err := stablehostd.NewWorkerController(daemon)
	if err != nil {
		return nil, errors.Join(ErrHostInvalid, err)
	}
	healthSource.set(runtime, workerComponents)
	host := &Host{runtime: runtime, hostd: daemon, workers: workers, http: httpService, handler: mux, sessions: sessions, executions: executions, health: healthSource, transferRoot: filepath.Join(config.Runtime.StateRoot, "file-transfers"), cleanupUnstarted: durable.Close, updateGate: dependencies.UpdateGate}
	if host.updateGate == nil {
		host.updateGate, err = newStandaloneUpdateGate(standaloneUpdateGateConfig{MachineID: config.MachineID, StatePath: filepath.Join(config.Runtime.StateRoot, "updates", "standalone-deployment-gate.json"), Health: mux, Workloads: host.WorkloadStatus})
		if err != nil {
			return nil, errors.Join(ErrHostInvalid, err)
		}
	}
	return host, nil
}

func commandWithManagedEnvironment(command pty.Command, managed envinject.EnvironmentSource) (pty.Command, error) {
	if managed == nil {
		return command, nil
	}
	values, err := managed.Environment()
	if err != nil {
		return pty.Command{}, err
	}
	command.Env, err = envinject.Merge(command.Env, values)
	if err != nil {
		return pty.Command{}, err
	}
	return command, nil
}

// WorkloadStatus is the stable host's monotonic snapshot used to fence a
// supervisor maintenance activation. It counts ownership-bearing workloads,
// not merely network clients, and advances whenever that set changes.
func (h *Host) WorkloadStatus() hostdproto.WorkloadStatus {
	if h == nil {
		return hostdproto.WorkloadStatus{Generation: 1}
	}
	counts := map[string]uint64{}
	identities := make([]string, 0)
	if h.sessions != nil {
		for key, value := range h.sessions.ResourceCounts() {
			counts[key] = value
		}
		for _, value := range h.sessions.List() {
			identities = append(identities, fmt.Sprintf("session\x00%s\x00%d\x00%s", value.ID, value.Generation, value.State))
		}
	}
	if h.executions != nil {
		values := h.executions.ActiveSnapshots()
		counts["executions"] = uint64(len(values))
		for _, value := range values {
			identities = append(identities, fmt.Sprintf("execution\x00%s\x00%s\x00%d", value.OperationID, value.State, value.NextSequence))
		}
	}
	if h.transferRoot != "" {
		counts["transfers"] = transferWorkloadCount(h.transferRoot)
	}
	if h.hostd != nil {
		workloads := h.hostd.Workloads()
		if workloads.Previews != nil {
			for key, value := range workloads.Previews.ResourceCounts() {
				counts[key] += value
			}
			for _, value := range workloads.Previews.List() {
				if value.State != preview.Removed {
					identities = append(identities, fmt.Sprintf("preview\x00%s\x00%d\x00%s", value.Identity, value.Revision, value.State))
				}
			}
		}
		if workloads.Tunnels != nil {
			for key, value := range workloads.Tunnels.ResourceCounts() {
				counts[key] += value
			}
			if source, ok := workloads.Tunnels.(interface{ WorkloadIdentities() []string }); ok {
				for _, value := range source.WorkloadIdentities() {
					identities = append(identities, "tunnel\x00"+value)
				}
			}
		}
	}
	keys := make([]string, 0, len(counts))
	var protected uint64
	for key, value := range counts {
		keys = append(keys, key)
		protected += value
	}
	sort.Strings(keys)
	sort.Strings(identities)
	var fingerprint string
	for _, key := range keys {
		fingerprint += fmt.Sprintf("%s=%d;", key, counts[key])
	}
	for _, identity := range identities {
		fingerprint += fmt.Sprintf("%d:%s;", len(identity), identity)
	}
	h.workloadMu.Lock()
	defer h.workloadMu.Unlock()
	if h.workloadGeneration == 0 {
		h.workloadGeneration = 1
		h.workloadFingerprint = fingerprint
	} else if fingerprint != h.workloadFingerprint {
		h.workloadGeneration++
		h.workloadFingerprint = fingerprint
	}
	return hostdproto.WorkloadStatus{Generation: h.workloadGeneration, Protected: protected}
}

func writeAgentToken(path string, random io.Reader) (string, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrHostInvalid
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	if info, err = os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return "", ErrHostInvalid
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := atomicfile.Write(path, []byte(token+"\n"), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return "", err
	}
	return token, nil
}

func (h *Host) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	h.workerMu.RLock()
	worker := h.runtime
	h.workerMu.RUnlock()
	if h.hostd == nil || h.workers == nil {
		return worker.Start(ctx)
	}
	if err := h.hostd.Start(ctx); err != nil {
		return err
	}
	if err := h.workers.Start(ctx, worker); err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return errors.Join(err, h.hostd.Shutdown(shutdownCtx))
	}
	return nil
}

// StartHostd starts only the stable daemon. The hostd process uses this entry
// point before it launches the separately fenced runtime worker. Starting the
// in-process Runtime here would create a second lifecycle owner and can stop
// stable services when the external worker is activated or replaced.
func (h *Host) StartHostd(ctx context.Context) error {
	if h == nil || h.hostd == nil {
		return ErrHostInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return h.hostd.Start(ctx)
}

// StartStable starts hostd-owned workloads and the coordination services whose
// health is exposed by the stable control plane. The separately fenced worker
// proves the selected runtime artifact and owns its lifecycle lease; it must
// not leave the actual authorization and observation services in New state.
func (h *Host) StartStable(ctx context.Context) error {
	return h.Start(ctx)
}

// ReplaceWorker swaps coordination only. Hostd-owned workload managers,
// accepted ingress, PTYs and streams continue running throughout the change.
func (h *Host) ReplaceWorker(ctx context.Context, candidate *Runtime) error {
	if h.workers == nil {
		return ErrHostInvalid
	}
	if candidate == nil {
		return ErrHostInvalid
	}
	replaceErr := h.workers.Replace(ctx, candidate)
	if replaceErr != nil {
		var committed *stablehostd.ReplacementCommittedError
		if !errors.As(replaceErr, &committed) {
			return replaceErr
		}
	}
	h.workerMu.Lock()
	h.runtime = candidate
	h.workerMu.Unlock()
	if h.health != nil {
		h.health.set(candidate, candidate.config.Components)
	}
	return replaceErr
}

func (h *Host) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	h.workerMu.RLock()
	worker := h.runtime
	h.workerMu.RUnlock()
	if worker != nil && worker.State() == New && h.cleanupUnstarted != nil {
		cleanup := h.cleanupUnstarted
		h.cleanupUnstarted = nil
		return cleanup()
	}
	if h.hostd == nil || h.workers == nil {
		return worker.Shutdown(ctx)
	}
	return errors.Join(h.workers.Shutdown(ctx), h.hostd.Shutdown(ctx))
}

// ShutdownHostd drains the stable daemon after the external runtime worker has
// stopped. It deliberately does not touch the in-process Runtime, which was
// never started by StartHostd.
func (h *Host) ShutdownHostd(ctx context.Context) error {
	if h == nil || h.hostd == nil {
		return ErrHostInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return h.hostd.Shutdown(ctx)
}

// ShutdownStable is used by the stable hostd process after its external worker
// has been stopped. It drains coordination before durable hostd workloads.
func (h *Host) ShutdownStable(ctx context.Context) error {
	return h.Shutdown(ctx)
}
func (h *Host) State() State {
	h.workerMu.RLock()
	defer h.workerMu.RUnlock()
	return h.runtime.State()
}

type shutdownService struct{ shutdown func(context.Context) error }

func (shutdownService) Start(context.Context) error          { return nil }
func (s shutdownService) Shutdown(ctx context.Context) error { return s.shutdown(ctx) }

// workerLifecycleService represents the replaceable runtime process itself.
// It has no workload ownership; hostd owns all state which survives a worker
// update.
type workerLifecycleService struct{}

func (workerLifecycleService) Start(context.Context) error    { return nil }
func (workerLifecycleService) Shutdown(context.Context) error { return nil }

type serviceGroup []Service

func (g serviceGroup) Start(ctx context.Context) error {
	started := 0
	for i, service := range g {
		if err := service.Start(ctx); err != nil {
			for j := started - 1; j >= 0; j-- {
				_ = g[j].Shutdown(ctx)
			}
			return err
		}
		started = i + 1
	}
	return nil
}

func (g serviceGroup) Shutdown(ctx context.Context) error {
	var result error
	for i := len(g) - 1; i >= 0; i-- {
		result = errors.Join(result, g[i].Shutdown(ctx))
	}
	return result
}

type lockedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *lockedReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(buffer)
}

type runtimeHealthSource struct {
	mu      sync.RWMutex
	runtime *Runtime
	dynamic map[string]capabilityHealthProvider
}

type capabilityHealthProvider interface {
	CapabilityHealth() health.Capability
}

func (s *runtimeHealthSource) set(runtime *Runtime, components []Component) {
	dynamic := make(map[string]capabilityHealthProvider)
	for _, component := range components {
		if provider, ok := component.Service.(capabilityHealthProvider); ok {
			dynamic[component.Capability] = provider
		}
	}
	s.mu.Lock()
	s.runtime, s.dynamic = runtime, dynamic
	s.mu.Unlock()
}
func (s *runtimeHealthSource) Snapshot() (snapshot health.Snapshot) {
	s.mu.RLock()
	runtime := s.runtime
	dynamic := make(map[string]capabilityHealthProvider, len(s.dynamic))
	for capability, provider := range s.dynamic {
		dynamic[capability] = provider
	}
	s.mu.RUnlock()
	if runtime != nil {
		snapshot = runtime.Health()
		for capability, provider := range dynamic {
			snapshot.Capabilities[capability] = provider.CapabilityHealth()
		}
	}
	return snapshot
}
