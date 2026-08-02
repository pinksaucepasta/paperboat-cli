//go:build darwin || linux

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configapply"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/servelease"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
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
	PreviewControl            preview.PreviewControl
	PreviewRoutesChanged      func()
	PreviewService            Service
	PreviewLauncher           server.PreviewLauncher
	PreviewRecovery           Service
	RuntimeObservationService Service
	ConfigApply               configapply.Handler
	ConfigApplyProof          bool
	ConfigSync                Service
	Updates                   interface {
		Activate(context.Context, bootstrap.ArtifactManifest) (string, error)
	}
	Random                 io.Reader
	HostedLifecycle        HostedLifecycle
	SessionLauncherFactory func(*session.Manager) (server.SessionLauncher, error)
	Metrics                *observability.Registry
	CodexSessions          *codexsession.Manager
	ServeLeases            *servelease.Manager
	LocalControlToken      string
}

type HostedLifecycle interface {
	Service
	protocol.CapabilityProvider
}

type Host struct {
	runtime  *Runtime
	http     *HTTPService
	handler  http.Handler
	sessions *session.Manager
}

func NewReceiveCoordinator(ctx context.Context, config HostConfig, dependencies HostDependencies) (_ *Host, resultErr error) {
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
	transferService, err := filetransfer.New(filetransfer.Config{Root: filepath.Join(config.Runtime.StateRoot, "file-transfers"), LocalMachineID: config.MachineID, Store: durable, PublishRoot: config.InboxPath, Random: rand.Reader, Policy: config.FileTransferPolicy})
	if err != nil {
		return nil, err
	}
	transferHandler, err := server.NewFileTransferHandler(server.FileTransferHandlerConfig{
		Service: transferService, Journal: journal, Authorizer: dependencies.Authorizer,
		AuthorizeCreate: func(authorization server.Authorization, request server.CreateFileTransferRequest) bool {
			return authorization.MachineID == config.MachineID && authorization.UserID != "" && request.SourceMachineID == authorization.SourceMachineID && request.InitiatingUserID == authorization.UserID && request.DestinationMachineID == config.MachineID && request.SessionID == ""
		},
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if dependencies.ServeLeases != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/serve-leases", servelease.Handler{Manager: dependencies.ServeLeases, Token: dependencies.LocalControlToken})
	}
	mux.Handle("/v1/file-transfers", transferHandler)
	mux.Handle("/v1/file-transfers/", transferHandler)
	if dependencies.PreviewLauncher != nil {
		handler, launchErr := server.NewPreviewLaunchHandler(server.PreviewLaunchHandlerConfig{Authorizer: dependencies.Authorizer, Launcher: dependencies.PreviewLauncher, MachineID: config.MachineID})
		if launchErr != nil {
			return nil, launchErr
		}
		mux.Handle("/v1/preview-launches", handler)
	}
	healthSource := &runtimeHealthSource{}
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		workloads := map[string]uint64{"transfers": transferWorkloadCount(filepath.Join(config.Runtime.StateRoot, "file-transfers")), "serves_detached": uint64(activeDetachedServeCount(config.Runtime.StateRoot, time.Now().UTC()))}
		if dependencies.ServeLeases != nil {
			workloads["serves_foreground"] = uint64(dependencies.ServeLeases.Count())
		}
		_ = json.NewEncoder(writer).Encode(struct {
			health.Snapshot
			FileTransferPolicy filetransfer.Policy `json:"file_transfer_policy"`
			Workloads          map[string]uint64   `json:"workloads"`
		}{Snapshot: healthSource.Snapshot(), FileTransferPolicy: config.FileTransferPolicy.Current(), Workloads: workloads})
	})
	if dependencies.Metrics != nil {
		mux.Handle("/metrics", dependencies.Metrics.Handler())
	}
	httpService, err := NewHTTPService(HTTPConfig{Address: config.ListenAddress, Handler: mux, Listener: dependencies.Listener})
	if err != nil {
		return nil, err
	}
	components := []Component{
		{Capability: "storage", Required: true, Service: shutdownService{shutdown: func(context.Context) error { return durable.Close() }}},
		{Capability: "file_transfer_cleanup", Required: true, Service: &filetransfer.CleanupWorker{Service: transferService}},
	}
	if dependencies.AuthorizationService != nil {
		components = append(components, Component{Capability: "authorization", Required: false, Service: dependencies.AuthorizationService})
	}
	if dependencies.PreviewRecovery != nil {
		components = append(components, Component{Capability: "preview_recovery", Required: false, Service: dependencies.PreviewRecovery})
	}
	if dependencies.ServeLeases != nil {
		components = append(components, Component{Capability: "serve_lease", Required: false, Service: dependencies.ServeLeases})
	}
	components = append(components,
		Component{Capability: "runtime_observation", Required: true, Service: dependencies.RuntimeObservationService},
		Component{Capability: "edge", Required: true, Service: dependencies.Connector},
		Component{Capability: "control_plane", Required: true, Service: httpService},
	)
	runtime, err := NewRuntime(Config{Version: config.Runtime.Version, Components: components, ShutdownTimeout: config.ShutdownTimeout})
	if err != nil {
		return nil, err
	}
	healthSource.set(runtime, components)
	return &Host{runtime: runtime, http: httpService, handler: mux}, nil
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
		"PAPERBOAT_PREVIEW_REGISTRATION_ENDPOINT=http://"+config.ListenAddress+"/v1/preview-registrations",
		"PAPERBOAT_FILE_TRANSFER_ENDPOINT=http://"+config.ListenAddress+"/v1/file-transfers",
		"PAPERBOAT_RUNTIME_AGENT_TOKEN_FILE="+config.AgentTokenFile,
		"PAPERBOAT_WORKSPACE_ROOT="+config.WorkspaceRoot,
	)
	invalidPreview := dependencies.PreviewService != nil && dependencies.Previews == nil
	invalidConfigApply := dependencies.ConfigApplyProof && dependencies.ConfigApply == nil
	invalidHosted := config.Runtime.Profile == runtimeconfig.Hosted && dependencies.HostedLifecycle == nil ||
		config.Runtime.Profile == runtimeconfig.BYOD && dependencies.HostedLifecycle != nil
	if invalidPreview {
		return nil, errors.Join(ErrHostInvalid, errors.New("invalid preview dependencies"))
	}
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
		Launch: func(command pty.Command) (session.PTYProcess, error) { return adapter.Start(command) },
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
	dispatcher, err := server.NewDispatcher(server.DispatcherConfig{
		Sessions: sessions, Health: healthSource, SessionLauncher: sessionLauncher,
		WorkspaceRoot: config.WorkspaceRoot, Random: random,
		Previews: dependencies.Previews, PreviewControl: dependencies.PreviewControl,
		ConfigApply: dependencies.ConfigApply,
		Updates:     dependencies.Updates,
		Writers:     writers,
	})
	if err != nil {
		return nil, err
	}
	transferService, err := filetransfer.New(filetransfer.Config{
		Root: filepath.Join(config.Runtime.StateRoot, "file-transfers"), LocalMachineID: config.MachineID, Store: durable,
		PublishRoot: config.InboxPath, Random: random, Policy: config.FileTransferPolicy,
	})
	if err != nil {
		return nil, err
	}
	transferHandler, err := server.NewFileTransferHandler(server.FileTransferHandlerConfig{
		Service: transferService, Journal: journal, Authorizer: dependencies.Authorizer,
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
		PeerTimeout:       config.Runtime.Limits.PeerTimeout,
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
	if dependencies.ServeLeases != nil && dependencies.LocalControlToken != "" {
		mux.Handle("/v1/serve-leases", servelease.Handler{Manager: dependencies.ServeLeases, Token: dependencies.LocalControlToken})
	}
	mux.Handle("/v1/runtime", websocketHandler)
	if dependencies.CodexSessions != nil {
		codexHandler, codexErr := codexsession.NewHandler(codexsession.HandlerConfig{Manager: dependencies.CodexSessions, Authorizer: dependencies.Authorizer})
		if codexErr != nil {
			return nil, codexErr
		}
		mux.Handle("/v1/codex-sessions/{session_id}/ws", codexHandler)
		managementHandler, managementErr := codexsession.NewManagementHandler(dependencies.CodexSessions, dependencies.Authorizer)
		if managementErr != nil {
			return nil, managementErr
		}
		mux.Handle("POST /v1/codex-sessions/{session_id}", managementHandler)
		mux.Handle("POST /v1/codex-sessions/{session_id}/renew", managementHandler)
		mux.Handle("GET /v1/codex-sessions/{session_id}/directories", managementHandler)
		mux.Handle("DELETE /v1/codex-sessions/{session_id}", managementHandler)
	}
	mux.Handle("/v1/file-transfers", transferHandler)
	mux.Handle("/v1/file-transfers/", transferHandler)
	if dependencies.PreviewLauncher != nil {
		previewLaunchHandler, launchErr := server.NewPreviewLaunchHandler(server.PreviewLaunchHandlerConfig{Authorizer: dependencies.Authorizer, Launcher: dependencies.PreviewLauncher, MachineID: config.MachineID})
		if launchErr != nil {
			return nil, launchErr
		}
		mux.Handle("/v1/preview-launches", previewLaunchHandler)
	}
	if dependencies.Previews != nil && dependencies.PreviewControl != nil && config.EnvironmentID != "" {
		agentHandler, agentErr := preview.NewAgentHandler(preview.AgentHandlerConfig{Token: agentToken, EnvironmentID: config.EnvironmentID, Registry: dependencies.Previews, Control: dependencies.PreviewControl, RoutesChanged: dependencies.PreviewRoutesChanged})
		if agentErr != nil {
			return nil, agentErr
		}
		mux.Handle("/v1/preview-registrations", agentHandler)
	}
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		snapshot := healthSource.Snapshot()
		workloads := hostWorkloadCounts(sessions, filepath.Join(config.Runtime.StateRoot, "file-transfers"))
		workloads["serves_detached"] = uint64(activeDetachedServeCount(config.Runtime.StateRoot, time.Now().UTC()))
		if dependencies.ServeLeases != nil {
			workloads["serves_foreground"] = uint64(dependencies.ServeLeases.Count())
		}
		_ = json.NewEncoder(writer).Encode(struct {
			health.Snapshot
			FileTransferPolicy filetransfer.Policy `json:"file_transfer_policy"`
			Workloads          map[string]uint64   `json:"workloads"`
		}{Snapshot: snapshot, FileTransferPolicy: config.FileTransferPolicy.Current(), Workloads: workloads})
	})
	if dependencies.Metrics != nil {
		mux.Handle("/metrics", dependencies.Metrics.Handler())
	}
	httpService, err := NewHTTPService(HTTPConfig{Address: config.ListenAddress, Handler: mux, Listener: dependencies.Listener, NativeHandler: func(conn net.Conn) { _ = nativeManager.Serve(conn) }})
	if err != nil {
		return nil, err
	}
	components := make([]Component, 0, 8)
	transferCleanup := &filetransfer.CleanupWorker{Service: transferService}
	components = append(components,
		Component{Capability: "storage", Required: true, Service: shutdownService{shutdown: func(context.Context) error { return durable.Close() }}},
		Component{Capability: "sessions", Required: true, Service: shutdownService{shutdown: sessions.ShutdownForRecovery}},
		Component{Capability: "file_transfer_cleanup", Required: true, Service: transferCleanup},
	)
	if dependencies.CodexSessions != nil {
		components = append(components, Component{Capability: "codex.v1", Required: false, Service: &codexSessionService{manager: dependencies.CodexSessions}})
	}
	if dependencies.AuthorizationService != nil {
		components = append(components, Component{Capability: "authorization", Required: false, Service: dependencies.AuthorizationService})
	}
	if dependencies.ConfigSync != nil {
		components = append(components, Component{
			Capability: "config_sync", Required: config.Runtime.Profile == runtimeconfig.BYOD,
			Service: dependencies.ConfigSync,
		})
	}
	components = append(components, Component{Capability: "protocol", Required: true, Service: protocolServer})
	if dependencies.PreviewService != nil {
		components = append(components, Component{Capability: "target", Required: false, Service: dependencies.PreviewService})
	}
	if dependencies.PreviewRecovery != nil {
		components = append(components, Component{Capability: "preview_recovery", Required: false, Service: dependencies.PreviewRecovery})
	}
	if dependencies.ServeLeases != nil {
		components = append(components, Component{Capability: "serve_lease", Required: false, Service: dependencies.ServeLeases})
	}
	if dependencies.RuntimeObservationService != nil {
		components = append(components, Component{Capability: "runtime_observation", Required: false, Service: dependencies.RuntimeObservationService})
	}
	if dependencies.Connector != nil {
		components = append(components, Component{Capability: "edge", Required: true, Service: dependencies.Connector})
	}
	// Start hosted preparation after transport dependencies. Reverse shutdown then
	// flushes hosted state before connector drain and the final runtime observation.
	if dependencies.HostedLifecycle != nil {
		components = append(components, Component{Capability: "hosted_lifecycle", Required: true, Service: dependencies.HostedLifecycle})
	}
	components = append(components, Component{Capability: "control_plane", Required: true, Service: httpService})
	runtime, err := NewRuntime(Config{Version: config.Runtime.Version, Components: components, ShutdownTimeout: config.ShutdownTimeout})
	if err != nil {
		return nil, err
	}
	healthSource.set(runtime, components)
	return &Host{runtime: runtime, http: httpService, handler: mux, sessions: sessions}, nil
}

func hostWorkloadCounts(sessions *session.Manager, transferRoot string) map[string]uint64 {
	counts := sessions.ResourceCounts()
	entries, err := os.ReadDir(transferRoot)
	if errors.Is(err, os.ErrNotExist) {
		counts["transfers"] = 0
		return counts
	}
	if err != nil {
		counts["transfer_count_unavailable"] = 1
		return counts
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".content" {
			counts["transfers"]++
		}
	}
	return counts
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
	temporary, err := os.CreateTemp(directory, ".agent-token-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := io.WriteString(temporary, token+"\n"); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return token, nil
}

func (h *Host) Start(ctx context.Context) error    { return h.runtime.Start(ctx) }
func (h *Host) Shutdown(ctx context.Context) error { return h.runtime.Shutdown(ctx) }
func (h *Host) State() State                       { return h.runtime.State() }

type shutdownService struct{ shutdown func(context.Context) error }

func (shutdownService) Start(context.Context) error          { return nil }
func (s shutdownService) Shutdown(ctx context.Context) error { return s.shutdown(ctx) }

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
