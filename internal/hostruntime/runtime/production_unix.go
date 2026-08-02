//go:build darwin || linux

package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/availability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hosted"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/servelease"
)

var ErrProductionInvalid = errors.New("invalid production host configuration")

type productionClock struct{}

func (productionClock) Now() time.Time { return time.Now().UTC() }

func NewProductionHost(ctx context.Context, version string, environ func(string) string) (*Host, error) {
	if environ == nil {
		return nil, ErrProductionInvalid
	}
	runtimeConfig, err := runtimeconfig.FromEnv(version, environ)
	if err != nil {
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	bootState, recoveryExitSignal, err := recordWorkerBoot(runtimeConfig.StateRoot)
	if err != nil {
		return nil, err
	}
	metrics, err := observability.NewRegistry(observability.DefaultDescriptors())
	if err != nil {
		return nil, err
	}
	_ = metrics.Record("paperboat_runtime_restart_total", float64(bootState.Generation), nil)
	if runtimeConfig.Profile == runtimeconfig.BYOD {
		store, openErr := runtimeidentity.Open(runtimeidentity.Config{StateRoot: runtimeConfig.StateRoot})
		if openErr == nil {
			registration, registrationErr := store.Registration()
			if registrationErr == nil && shouldRunReceiveCoordinator(registration.SetupMode, environ("PAPERBOAT_SETUP_MODE")) {
				return newProductionReceiveCoordinator(ctx, version, environ, runtimeConfig, bootState, recoveryExitSignal, metrics, registration)
			}
		}
	}
	var hostedConfig hosted.Config
	if runtimeConfig.Profile == runtimeconfig.Hosted {
		hostedConfig, err = hosted.FromEnv(environ)
		if err != nil {
			return nil, err
		}
		if setupName := environ("PAPERBOAT_SETUP_SCRIPT_ENV"); setupName != "" && safeProductionEnvironmentName(setupName) {
			_ = os.Unsetenv(setupName)
		}
	}
	controlURL, err := validatedControlURL(environ("PAPERBOAT_CONTROL_URL"))
	if err != nil {
		return nil, err
	}
	issuer := strings.TrimRight(valueOrRuntime(environ("PAPERBOAT_CONTROL_ISSUER"), controlURL.String()), "/")
	transport, err := productionTransport(environ("PAPERBOAT_CONTROL_CA_FILE"))
	if err != nil {
		return nil, err
	}
	operationID := func() (string, error) {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return "op_admit_" + hex.EncodeToString(bytes), nil
	}
	renewingTokens, err := enrollment.NewRenewingTokenSource(enrollment.RenewingTokenConfig{ControlURL: controlURL.String(), StateRoot: runtimeConfig.StateRoot, Transport: transport, RenewBefore: 10 * time.Minute, Timeout: 15 * time.Second, Clock: func() time.Time { return time.Now().UTC() }, OperationID: operationID, Metrics: metrics})
	if err != nil {
		return nil, err
	}
	var enrollmentClient *enrollment.Client
	if _, loadErr := enrollment.LoadRuntimeIdentityForRenewal(runtimeConfig.StateRoot, time.Now().UTC()); loadErr != nil {
		var clientErr error
		enrollmentClient, clientErr = enrollment.NewClient(transport, 15*time.Second)
		if clientErr != nil {
			return nil, clientErr
		}
		enrollmentConfig := enrollment.Config{
			ControlURL: controlURL.String(), ControlCAFile: environ("PAPERBOAT_CONTROL_CA_FILE"),
			StateRoot: runtimeConfig.StateRoot,
		}
		if runtimeConfig.Profile == runtimeconfig.Hosted {
			_, err = retryHostedControl(ctx, func(attemptCtx context.Context) (enrollment.RuntimeIdentity, error) {
				return enrollmentClient.EnrollHosted(attemptCtx, enrollmentConfig)
			})
		} else {
			grantName := valueOrRuntime(environ("PAPERBOAT_ENROLLMENT_CREDENTIAL_ENV"), "PAPERBOAT_ENROLLMENT_CREDENTIAL")
			if !safeProductionEnvironmentName(grantName) {
				return nil, ErrProductionInvalid
			}
			enrollmentConfig.EnrollmentCredential = environ(grantName)
			if enrollmentConfig.EnrollmentCredential == "" {
				return nil, loadErr
			}
			_, err = enrollmentClient.Enroll(ctx, enrollmentConfig)
			_ = os.Unsetenv(grantName)
		}
		if err != nil {
			if runtimeConfig.Profile == runtimeconfig.Hosted {
				return nil, fmt.Errorf("hosted identity bootstrap: %w", err)
			}
			return nil, err
		}
	}
	identity, err := enrollment.LoadRuntimeIdentityForRenewal(runtimeConfig.StateRoot, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	machineID := environ("PAPERBOAT_MACHINE_ID")
	if machineID == "" || machineID != identity.MachineID {
		return nil, ErrProductionInvalid
	}
	inboxPath := ""
	if runtimeConfig.Profile == runtimeconfig.BYOD {
		identityStore, openErr := runtimeidentity.Open(runtimeidentity.Config{StateRoot: runtimeConfig.StateRoot})
		if openErr != nil {
			return nil, openErr
		}
		registration, registrationErr := identityStore.Registration()
		if registrationErr != nil || registration.MachineID != machineID || !filepath.IsAbs(registration.InboxPath) || filepath.Clean(registration.InboxPath) != registration.InboxPath {
			return nil, errors.Join(ErrProductionInvalid, registrationErr)
		}
		inboxPath = registration.InboxPath
	}
	if runtimeConfig.Profile == runtimeconfig.Hosted {
		if enrollmentClient == nil {
			enrollmentClient, err = enrollment.NewClient(transport, 15*time.Second)
			if err != nil {
				return nil, err
			}
		}
		bootstrap, bootstrapErr := retryHostedControl(ctx, func(attemptCtx context.Context) (enrollment.HostedBootstrap, error) {
			return enrollmentClient.HostedBootstrap(attemptCtx, enrollment.Config{
				ControlURL: controlURL.String(), ControlCAFile: environ("PAPERBOAT_CONTROL_CA_FILE"),
				StateRoot: runtimeConfig.StateRoot,
			})
		})
		if bootstrapErr != nil {
			return nil, fmt.Errorf("hosted bootstrap: %w", bootstrapErr)
		}
		hostedConfig.SetupScript = bootstrap.SetupScript
		hostedConfig.GitToken = bootstrap.SourcePassword
	}
	fetcher, err := auth.NewHTTPJWKSFetcher(controlURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(), []string{controlURL.Hostname()}, transport)
	if err != nil {
		return nil, err
	}
	cache, err := auth.NewJWKSCache(auth.JWKSConfig{Fetcher: fetcher, Clock: productionClock{}, TTL: 5 * time.Minute, RetainMissing: auth.DefaultRetainMissing, PersistencePath: filepath.Join(runtimeConfig.StateRoot, "authorization", "jwks.json")})
	if err != nil {
		return nil, err
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_ = cache.Refresh(refreshCtx)
	cancel()
	revocations := auth.NewRevocationCache()
	revocationRefresh, err := newRevocationRefreshService(controlURL.ResolveReference(&url.URL{Path: "/v1/helper-trust/revocations"}).String(), renewingTokens, enrollment.ProofSource{StateRoot: runtimeConfig.StateRoot}, operationID, revocations, transport, 15*time.Second)
	if err != nil {
		return nil, err
	}
	authorizationRefresh := serviceGroup{&jwksRefreshService{cache: cache, interval: time.Minute}, revocationRefresh}
	verifier := auth.Verifier{Keys: cache, Clock: productionClock{}, Replays: auth.NewReplayCache(4096, productionClock{}), Revocations: revocations, ClockSkew: 30 * time.Second, RefreshTimeout: 2 * time.Second}
	authorizer, err := NewCredentialAuthorizer(CredentialAuthConfig{Issuer: issuer, EnvironmentID: identity.EnvironmentID, MachineID: machineID, HelperID: identity.HelperID, Verifier: verifier, Revocations: revocations})
	if err != nil {
		return nil, err
	}
	source, err := connector.NewHTTPSAdmissionSource(connector.AdmissionSourceConfig{
		Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/connectors/admission"}).String(), AllowedHosts: []string{controlURL.Hostname()},
		Tokens: renewingTokens, Proofs: enrollment.ProofSource{StateRoot: runtimeConfig.StateRoot}, Verifier: verifier,
		Clock: productionClock{}, Issuer: issuer, EnvironmentID: identity.EnvironmentID, MachineID: machineID, ConnectorID: "runtime", EdgePool: valueOrRuntime(environ("PAPERBOAT_EDGE_POOL"), "default"), OperationID: operationID, Transport: transport,
	})
	if err != nil {
		return nil, err
	}
	readyTimeout := durationRuntime(environ("PAPERBOAT_CONNECTOR_READY_TIMEOUT_SECONDS"), 15*time.Second)
	preferencePath := filepath.Join(runtimeConfig.StateRoot, "connector", "transport.json")
	dialer, err := connector.NewFRPDialer(connector.FRPDialerConfig{ReadyTimeout: readyTimeout, RouteKinds: []string{"runtime_https_wss"}, PreferencePath: preferencePath})
	if err != nil {
		return nil, err
	}
	transferPolicy := filetransfer.NewPolicyStore(filetransfer.DefaultPolicy)
	manager, err := connector.New(connector.Config{EnvironmentID: identity.EnvironmentID, MachineID: machineID, ConnectorID: "runtime", EdgePool: valueOrRuntime(environ("PAPERBOAT_EDGE_POOL"), "default"), Dialer: dialer, DrainTimeout: 10 * time.Second, Transport: productionConnectorTransport(environ("PAPERBOAT_CONNECTOR_TERMINAL_TRANSPORT")), AdmissionAccepted: func(policy auth.FileTransferPolicy) {
		_ = transferPolicy.Update(filetransfer.Policy{Revision: policy.Revision, MaxFileBytes: policy.MaxFileBytes, MaxBatchFiles: policy.MaxBatchFiles, MaxBatchBytes: policy.MaxBatchBytes, MaxConcurrentTransfers: policy.MaxConcurrentTransfers, RetentionSeconds: policy.RetentionSeconds, DeliveryTimeoutSeconds: policy.DeliveryTimeoutSeconds, MaxPendingSpoolBytes: policy.MaxPendingSpoolBytes})
	}})
	if err != nil {
		return nil, err
	}
	supervisor, err := connector.NewSupervisor(connector.SupervisorConfig{Manager: manager, Admissions: source, InitialBackoff: time.Second, MaxBackoff: 45 * time.Second, Metrics: metrics})
	if err != nil {
		return nil, err
	}
	networkChanges, err := newNetworkChangeService(2*time.Second, supervisor.NetworkChanged)
	if err != nil {
		return nil, err
	}
	connectorService := &connectorReadinessService{supervisor: supervisor, manager: manager, networkChanges: networkChanges}
	var runtimeObservation *runtimeObservationService
	var availabilityService *availability.Service
	var updateClient *hostservice.Client
	if runtimeConfig.Profile == runtimeconfig.BYOD {
		resolver, resolverErr := availability.NewResolver(controlURL.ResolveReference(&url.URL{Path: "/v1/helper-runtime-policies/resolve"}).String(), renewingTokens, enrollment.ProofSource{StateRoot: runtimeConfig.StateRoot}, operationID, &http.Client{Transport: transport, Timeout: 10 * time.Second})
		if resolverErr != nil {
			return nil, resolverErr
		}
		hostClient, hostErr := availability.NewHostClient("/var/run/paperboat/host-service.sock", 5*time.Second)
		if hostErr != nil {
			return nil, hostErr
		}
		availabilityService, err = availability.NewService(resolver, hostClient, runtimeConfig.Limits.HeartbeatInterval, metrics)
		if err != nil {
			return nil, err
		}
		updateClient, err = hostservice.NewClient("/var/run/paperboat/host-service.sock", 2*time.Minute)
		if err != nil {
			return nil, err
		}
	}
	{
		runtimeEndpoint := controlURL.ResolveReference(&url.URL{Path: "/v1/runtime-observations"}).String()
		scope := environ("PAPERBOAT_RUNTIME_SERVICE_SCOPE")
		if scope != "system" && scope != "user" {
			scope = "unknown"
		}
		sender := &runtimeObservationSender{endpoint: runtimeEndpoint, tokens: renewingTokens, proofs: enrollment.ProofSource{StateRoot: runtimeConfig.StateRoot}, operationID: operationID, environmentID: identity.EnvironmentID, machineID: machineID, reporterVersion: version, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}, availability: availabilityService, receiptPath: filepath.Join(runtimeConfig.StateRoot, "runtime", "server-heartbeat.json"), workerGeneration: bootState.Generation, osBootID: bootState.OSBootID, serviceScope: scope, connector: manager}
		runtimeObservation = &runtimeObservationService{sender: sender, interval: runtimeConfig.Limits.HeartbeatInterval, timeout: 10 * time.Second}
	}
	var hostedLifecycle *hosted.Lifecycle
	workspaceRoot := environ("PAPERBOAT_WORKSPACE_ROOT")
	agentShell := "/bin/bash"
	if runtimeConfig.Profile == runtimeconfig.BYOD {
		agentShell, err = validatedBYODShell(environ("PAPERBOAT_SHELL"))
		if err != nil {
			return nil, err
		}
	}
	agentEnvironment := []string{"PATH=" + os.Getenv("PATH"), "SHELL=" + agentShell, "TERM=xterm-256color"}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && filepath.IsAbs(home) {
		agentEnvironment = append(agentEnvironment, "HOME="+home)
	}
	shutdownTimeout := 30 * time.Second
	if runtimeConfig.Profile == runtimeconfig.Hosted {
		hostedLifecycle, err = hosted.New(hostedConfig, hosted.Hooks{}, nil)
		if err != nil {
			return nil, err
		}
		// Prepare the checkout before constructing the PTY adapter. The adapter
		// validates its root eagerly, while hosted lifecycle owns creating/cloning it.
		if err := hostedLifecycle.Start(ctx); err != nil {
			return nil, err
		}
		if tokenName := environ("PAPERBOAT_GITHUB_TOKEN_ENV"); safeProductionEnvironmentName(tokenName) {
			_ = os.Unsetenv(tokenName)
		}
		workspaceRoot = hostedConfig.VolumeRoot
		shutdownTimeout = hostedConfig.FlushTimeout + 15*time.Second
	} else {
		if err := validateBYODWorkspace(workspaceRoot); err != nil {
			return nil, err
		}
	}
	listen := valueOrRuntime(environ("PAPERBOAT_RUNTIME_LISTEN_ADDRESS"), "127.0.0.1:8080")
	localControlToken, err := writeLocalControlToken(runtimeConfig.StateRoot)
	if err != nil {
		return nil, err
	}
	if err := writeWorkerLocal(runtimeConfig.StateRoot, listen); err != nil {
		return nil, err
	}
	runtimeService := Service(runtimeObservation)
	if availabilityService != nil {
		runtimeService = serviceGroup{availabilityService, runtimeObservation}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	previewManager := &CoordinatorPreviewManager{Executable: executable, StateRoot: runtimeConfig.StateRoot}
	_ = metrics.Record("paperboat_runtime_active_resources", float64(activeDetachedServeCount(runtimeConfig.StateRoot, time.Now().UTC())), map[string]string{"kind": "serves_detached"})
	serveLeases, err := newServeLeaseManager(controlURL.String(), runtimeConfig.StateRoot, machineID, bootState.Generation, transport, metrics)
	if err != nil {
		return nil, err
	}
	codexManager, err := codexsession.New(codexsession.Config{
		StateRoot: filepath.Join(runtimeConfig.StateRoot, "codex"), WorkspaceRoot: workspaceRoot,
		Environment: agentEnvironment, CodexPath: valueOrRuntime(environ("PAPERBOAT_CODEX_PATH"), "codex"), MaxSessions: 4,
	})
	if err != nil {
		return nil, err
	}
	dependencies := HostDependencies{Authorizer: authorizer, AuthorizationService: authorizationRefresh, Connector: connectorService, PreviewLauncher: previewManager, PreviewRecovery: previewManager, RuntimeObservationService: runtimeService, Updates: updateClient, Metrics: metrics, CodexSessions: codexManager, ServeLeases: serveLeases, LocalControlToken: localControlToken}
	if runtimeConfig.Profile == runtimeconfig.Hosted {
		dependencies.HostedLifecycle = hostedLifecycle
	}
	return NewHost(ctx, HostConfig{Runtime: runtimeConfig, ListenAddress: listen, WorkspaceRoot: workspaceRoot, ShellPath: agentShell, AgentEnvironment: agentEnvironment, EnvironmentID: identity.EnvironmentID, MachineID: machineID, InboxPath: inboxPath, ShutdownTimeout: shutdownTimeout, RecoveryExitSignal: recoveryExitSignal, FileTransferPolicy: transferPolicy}, dependencies)
}

func shouldRunReceiveCoordinator(registrationMode, installedMode string) bool {
	return registrationMode == "receive" && installedMode != "host"
}

func newProductionReceiveCoordinator(ctx context.Context, version string, environ func(string) string, runtimeConfig runtimeconfig.Config, bootState workerBootState, recoveryExitSignal string, metrics *observability.Registry, registration runtimeidentity.Registration) (*Host, error) {
	controlURL, err := validatedControlURL(environ("PAPERBOAT_CONTROL_URL"))
	if err != nil || registration.MachineID != environ("PAPERBOAT_MACHINE_ID") || registration.EnvironmentID == "" {
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	issuer := strings.TrimRight(valueOrRuntime(environ("PAPERBOAT_CONTROL_ISSUER"), controlURL.String()), "/")
	transport, err := productionTransport(environ("PAPERBOAT_CONTROL_CA_FILE"))
	if err != nil {
		return nil, err
	}
	operationID := func() (string, error) {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		return "op_receive_" + hex.EncodeToString(value), nil
	}
	control, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL.String(), StateRoot: runtimeConfig.StateRoot, Transport: transport, Timeout: 15 * time.Second, RenewBefore: 10 * time.Minute, OperationID: operationID})
	if err != nil {
		return nil, err
	}
	fetcher, err := auth.NewHTTPJWKSFetcher(controlURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(), []string{controlURL.Hostname()}, transport)
	if err != nil {
		return nil, err
	}
	cache, err := auth.NewJWKSCache(auth.JWKSConfig{Fetcher: fetcher, Clock: productionClock{}, TTL: 5 * time.Minute, RetainMissing: auth.DefaultRetainMissing, PersistencePath: filepath.Join(runtimeConfig.StateRoot, "authorization", "jwks.json")})
	if err != nil {
		return nil, err
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_ = cache.Refresh(refreshCtx)
	cancel()
	revocations := auth.NewRevocationCache()
	revocationRefresh, err := newRevocationRefreshService(controlURL.ResolveReference(&url.URL{Path: "/v1/helper-trust/revocations"}).String(), control, control, operationID, revocations, transport, 15*time.Second)
	if err != nil {
		return nil, err
	}
	authorizationRefresh := serviceGroup{&jwksRefreshService{cache: cache, interval: time.Minute}, revocationRefresh}
	verifier := auth.Verifier{Keys: cache, Clock: productionClock{}, Replays: auth.NewReplayCache(4096, productionClock{}), Revocations: revocations, ClockSkew: 30 * time.Second, RefreshTimeout: 2 * time.Second}
	authorizer, err := NewCredentialAuthorizer(CredentialAuthConfig{Issuer: issuer, EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID, HelperID: "machine-control", Verifier: verifier, Revocations: revocations})
	if err != nil {
		return nil, err
	}
	admissions, err := connector.NewHTTPSAdmissionSource(connector.AdmissionSourceConfig{
		Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/connectors/admission"}).String(), AllowedHosts: []string{controlURL.Hostname()}, Tokens: control, Proofs: control,
		Verifier: verifier, Clock: productionClock{}, Issuer: issuer, EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID,
		ConnectorID: "runtime", EdgePool: valueOrRuntime(environ("PAPERBOAT_EDGE_POOL"), "default"), OperationID: operationID, Transport: transport,
	})
	if err != nil {
		return nil, err
	}
	dialer, err := connector.NewFRPDialer(connector.FRPDialerConfig{ReadyTimeout: durationRuntime(environ("PAPERBOAT_CONNECTOR_READY_TIMEOUT_SECONDS"), 15*time.Second), RouteKinds: []string{"runtime_https_wss"}, PreferencePath: filepath.Join(runtimeConfig.StateRoot, "connector", "transport.json")})
	if err != nil {
		return nil, err
	}
	transferPolicy := filetransfer.NewPolicyStore(filetransfer.DefaultPolicy)
	manager, err := connector.New(connector.Config{EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID, ConnectorID: "runtime", EdgePool: valueOrRuntime(environ("PAPERBOAT_EDGE_POOL"), "default"), Dialer: dialer, DrainTimeout: 10 * time.Second, Transport: productionConnectorTransport(environ("PAPERBOAT_CONNECTOR_TERMINAL_TRANSPORT")), AdmissionAccepted: func(policy auth.FileTransferPolicy) {
		_ = transferPolicy.Update(filetransfer.Policy{Revision: policy.Revision, MaxFileBytes: policy.MaxFileBytes, MaxBatchFiles: policy.MaxBatchFiles, MaxBatchBytes: policy.MaxBatchBytes, MaxConcurrentTransfers: policy.MaxConcurrentTransfers, RetentionSeconds: policy.RetentionSeconds, DeliveryTimeoutSeconds: policy.DeliveryTimeoutSeconds, MaxPendingSpoolBytes: policy.MaxPendingSpoolBytes})
	}})
	if err != nil {
		return nil, err
	}
	supervisor, err := connector.NewSupervisor(connector.SupervisorConfig{Manager: manager, Admissions: admissions, InitialBackoff: time.Second, MaxBackoff: 45 * time.Second, Metrics: metrics})
	if err != nil {
		return nil, err
	}
	networkChanges, err := newNetworkChangeService(2*time.Second, supervisor.NetworkChanged)
	if err != nil {
		return nil, err
	}
	connectorService := &connectorReadinessService{supervisor: supervisor, manager: manager, networkChanges: networkChanges}
	scope := environ("PAPERBOAT_RUNTIME_SERVICE_SCOPE")
	if scope != "system" && scope != "user" {
		scope = "unknown"
	}
	sender := &runtimeObservationSender{endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/runtime-observations"}).String(), tokens: control, proofs: control, operationID: operationID, environmentID: registration.EnvironmentID, machineID: registration.MachineID, reporterVersion: version, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}, receiptPath: filepath.Join(runtimeConfig.StateRoot, "runtime", "server-heartbeat.json"), workerGeneration: bootState.Generation, osBootID: bootState.OSBootID, serviceScope: scope, connector: manager, capabilities: []string{"file_receive", "preview_launch"}}
	observation := &runtimeObservationService{sender: sender, interval: runtimeConfig.Limits.HeartbeatInterval, timeout: 10 * time.Second}
	listen := valueOrRuntime(environ("PAPERBOAT_RUNTIME_LISTEN_ADDRESS"), "127.0.0.1:8080")
	localControlToken, err := writeLocalControlToken(runtimeConfig.StateRoot)
	if err != nil {
		return nil, err
	}
	if err := writeWorkerLocal(runtimeConfig.StateRoot, listen); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	previewManager := &CoordinatorPreviewManager{Executable: executable, StateRoot: runtimeConfig.StateRoot}
	_ = metrics.Record("paperboat_runtime_active_resources", float64(activeDetachedServeCount(runtimeConfig.StateRoot, time.Now().UTC())), map[string]string{"kind": "serves_detached"})
	serveLeases, err := newServeLeaseManager(controlURL.String(), runtimeConfig.StateRoot, registration.MachineID, bootState.Generation, transport, metrics)
	if err != nil {
		return nil, err
	}
	return NewReceiveCoordinator(ctx, HostConfig{Runtime: runtimeConfig, ListenAddress: listen, WorkspaceRoot: registration.InboxPath, EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID, InboxPath: registration.InboxPath, ShutdownTimeout: 30 * time.Second, RecoveryExitSignal: recoveryExitSignal, FileTransferPolicy: transferPolicy}, HostDependencies{Authorizer: authorizer, AuthorizationService: authorizationRefresh, Connector: connectorService, PreviewLauncher: previewManager, PreviewRecovery: previewManager, RuntimeObservationService: observation, Metrics: metrics, ServeLeases: serveLeases, LocalControlToken: localControlToken})
}

func activeDetachedServeCount(stateRoot string, now time.Time) int {
	entries, err := os.ReadDir(filepath.Join(stateRoot, "previews", "active"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		descriptor, err := readPreviewRuntimeDescriptor(filepath.Join(stateRoot, "previews", "active", entry.Name()))
		if err == nil && descriptor.Serve != nil && descriptor.Serve.OwnerMode == "detached" && (descriptor.Indefinite || descriptor.ExpiresAt != nil && descriptor.ExpiresAt.After(now)) {
			count++
		}
	}
	return count
}

type serveRuntimeEvents struct {
	logger     *observability.Logger
	machineID  string
	generation uint64
}

func (e serveRuntimeEvents) Record(ctx context.Context, operation, result string) {
	if e.logger != nil {
		_ = e.logger.Log(ctx, observability.Event{Component: "serve", Operation: operation, Result: result, MachineID: e.machineID, State: result, Role: "foreground", Generation: e.generation})
	}
}

func newServeLeaseManager(controlURL, stateRoot, machineID string, generation uint64, transport http.RoundTripper, metrics *observability.Registry) (*servelease.Manager, error) {
	logger, err := observability.NewLogger(slog.Default())
	if err != nil {
		return nil, err
	}
	return servelease.New(servelease.Config{
		TTL: 15 * time.Second, Interval: time.Second, Metrics: metrics, StatePath: filepath.Join(stateRoot, "runtime", "serve-leases.json"),
		Events: serveRuntimeEvents{logger: logger, machineID: machineID, generation: generation},
		Expired: func(expireCtx context.Context, lease servelease.Lease) error {
			return revokeProductionPreviewByName(expireCtx, controlURL, stateRoot, lease.Name, transport)
		},
	})
}

func writeLocalControlToken(stateRoot string) (string, error) {
	if !filepath.IsAbs(stateRoot) {
		return "", ErrProductionInvalid
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(value)
	directory := filepath.Join(stateRoot, "runtime")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "local-control-token")
	temporary, err := os.CreateTemp(directory, ".local-control-token-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.WriteString(token); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return "", err
	}
	return token, nil
}

func writeWorkerLocal(stateRoot, listenAddress string) error {
	body, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}{"paperboat.worker-local/v1", listenAddress})
	if err != nil {
		return err
	}
	path := filepath.Join(stateRoot, "runtime", "worker-local.json")
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".worker-local-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func retryHostedControl[T any](ctx context.Context, operation func(context.Context) (T, error)) (T, error) {
	var zero T
	if operation == nil {
		return zero, ErrProductionInvalid
	}
	backoff := time.Second
	for {
		result, err := operation(ctx)
		if err == nil {
			return result, nil
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
		if backoff < 5*time.Second {
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
}

func validatedBYODShell(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/bin/sh"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.Join(ErrProductionInvalid, errors.New("BYOD shell must be an absolute canonical path"))
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.Join(ErrProductionInvalid, errors.New("BYOD shell must be an executable regular file"))
	}
	return path, nil
}

func validateBYODWorkspace(root string) error {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.Join(ErrProductionInvalid, errors.New("BYOD workspace must be an absolute canonical path"))
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrProductionInvalid, errors.New("BYOD workspace must be an existing non-symlink directory"))
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return errors.Join(ErrProductionInvalid, errors.New("BYOD workspace symlink resolution is not permitted"))
	}
	return nil
}

type runtimeObservationService struct {
	mu       sync.Mutex
	sender   *runtimeObservationSender
	interval time.Duration
	timeout  time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

func (s *runtimeObservationService) Start(ctx context.Context) error {
	if s.sender == nil || s.interval <= 0 || s.timeout <= 0 {
		return ErrProductionInvalid
	}
	initial, cancel := context.WithTimeout(ctx, s.timeout)
	err := s.sender.Send(initial)
	cancel()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return ErrProductionInvalid
	}
	runCtx, stop := context.WithCancel(context.Background())
	s.cancel, s.done = stop, make(chan struct{})
	go s.loop(runCtx, s.done)
	return nil
}

func (s *runtimeObservationService) loop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendCtx, cancel := context.WithTimeout(ctx, s.timeout)
			_ = s.sender.Send(sendCtx)
			cancel()
		}
	}
}

func (s *runtimeObservationService) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	final, stop := context.WithTimeout(ctx, s.timeout)
	err := s.sender.Send(final)
	stop()
	return err
}

type runtimeObservationSender struct {
	endpoint, environmentID, machineID, reporterVersion string
	tokens                                              interface {
		Token(context.Context) (string, error)
	}
	proofs interface {
		Proof(context.Context, string, string, string, []byte) ([]byte, error)
	}
	operationID  func() (string, error)
	client       *http.Client
	availability interface {
		Observation() *availability.Observation
	}
	receiptPath      string
	workerGeneration uint64
	osBootID         string
	serviceScope     string
	connector        interface{ Status() connector.Status }
	capabilities     []string
}

func (s *runtimeObservationSender) Send(ctx context.Context) error {
	now := time.Now().UTC()
	body, err := json.Marshal(struct {
		EnvironmentID      string                         `json:"environment_id"`
		ResourceID         string                         `json:"resource_id"`
		ReporterVersion    string                         `json:"reporter_version"`
		SampledAt          time.Time                      `json:"sampled_at"`
		Availability       *availability.Observation      `json:"availability,omitempty"`
		RuntimeDiagnostics *runtimeDiagnosticsObservation `json:"runtime_diagnostics,omitempty"`
	}{s.environmentID, s.machineID, s.reporterVersion, now, availabilityObservation(s.availability), s.runtimeDiagnostics(now)})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return err
	}
	operationID, err := s.operationID()
	if err != nil {
		return err
	}
	proof, err := s.proofs.Proof(ctx, operationID, http.MethodPost, "/v1/runtime-observations", body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("runtime observation rejected with status %d", response.StatusCode)
	}
	if s.receiptPath == "" {
		return nil
	}
	return writeServerHeartbeatReceipt(s.receiptPath, serverHeartbeatReceipt{Schema: "paperboat.server-heartbeat/v1", WorkerGeneration: s.workerGeneration, ReporterVersion: s.reporterVersion, AcceptedAt: time.Now().UTC()})
}

type runtimeDiagnosticsObservation struct {
	Capabilities        []string  `json:"capabilities"`
	WorkerGeneration    uint64    `json:"worker_generation"`
	OSBootID            string    `json:"os_boot_id"`
	ConnectorState      string    `json:"connector_state"`
	ConnectorGeneration uint64    `json:"connector_generation"`
	WorkerServiceScope  string    `json:"worker_service_scope"`
	ObservedAt          time.Time `json:"observed_at"`
}

func (s *runtimeObservationSender) runtimeDiagnostics(observedAt time.Time) *runtimeDiagnosticsObservation {
	if s.workerGeneration < 1 || s.osBootID == "" || s.connector == nil {
		return nil
	}
	status := s.connector.Status()
	state := "unavailable"
	if status.Connected {
		state = "ready"
	} else if status.Stopping {
		state = "degraded"
	}
	capabilities := s.capabilities
	if len(capabilities) == 0 {
		capabilities = []string{"file_receive", "preview_launch", "terminal_host", "codex_host", "session_host", "keep_awake"}
	}
	return &runtimeDiagnosticsObservation{Capabilities: append([]string(nil), capabilities...), WorkerGeneration: s.workerGeneration, OSBootID: s.osBootID, ConnectorState: state, ConnectorGeneration: status.Generation, WorkerServiceScope: s.serviceScope, ObservedAt: observedAt}
}

type serverHeartbeatReceipt struct {
	Schema           string    `json:"schema"`
	WorkerGeneration uint64    `json:"worker_generation"`
	ReporterVersion  string    `json:"reporter_version"`
	AcceptedAt       time.Time `json:"accepted_at"`
}

func writeServerHeartbeatReceipt(path string, receipt serverHeartbeatReceipt) error {
	if !filepath.IsAbs(path) || receipt.WorkerGeneration < 1 || receipt.ReporterVersion == "" || receipt.AcceptedAt.IsZero() {
		return ErrProductionInvalid
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProductionInvalid
	}
	temporary, err := os.CreateTemp(directory, ".server-heartbeat-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func availabilityObservation(source interface {
	Observation() *availability.Observation
}) *availability.Observation {
	if source == nil {
		return nil
	}
	return source.Observation()
}

type connectorReadinessService struct {
	supervisor     *connector.Supervisor
	manager        *connector.Manager
	networkChanges Service
}

func (s *connectorReadinessService) Start(ctx context.Context) error {
	if err := s.supervisor.Start(ctx); err != nil {
		return err
	}
	if s.networkChanges != nil {
		if err := s.networkChanges.Start(ctx); err != nil {
			return errors.Join(err, s.supervisor.Shutdown(context.Background()))
		}
	}
	return nil
}
func (s *connectorReadinessService) Shutdown(ctx context.Context) error {
	var networkErr error
	if s.networkChanges != nil {
		networkErr = s.networkChanges.Shutdown(ctx)
	}
	return errors.Join(networkErr, s.supervisor.Shutdown(ctx))
}

type jwksRefreshService struct {
	cache    *auth.JWKSCache
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

func (s *jwksRefreshService) Start(context.Context) error {
	if s.cache == nil || s.interval <= 0 || s.cancel != nil {
		return ErrProductionInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan struct{})
	go func() {
		defer close(s.done)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				attemptCtx, attemptCancel := context.WithTimeout(ctx, 10*time.Second)
				_ = s.cache.Refresh(attemptCtx)
				attemptCancel()
				timer.Reset(s.interval)
			}
		}
	}()
	return nil
}

func (s *jwksRefreshService) Shutdown(ctx context.Context) error {
	if s.cancel == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
		s.cancel, s.done = nil, nil
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *connectorReadinessService) CapabilityHealth() health.Capability {
	status := s.manager.Status()
	if status.Stopping {
		return health.Capability{State: health.Unavailable, Reason: "stopped"}
	}
	if status.Connected {
		return health.Capability{State: health.Ready}
	}
	return health.Capability{State: health.Unavailable, Reason: "connector_unavailable", RetryAfterMs: 1000}
}

func validatedControlURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrProductionInvalid
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}
func productionTransport(caPath string) (http.RoundTripper, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if caPath != "" {
		if !filepath.IsAbs(caPath) {
			return nil, ErrProductionInvalid
		}
		info, err := os.Lstat(caPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > 1<<20 {
			return nil, ErrProductionInvalid
		}
		encoded, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(encoded) {
			return nil, ErrProductionInvalid
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}
func valueOrRuntime(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
func productionConnectorTransport(value string) connector.Transport {
	return connector.Transport(valueOrRuntime(value, string(connector.Auto)))
}
func durationRuntime(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value + "s")
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
func safeProductionEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if !(r >= 'A' && r <= 'Z' || r == '_' || index > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
