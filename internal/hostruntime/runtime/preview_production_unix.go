//go:build darwin || linux || windows

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

type ProductionPreviewWorkerConfig struct {
	ControlURL        string
	StateRoot         string
	Name              string
	Port              uint16
	Duration          time.Duration
	Indefinite        bool
	ExpiresAt         *time.Time
	DescriptorPath    string
	ServiceDefinition string
	Transport         http.RoundTripper
	Ready             func(preview.ControlRecord) error
	ServiceRunner     hostservice.Runner
	SourceKind        string
	OwnerMode         string
}

func RunProductionPreviewWorker(ctx context.Context, config ProductionPreviewWorkerConfig) (runErr error) {
	startedAt := time.Now()
	stage := func(name string) {
		slog.Info("public preview startup", "stage", name, "duration_ms", time.Since(startedAt).Milliseconds())
	}
	controlURL, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || controlURL.Scheme != "https" || controlURL.Hostname() == "" || !filepath.IsAbs(config.StateRoot) || config.Name == "" || config.Port == 0 || config.Indefinite && (config.Duration != 0 || config.ExpiresAt != nil) || !config.Indefinite && config.Duration <= 0 && config.ExpiresAt == nil {
		return ErrProductionInvalid
	}
	var durable *PreviewRuntimeDescriptor
	if config.DescriptorPath != "" || config.ServiceDefinition != "" {
		if !filepath.IsAbs(config.DescriptorPath) || config.ServiceDefinition != "" && !filepath.IsAbs(config.ServiceDefinition) {
			return ErrProductionInvalid
		}
		descriptor, descriptorErr := readPreviewRuntimeDescriptor(config.DescriptorPath)
		if descriptorErr != nil || descriptor.Name != config.Name || descriptor.Port != config.Port || descriptor.Indefinite != config.Indefinite || descriptor.ServiceDefinition != config.ServiceDefinition || !samePreviewExpiry(descriptor.ExpiresAt, config.ExpiresAt) {
			return errors.Join(ErrProductionInvalid, descriptorErr)
		}
		durable = &descriptor
	}
	if config.ServiceDefinition != "" && (durable == nil || durable.Serve == nil) {
		home, homeErr := os.UserHomeDir()
		expected, _, pathErr := previewServiceDefinition(home, config.Name, runtime.GOOS)
		if homeErr != nil || pathErr != nil || config.ServiceDefinition != expected {
			return errors.Join(ErrProductionInvalid, homeErr, pathErr)
		}
		runner := config.ServiceRunner
		if runner == nil {
			runner = hostservice.ExecRunner{}
		}
		defer func() {
			if runErr == nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				runErr = errors.Join(runErr, retireCompletedServeService(cleanupCtx, config.Name, config.DescriptorPath, config.ServiceDefinition, runner))
			}
		}()
	}
	if config.ExpiresAt != nil {
		config.Duration = time.Until(config.ExpiresAt.UTC())
		if config.Duration <= 0 {
			if durable != nil {
				_ = os.Remove(config.DescriptorPath)
			}
			return nil
		}
	}
	store, err := identity.Open(identity.Config{StateRoot: config.StateRoot})
	if err != nil {
		return err
	}
	registration, err := store.Registration()
	if err != nil || registration.ServerURL != controlURL.String() {
		return ErrProductionInvalid
	}
	machines, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL.String(), StateRoot: config.StateRoot, Transport: config.Transport})
	if err != nil {
		return err
	}
	operationID := func() (string, error) { return randomProductionOperationID() }
	credentials, err := preview.NewCredentialSource(preview.CredentialSourceConfig{Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/previews/credentials"}).String(), AllowedHosts: []string{controlURL.Hostname()}, Identities: machines, Proofs: machines, OperationID: operationID, Transport: config.Transport})
	if err != nil {
		return err
	}
	control, err := preview.NewControlClient(preview.ControlClientConfig{Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/previews/operations"}).String(), AllowedHosts: []string{controlURL.Hostname()}, EnvironmentID: registration.EnvironmentID, Tokens: credentials, Identities: machines, Proofs: machines, Transport: config.Transport})
	if err != nil {
		return err
	}
	target := preview.Target{Host: "127.0.0.1", Port: config.Port}
	var remote preview.ControlRecord
	items, listErr := control.List(ctx)
	if listErr == nil {
		for _, item := range items {
			if item.LogicalName == config.Name && item.State != "removed" && item.State != "expired" && (config.Indefinite || item.ExpiresAt != nil && item.ExpiresAt.After(time.Now().UTC())) {
				remote = item
				break
			}
		}
	}
	if remote.PreviewKey == "" || remote.TargetPort != int32(config.Port) {
		if config.SourceKind == "" && config.OwnerMode == "" {
			remote, err = control.Register(ctx, config.Name, target, true, config.Duration, config.Indefinite)
		} else {
			remote, err = control.RegisterWithMetadata(ctx, config.Name, target, true, config.Duration, config.Indefinite, config.SourceKind, config.OwnerMode)
		}
		if err != nil {
			return err
		}
	}
	stage("registered")
	removeRemote := true
	defer func() {
		// A durable service can be interrupted at any startup stage, including
		// after registration but before connector readiness. Preserve the remote
		// route for every supervisor cancellation, not only cancellation after the
		// worker reaches its steady-state loop.
		if durable != nil && ctx.Err() != nil {
			removeRemote = false
		}
		if removeRemote {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := control.Remove(cleanupCtx, config.Name); err != nil {
				runErr = errors.Join(runErr, err)
			}
		}
	}()
	registry, err := preview.New(preview.Config{Prober: preview.TCPProber{Dialer: net.Dialer{Timeout: 2 * time.Second}}, MaxTargets: 1, MaxConcurrentProbes: 1})
	if err != nil {
		return err
	}
	if _, err = registry.RegisterCanonical(remote.PreviewKey, remote.URL, registration.EnvironmentID, config.Name, target); err != nil {
		return err
	}
	sender, err := preview.NewHTTPSender(preview.HTTPSenderConfig{Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/previews/observations"}).String(), AllowedHosts: []string{controlURL.Hostname()}, Tokens: credentials, Identities: machines, Proofs: machines, OperationID: operationID, Transport: config.Transport})
	if err != nil {
		return err
	}
	monitor, err := preview.NewMonitor(preview.MonitorConfig{Registry: registry})
	if err != nil {
		return err
	}
	reporter, err := preview.NewReporter(preview.ReporterConfig{Registry: registry, Sender: sender, Interval: 5 * time.Second, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	fetcher, err := auth.NewHTTPJWKSFetcher(controlURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(), []string{controlURL.Hostname()}, config.Transport)
	if err != nil {
		return err
	}
	keys, err := auth.NewJWKSCache(auth.JWKSConfig{Fetcher: fetcher, Clock: productionClock{}, TTL: 5 * time.Minute, RetainMissing: auth.DefaultRetainMissing, PersistencePath: filepath.Join(config.StateRoot, "authorization", "jwks.json")})
	if err != nil {
		return err
	}
	refreshCtx, cancelRefresh := context.WithTimeout(ctx, 10*time.Second)
	err = keys.Refresh(refreshCtx)
	cancelRefresh()
	if err != nil {
		return err
	}
	stage("authority_ready")
	verifier := auth.Verifier{Keys: keys, Clock: productionClock{}, Replays: auth.NewReplayCache(256, productionClock{}), Revocations: auth.NewRevocationCache(), ClockSkew: 30 * time.Second, RefreshTimeout: 2 * time.Second}
	admissions, err := connector.NewHTTPSAdmissionSource(connector.AdmissionSourceConfig{Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/connectors/admission"}).String(), AllowedHosts: []string{controlURL.Hostname()}, Tokens: machines, Proofs: machines, Verifier: verifier, Clock: productionClock{}, Issuer: strings.TrimRight(controlURL.String(), "/"), EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID, ConnectorID: remote.PreviewKey, EdgePool: "default", OperationID: operationID, Transport: config.Transport})
	if err != nil {
		return err
	}
	dialer, err := connector.NewPublicPreviewDialer(connector.PublicPreviewDialerConfig{})
	if err != nil {
		return err
	}
	manager, err := connector.New(connector.Config{EnvironmentID: registration.EnvironmentID, MachineID: registration.MachineID, ConnectorID: remote.PreviewKey, EdgePool: "default", Dialer: dialer, DrainTimeout: 10 * time.Second, Transport: connector.QUIC})
	if err != nil {
		return err
	}
	connectorService, err := connector.NewSupervisor(connector.SupervisorConfig{Manager: manager, Admissions: admissions, InitialBackoff: time.Second, MaxBackoff: 30 * time.Second})
	if err != nil {
		return err
	}
	if err = monitor.Start(ctx); err != nil {
		return err
	}
	defer shutdownPreviewComponent(monitor.Shutdown)
	if err = reporter.Start(ctx); err != nil {
		return err
	}
	defer shutdownPreviewComponent(reporter.Shutdown)
	if err = connectorService.Start(ctx); err != nil {
		return err
	}
	stage("connector_started")
	defer shutdownPreviewComponent(connectorService.Shutdown)
	if err = monitor.RunOnce(ctx); err != nil {
		return err
	}
	stage("target_probed")
	if _, err = reporter.DeliverOnce(ctx); err != nil {
		return err
	}
	stage("observation_delivered")
	if err = waitForPreviewConnector(ctx, manager); err != nil {
		return err
	}
	status := manager.Status()
	slog.Info("public preview carrier ready", "transport", status.Transport, "generation", status.Generation, "duration_ms", time.Since(startedAt).Milliseconds())
	remote.State = "ready"
	if config.Ready != nil {
		if err = config.Ready(remote); err != nil {
			return err
		}
	}
	if durable != nil {
		durable.Record = &remote
		if err = writePreviewRuntimeDescriptor(config.DescriptorPath, *durable); err != nil {
			return err
		}
	}
	defer func() {
		if runErr == nil && durable != nil {
			_ = os.Remove(config.DescriptorPath)
		}
	}()

	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	var expiry <-chan time.Time
	var expiryTimer *time.Timer
	if !config.Indefinite {
		remaining := config.Duration
		if remote.ExpiresAt != nil {
			remaining = time.Until(remote.ExpiresAt.UTC())
		}
		if remaining < 0 {
			remaining = 0
		}
		expiryTimer = time.NewTimer(remaining)
		defer expiryTimer.Stop()
		expiry = expiryTimer.C
	}
	for {
		select {
		case <-ctx.Done():
			// A durable worker is stopped during service restarts, user logoff,
			// and operating-system shutdown. Keep its server route so the same
			// descriptor and URL can reconnect when the service starts again.
			// Foreground previews still revoke their route when their command is
			// canceled.
			if durable != nil {
				removeRemote = false
			}
			return ctx.Err()
		case <-expiry:
			_, _ = registry.Expire(remote.PreviewKey)
			_, _ = reporter.DeliverOnce(context.Background())
			return nil
		case <-poll.C:
			items, listErr := control.List(ctx)
			if listErr != nil {
				continue
			}
			found := false
			for _, item := range items {
				if item.PreviewKey == remote.PreviewKey && item.State != "removed" && item.State != "expired" {
					found = true
					break
				}
			}
			if !found {
				removeRemote = false
				_, _ = registry.Remove(remote.PreviewKey)
				return nil
			}
		}
	}
}

func waitForPreviewConnector(ctx context.Context, manager *connector.Manager) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if manager.Status().Connected {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func samePreviewExpiry(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func shutdownPreviewComponent(shutdown func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = shutdown(ctx)
}
