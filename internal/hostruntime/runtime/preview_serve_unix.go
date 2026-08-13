//go:build darwin || linux

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
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

type ProductionServeWorkerConfig struct {
	ControlURL        string
	StateRoot         string
	Name              string
	ExpiresAt         *time.Time
	Indefinite        bool
	DescriptorPath    string
	ServiceDefinition string
	Transport         http.RoundTripper
	ServiceRunner     hostservice.Runner
	PreviewRunner     servepkg.PreviewRunner
}

func RunProductionServeWorker(ctx context.Context, config ProductionServeWorkerConfig) error {
	if ctx == nil || !filepath.IsAbs(config.StateRoot) || config.Name == "" || !filepath.IsAbs(config.DescriptorPath) ||
		config.ServiceDefinition != "" && !filepath.IsAbs(config.ServiceDefinition) || config.Indefinite == (config.ExpiresAt != nil) {
		return ErrProductionInvalid
	}
	descriptor, err := readPreviewRuntimeDescriptor(config.DescriptorPath)
	if err != nil || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name != config.Name ||
		descriptor.ServiceDefinition != config.ServiceDefinition || descriptor.Indefinite != config.Indefinite ||
		!samePreviewExpiry(descriptor.ExpiresAt, config.ExpiresAt) || !validServeRuntimeDescriptor(descriptor.Serve) {
		return errors.Join(ErrProductionInvalid, err)
	}
	registrationStore, err := identity.Open(identity.Config{StateRoot: config.StateRoot})
	var registration identity.Registration
	if err == nil {
		registration, _ = registrationStore.Registration()
	}
	logger, err := observability.NewLogger(slog.Default())
	if err != nil {
		return err
	}
	logEvent := func(operation, result string, duration time.Duration) {
		_ = logger.Log(context.Background(), observability.Event{Component: "serve", Operation: operation, Result: result, Duration: duration, MachineID: registration.MachineID, State: result, Role: "detached", Generation: descriptor.ServiceGeneration})
	}
	restartStarted := time.Now()
	source, err := servepkg.ResolvePinnedSource(descriptor.Serve.SourcePath, descriptor.Serve.SourceKind, descriptor.Serve.SourceIdentity)
	if err != nil {
		logEvent("source_invalidation", "failed", time.Since(restartStarted))
		cleanupErr := reconcileInvalidServeSource(ctx, config, descriptor.Serve.Visibility == "public")
		if cleanupErr == nil {
			logEvent("cleanup", "removed", time.Since(restartStarted))
			return nil
		}
		logEvent("cleanup", "failed", time.Since(restartStarted))
		return errors.Join(err, cleanupErr)
	}
	logEvent("restart", "ok", time.Since(restartStarted))
	duration := time.Duration(0)
	if config.ExpiresAt != nil {
		duration = time.Until(config.ExpiresAt.UTC())
		if duration <= 0 {
			_ = os.Remove(config.DescriptorPath)
			return nil
		}
	}
	observe := func(event servepkg.LifecycleEvent) {
		logEvent(event.Operation, event.Result, event.Duration)
	}
	if descriptor.Serve.Visibility == "private" {
		local, startErr := servepkg.StartLocal(ctx, servepkg.LocalConfig{
			Source: source, Duration: duration, Indefinite: config.Indefinite, SPA: descriptor.Serve.SPA, ListenPort: descriptor.Serve.ListenPort, Observe: observe,
			Ready: func(localURL string) error {
				descriptor.Port = uint16Port(localURL)
				descriptor.Record = &preview.ControlRecord{URL: localURL, State: "ready", ExpiresAt: config.ExpiresAt}
				return writePreviewRuntimeDescriptor(config.DescriptorPath, descriptor)
			},
		})
		if startErr != nil {
			return startErr
		}
		waitErr := local.Wait()
		cleanupErr := retireCompletedServeService(context.Background(), config.Name, config.DescriptorPath, config.ServiceDefinition, config.ServiceRunner)
		return errors.Join(waitErr, cleanupErr)
	}
	previewRunner := config.PreviewRunner
	if previewRunner == nil {
		previewRunner = func(previewCtx context.Context, run servepkg.PreviewRunConfig) error {
			return RunProductionPreviewWorker(previewCtx, ProductionPreviewWorkerConfig{
				ControlURL: config.ControlURL, StateRoot: config.StateRoot, Name: config.Name, Port: run.Port,
				Duration: run.Duration, Indefinite: run.Indefinite, ExpiresAt: config.ExpiresAt,
				DescriptorPath: config.DescriptorPath, ServiceDefinition: config.ServiceDefinition, Ready: run.Ready,
				SourceKind: string(descriptor.Serve.SourceKind), OwnerMode: descriptor.Serve.OwnerMode,
				Transport: config.Transport, ServiceRunner: config.ServiceRunner,
			})
		}
	}
	foreground, err := servepkg.StartForeground(ctx, servepkg.ForegroundConfig{
		Source: source, Name: config.Name, Duration: duration, Indefinite: config.Indefinite, SPA: descriptor.Serve.SPA,
		Observe: observe,
		Preview: func(previewCtx context.Context, run servepkg.PreviewRunConfig) error {
			descriptor.Port = run.Port
			if err := writePreviewRuntimeDescriptor(config.DescriptorPath, descriptor); err != nil {
				return err
			}
			return previewRunner(previewCtx, run)
		},
	})
	if err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return retireCompletedServeService(context.Background(), config.Name, config.DescriptorPath, config.ServiceDefinition, config.ServiceRunner)
		}
		return err
	}
	waitErr := foreground.Wait()
	cleanupErr := retireCompletedServeService(context.Background(), config.Name, config.DescriptorPath, config.ServiceDefinition, config.ServiceRunner)
	return errors.Join(waitErr, cleanupErr)
}

func reconcileInvalidServeSource(ctx context.Context, config ProductionServeWorkerConfig, public bool) error {
	if public {
		if err := revokeProductionPreviewByName(ctx, config.ControlURL, config.StateRoot, config.Name, config.Transport); err != nil {
			return err
		}
	}
	runner := config.ServiceRunner
	if runner == nil {
		runner = hostservice.ExecRunner{}
	}
	if config.ServiceDefinition != "" {
		if err := retirePreviewService(ctx, config.Name, config.ServiceDefinition, runner); err != nil {
			return err
		}
	}
	err := os.Remove(config.DescriptorPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func uint16Port(rawURL string) uint16 {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	port, err := net.LookupPort("tcp", parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return uint16(port)
}

func revokeProductionPreviewByName(ctx context.Context, controlAddress, stateRoot, name string, transport http.RoundTripper) error {
	controlURL, err := url.Parse(strings.TrimSpace(controlAddress))
	if err != nil || controlURL.Scheme != "https" || controlURL.Hostname() == "" {
		return errors.Join(ErrProductionInvalid, err)
	}
	store, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		return err
	}
	registration, err := store.Registration()
	if err != nil || registration.ServerURL != controlURL.String() {
		return errors.Join(ErrProductionInvalid, err)
	}
	machines, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL.String(), StateRoot: stateRoot, Transport: transport})
	if err != nil {
		return err
	}
	operationID := func() (string, error) { return randomProductionOperationID() }
	credentials, err := preview.NewCredentialSource(preview.CredentialSourceConfig{
		Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/previews/credentials"}).String(), AllowedHosts: []string{controlURL.Hostname()},
		Identities: machines, Proofs: machines, OperationID: operationID, Transport: transport,
	})
	if err != nil {
		return err
	}
	control, err := preview.NewControlClient(preview.ControlClientConfig{
		Endpoint: controlURL.ResolveReference(&url.URL{Path: "/v1/previews/operations"}).String(), AllowedHosts: []string{controlURL.Hostname()},
		EnvironmentID: registration.EnvironmentID, Tokens: credentials, Identities: machines, Proofs: machines, Transport: transport,
	})
	if err != nil {
		return err
	}
	items, err := control.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.LogicalName == name && item.State != "removed" && item.State != "expired" {
			if _, err := control.Remove(ctx, name); err != nil {
				return err
			}
			break
		}
	}
	return nil
}
