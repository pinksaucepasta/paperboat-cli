//go:build darwin || linux || windows

package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	clientapi "github.com/pinksaucepasta/paperboat/internal/api"
	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/privateproxyconfig"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

// productionPreviewAssembly owns the single preview carrier runtime used by
// stable hostd. The dispatch manager, owner registry, and carrier provider
// share this object so independent server dispatches cannot create competing
// carriers for the same machine identity.
type productionPreviewAssembly struct {
	runtime       *preview.MachinePreviewRuntime
	dispatcher    *preview.DispatchManager
	owners        *preview.RuntimeOwnerSessionRegistry
	ownerLeases   *preview.OwnerSessionLeaseManager
	privateAccess *privatepreviewproxy.AccessService
	privateTCP    *preview.PrivateTCPAccessManager
	cancel        context.CancelFunc
	runtimeDone   chan struct{}
	once          sync.Once
}

type productionPreviewAssemblyConfig struct {
	ControlURL        string
	StateRoot         string
	MachineID         string
	LocalControlToken string
	Transport         http.RoundTripper
	RunContext        context.Context
	Carrier           connector.DataCarrierPoolConfig
	OriginDial        preview.PreviewOriginDialer
	PrivatePAC        privatepreviewproxy.PACConfigurator
}

func newProductionPreviewAssembly(config productionPreviewAssemblyConfig) (*productionPreviewAssembly, error) {
	if config.RunContext == nil {
		return nil, errors.Join(ErrProductionInvalid, preview.ErrMachinePreviewRuntimeInvalid)
	}
	runtime, err := preview.NewMachinePreviewRuntime(preview.MachinePreviewRuntimeConfig{
		ControlURL: config.ControlURL,
		StateRoot:  config.StateRoot,
		RunContext: config.RunContext,
		Transport:  config.Transport,
		Carrier:    config.Carrier,
		OriginDial: config.OriginDial,
	})
	if err != nil {
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	privateSource, err := runtime.PrivateAccessSource()
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	privatePAC := config.PrivatePAC
	if privatePAC == nil {
		if err := os.MkdirAll(filepath.Join(config.StateRoot, "private-access"), 0o700); err != nil {
			_ = runtime.Close(context.WithoutCancel(config.RunContext))
			return nil, errors.Join(ErrProductionInvalid, err)
		}
		privatePAC, err = privateproxyconfig.NewPlatformManager(config.StateRoot)
		if err != nil {
			_ = runtime.Close(context.WithoutCancel(config.RunContext))
			return nil, errors.Join(ErrProductionInvalid, err)
		}
	}
	privateService, err := privatepreviewproxy.NewAccessService(privatepreviewproxy.AccessServiceConfig{
		Proxy: privatepreviewproxy.AccessProxyConfig{Source: privateSource}, Configurator: privatePAC,
	})
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	authSource, err := runtime.MachineAuthSource()
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	apiClient := clientapi.New(config.ControlURL, clientconfig.Credential{}, &http.Client{Transport: config.Transport, Timeout: 15 * time.Second})
	apiClient.SetMachineAuth(authSource)
	leases, err := preview.NewAPILeaseClient(apiClient)
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	readiness, err := preview.NewHTTPDispatchReadinessObserver(preview.HTTPDispatchReadinessObserverConfig{
		ControlURL:   config.ControlURL,
		AllowedHosts: []string{controlHostname(config.ControlURL)},
		Identities:   authSource,
		Proofs:       authSource,
		Transport:    config.Transport,
	})
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	ctx, cancel := context.WithCancel(config.RunContext)
	runtimeDone := make(chan struct{})
	owners, err := preview.NewRuntimeOwnerSessionRegistry(preview.RuntimeOwnerSessionRegistryConfig{
		MachineID: config.MachineID, RuntimeDone: runtimeDone,
	})
	if err != nil {
		cancel()
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	ownerLeases, err := preview.NewOwnerSessionLeaseManager(preview.OwnerSessionLeaseManagerConfig{
		MachineID: config.MachineID, ControlToken: config.LocalControlToken, Registry: owners,
		RunContext: ctx,
	})
	if err != nil {
		_ = owners.Shutdown(context.WithoutCancel(config.RunContext))
		cancel()
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	dispatcher, err := preview.NewDispatchManager(preview.DispatchManagerConfig{
		MachineID:  config.MachineID,
		Leases:     leases,
		Carriers:   runtime,
		Readiness:  readiness,
		Owners:     owners,
		RunContext: ctx,
	})
	if err != nil {
		_ = ownerLeases.Close()
		_ = owners.Shutdown(context.WithoutCancel(config.RunContext))
		cancel()
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	privateTCP, err := preview.NewPrivateTCPAccessManager(preview.PrivateTCPAccessManagerConfig{Runtime: runtime, ControlToken: config.LocalControlToken, RunContext: ctx})
	if err != nil {
		_ = dispatcher.Shutdown(context.WithoutCancel(config.RunContext))
		_ = ownerLeases.Close()
		_ = owners.Shutdown(context.WithoutCancel(config.RunContext))
		cancel()
		_ = runtime.Close(context.WithoutCancel(config.RunContext))
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	return &productionPreviewAssembly{runtime: runtime, dispatcher: dispatcher, owners: owners, ownerLeases: ownerLeases, privateAccess: privateService, privateTCP: privateTCP, cancel: cancel, runtimeDone: runtimeDone}, nil
}

func controlHostname(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func (a *productionPreviewAssembly) Dispatch(ctx context.Context, authorization preview.DispatchAuthorization, request preview.DispatchRequest) (preview.DispatchOutcome, error) {
	if a == nil || a.dispatcher == nil {
		return preview.DispatchOutcome{}, preview.ErrDispatchUnavailable
	}
	return a.dispatcher.Dispatch(ctx, authorization, request)
}

func (a *productionPreviewAssembly) Start(ctx context.Context) error {
	if a == nil || a.privateAccess == nil || ctx == nil {
		return ErrProductionInvalid
	}
	return startPreviewPrivateAccess(ctx, a.privateAccess, runtime.GOOS == "windows")
}

type previewPrivateAccessLifecycle interface {
	Start(context.Context) error
}

// Windows installs the stable host runtime in a service-owned process. Its
// private-preview PAC belongs to the interactive user's registry and can be
// unavailable while that service is starting. Keep the machine preview,
// owner-session, and durable tunnel runtimes alive when only this optional
// user-scoped integration cannot start.
func startPreviewPrivateAccess(ctx context.Context, service previewPrivateAccessLifecycle, isolateFailure bool) error {
	if service == nil || ctx == nil {
		return ErrProductionInvalid
	}
	err := service.Start(ctx)
	if isolateFailure {
		return nil
	}
	return err
}

func (a *productionPreviewAssembly) Shutdown(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrProductionInvalid
	}
	var result error
	a.once.Do(func() {
		if a.privateTCP != nil {
			result = errors.Join(result, a.privateTCP.Close())
		}
		if a.privateAccess != nil {
			result = errors.Join(result, a.privateAccess.Shutdown(ctx))
		}
		if a.cancel != nil {
			a.cancel()
		}
		if a.dispatcher != nil {
			result = errors.Join(result, a.dispatcher.Shutdown(ctx))
		}
		if a.ownerLeases != nil {
			result = errors.Join(result, a.ownerLeases.Close())
		}
		if a.owners != nil {
			result = errors.Join(result, a.owners.Shutdown(ctx))
		}
		if a.runtime != nil {
			result = errors.Join(result, a.runtime.Close(ctx))
		}
		if a.runtimeDone != nil {
			close(a.runtimeDone)
		}
	})
	return result
}

func (a *productionPreviewAssembly) PrivateTCPAccess() http.Handler {
	if a == nil {
		return nil
	}
	return a.privateTCP
}

func (a *productionPreviewAssembly) OwnerSessionLeases() *preview.OwnerSessionLeaseManager {
	if a == nil {
		return nil
	}
	return a.ownerLeases
}

var _ interface {
	Dispatch(context.Context, preview.DispatchAuthorization, preview.DispatchRequest) (preview.DispatchOutcome, error)
	Start(context.Context) error
	Shutdown(context.Context) error
} = (*productionPreviewAssembly)(nil)
