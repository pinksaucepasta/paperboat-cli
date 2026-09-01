package tunnelmanager

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

// OriginProber performs a safe, non-mutating readiness probe for one route.
// Implementations must honor the route connect timeout and caller context.
type OriginProber interface {
	ProbeOrigin(context.Context, hoststate.TunnelConfigRoute) error
}

// CarrierBuilder stages the authenticated carrier and route generation. A
// staged carrier is not eligible for edge traffic until Activate succeeds.
type CarrierBuilder interface {
	PrepareCarrier(context.Context, ApplyRequest) (PreparedCarrier, error)
}

type PreparedCarrier interface {
	Activate(context.Context) (RunningCarrier, error)
	Abort(context.Context) error
}

type RunningCarrier interface {
	Drain(context.Context) error
	Close(context.Context) error
}

type RuntimeFactoryConfig struct {
	Builder             CarrierBuilder
	Origins             OriginProber
	OriginStreams       *OriginStreamForwarder
	MaximumOriginProbes int
}

// RuntimeFactory is the production TunnelManager factory boundary. It keeps
// carrier staging, origin readiness, and stable runtime identity in one
// candidate without allowing the transport to rewrite durable identifiers.
type RuntimeFactory struct {
	config RuntimeFactoryConfig
}

func NewRuntimeFactory(config RuntimeFactoryConfig) (*RuntimeFactory, error) {
	if config.MaximumOriginProbes == 0 {
		config.MaximumOriginProbes = 8
	}
	if config.Builder == nil || config.Origins == nil || config.MaximumOriginProbes < 1 || config.MaximumOriginProbes > 128 {
		return nil, ErrInvalidConfig
	}
	return &RuntimeFactory{config: config}, nil
}

func (f *RuntimeFactory) Prepare(ctx context.Context, request ApplyRequest) (Candidate, error) {
	if f == nil || ctx == nil || request.Tunnel.ID == "" || request.Connector.ID == "" || request.Snapshot.Generation == 0 || request.Decoded.TunnelID != request.Tunnel.ID || request.Decoded.Generation != request.Snapshot.Generation {
		return nil, ErrInvalidConfig
	}
	prepared, err := f.config.Builder.PrepareCarrier(ctx, request)
	if err != nil {
		return nil, err
	}
	if prepared == nil {
		return nil, ErrConnectorUnavailable
	}
	routes := append([]hoststate.TunnelConfigRoute(nil), request.Decoded.Routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].ID < routes[j].ID })
	return &runtimeCandidate{request: request, prepared: prepared, prober: f.config.Origins, originStreams: f.config.OriginStreams, maximumProbes: f.config.MaximumOriginProbes, routes: routes}, nil
}

type runtimeCandidate struct {
	request       ApplyRequest
	prepared      PreparedCarrier
	prober        OriginProber
	originStreams *OriginStreamForwarder
	maximumProbes int
	routes        []hoststate.TunnelConfigRoute
}

func (c *runtimeCandidate) ProbeOrigins(ctx context.Context) (ProbeResult, error) {
	if c == nil || c.prepared == nil || c.prober == nil || ctx == nil {
		return ProbeResult{}, ErrInvalidConfig
	}
	active := make([]hoststate.TunnelConfigRoute, 0, len(c.routes))
	for _, route := range c.routes {
		if route.DesiredState == "active" {
			active = append(active, route)
		}
	}
	if len(active) == 0 {
		return ProbeResult{Ready: true}, nil
	}
	type result struct {
		id  string
		err error
	}
	results := make(chan result, len(active))
	jobs := make(chan hoststate.TunnelConfigRoute)
	var group sync.WaitGroup
	workers := c.maximumProbes
	if workers > len(active) {
		workers = len(active)
	}
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for route := range jobs {
				if err := ctx.Err(); err != nil {
					results <- result{id: route.ID, err: err}
					continue
				}
				results <- result{id: route.ID, err: c.prober.ProbeOrigin(ctx, route)}
			}
		}()
	}
	for _, route := range active {
		jobs <- route
	}
	close(jobs)
	group.Wait()
	close(results)
	probe := ProbeResult{Ready: true}
	var joined error
	for value := range results {
		if value.err == nil {
			probe.HealthyRoutes = append(probe.HealthyRoutes, value.id)
			continue
		}
		probe.Ready = false
		probe.FailedRoutes = append(probe.FailedRoutes, value.id)
		joined = errors.Join(joined, value.err)
	}
	sort.Strings(probe.HealthyRoutes)
	sort.Strings(probe.FailedRoutes)
	if !probe.Ready {
		probe.FailureCode = CodeOriginUnavailable
		return probe, errors.Join(ErrOriginUnavailable, joined)
	}
	return probe, nil
}

func (c *runtimeCandidate) Activate(ctx context.Context) (Active, error) {
	if c == nil || c.prepared == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	running, err := c.prepared.Activate(ctx)
	if err != nil || running == nil {
		if err == nil {
			err = ErrConnectorUnavailable
		}
		return nil, err
	}
	if c.originStreams != nil {
		provider, ok := running.(interface {
			ActiveDataCarrier() *connector.ActiveDataCarrier
		})
		if !ok || provider.ActiveDataCarrier() == nil {
			_ = running.Close(context.Background())
			return nil, ErrConnectorUnavailable
		}
		streams, streamErr := c.originStreams.Start(context.Background(), provider.ActiveDataCarrier(), c.routes)
		if streamErr != nil {
			_ = running.Close(context.Background())
			return nil, streamErr
		}
		running = originStreamRunningCarrier{RunningCarrier: running, streams: streams}
	}
	return &runtimeActive{request: c.request, running: running}, nil
}

type originStreamRunningCarrier struct {
	RunningCarrier
	streams *RunningOriginStreams
}

func (c originStreamRunningCarrier) ActiveDataCarrier() *connector.ActiveDataCarrier {
	provider, _ := c.RunningCarrier.(interface {
		ActiveDataCarrier() *connector.ActiveDataCarrier
	})
	if provider == nil {
		return nil
	}
	return provider.ActiveDataCarrier()
}

func (c originStreamRunningCarrier) Close(ctx context.Context) error {
	var streamErr error
	if c.streams != nil {
		streamErr = c.streams.Close(ctx)
	}
	return errors.Join(streamErr, c.RunningCarrier.Close(ctx))
}

func (c *runtimeCandidate) Abort(ctx context.Context) error {
	if c == nil || c.prepared == nil || ctx == nil {
		return ErrInvalidConfig
	}
	return c.prepared.Abort(ctx)
}

type runtimeActive struct {
	request ApplyRequest
	running RunningCarrier
}

func (a *runtimeActive) TunnelID() string                { return a.request.Tunnel.ID }
func (a *runtimeActive) ConnectorID() string             { return a.request.Connector.ID }
func (a *runtimeActive) Generation() uint64              { return a.request.Snapshot.Generation }
func (a *runtimeActive) ContentHash() string             { return a.request.Snapshot.ContentHash }
func (a *runtimeActive) Drain(ctx context.Context) error { return a.running.Drain(ctx) }
func (a *runtimeActive) Close(ctx context.Context) error { return a.running.Close(ctx) }

func (a *runtimeActive) updateGateRoute() (string, string, uint64, bool) {
	if a == nil {
		return "", "", 0, false
	}
	for _, route := range a.request.Decoded.Routes {
		if route.Protocol != "http" || route.DesiredState != "active" {
			continue
		}
		hostname := route.MatchHostname
		if hostname == "" {
			hostname = a.request.Decoded.StableEndpoint
		}
		if route.ID != "" && hostname != "" {
			return route.ID, hostname, a.request.Snapshot.Generation, true
		}
	}
	return "", "", 0, false
}

// ActiveDataCarrier exposes the concrete authenticated carrier only when the
// staged runtime was built by DataCarrierBuilder. Other RunningCarrier
// implementations remain valid manager candidates and simply return nil.
func (a *runtimeActive) ActiveDataCarrier() *connector.ActiveDataCarrier {
	if a == nil || a.running == nil {
		return nil
	}
	provider, ok := a.running.(interface {
		ActiveDataCarrier() *connector.ActiveDataCarrier
	})
	if !ok {
		return nil
	}
	return provider.ActiveDataCarrier()
}

var _ Factory = (*RuntimeFactory)(nil)
