package tunnelmanager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

type factoryCarrierBuilder struct {
	prepared *factoryPreparedCarrier
	request  ApplyRequest
}

func (b *factoryCarrierBuilder) PrepareCarrier(_ context.Context, request ApplyRequest) (PreparedCarrier, error) {
	b.request = request
	return b.prepared, nil
}

type factoryPreparedCarrier struct {
	running *factoryRunningCarrier
	aborts  int
}

func (c *factoryPreparedCarrier) Activate(context.Context) (RunningCarrier, error) {
	return c.running, nil
}
func (c *factoryPreparedCarrier) Abort(context.Context) error { c.aborts++; return nil }

type factoryRunningCarrier struct{ drains, closes int }

func (c *factoryRunningCarrier) Drain(context.Context) error { c.drains++; return nil }
func (c *factoryRunningCarrier) Close(context.Context) error { c.closes++; return nil }

type recordingOriginProber struct {
	mu        sync.Mutex
	seen      []string
	active    int
	maximum   int
	failRoute string
}

func (p *recordingOriginProber) ProbeOrigin(ctx context.Context, route hoststate.TunnelConfigRoute) error {
	p.mu.Lock()
	p.seen = append(p.seen, route.ID)
	p.active++
	if p.active > p.maximum {
		p.maximum = p.active
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond):
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	if route.ID == p.failRoute {
		return errors.New("origin offline")
	}
	return nil
}

func TestRuntimeFactoryProbesRoutesBoundedAndPreservesIdentity(t *testing.T) {
	request := factoryApplyRequest(t)
	running := &factoryRunningCarrier{}
	prepared := &factoryPreparedCarrier{running: running}
	builder := &factoryCarrierBuilder{prepared: prepared}
	prober := &recordingOriginProber{}
	factory, err := NewRuntimeFactory(RuntimeFactoryConfig{Builder: builder, Origins: prober, MaximumOriginProbes: 1})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := factory.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := candidate.ProbeOrigins(context.Background())
	if err != nil || !probe.Ready || len(probe.HealthyRoutes) != 2 || probe.HealthyRoutes[0] != "route_01" || probe.HealthyRoutes[1] != "route_02" || prober.maximum != 1 {
		t.Fatalf("probe=%+v maximum=%d err=%v", probe, prober.maximum, err)
	}
	active, err := candidate.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if active.TunnelID() != request.Tunnel.ID || active.ConnectorID() != request.Connector.ID || active.Generation() != request.Snapshot.Generation || active.ContentHash() != request.Snapshot.ContentHash {
		t.Fatalf("active identity changed: tunnel=%s connector=%s generation=%d hash=%s", active.TunnelID(), active.ConnectorID(), active.Generation(), active.ContentHash())
	}
	if err := active.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := active.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if running.drains != 1 || running.closes != 1 || builder.request.Connector.Credential.Reference != request.Connector.Credential.Reference {
		t.Fatalf("carrier lifecycle=%+v request=%+v", running, builder.request)
	}
}

func TestRuntimeFactoryOriginFailureKeepsCarrierStaged(t *testing.T) {
	request := factoryApplyRequest(t)
	prepared := &factoryPreparedCarrier{running: &factoryRunningCarrier{}}
	factory, err := NewRuntimeFactory(RuntimeFactoryConfig{Builder: &factoryCarrierBuilder{prepared: prepared}, Origins: &recordingOriginProber{failRoute: "route_02"}, MaximumOriginProbes: 2})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := factory.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := candidate.ProbeOrigins(context.Background())
	if !errors.Is(err, ErrOriginUnavailable) || probe.Ready || probe.FailureCode != CodeOriginUnavailable || len(probe.FailedRoutes) != 1 || probe.FailedRoutes[0] != "route_02" {
		t.Fatalf("probe=%+v err=%v", probe, err)
	}
	if err := candidate.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prepared.aborts != 1 {
		t.Fatalf("aborts=%d", prepared.aborts)
	}
}

func factoryApplyRequest(t *testing.T) ApplyRequest {
	t.Helper()
	snapshot := tunnelSnapshot(t, 3)
	decoded, err := hoststate.ParseTunnelConfigSnapshot(snapshot.Payload, snapshot.TunnelID, snapshot.Generation)
	if err != nil {
		t.Fatal(err)
	}
	second := decoded.Routes[0]
	second.ID = "route_02"
	second.Name = "secondary"
	second.OriginAddress = "127.0.0.1:3001"
	decoded.Routes = append(decoded.Routes, second)
	return ApplyRequest{
		Tunnel:    hoststate.Tunnel{ID: "tunnel_01", StableEndpointID: testManagedTunnelEndpointID, DesiredState: "active", DesiredGeneration: 3, DesiredSnapshot: snapshot},
		Connector: hoststate.Connector{ID: "connector_01", TunnelID: "tunnel_01", HostID: "host_01", Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_01", Generation: 1}, RotationGeneration: 1},
		Snapshot:  snapshot, Decoded: decoded,
	}
}
