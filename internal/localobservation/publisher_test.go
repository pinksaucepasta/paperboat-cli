package localobservation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type observationClient struct {
	observations chan localapi.TransportObservation
}

func (c *observationClient) PublishTransportObservation(_ context.Context, observation localapi.TransportObservation) error {
	c.observations <- observation
	return nil
}

type observationPool struct {
	mu      sync.Mutex
	changes chan struct{}
	state   connectionmanager.ClassSnapshot
}

func (p *observationPool) Changes() <-chan struct{} { return p.changes }
func (p *observationPool) Snapshot(class peerquic.Class) (connectionmanager.ClassSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.state
	state.Class = class
	return state, nil
}
func (p *observationPool) set(path connectionmanager.Path, leases uint64) {
	p.mu.Lock()
	p.state.ActivePath, p.state.Leases = path, leases
	p.mu.Unlock()
	select {
	case p.changes <- struct{}{}:
	default:
	}
}

func TestPublisherReportsPoolChangesAndExplicitRelease(t *testing.T) {
	now := time.Date(2026, 8, 4, 19, 0, 0, 0, time.UTC)
	client := &observationClient{observations: make(chan localapi.TransportObservation, 8)}
	pool := &observationPool{changes: make(chan struct{}, 1), state: connectionmanager.ClassSnapshot{ActivePath: connectionmanager.PathRelayQUIC, StandbyPath: connectionmanager.PathWSS, ActiveRelayRegion: "bom", Leases: 1}}
	publisher, err := New(Config{Client: client, Pool: pool, MachineID: "machine_1", Classes: []peerquic.Class{peerquic.ClassInteractive}, Clock: func() time.Time { return now }, Heartbeat: time.Second, Lifetime: 15 * time.Second, Network: func() networkcheck.STUNObservation {
		return networkcheck.STUNObservation{IPv4: "endpoint_independent", IPv6: "destination_dependent", CaptivePortal: "clear", PMTU: "standard", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	first := receiveObservation(t, client.observations)
	if first.Sequence != 1 || first.ActiveConsumers != 1 || first.SelectedPath != "relay" || first.StandbyPath != "wss" || first.RelayRegion != "bom" || first.ExpiresAt.Sub(first.ObservedAt) != 15*time.Second || first.NATMappingIPv4 != "endpoint_independent" || first.NATMappingIPv6 != "destination_dependent" || first.CaptivePortal != "clear" || first.PMTU != "standard" {
		t.Fatalf("first=%#v", first)
	}
	pool.set(connectionmanager.PathWSS, 2)
	second := receiveObservation(t, client.observations)
	if second.Sequence != 2 || second.ActiveConsumers != 2 || second.SelectedPath != "wss" || second.RelayRegion != "bom" {
		t.Fatalf("second=%#v", second)
	}
	if err := publisher.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleared := receiveObservation(t, client.observations)
	if cleared.Sequence != 3 || cleared.ActiveConsumers != 0 || cleared.SelectedPath != "none" || cleared.RelayRegion != "" || cleared.NATMappingIPv4 != "unknown" || cleared.NATMappingIPv6 != "unknown" || cleared.CaptivePortal != "unknown" || cleared.PMTU != "unknown" {
		t.Fatalf("cleared=%#v", cleared)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run err=%v", err)
	}
}

func TestPublisherRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
	client := &observationClient{observations: make(chan localapi.TransportObservation, 1)}
	pool := &observationPool{changes: make(chan struct{}, 1)}
	if _, err := New(Config{Client: client, Pool: pool, MachineID: "machine_1", Classes: []peerquic.Class{peerquic.ClassInteractive, peerquic.ClassInteractive}}); err == nil {
		t.Fatal("duplicate class accepted")
	}
}

func receiveObservation(t *testing.T, observations <-chan localapi.TransportObservation) localapi.TransportObservation {
	t.Helper()
	select {
	case observation := <-observations:
		return observation
	case <-time.After(time.Second):
		t.Fatal("observation was not published")
		return localapi.TransportObservation{}
	}
}
