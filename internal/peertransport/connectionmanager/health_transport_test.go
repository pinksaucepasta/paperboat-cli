package connectionmanager

import (
	"context"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type healthCapableConnection struct {
	fakeConnection
	path      Path
	transport ActiveHealthTransport
	err       error
}

func (c *healthCapableConnection) ActiveHealthCapability() (ActiveHealthCapability, error) {
	return ActiveHealthCapability{Path: c.path, Transport: c.transport}, c.err
}

type selectedHealthTransport struct{}

func (selectedHealthTransport) HealthExchange(context.Context, [16]byte) (uint32, error) {
	return 0, nil
}

func TestConnectionHealthTransportUsesSelectedConnectionCapability(t *testing.T) {
	transport := selectedHealthTransport{}
	connection := &healthCapableConnection{path: PathRelayQUIC, transport: transport}
	got, err := ConnectionHealthTransport(Selection{Generation: 4, Path: PathRelayQUIC, Connection: connection})
	if err != nil || got != transport {
		t.Fatalf("transport=%T error=%v", got, err)
	}
}

func TestConnectionHealthTransportRejectsMissingOrMismatchedCapability(t *testing.T) {
	selection := Selection{Generation: 1, Path: PathWSS, Connection: &fakeConnection{}}
	if _, err := ConnectionHealthTransport(selection); err == nil {
		t.Fatal("accepted connection without health capability")
	}
	selection.Connection = &healthCapableConnection{path: PathRelayQUIC, transport: selectedHealthTransport{}}
	if _, err := ConnectionHealthTransport(selection); err == nil {
		t.Fatal("accepted health capability for another path")
	}
	selection.Connection = &healthCapableConnection{path: PathWSS}
	if _, err := ConnectionHealthTransport(selection); err == nil {
		t.Fatal("accepted nil health capability")
	}
	selection.Connection = &healthCapableConnection{fakeConnection: fakeConnection{state: StateReady}, path: PathWSS, transport: selectedHealthTransport{}}
	if _, err := ConnectionHealthTransport(selection); err == nil {
		t.Fatal("accepted health capability before initial admission")
	}
}

func TestPoolUsesConnectionOwnedHealthCapabilityByDefault(t *testing.T) {
	connector := newFakeConnector()
	health := newPoolHealthRunner()
	pool, err := NewPool(testRacer(t, connector), PoolConfig{IdleGrace: time.Minute, Health: health})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), peerquic.ClassInteractive, ModeAuto, NetworkDirectInfeasible)
		done <- lease
	}()
	attempt := receiveAttempt(t, connector.started)
	connection := &healthCapableConnection{path: attempt.Path, transport: selectedHealthTransport{}}
	connector.results[attempt.Path] <- connectResult{connection: connection}
	lease := <-done
	if lease == nil {
		t.Fatal("acquisition failed")
	}
	run := health.next(t)
	lease.Release()
	run.assertCanceled(t)
	_ = pool.Close()
}
