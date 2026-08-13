package networkmonitor

import (
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/util/eventbus"
)

func TestMappingRenewalDelayIsJitteredBeforeExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	goodUntil := now.Add(100 * time.Second)
	minimum, ok := mappingRenewalDelay(now, goodUntil, 0)
	if !ok || minimum != 55*time.Second {
		t.Fatalf("minimum=%v ok=%v", minimum, ok)
	}
	maximum, ok := mappingRenewalDelay(now, goodUntil, ^uint64(0))
	if !ok || maximum != 65*time.Second {
		t.Fatalf("maximum=%v ok=%v", maximum, ok)
	}
	if _, ok := mappingRenewalDelay(now, now, 0); ok {
		t.Fatal("expired lease scheduled")
	}
}

func TestMappingProtocolNormalizesOnlyBoundedUpstreamTypes(t *testing.T) {
	for input, want := range map[string]string{
		"pcp": "pcp", "pmp": "nat_pmp", "upnp": "upnp",
		"": "unknown", "router 192.0.2.1": "unknown", "nat-pmp": "unknown",
	} {
		if got := mappingProtocol(input); got != want {
			t.Fatalf("input=%q got=%q want=%q", input, got, want)
		}
	}
}

func TestLeaseRenewalConsumesUpstreamLeaseEventAndStops(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	var calls atomic.Int32
	triggered := make(chan struct{}, 1)
	renewal := newLeaseRenewal(bus, func() bool {
		calls.Add(1)
		select {
		case triggered <- struct{}{}:
		default:
		}
		return true
	})
	publisherClient := bus.Client("mapping-renewal-test")
	publisher := eventbus.Publish[portmappertype.Mapping](publisherClient)
	publisher.Publish(portmappertype.Mapping{GoodUntil: time.Now().Add(40 * time.Millisecond)})
	select {
	case <-triggered:
	case <-time.After(time.Second):
		t.Fatal("lease renewal was not triggered")
	}
	renewal.Close()
	before := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != before {
		t.Fatalf("renewal continued after close: before=%d after=%d", before, calls.Load())
	}
	publisher.Close()
	publisherClient.Close()
}
