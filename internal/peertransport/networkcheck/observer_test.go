package networkcheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestSTUNObserverReducesRawMappingsBeforeReturning(t *testing.T) {
	resolver := testResolver{"a.example.test": {netip.MustParseAddr("198.51.100.10")}, "b.example.test": {netip.MustParseAddr("198.51.100.11")}}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var published STUNObservation
	observer := STUNObserver{Resolver: resolver, Timeout: 20 * time.Millisecond, OnObservation: func(value STUNObservation) { published = value }}
	// Resolution and wire behavior are separately covered; an unreachable
	// destination must collapse to unknown without exposing its address.
	result := observer.Observe(context.Background(), client, nil, []string{"stun:a.example.test:3478", "stun:b.example.test:3478"})
	if result.IPv4 != "unknown" || result.IPv6 != "unknown" || result.Validate() != nil || published != result {
		t.Fatalf("result=%#v published=%#v", result, published)
	}
}

func TestSTUNObserverPublishesOnlyReducedPortalCategory(t *testing.T) {
	portal := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", "https://login.example.test/private-address")
		writer.WriteHeader(http.StatusFound)
	}))
	defer portal.Close()
	var published STUNObservation
	observer := STUNObserver{Resolver: testResolver{}, Timeout: time.Second, HTTPClient: portal.Client(), PortalEndpoint: portal.URL + "/network-check/v1", OnObservation: func(value STUNObservation) { published = value }}
	result := observer.Observe(context.Background(), nil, nil, nil)
	if result.CaptivePortal != "suspected" || result.IPv4 != "unknown" || result.IPv6 != "unknown" || published != result || result.Validate() != nil {
		t.Fatalf("result=%#v published=%#v", result, published)
	}
}

func TestSTUNObservationRejectsUnsafeCategories(t *testing.T) {
	if err := (STUNObservation{IPv4: "198.51.100.10", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}).Validate(); err == nil {
		t.Fatal("address-shaped observation accepted")
	}
}
