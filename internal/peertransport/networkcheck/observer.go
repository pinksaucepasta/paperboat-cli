package networkcheck

import (
	"context"
	"net"
	"net/http"
	"time"
)

type STUNObservation struct {
	IPv4            string
	IPv6            string
	CaptivePortal   string
	PMTU            string
	RouterProtocol  string
	RouterMapping   string
	MappingLifetime string
}

func (o STUNObservation) Validate() error {
	if !oneOf(o.IPv4, "unknown", "endpoint_independent", "destination_dependent") || !oneOf(o.IPv6, "unknown", "endpoint_independent", "destination_dependent") || !oneOf(o.CaptivePortal, "unknown", "clear", "suspected") || !oneOf(o.PMTU, "unknown", "below_quic_floor", "minimum_1200", "standard", "extended") || !oneOf(o.RouterProtocol, "unknown", "none", "pcp", "nat_pmp", "upnp") || !oneOf(o.RouterMapping, "unknown", "unavailable", "verified", "untrusted", "unreachable") || !oneOf(o.MappingLifetime, "unknown", "under_30s", "30s_to_2m", "2m_to_10m", "over_10m") {
		return ErrInvalidSTUNProbe
	}
	return nil
}

type STUNObserver struct {
	Resolver       Resolver
	Timeout        time.Duration
	HTTPClient     *http.Client
	PortalEndpoint string
	OnObservation  func(STUNObservation)
}

func (o STUNObserver) Observe(ctx context.Context, ipv4, ipv6 net.PacketConn, urls []string) STUNObservation {
	result := STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	defer func() {
		if o.OnObservation != nil {
			o.OnObservation(result)
		}
	}()
	if ctx == nil || o.Resolver == nil || o.Timeout <= 0 || o.Timeout > 5*time.Second {
		return result
	}
	if ipv4 != nil {
		if destinations, err := ResolveSTUNDestinations(ctx, urls, "ip4", o.Resolver); err == nil {
			if mapped, measureErr := MeasureSTUNMappings(ctx, ipv4, destinations, o.Timeout); measureErr == nil {
				result.IPv4 = MappingCategory(mapped)
			}
		}
	}
	if ipv6 != nil {
		if destinations, err := ResolveSTUNDestinations(ctx, urls, "ip6", o.Resolver); err == nil {
			if mapped, measureErr := MeasureSTUNMappings(ctx, ipv6, destinations, o.Timeout); measureErr == nil {
				result.IPv6 = MappingCategory(mapped)
			}
		}
	}
	if o.HTTPClient != nil && o.PortalEndpoint != "" {
		portalCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		portal, err := ProbeCaptivePortal(portalCtx, o.HTTPClient, o.PortalEndpoint)
		cancel()
		if err == nil && portal.Complete {
			if portal.Suspected {
				result.CaptivePortal = "suspected"
			} else {
				result.CaptivePortal = "clear"
			}
		}
	}
	return result
}
