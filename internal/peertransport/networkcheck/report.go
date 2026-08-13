package networkcheck

import (
	"errors"
	"net/netip"
	"time"
)

const SchemaV1 = "paperboat.network-check/v1"

type Report struct {
	Schema          string    `json:"schema"`
	ObservedAt      time.Time `json:"observed_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	UDP             string    `json:"udp"`
	IPv4            string    `json:"ipv4"`
	IPv6            string    `json:"ipv6"`
	NATMapping      string    `json:"nat_mapping"`
	CaptivePortal   string    `json:"captive_portal"`
	RouterProtocol  string    `json:"router_protocol"`
	RouterMapping   string    `json:"router_mapping"`
	MappingLifetime string    `json:"mapping_lifetime"`
	PMTU            string    `json:"pmtu"`
	Failure         string    `json:"failure"`
}

func (r Report) Validate() error {
	if r.Schema != SchemaV1 || r.ObservedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.ObservedAt) || r.ExpiresAt.Sub(r.ObservedAt) > 15*time.Minute ||
		!oneOf(r.UDP, "unknown", "available", "blocked") || !oneOf(r.IPv4, "unknown", "available", "unavailable") || !oneOf(r.IPv6, "unknown", "available", "unavailable") ||
		!oneOf(r.NATMapping, "unknown", "endpoint_independent", "destination_dependent") || !oneOf(r.CaptivePortal, "unknown", "clear", "suspected") ||
		!oneOf(r.RouterProtocol, "unknown", "none", "pcp", "nat_pmp", "upnp") || !oneOf(r.RouterMapping, "unknown", "unavailable", "verified", "untrusted", "unreachable") ||
		!oneOf(r.MappingLifetime, "unknown", "under_30s", "30s_to_2m", "2m_to_10m", "over_10m") || !oneOf(r.PMTU, "unknown", "below_quic_floor", "minimum_1200", "standard", "extended") ||
		!oneOf(r.Failure, "none", "timeout", "udp_blocked", "nat", "captive_portal", "unreachable", "transient") {
		return errors.New("invalid network check report")
	}
	return nil
}

func MappingCategory(mapped []netip.AddrPort) string {
	if len(mapped) < 2 {
		return "unknown"
	}
	first := mapped[0]
	if !validMapped(first) {
		return "unknown"
	}
	for _, current := range mapped[1:] {
		if !validMapped(current) {
			return "unknown"
		}
		if current != first {
			return "destination_dependent"
		}
	}
	return "endpoint_independent"
}

func MappingLifetimeBucket(value time.Duration) string {
	switch {
	case value <= 0:
		return "unknown"
	case value < 30*time.Second:
		return "under_30s"
	case value < 2*time.Minute:
		return "30s_to_2m"
	case value < 10*time.Minute:
		return "2m_to_10m"
	default:
		return "over_10m"
	}
}

func PMTUCategory(payload uint16, proved bool) string {
	if !proved {
		return "unknown"
	}
	switch {
	case payload < 1200:
		return "below_quic_floor"
	case payload == 1200:
		return "minimum_1200"
	case payload <= 1372:
		return "standard"
	default:
		return "extended"
	}
}

func validMapped(value netip.AddrPort) bool {
	return value.IsValid() && value.Port() != 0 && value.Addr().IsGlobalUnicast()
}

func oneOf(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
