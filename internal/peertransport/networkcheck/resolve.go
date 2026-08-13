package networkcheck

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func ResolveSTUNDestinations(ctx context.Context, rawURLs []string, family string, resolver Resolver) ([]netip.AddrPort, error) {
	return resolveSTUNDestinations(ctx, rawURLs, family, resolver, 2)
}

func resolveSTUNReachabilityDestinations(ctx context.Context, rawURLs []string, family string, resolver Resolver) ([]netip.AddrPort, error) {
	return resolveSTUNDestinations(ctx, rawURLs, family, resolver, 1)
}

func resolveSTUNDestinations(ctx context.Context, rawURLs []string, family string, resolver Resolver, minimum int) ([]netip.AddrPort, error) {
	if ctx == nil || resolver == nil || !oneOf(family, "ip4", "ip6") || minimum < 1 || minimum > 2 || len(rawURLs) < minimum || len(rawURLs) > maximumSTUNDestinations {
		return nil, ErrInvalidSTUNProbe
	}
	urls, err := iceagent.ValidateSTUNURLs(rawURLs)
	if err != nil {
		return nil, errors.Join(ErrInvalidSTUNProbe, err)
	}
	destinations := make([]netip.AddrPort, 0, len(urls))
	seen := make(map[netip.AddrPort]bool)
	for _, uri := range urls {
		addresses, err := resolver.LookupNetIP(ctx, family, uri.Host)
		if err != nil {
			return nil, errors.Join(ErrSTUNUnavailable, err)
		}
		for _, address := range addresses {
			value := address.Unmap()
			if family == "ip4" && !value.Is4() || family == "ip6" && !value.Is6() || !value.IsGlobalUnicast() || value.IsPrivate() || value.IsLoopback() || value.IsLinkLocalUnicast() {
				continue
			}
			destination := netip.AddrPortFrom(value, uint16(uri.Port))
			if !seen[destination] {
				seen[destination] = true
				destinations = append(destinations, destination)
			}
		}
	}
	slices.SortFunc(destinations, func(left, right netip.AddrPort) int { return left.Compare(right) })
	if len(destinations) < minimum {
		return nil, ErrSTUNUnavailable
	}
	if len(destinations) > maximumSTUNDestinations {
		destinations = destinations[:maximumSTUNDestinations]
	}
	return destinations, nil
}
