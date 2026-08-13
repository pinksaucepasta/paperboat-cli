package networkcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
)

type ProbeRegion struct {
	Region   string
	STUNURL  string
	HTTPSURL string
}

type RegionalProbeConfig struct {
	Timeout time.Duration
	STUN    func(context.Context, string) (time.Duration, error)
	HTTPS   func(context.Context, string) (time.Duration, error)
}

type RegionalProbe struct{ config RegionalProbeConfig }

func NewRegionalProbe(config RegionalProbeConfig) (*RegionalProbe, error) {
	if config.Timeout <= 0 || config.Timeout > 5*time.Second || config.STUN == nil || config.HTTPS == nil {
		return nil, errors.New("invalid regional probe configuration")
	}
	return &RegionalProbe{config: config}, nil
}

func (p *RegionalProbe) Probe(ctx context.Context, region ProbeRegion) (time.Duration, error) {
	if p == nil || ctx == nil || !validRegionalID(region.Region) || region.STUNURL == "" || region.HTTPSURL == "" {
		return 0, errors.New("invalid regional probe")
	}
	probeCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	if rtt, err := p.config.STUN(probeCtx, region.STUNURL); err == nil && validRegionalRTT(rtt) {
		return rtt, nil
	}
	if err := probeCtx.Err(); err != nil {
		return 0, err
	}
	rtt, err := p.config.HTTPS(probeCtx, region.HTTPSURL)
	if err != nil || !validRegionalRTT(rtt) {
		if err == nil {
			err = ErrUnreachable
		}
		return 0, err
	}
	return rtt, nil
}

func HTTPSRegionalLatency(clock func() time.Time, client *http.Client) func(context.Context, string) (time.Duration, error) {
	return func(ctx context.Context, endpoint string) (time.Duration, error) {
		if clock == nil || client == nil {
			return 0, errors.New("invalid HTTPS regional latency probe")
		}
		started := clock()
		result, err := ProbeCaptivePortal(ctx, client, endpoint)
		elapsed := clock().Sub(started)
		if err != nil || !result.Complete || result.Suspected || !validRegionalRTT(elapsed) {
			if err == nil {
				err = ErrUnreachable
			}
			return 0, err
		}
		return elapsed, nil
	}
}

func STUNRegionalLatency(resolver Resolver, timeout time.Duration) func(context.Context, string) (time.Duration, error) {
	return func(ctx context.Context, endpoint string) (time.Duration, error) {
		if ctx == nil || resolver == nil || timeout <= 0 || timeout > 5*time.Second {
			return 0, ErrInvalidSTUNProbe
		}
		destination, family, err := resolveRegionalSTUN(ctx, resolver, endpoint)
		if err != nil {
			return 0, err
		}
		connection, err := net.ListenUDP(family, nil)
		if err != nil {
			return 0, errors.Join(ErrSTUNUnavailable, err)
		}
		defer connection.Close()
		started := time.Now()
		if _, err := measureSTUNDestination(ctx, connection, destination, timeout); err != nil {
			return 0, err
		}
		rtt := time.Since(started)
		if !validRegionalRTT(rtt) {
			return 0, ErrSTUNUnavailable
		}
		return rtt, nil
	}
}

func resolveRegionalSTUN(ctx context.Context, resolver Resolver, endpoint string) (netip.AddrPort, string, error) {
	urls, err := iceagent.ValidateSTUNURLs([]string{endpoint})
	if err != nil || len(urls) != 1 || urls[0].Port < 1 || urls[0].Port > 65535 {
		return netip.AddrPort{}, "", errors.Join(ErrInvalidSTUNProbe, err)
	}
	for _, family := range []string{"ip4", "ip6"} {
		addresses, lookupErr := resolver.LookupNetIP(ctx, family, urls[0].Host)
		if lookupErr != nil {
			continue
		}
		valid := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			address = address.Unmap()
			if family == "ip4" && !address.Is4() || family == "ip6" && !address.Is6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
				continue
			}
			valid = append(valid, address)
		}
		if len(valid) > 0 {
			sort.Slice(valid, func(i, j int) bool { return valid[i].Compare(valid[j]) < 0 })
			return netip.AddrPortFrom(valid[0], uint16(urls[0].Port)), "udp" + family[2:], nil
		}
	}
	return netip.AddrPort{}, "", ErrSTUNUnavailable
}

func validRegionalRTT(value time.Duration) bool {
	return value > 0 && value <= time.Minute
}
