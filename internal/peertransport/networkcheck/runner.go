package networkcheck

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
)

var (
	ErrUDPBlocked    = errors.New("network-check UDP blocked")
	ErrNAT           = errors.New("network-check NAT failure")
	ErrCaptivePortal = errors.New("network-check captive portal")
	ErrUnreachable   = errors.New("network-check unreachable")
)

type StackResult struct {
	UDP  bool
	IPv4 bool
	IPv6 bool
}

type PortalResult struct {
	Complete  bool
	Suspected bool
}

type RouterResult struct {
	Protocol      string
	Mapping       string
	LifetimeLower time.Duration
}

type PMTUResult struct {
	Payload uint16
	Proved  bool
}

type Probes struct {
	Stack  func(context.Context) (StackResult, error)
	STUN   func(context.Context) ([]netip.AddrPort, error)
	Portal func(context.Context) (PortalResult, error)
	Router func(context.Context) (RouterResult, error)
	PMTU   func(context.Context) (PMTUResult, error)
}

type RunnerConfig struct {
	Timeout      time.Duration
	ProbeTimeout time.Duration
	ReportTTL    time.Duration
	Clock        func() time.Time
	Cache        *Cache
}

type Runner struct{ config RunnerConfig }

func NewRunner(config RunnerConfig) (*Runner, error) {
	if config.Timeout <= 0 || config.Timeout > time.Minute || config.ProbeTimeout <= 0 || config.ProbeTimeout > config.Timeout || config.ReportTTL <= 0 || config.ReportTTL > 15*time.Minute || config.Clock == nil || config.Cache == nil {
		return nil, errors.New("invalid network-check runner configuration")
	}
	return &Runner{config: config}, nil
}

func (r *Runner) Run(ctx context.Context, fingerprint networkadaptation.Fingerprint, probes Probes) (Report, error) {
	if r == nil || ctx == nil || !fingerprint.Valid() || probes.Stack == nil || probes.STUN == nil || probes.Portal == nil || probes.Router == nil || probes.PMTU == nil {
		return Report{}, errors.New("invalid network-check run")
	}
	runCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	type results struct {
		stack     StackResult
		stackErr  error
		mapped    []netip.AddrPort
		stunErr   error
		portal    PortalResult
		portalErr error
		router    RouterResult
		routerErr error
		pmtu      PMTUResult
		pmtuErr   error
	}
	var result results
	var wait sync.WaitGroup
	run := func(probe func(context.Context), count int) {
		wait.Add(count)
		probe(runCtx)
	}
	probeContext := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(runCtx, r.config.ProbeTimeout)
	}
	run(func(context.Context) {
		go func() {
			defer wait.Done()
			probeCtx, done := probeContext()
			defer done()
			result.stack, result.stackErr = probes.Stack(probeCtx)
		}()
		go func() {
			defer wait.Done()
			probeCtx, done := probeContext()
			defer done()
			result.mapped, result.stunErr = probes.STUN(probeCtx)
		}()
		go func() {
			defer wait.Done()
			probeCtx, done := probeContext()
			defer done()
			result.portal, result.portalErr = probes.Portal(probeCtx)
		}()
		go func() {
			defer wait.Done()
			probeCtx, done := probeContext()
			defer done()
			result.router, result.routerErr = probes.Router(probeCtx)
		}()
		go func() {
			defer wait.Done()
			probeCtx, done := probeContext()
			defer done()
			result.pmtu, result.pmtuErr = probes.PMTU(probeCtx)
		}()
	}, 5)
	wait.Wait()
	now := r.config.Clock().UTC()
	report := Report{Schema: SchemaV1, ObservedAt: now, ExpiresAt: now.Add(r.config.ReportTTL), UDP: "unknown", IPv4: "unknown", IPv6: "unknown", NATMapping: "unknown", CaptivePortal: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", PMTU: "unknown", Failure: failureCategory(result.stackErr, result.stunErr, result.portalErr, result.routerErr, result.pmtuErr)}
	if result.stackErr == nil {
		report.UDP = availability(result.stack.UDP, "available", "blocked")
		report.IPv4 = availability(result.stack.IPv4, "available", "unavailable")
		report.IPv6 = availability(result.stack.IPv6, "available", "unavailable")
	}
	if result.stunErr == nil {
		report.NATMapping = MappingCategory(result.mapped)
	}
	if result.portalErr == nil && result.portal.Complete {
		report.CaptivePortal = availability(result.portal.Suspected, "suspected", "clear")
	}
	if result.routerErr == nil && oneOf(result.router.Protocol, "none", "pcp", "nat_pmp", "upnp") && oneOf(result.router.Mapping, "unavailable", "verified", "untrusted", "unreachable") {
		report.RouterProtocol, report.RouterMapping = result.router.Protocol, result.router.Mapping
		report.MappingLifetime = MappingLifetimeBucket(result.router.LifetimeLower)
	}
	if result.pmtuErr == nil {
		report.PMTU = PMTUCategory(result.pmtu.Payload, result.pmtu.Proved)
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	if err := r.config.Cache.Store(fingerprint, report, now); err != nil {
		return Report{}, err
	}
	return report, nil
}

func availability(value bool, yes, no string) string {
	if value {
		return yes
	}
	return no
}

func failureCategory(values ...error) string {
	for _, target := range []struct {
		err  error
		code string
	}{{ErrCaptivePortal, "captive_portal"}, {ErrUDPBlocked, "udp_blocked"}, {ErrNAT, "nat"}, {ErrUnreachable, "unreachable"}, {context.DeadlineExceeded, "timeout"}} {
		for _, value := range values {
			if errors.Is(value, target.err) {
				return target.code
			}
		}
	}
	for _, value := range values {
		if value != nil {
			return "transient"
		}
	}
	return "none"
}
