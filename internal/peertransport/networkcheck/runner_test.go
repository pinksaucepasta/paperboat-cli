package networkcheck

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRunnerExecutesIndependentProbesAndPublishesOnlySafeReport(t *testing.T) {
	now := time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC)
	cache := NewCache()
	runner, err := NewRunner(RunnerConfig{Timeout: time.Second, ProbeTimeout: 500 * time.Millisecond, ReportTTL: 5 * time.Minute, Clock: func() time.Time { return now }, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan string, 5)
	release := make(chan struct{})
	wait := func(name string) { started <- name; <-release }
	first, second := netip.MustParseAddrPort("198.51.100.10:41000"), netip.MustParseAddrPort("198.51.100.10:42000")
	probes := Probes{
		Stack: func(context.Context) (StackResult, error) {
			wait("stack")
			return StackResult{UDP: true, IPv4: true}, nil
		},
		STUN: func(context.Context) ([]netip.AddrPort, error) {
			wait("stun")
			return []netip.AddrPort{first, second}, nil
		},
		Portal: func(context.Context) (PortalResult, error) { wait("portal"); return PortalResult{Complete: true}, nil },
		Router: func(context.Context) (RouterResult, error) {
			wait("router")
			return RouterResult{Protocol: "pcp", Mapping: "verified", LifetimeLower: 3 * time.Minute}, nil
		},
		PMTU: func(context.Context) (PMTUResult, error) {
			wait("pmtu")
			return PMTUResult{Payload: 1372, Proved: true}, nil
		},
	}
	done := make(chan Report, 1)
	go func() { report, _ := runner.Run(context.Background(), testFingerprint(500), probes); done <- report }()
	for range 5 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("network probes did not start independently")
		}
	}
	close(release)
	report := <-done
	if report.UDP != "available" || report.IPv4 != "available" || report.IPv6 != "unavailable" || report.NATMapping != "destination_dependent" || report.CaptivePortal != "clear" || report.RouterProtocol != "pcp" || report.RouterMapping != "verified" || report.MappingLifetime != "2m_to_10m" || report.PMTU != "standard" || report.Failure != "none" {
		t.Fatalf("report=%#v", report)
	}
	if cached, found := cache.Load(testFingerprint(500), now); !found || cached != report {
		t.Fatalf("cached=%#v found=%t", cached, found)
	}
	encoded, _ := json.Marshal(report)
	for _, forbidden := range []string{"198.51.100.10", "41000", "42000", "fingerprint", "gateway", "candidate"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("report exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestRunnerContinuesAfterFailuresWithTypedPrecedence(t *testing.T) {
	now := time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC)
	runner, _ := NewRunner(RunnerConfig{Timeout: time.Second, ProbeTimeout: 100 * time.Millisecond, ReportTTL: time.Minute, Clock: func() time.Time { return now }, Cache: NewCache()})
	report, err := runner.Run(context.Background(), testFingerprint(501), Probes{
		Stack:  func(context.Context) (StackResult, error) { return StackResult{}, ErrUDPBlocked },
		STUN:   func(context.Context) ([]netip.AddrPort, error) { return nil, errors.New("raw 192.0.2.1 failure") },
		Portal: func(context.Context) (PortalResult, error) { return PortalResult{}, ErrCaptivePortal },
		Router: func(context.Context) (RouterResult, error) { return RouterResult{}, ErrUnreachable },
		PMTU:   func(context.Context) (PMTUResult, error) { return PMTUResult{}, context.DeadlineExceeded },
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failure != "captive_portal" || report.UDP != "unknown" || report.NATMapping != "unknown" {
		t.Fatalf("report=%#v", report)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "192.0.2.1") {
		t.Fatalf("raw error entered report: %s", encoded)
	}
}
