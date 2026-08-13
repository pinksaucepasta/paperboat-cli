package networkcheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegionalProbeUsesSTUNWithoutHTTPSWhenUDPWorks(t *testing.T) {
	httpsCalls := 0
	probe, err := NewRegionalProbe(RegionalProbeConfig{Timeout: time.Second,
		STUN: func(context.Context, string) (time.Duration, error) { return 12 * time.Millisecond, nil },
		HTTPS: func(context.Context, string) (time.Duration, error) {
			httpsCalls++
			return 20 * time.Millisecond, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rtt, err := probe.Probe(context.Background(), ProbeRegion{Region: "fsn1", STUNURL: "stun:example.test:3478", HTTPSURL: "https://example.test/network-check/v1"})
	if err != nil || rtt != 12*time.Millisecond || httpsCalls != 0 {
		t.Fatalf("rtt=%s https_calls=%d err=%v", rtt, httpsCalls, err)
	}
}

func TestRegionalProbeFallsBackToHTTPSAfterUDPFailure(t *testing.T) {
	probe, _ := NewRegionalProbe(RegionalProbeConfig{Timeout: time.Second,
		STUN:  func(context.Context, string) (time.Duration, error) { return 0, ErrUDPBlocked },
		HTTPS: func(context.Context, string) (time.Duration, error) { return 25 * time.Millisecond, nil },
	})
	rtt, err := probe.Probe(context.Background(), ProbeRegion{Region: "hel1", STUNURL: "stun:example.test:3478", HTTPSURL: "https://example.test/network-check/v1"})
	if err != nil || rtt != 25*time.Millisecond {
		t.Fatalf("rtt=%s err=%v", rtt, err)
	}
}

func TestRegionalProbeDoesNotHideExpiredDeadlineWithFallback(t *testing.T) {
	probe, _ := NewRegionalProbe(RegionalProbeConfig{Timeout: time.Second,
		STUN: func(ctx context.Context, _ string) (time.Duration, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
		HTTPS: func(context.Context, string) (time.Duration, error) { return time.Millisecond, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := probe.Probe(ctx, ProbeRegion{Region: "hel1", STUNURL: "stun:example.test:3478", HTTPSURL: "https://example.test/network-check/v1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
