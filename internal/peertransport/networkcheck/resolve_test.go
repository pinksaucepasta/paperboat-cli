package networkcheck

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type testResolver map[string][]netip.Addr

func (r testResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	values, found := r[host]
	if !found {
		return nil, errors.New("not found")
	}
	return values, nil
}

func TestResolveSTUNDestinationsAppliesPionPolicyAndAddressBounds(t *testing.T) {
	resolver := testResolver{
		"a.example.test": {netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1")},
		"b.example.test": {netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.20")},
	}
	got, err := ResolveSTUNDestinations(context.Background(), []string{"stun:a.example.test:3478", "stun:b.example.test:3479"}, "ip4", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].String() != "198.51.100.10:3479" || got[1].String() != "198.51.100.20:3478" || got[2].String() != "198.51.100.20:3479" {
		t.Fatalf("destinations=%v", got)
	}
	for _, raw := range []string{"turn:a.example.test:3478", "stuns:a.example.test:5349", "stun:a.example.test:3478?transport=tcp"} {
		if _, err := ResolveSTUNDestinations(context.Background(), []string{raw, "stun:b.example.test:3478"}, "ip4", resolver); !errors.Is(err, ErrInvalidSTUNProbe) {
			t.Fatalf("URL %q error=%v", raw, err)
		}
	}
}

func TestResolveSTUNDestinationsRequiresTwoPublicTargets(t *testing.T) {
	resolver := testResolver{"a.example.test": {netip.MustParseAddr("127.0.0.1")}, "b.example.test": {netip.MustParseAddr("10.0.0.1")}}
	if _, err := ResolveSTUNDestinations(context.Background(), []string{"stun:a.example.test:3478", "stun:b.example.test:3478"}, "ip4", resolver); !errors.Is(err, ErrSTUNUnavailable) {
		t.Fatalf("private-only error=%v", err)
	}
}

func TestReachabilityResolutionAcceptsOnePublicTarget(t *testing.T) {
	resolver := testResolver{
		"a.example.test": {netip.MustParseAddr("2001:db8::1")},
	}
	got, err := resolveSTUNReachabilityDestinations(context.Background(), []string{"stun:a.example.test:3478"}, "ip6", resolver)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddrPort("[2001:db8::1]:3478") {
		t.Fatalf("destinations=%v error=%v", got, err)
	}
}
