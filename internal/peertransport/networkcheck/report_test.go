package networkcheck

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
)

func TestMappingCategoryUsesMultipleDestinationsWithoutRetainingAddresses(t *testing.T) {
	first := netip.MustParseAddrPort("198.51.100.10:41000")
	second := netip.MustParseAddrPort("198.51.100.10:42000")
	if got := MappingCategory([]netip.AddrPort{first, first}); got != "endpoint_independent" {
		t.Fatalf("same mappings=%q", got)
	}
	if got := MappingCategory([]netip.AddrPort{first, second}); got != "destination_dependent" {
		t.Fatalf("varying mappings=%q", got)
	}
	if got := MappingCategory([]netip.AddrPort{first}); got != "unknown" {
		t.Fatalf("one mapping=%q", got)
	}
	report := validReport()
	report.NATMapping = MappingCategory([]netip.AddrPort{first, second})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"198.51.100.10", "41000", "42000", "address", "candidate", "fingerprint"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("report exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestSafeBucketsHaveExplicitProofBoundaries(t *testing.T) {
	if MappingLifetimeBucket(29*time.Second) != "under_30s" || MappingLifetimeBucket(30*time.Second) != "30s_to_2m" || MappingLifetimeBucket(10*time.Minute) != "over_10m" {
		t.Fatal("mapping lifetime boundary mismatch")
	}
	if PMTUCategory(1452, false) != "unknown" || PMTUCategory(1199, true) != "below_quic_floor" || PMTUCategory(1200, true) != "minimum_1200" || PMTUCategory(1372, true) != "standard" || PMTUCategory(1373, true) != "extended" {
		t.Fatal("PMTU boundary mismatch")
	}
}

func TestCacheExpiresInvalidatesAndBoundsReports(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	cache := NewCache()
	for marker := 0; marker <= maximumReports; marker++ {
		fingerprint := testFingerprint(uint16(marker + 1))
		report := validReport()
		report.ObservedAt = now.Add(time.Duration(marker) * time.Millisecond)
		report.ExpiresAt = report.ObservedAt.Add(time.Minute)
		if err := cache.Store(fingerprint, report, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, found := cache.Load(testFingerprint(1), now); found {
		t.Fatal("oldest report was not evicted")
	}
	if _, found := cache.Load(testFingerprint(maximumReports+1), now.Add(2*time.Minute)); found {
		t.Fatal("expired report remained available")
	}
	if count := cache.Invalidate(); count != 0 {
		t.Fatalf("post-expiry invalidation count=%d", count)
	}
}

func validReport() Report {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	return Report{Schema: SchemaV1, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute), UDP: "available", IPv4: "available", IPv6: "available", NATMapping: "unknown", CaptivePortal: "clear", RouterProtocol: "none", RouterMapping: "unavailable", MappingLifetime: "unknown", PMTU: "minimum_1200", Failure: "none"}
}

func testFingerprint(marker uint16) networkadaptation.Fingerprint {
	observation := networkadaptation.NetworkObservation{Interfaces: []networkadaptation.Interface{{Name: "en0", Kind: networkadaptation.InterfacePhysical, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}}, DefaultInterface: "en0", IPv4: true, NetworkIdentity: fmt.Sprintf("network-%d", marker)}
	fingerprint, err := networkadaptation.DeriveFingerprint([]byte("0123456789abcdef0123456789abcdef"), observation)
	if err != nil {
		panic(err)
	}
	return fingerprint
}
