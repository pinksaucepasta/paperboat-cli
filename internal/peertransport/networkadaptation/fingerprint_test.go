package networkadaptation

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestFingerprintIsCanonicalAndInstallationScoped(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	first := NetworkObservation{
		Interfaces: []Interface{
			{Name: "wlan0", Kind: InterfacePhysical, Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("192.168.1.0/24")}},
			{Name: "tun0", Kind: InterfaceVPN, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		},
		DefaultInterface: "wlan0", NetworkIdentity: "wifi-network", IPv4: true, IPv6: true, VPN: true,
	}
	second := first
	second.Interfaces = []Interface{first.Interfaces[1], first.Interfaces[0]}
	second.Interfaces[1].Prefixes = []netip.Prefix{first.Interfaces[0].Prefixes[1], first.Interfaces[0].Prefixes[0]}
	a, err := DeriveFingerprint(secret, first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveFingerprint(secret, second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !a.valid() {
		t.Fatalf("canonical fingerprints differ: %x != %x", a, b)
	}
	other, _ := DeriveFingerprint(bytes.Repeat([]byte{2}, 32), first)
	if other == a {
		t.Fatal("fingerprint was reusable across installation secrets")
	}
	changed := first
	changed.NetworkIdentity = "other-network"
	different, _ := DeriveFingerprint(secret, changed)
	if different == a {
		t.Fatal("network identity change retained fingerprint")
	}
}

func TestFingerprintRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	valid := NetworkObservation{Interfaces: []Interface{{Name: "en0", Kind: InterfacePhysical, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}}, DefaultInterface: "en0", IPv4: true}
	tests := map[string]NetworkObservation{
		"missing default": {Interfaces: valid.Interfaces, DefaultInterface: "en1", IPv4: true},
		"duplicate":       {Interfaces: append(valid.Interfaces, valid.Interfaces[0]), DefaultInterface: "en0", IPv4: true},
		"host address":    {Interfaces: []Interface{{Name: "en0", Kind: InterfacePhysical, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}}}, DefaultInterface: "en0", IPv4: true},
		"no family":       {Interfaces: valid.Interfaces, DefaultInterface: "en0"},
	}
	for name, observation := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveFingerprint(secret, observation); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := DeriveFingerprint(secret[:31], valid); err == nil {
		t.Fatal("short installation secret accepted")
	}
}
