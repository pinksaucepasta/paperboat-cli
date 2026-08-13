package networkcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestMappingVerifierRequiresExactExternalObservationFromOwnedSocket(t *testing.T) {
	expected := netip.MustParseAddrPort("198.51.100.20:43123")
	server := startSTUNServer(t, expected, false)
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	localPort := uint16(connection.LocalAddr().(*net.UDPAddr).Port)
	resolver := testResolver{"stun.example.test": {server.Addr()}}
	verifier := MappingVerifier{Resolver: resolver, Timeout: time.Second, Resolve: func(context.Context, []string, string, Resolver) ([]netip.AddrPort, error) {
		return []netip.AddrPort{server}, nil
	}}
	url := "stun:stun.example.test:" + strconv.Itoa(int(server.Port()))
	if err := verifier.VerifySocketMapping(context.Background(), expected, localPort, connection, []string{url}); err != nil {
		t.Fatal(err)
	}
}

func TestMappingVerifierRejectsMismatchedOrWrongSocketEvidence(t *testing.T) {
	observed := netip.MustParseAddrPort("198.51.100.20:43123")
	server := startSTUNServer(t, observed, false)
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	localPort := uint16(connection.LocalAddr().(*net.UDPAddr).Port)
	verifier := MappingVerifier{Resolver: testResolver{"stun.example.test": {server.Addr()}}, Timeout: time.Second, Resolve: func(context.Context, []string, string, Resolver) ([]netip.AddrPort, error) {
		return []netip.AddrPort{server}, nil
	}}
	url := "stun:stun.example.test:" + strconv.Itoa(int(server.Port()))
	if err := verifier.VerifySocketMapping(context.Background(), netip.MustParseAddrPort("198.51.100.20:43124"), localPort, connection, []string{url}); !errors.Is(err, ErrMappingVerification) {
		t.Fatalf("mismatch error=%v", err)
	}
	if err := verifier.VerifySocketMapping(context.Background(), observed, localPort+1, connection, []string{url}); !errors.Is(err, ErrMappingVerification) {
		t.Fatalf("wrong socket error=%v", err)
	}
}
