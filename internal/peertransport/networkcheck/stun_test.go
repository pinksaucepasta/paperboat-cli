package networkcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func TestMeasureSTUNMappingsUsesSameSocketAndClassifiesDestinations(t *testing.T) {
	first := startSTUNServer(t, netip.MustParseAddrPort("198.51.100.10:41000"), false)
	second := startSTUNServer(t, netip.MustParseAddrPort("198.51.100.10:42000"), false)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mapped, err := MeasureSTUNMappings(context.Background(), client, []netip.AddrPort{first, second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(mapped) != 2 || MappingCategory(mapped) != "destination_dependent" {
		t.Fatalf("mapped=%v category=%q", mapped, MappingCategory(mapped))
	}
}

func TestMeasureSTUNMappingsRejectsTamperingAndBounds(t *testing.T) {
	tampered := startSTUNServer(t, netip.MustParseAddrPort("198.51.100.10:41000"), true)
	valid := startSTUNServer(t, netip.MustParseAddrPort("198.51.100.10:41000"), false)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := MeasureSTUNMappings(ctx, client, []netip.AddrPort{tampered, valid}, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrSTUNUnavailable) {
		t.Fatalf("tampered response error=%v", err)
	}
	if _, err := MeasureSTUNMappings(context.Background(), client, []netip.AddrPort{valid, valid}, time.Second); !errors.Is(err, ErrInvalidSTUNProbe) {
		t.Fatalf("duplicate destination error=%v", err)
	}
}

func startSTUNServer(t *testing.T, mapped netip.AddrPort, tamper bool) netip.AddrPort {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, maximumSTUNPacketBytes)
		count, source, readErr := connection.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:count]...)}
		if request.Decode() != nil || request.Type != stun.BindingRequest || stun.Fingerprint.Check(request) != nil {
			return
		}
		response, buildErr := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(request.TransactionID), &stun.XORMappedAddress{IP: net.IP(mapped.Addr().AsSlice()), Port: int(mapped.Port())}, stun.Fingerprint)
		if buildErr != nil {
			return
		}
		if tamper {
			response.Raw[len(response.Raw)-1] ^= 1
		}
		_, _ = connection.WriteToUDP(response.Raw, source)
	}()
	return connection.LocalAddr().(*net.UDPAddr).AddrPort()
}
