package networkcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

const (
	maximumSTUNDestinations = 8
	maximumSTUNPacketBytes  = 2048
)

var (
	ErrInvalidSTUNProbe = errors.New("invalid network-check STUN probe")
	ErrSTUNUnavailable  = errors.New("network-check STUN unavailable")
)

// ProbeSTUNReachability proves that one address family can exchange a STUN
// binding transaction. A successful UDP dial alone is not reachability proof.
func ProbeSTUNReachability(ctx context.Context, family string, rawURLs []string, resolver Resolver, timeout time.Duration) bool {
	if ctx == nil || resolver == nil || timeout <= 0 || timeout > 5*time.Second || family != "ip4" && family != "ip6" {
		return false
	}
	destinations, err := resolveSTUNReachabilityDestinations(ctx, rawURLs, family, resolver)
	if err != nil || len(destinations) == 0 {
		return false
	}
	network, address := "udp4", "0.0.0.0:0"
	if family == "ip6" {
		network, address = "udp6", "[::]:0"
	}
	connection, err := net.ListenPacket(network, address)
	if err != nil {
		return false
	}
	defer connection.Close()
	for _, destination := range destinations {
		if _, err := measureSTUNDestination(ctx, connection, destination, timeout); err == nil {
			return true
		}
	}
	return false
}

// MeasureSTUNMappings sends Pion-encoded binding requests from one owned UDP
// socket. Raw mapped addresses exist only in the returned ephemeral value and
// must be reduced with MappingCategory before entering a report or cache.
func MeasureSTUNMappings(ctx context.Context, connection net.PacketConn, destinations []netip.AddrPort, timeout time.Duration) ([]netip.AddrPort, error) {
	if ctx == nil || connection == nil || len(destinations) < 2 || len(destinations) > maximumSTUNDestinations || timeout <= 0 || timeout > 5*time.Second {
		return nil, ErrInvalidSTUNProbe
	}
	seen := make(map[netip.AddrPort]bool, len(destinations))
	for _, destination := range destinations {
		if !destination.IsValid() || destination.Port() == 0 || destination.Addr().IsUnspecified() || destination.Addr().IsMulticast() || seen[destination] {
			return nil, ErrInvalidSTUNProbe
		}
		seen[destination] = true
	}
	defer func() { _ = connection.SetDeadline(time.Time{}) }()
	mappings := make([]netip.AddrPort, 0, len(destinations))
	for _, destination := range destinations {
		mapped, err := measureSTUNDestination(ctx, connection, destination, timeout)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, mapped)
	}
	return mappings, nil
}

func measureSTUNDestination(ctx context.Context, connection net.PacketConn, destination netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("build Pion STUN binding request: %w", err)
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return netip.AddrPort{}, fmt.Errorf("set STUN deadline: %w", err)
	}
	remote := net.UDPAddrFromAddrPort(destination)
	if _, err := connection.WriteTo(request.Raw, remote); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return netip.AddrPort{}, ctxErr
		}
		return netip.AddrPort{}, errors.Join(ErrSTUNUnavailable, err)
	}
	buffer := make([]byte, maximumSTUNPacketBytes)
	for {
		count, source, err := connection.ReadFrom(buffer)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return netip.AddrPort{}, ctxErr
			}
			return netip.AddrPort{}, errors.Join(ErrSTUNUnavailable, err)
		}
		if sourceAddrPort(source) != destination {
			continue
		}
		response := &stun.Message{Raw: append([]byte(nil), buffer[:count]...)}
		if err := response.Decode(); err != nil || response.TransactionID != request.TransactionID || response.Type != stun.BindingSuccess || stun.Fingerprint.Check(response) != nil {
			continue
		}
		var xorMapped stun.XORMappedAddress
		if err := xorMapped.GetFrom(response); err != nil {
			continue
		}
		mapped, ok := netip.AddrFromSlice(xorMapped.IP)
		if !ok || xorMapped.Port < 1 || xorMapped.Port > 65535 {
			continue
		}
		result := netip.AddrPortFrom(mapped.Unmap(), uint16(xorMapped.Port))
		if !validMapped(result) {
			continue
		}
		return result, nil
	}
}

func sourceAddrPort(address net.Addr) netip.AddrPort {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp.Port < 1 || udp.Port > 65535 {
		return netip.AddrPort{}
	}
	value, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(value.Unmap(), uint16(udp.Port))
}
