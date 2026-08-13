package networkcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

var ErrMappingVerification = errors.New("router mapping verification failed")

// MappingVerifier proves a router-reported endpoint from the exact owned ICE
// socket by comparing it with an external Pion STUN observation.
type MappingVerifier struct {
	Resolver Resolver
	Timeout  time.Duration
	Resolve  func(context.Context, []string, string, Resolver) ([]netip.AddrPort, error)
}

func (v MappingVerifier) VerifySocketMapping(ctx context.Context, expected netip.AddrPort, localPort uint16, connection net.PacketConn, urls []string) error {
	if ctx == nil || v.Resolver == nil || v.Timeout <= 0 || v.Timeout > 5*time.Second || !validMapped(expected) || localPort == 0 || connection == nil || packetPort(connection.LocalAddr()) != localPort {
		return ErrMappingVerification
	}
	resolve := v.Resolve
	if resolve == nil {
		resolve = ResolveSTUNDestinations
	}
	destinations, err := resolve(ctx, urls, "ip4", v.Resolver)
	if err != nil || len(destinations) == 0 {
		return errors.Join(ErrMappingVerification, err)
	}
	for _, destination := range destinations {
		mapped, probeErr := measureSTUNDestination(ctx, connection, destination, v.Timeout)
		if probeErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if mapped == expected {
			_ = connection.SetDeadline(time.Time{})
			return nil
		}
	}
	_ = connection.SetDeadline(time.Time{})
	return ErrMappingVerification
}

func packetPort(address net.Addr) uint16 {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp.Port < 1 || udp.Port > 65535 {
		return 0
	}
	return uint16(udp.Port)
}
