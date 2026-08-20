package iceagent

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// Pion's universal mux starts its reader before its constructor finishes.
// Holding the first read establishes initialization ordering for that goroutine.
type constructorGatedPacketConn struct {
	net.PacketConn
	ready <-chan struct{}
}

func (c *constructorGatedPacketConn) ReadFrom(value []byte) (int, net.Addr, error) {
	<-c.ready
	return c.PacketConn.ReadFrom(value)
}

// ownedUniversalUDPMux lets Pion gather host and server-reflexive candidates
// from the same Paperboat-owned IPv4 and IPv6 sockets.
type ownedUniversalUDPMux struct {
	muxes     []ice.UniversalUDPMux
	closeOnce sync.Once
	closeErr  error
}

func newOwnedUniversalUDPMux(muxes []ice.UniversalUDPMux) *ownedUniversalUDPMux {
	return &ownedUniversalUDPMux{muxes: append([]ice.UniversalUDPMux(nil), muxes...)}
}

func allowedHostAddresses() map[string]struct{} {
	result := make(map[string]struct{})
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || excludedInterface(iface.Name) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			result[ip.String()] = struct{}{}
		}
	}
	return result
}

func excludedInterface(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{"br-", "cni", "docker", "flannel", "tailscale", "tap", "tun", "utun", "virbr", "wg", "zt"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	// Linux container peers use veth* names. Windows Hyper-V uses
	// "vEthernet (...)" for real external switches, so a platform-neutral veth
	// prefix would remove the machine's only usable LAN interface.
	if runtime.GOOS != "windows" && strings.HasPrefix(name, "veth") {
		return true
	}
	return false
}

func (m *ownedUniversalUDPMux) GetConn(ufrag string, address net.Addr) (net.PacketConn, error) {
	mux, err := m.forLocal(address)
	if err != nil {
		return nil, err
	}
	return mux.GetConn(ufrag, address)
}

func (m *ownedUniversalUDPMux) RemoveConnByUfrag(ufrag string) {
	for _, mux := range m.muxes {
		mux.RemoveConnByUfrag(ufrag)
	}
}

func (m *ownedUniversalUDPMux) Close() error {
	m.closeOnce.Do(func() {
		for _, mux := range m.muxes {
			m.closeErr = errors.Join(m.closeErr, mux.Close())
		}
	})
	return m.closeErr
}

func (m *ownedUniversalUDPMux) GetListenAddresses() []net.Addr {
	allowed := allowedHostAddresses()
	var result []net.Addr
	for _, mux := range m.muxes {
		for _, address := range mux.GetListenAddresses() {
			udp, ok := address.(*net.UDPAddr)
			if !ok {
				continue
			}
			if _, ok := allowed[udp.IP.String()]; ok {
				result = append(result, address)
			}
		}
	}
	return result
}

func (m *ownedUniversalUDPMux) GetXORMappedAddr(address net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error) {
	return m.GetXORMappedAddrContext(context.Background(), address, deadline)
}

func (m *ownedUniversalUDPMux) GetXORMappedAddrContext(ctx context.Context, address net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error) {
	mux, err := m.forFamily(address)
	if err != nil {
		return nil, err
	}
	if contextual, ok := mux.(interface {
		GetXORMappedAddrContext(context.Context, net.Addr, time.Duration) (*stun.XORMappedAddress, error)
	}); ok {
		return contextual.GetXORMappedAddrContext(ctx, address, deadline)
	}
	return mux.GetXORMappedAddr(address, deadline)
}

func (m *ownedUniversalUDPMux) GetRelayedAddr(address net.Addr, deadline time.Duration) (*net.Addr, error) {
	mux, err := m.forFamily(address)
	if err != nil {
		return nil, err
	}
	return mux.GetRelayedAddr(address, deadline)
}

func (m *ownedUniversalUDPMux) GetConnForURL(ufrag, rawURL string, address net.Addr) (net.PacketConn, error) {
	mux, err := m.forLocal(address)
	if err != nil {
		return nil, err
	}
	return mux.GetConnForURL(ufrag, rawURL, address)
}

func (m *ownedUniversalUDPMux) forLocal(address net.Addr) (ice.UniversalUDPMux, error) {
	for _, mux := range m.muxes {
		for _, local := range mux.GetListenAddresses() {
			if local.Network() == address.Network() && local.String() == address.String() {
				return mux, nil
			}
		}
	}
	return m.forFamily(address)
}

func (m *ownedUniversalUDPMux) forFamily(address net.Addr) (ice.UniversalUDPMux, error) {
	wantIPv4, ok := udpAddressFamily(address)
	if !ok {
		return nil, errors.New("ICE UDP mux address is invalid")
	}
	for _, mux := range m.muxes {
		for _, local := range mux.GetListenAddresses() {
			isIPv4, valid := udpAddressFamily(local)
			if valid && isIPv4 == wantIPv4 {
				return mux, nil
			}
		}
	}
	return nil, errors.New("ICE UDP mux has no matching address family")
}

func udpAddressFamily(address net.Addr) (bool, bool) {
	udp, ok := address.(*net.UDPAddr)
	return ok && udp != nil && udp.IP != nil && udp.IP.To4() != nil, ok && udp != nil && udp.IP != nil
}
