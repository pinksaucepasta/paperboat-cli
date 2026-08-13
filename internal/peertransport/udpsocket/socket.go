package udpsocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

var ErrInvalid = errors.New("invalid owned UDP socket configuration")

type Config struct {
	IPv4         bool
	IPv6         bool
	BindAttempts int
	IPv6Viable   func(context.Context) bool
}

func DevelopmentConfig(ipv4, ipv6 bool) Config {
	return Config{IPv4: ipv4, IPv6: ipv6, BindAttempts: 8}
}

type Set struct {
	ipv4 *net.UDPConn
	ipv6 *net.UDPConn
	port uint16

	mu       sync.Mutex
	closed   bool
	closeErr error
}

func Open(ctx context.Context, config Config) (*Set, error) {
	if ctx == nil || !config.IPv4 && !config.IPv6 || config.BindAttempts < 1 || config.BindAttempts > 64 {
		return nil, ErrInvalid
	}
	var lastErr error
	for range config.BindAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		set, err := openAttempt(ctx, config)
		if err == nil {
			return set, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("bind owned UDP sockets after %d attempts: %w", config.BindAttempts, lastErr)
}

func openAttempt(ctx context.Context, config Config) (*Set, error) {
	set := &Set{}
	closeFailure := func(err error) (*Set, error) {
		_ = set.Close()
		return nil, err
	}
	port := 0
	if config.IPv4 {
		connection, err := listen(ctx, "udp4", "0.0.0.0:0")
		if err != nil {
			return closeFailure(fmt.Errorf("bind owned IPv4 UDP socket: %w", err))
		}
		set.ipv4 = connection
		port = connection.LocalAddr().(*net.UDPAddr).Port
	}
	// A wildcard UDP6 bind can succeed on hosts with no usable IPv6 route.
	// Do not advertise that dead family to ICE; preserve IPv6 when an actual
	// non-loopback address is configured on an interface.
	if config.IPv6 && ipv6Usable() && (config.IPv6Viable == nil || config.IPv6Viable(ctx)) {
		address := "[::]:0"
		if port != 0 {
			address = fmt.Sprintf("[::]:%d", port)
		}
		connection, err := listen(ctx, "udp6", address)
		if err != nil {
			return closeFailure(fmt.Errorf("bind owned IPv6 UDP socket: %w", err))
		}
		set.ipv6 = connection
		if port == 0 {
			port = connection.LocalAddr().(*net.UDPAddr).Port
		}
	}
	if port < 1 || port > 65535 {
		return closeFailure(ErrInvalid)
	}
	set.port = uint16(port)
	return set, nil
}

func ipv6Usable() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
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
			if ip != nil && ip.To4() == nil && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

func listen(ctx context.Context, network, address string) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{Control: socketControl(network)}
	packet, err := listenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	connection, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, ErrInvalid
	}
	return connection, nil
}

func (s *Set) Port() uint16 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0
	}
	return s.port
}

func (s *Set) IPv4() *net.UDPConn {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv4
}

func (s *Set) IPv6() *net.UDPConn {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv6
}

func (s *Set) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.ipv4 != nil {
		s.closeErr = errors.Join(s.closeErr, normalizeCloseError(s.ipv4.Close()))
	}
	if s.ipv6 != nil {
		s.closeErr = errors.Join(s.closeErr, normalizeCloseError(s.ipv6.Close()))
	}
	s.port = 0
	return s.closeErr
}

func normalizeCloseError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
