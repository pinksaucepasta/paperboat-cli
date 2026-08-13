package directpath

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

var ErrSocketSubstrateClosed = errors.New("direct socket substrate closed")

type SocketSubstrateConfig struct {
	Sockets           udpsocket.Config
	SocketMapping     SocketMappingSource
	MaximumPMTU       uint16
	ApplicationQueue  int
	PMTUResponseLimit time.Duration
	MaximumAttempts   int
}

// SocketSubstrate owns one daemon-wide UDP/mux generation. It retains no
// machine-specific data carrier; attempts borrow the mux only while active.
type SocketSubstrate struct {
	config SocketSubstrateConfig

	mu         sync.Mutex
	generation *socketGeneration
	closed     bool
}

type socketGeneration struct {
	network uint64
	sockets *udpsocket.Set
	ipv4    *networkadaptation.MultiplexedPacketConn
	ipv6    *networkadaptation.MultiplexedPacketConn
	mux     *iceagent.SharedUDPMux
	mapping portmapping.VerifiedMapping
	related netip.Addr
	done    chan struct{}
	once    sync.Once
	err     error
}

type SocketLease struct {
	generation *socketGeneration
	agent      *iceagent.Agent
	ipv4       *networkadaptation.PMTURegistration
	ipv6       *networkadaptation.PMTURegistration
	once       sync.Once
	err        error
}

func NewSocketSubstrate(config SocketSubstrateConfig) (*SocketSubstrate, error) {
	if config.MaximumPMTU < 1200 || config.ApplicationQueue < 1 || config.PMTUResponseLimit <= 0 || config.MaximumAttempts < 1 || config.MaximumAttempts > 4096 {
		return nil, ErrInvalid
	}
	return &SocketSubstrate{config: config}, nil
}

// Warm establishes the network-generation socket, mapping, and Pion mux. It
// is idempotent and performs no peer- or machine-specific work.
func (s *SocketSubstrate) Warm(ctx context.Context, network uint64, stunURLs []string) error {
	if s == nil || ctx == nil || network == 0 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSocketSubstrateClosed
	}
	if current := s.generation; current != nil && current.network == network && !closedChannel(current.done) {
		return nil
	}
	created, err := openSocketGeneration(ctx, s.config, network, stunURLs)
	if err != nil {
		return err
	}
	previous := s.generation
	s.generation = created
	if previous != nil {
		_ = previous.Close()
	}
	if created.mapping.Valid() {
		go s.watchMapping(created, created.mapping.Invalidated())
	}
	return nil
}

func openSocketGeneration(ctx context.Context, config SocketSubstrateConfig, network uint64, stunURLs []string) (*socketGeneration, error) {
	sockets, err := udpsocket.Open(ctx, config.Sockets)
	if err != nil {
		return nil, err
	}
	generation := &socketGeneration{network: network, sockets: sockets, done: make(chan struct{})}
	fail := func(cause error) (*socketGeneration, error) {
		return nil, errors.Join(cause, generation.Close())
	}
	if config.SocketMapping != nil && sockets.IPv4() != nil && len(stunURLs) > 0 {
		generation.mapping, generation.related, err = config.SocketMapping.AcquireSocketMapping(ctx, network, sockets.Port(), sockets.IPv4(), append([]string(nil), stunURLs...))
		if err != nil && !errors.Is(err, portmapping.ErrUntrusted) && !errors.Is(err, portmapping.ErrUnavailable) && !errors.Is(err, portmapping.ErrUnreachable) {
			return fail(err)
		}
	}
	packetConfig := func() networkadaptation.MultiplexedPacketConfig {
		return networkadaptation.MultiplexedPacketConfig{
			MaximumPMTU: config.MaximumPMTU, ApplicationQueue: config.ApplicationQueue,
			ResponseTimeout: config.PMTUResponseLimit, MaximumChannels: config.MaximumAttempts,
		}
	}
	if socket := sockets.IPv4(); socket != nil {
		value := packetConfig()
		value.Connection = socket
		generation.ipv4, err = networkadaptation.NewMultiplexedPacketConn(value)
		if err != nil {
			return fail(err)
		}
	}
	if socket := sockets.IPv6(); socket != nil {
		value := packetConfig()
		value.Connection = socket
		generation.ipv6, err = networkadaptation.NewMultiplexedPacketConn(value)
		if err != nil {
			return fail(err)
		}
	}
	generation.mux, err = iceagent.NewSharedUDPMux(generation.ipv4, generation.ipv6)
	if err != nil {
		return fail(err)
	}
	return generation, nil
}

func (s *SocketSubstrate) Acquire(ctx context.Context, network, attempt uint64, stunURLs []string, iceConfig iceagent.Config, pmtuKey []byte) (*SocketLease, error) {
	if s == nil || ctx == nil || network == 0 || attempt == 0 || len(pmtuKey) < 32 {
		return nil, ErrInvalid
	}
	if err := s.Warm(ctx, network, stunURLs); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.generation == nil || s.generation.network != network || closedChannel(s.generation.done) {
		return nil, ErrNetworkChanged
	}
	generation := s.generation
	lease := &SocketLease{generation: generation}
	fail := func(cause error) (*SocketLease, error) { return nil, errors.Join(cause, lease.Close()) }
	var err error
	if generation.ipv4 != nil {
		lease.ipv4, err = generation.ipv4.RegisterPMTU(pmtuKey, attempt, network)
		if err != nil {
			return fail(err)
		}
	}
	if generation.ipv6 != nil {
		lease.ipv6, err = generation.ipv6.RegisterPMTU(pmtuKey, attempt, network)
		if err != nil {
			return fail(err)
		}
	}
	lease.agent, err = iceagent.NewWithSharedUDPMux(iceConfig, generation.mux)
	if err != nil {
		return fail(err)
	}
	return lease, nil
}

func (s *SocketSubstrate) NetworkChanged(network uint64) bool {
	if s == nil || network == 0 {
		return false
	}
	s.mu.Lock()
	current := s.generation
	if current == nil || network < current.network {
		s.mu.Unlock()
		return false
	}
	s.generation = nil
	s.mu.Unlock()
	_ = current.Close()
	return true
}

func (s *SocketSubstrate) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	current := s.generation
	s.generation = nil
	s.mu.Unlock()
	if current != nil {
		return current.Close()
	}
	return nil
}

func (s *SocketSubstrate) watchMapping(generation *socketGeneration, invalidated <-chan struct{}) {
	if invalidated == nil {
		return
	}
	select {
	case <-generation.done:
		return
	case <-invalidated:
	}
	s.mu.Lock()
	if s.generation == generation {
		s.generation = nil
	}
	s.mu.Unlock()
	_ = generation.Close()
}

func (g *socketGeneration) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		close(g.done)
		g.err = errors.Join(g.err, g.mux.Close())
		if g.mux == nil {
			if g.ipv4 != nil {
				g.err = errors.Join(g.err, g.ipv4.Close())
			}
			if g.ipv6 != nil {
				g.err = errors.Join(g.err, g.ipv6.Close())
			}
		}
		g.err = errors.Join(g.err, g.sockets.Close())
	})
	return g.err
}

func (l *SocketLease) Agent() *iceagent.Agent {
	if l == nil {
		return nil
	}
	return l.agent
}

func (l *SocketLease) Port() uint16 {
	if l == nil || l.generation == nil || l.generation.sockets == nil {
		return 0
	}
	return l.generation.sockets.Port()
}

func (l *SocketLease) Mapping() (portmapping.VerifiedMapping, netip.Addr) {
	if l == nil || l.generation == nil {
		return portmapping.VerifiedMapping{}, netip.Addr{}
	}
	return l.generation.mapping, l.generation.related
}

func (l *SocketLease) RegistrationFor(address string) *networkadaptation.PMTURegistration {
	if l == nil {
		return nil
	}
	if address == "udp4" {
		return l.ipv4
	}
	if address == "udp6" {
		return l.ipv6
	}
	return nil
}

func (l *SocketLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.agent != nil {
			l.err = errors.Join(l.err, l.agent.Close())
		}
		if l.ipv4 != nil {
			l.err = errors.Join(l.err, l.ipv4.Close())
		}
		if l.ipv6 != nil {
			l.err = errors.Join(l.err, l.ipv6.Close())
		}
	})
	return l.err
}

func closedChannel(value <-chan struct{}) bool {
	select {
	case <-value:
		return true
	default:
		return false
	}
}
