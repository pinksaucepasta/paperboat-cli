// Package directpath assembles Paperboat's owned UDP sockets, shared PMTU
// packet handling, and constrained Pion ICE agent.
package directpath

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
	"github.com/pion/ice/v4"
)

var (
	ErrInvalid            = errors.New("invalid direct path assembly configuration")
	ErrPMTUIneligible     = errors.New("direct path is below the QUIC PMTU floor")
	ErrSessionStarted     = errors.New("direct path QUIC session already started")
	ErrMappingInvalidated = errors.New("verified router mapping invalidated after ICE gathering started")
	ErrNetworkChanged     = errors.New("direct path socket generation replaced by network change")
	ErrAssemblyClosed     = errors.New("active direct path assembly closed")
)

type Config struct {
	ICE               iceagent.Config
	Sockets           udpsocket.Config
	PMTUKey           []byte
	MaximumPMTU       uint16
	ApplicationQueue  int
	PMTUResponseLimit time.Duration
	AttemptGeneration uint64
	NetworkGeneration uint64
	STUNObserver      STUNObserver
	STUNProbeTimeout  time.Duration
	SocketMapping     SocketMappingSource
	Substrate         *SocketSubstrate
}

type STUNObserver interface {
	Observe(context.Context, net.PacketConn, net.PacketConn, []string) networkcheck.STUNObservation
}

type SocketMappingSource interface {
	AcquireSocketMapping(context.Context, uint64, uint16, net.PacketConn, []string) (portmapping.VerifiedMapping, netip.Addr, error)
}

// Assembly owns one ICE attempt and its exact socket generation. A network
// generation change always creates a replacement Assembly.
type Assembly struct {
	agent   *iceagent.Agent
	sockets *udpsocket.Set
	ipv4    *networkadaptation.SharedPacketConn
	ipv6    *networkadaptation.SharedPacketConn
	attempt uint64
	network uint64

	connectMu       sync.Mutex
	connectStarted  bool
	selectedMu      sync.Mutex
	selected        *networkadaptation.SharedPacketConn
	selectedPMTU    networkadaptation.PMTUDatagramExchanger
	lease           *SocketLease
	closed          bool
	nominated       *ice.Conn
	maximumPMTU     uint16
	pmtuKey         []byte
	sessionStarted  bool
	stunObservation networkcheck.STUNObservation

	lifecycleMu                    sync.Mutex
	closing                        bool
	gatherStarted                  bool
	mapping                        portmapping.VerifiedMapping
	mappingInvalidatedBeforeGather bool
	replacementGeneration          uint64
	replacement                    chan error
	done                           chan struct{}
	mappingWatch                   sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

func Open(ctx context.Context, config Config) (*Assembly, error) {
	if ctx == nil || config.AttemptGeneration == 0 || config.NetworkGeneration == 0 || config.STUNObserver != nil && (config.STUNProbeTimeout <= 0 || config.STUNProbeTimeout > 5*time.Second) || config.SocketMapping != nil && nilInterface(config.SocketMapping) {
		return nil, ErrInvalid
	}
	started := time.Now()
	timing := map[string]int64{}
	mark := func(name string) { timing[name] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer direct assembly timing", "attempt_generation", config.AttemptGeneration, "network_generation", config.NetworkGeneration, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	assembly := &Assembly{
		attempt: config.AttemptGeneration, network: config.NetworkGeneration,
		maximumPMTU: config.MaximumPMTU, pmtuKey: append([]byte(nil), config.PMTUKey...),
		replacement: make(chan error, 1), done: make(chan struct{}), replacementGeneration: config.NetworkGeneration,
	}
	fail := func(cause error) (*Assembly, error) {
		return nil, errors.Join(cause, assembly.Close())
	}
	if config.Substrate != nil {
		lease, acquireErr := config.Substrate.Acquire(ctx, config.NetworkGeneration, config.AttemptGeneration, config.ICE.STUNURLs, config.ICE, config.PMTUKey)
		if acquireErr != nil {
			return fail(acquireErr)
		}
		assembly.lease = lease
		assembly.agent = lease.Agent()
		mark("sockets_ready")
		assembly.stunObservation = networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
		if mapping, related := lease.Mapping(); mapping.Valid() {
			if err := assembly.ConfigureVerifiedMapping(mapping, related); err != nil {
				return fail(err)
			}
		}
		mark("socket_mapping_ready")
		mark("shared_sockets_ready")
		mark("agent_ready")
		return assembly, nil
	}
	sockets, err := udpsocket.Open(ctx, config.Sockets)
	if err != nil {
		return nil, err
	}
	assembly.sockets = sockets
	mark("sockets_ready")
	assembly.stunObservation = networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if config.STUNObserver != nil {
		probeCtx, cancel := context.WithTimeout(ctx, config.STUNProbeTimeout)
		assembly.stunObservation = config.STUNObserver.Observe(probeCtx, sockets.IPv4(), sockets.IPv6(), append([]string(nil), config.ICE.STUNURLs...))
		cancel()
		if err := assembly.stunObservation.Validate(); err != nil {
			return fail(errors.Join(ErrInvalid, err))
		}
	}
	mark("stun_observation_ready")
	var verifiedMapping portmapping.VerifiedMapping
	var relatedAddress netip.Addr
	if config.SocketMapping != nil && sockets.IPv4() != nil {
		verifiedMapping, relatedAddress, err = config.SocketMapping.AcquireSocketMapping(ctx, config.NetworkGeneration, sockets.Port(), sockets.IPv4(), append([]string(nil), config.ICE.STUNURLs...))
		if err != nil && !errors.Is(err, portmapping.ErrUntrusted) && !errors.Is(err, portmapping.ErrUnavailable) && !errors.Is(err, portmapping.ErrUnreachable) {
			return fail(err)
		}
	}
	mark("socket_mapping_ready")
	sharedConfig := func(connection net.PacketConn) networkadaptation.SharedPacketConfig {
		return networkadaptation.SharedPacketConfig{
			Connection: connection, PMTUKey: config.PMTUKey, MaximumPMTU: config.MaximumPMTU,
			ApplicationQueue: config.ApplicationQueue, ResponseTimeout: config.PMTUResponseLimit,
		}
	}
	if connection := sockets.IPv4(); connection != nil {
		mark("shared_ipv4_start")
		assembly.ipv4, err = networkadaptation.NewSharedPacketConn(sharedConfig(connection))
		if err != nil {
			return fail(err)
		}
		mark("shared_ipv4_ready")
	}
	if connection := sockets.IPv6(); connection != nil {
		mark("shared_ipv6_start")
		assembly.ipv6, err = networkadaptation.NewSharedPacketConn(sharedConfig(connection))
		if err != nil {
			return fail(err)
		}
		mark("shared_ipv6_ready")
	}
	mark("shared_sockets_ready")
	agent, err := iceagent.NewWithUDPMux(config.ICE, iceagent.OwnedMuxConfig{IPv4: assembly.ipv4, IPv6: assembly.ipv6})
	if err != nil {
		return fail(err)
	}
	mark("agent_ready")
	assembly.agent = agent
	if verifiedMapping.Valid() {
		if err := assembly.ConfigureVerifiedMapping(verifiedMapping, relatedAddress); err != nil {
			return fail(err)
		}
	}
	return assembly, nil
}

func (a *Assembly) STUNObservation() networkcheck.STUNObservation {
	if a == nil {
		return networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	}
	return a.stunObservation
}

func (a *Assembly) Port() uint16 {
	if a == nil || a.sockets == nil {
		return 0
	}
	return a.sockets.Port()
}

func (a *Assembly) Gather(ctx context.Context, emit func(string) error) error {
	if a == nil || a.agent == nil {
		return ErrInvalid
	}
	a.lifecycleMu.Lock()
	if a.closing {
		a.lifecycleMu.Unlock()
		return net.ErrClosed
	}
	select {
	case <-a.done:
		a.lifecycleMu.Unlock()
		return net.ErrClosed
	default:
	}
	if !a.mapping.Valid() && a.mapping.Invalidated() != nil {
		a.mappingInvalidatedBeforeGather = true
	}
	a.gatherStarted = true
	a.lifecycleMu.Unlock()
	return a.agent.Gather(ctx, emit)
}

func (a *Assembly) AddRemoteCandidate(candidate string) error {
	if a == nil || a.agent == nil {
		return ErrInvalid
	}
	return a.agent.AddRemoteCandidate(candidate)
}

// ConfigureVerifiedMapping adds one externally verified IPv4 mapping to the
// normal bounded candidate signaling path. It must run before Gather.
func (a *Assembly) ConfigureVerifiedMapping(mapping portmapping.VerifiedMapping, related netip.Addr) error {
	if a == nil || a.agent == nil || !mapping.Valid() || mapping.Generation() != a.network || mapping.LocalPort() != a.Port() {
		return ErrInvalid
	}
	candidate, err := iceagent.NewMappedCandidate(mapping, related)
	if err != nil {
		return err
	}
	if err := a.agent.ConfigureMappedCandidate(candidate); err != nil {
		return err
	}
	invalidated := mapping.Invalidated()
	if invalidated == nil {
		return ErrInvalid
	}
	a.lifecycleMu.Lock()
	if a.closing {
		a.lifecycleMu.Unlock()
		return net.ErrClosed
	}
	select {
	case <-a.done:
		a.lifecycleMu.Unlock()
		return net.ErrClosed
	default:
	}
	a.mapping = mapping
	a.mappingWatch.Add(1)
	a.lifecycleMu.Unlock()
	go a.watchMapping(invalidated)
	return nil
}

func (a *Assembly) ReplacementRequired() <-chan error {
	if a == nil {
		return nil
	}
	return a.replacement
}

func (a *Assembly) Done() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.done
}

// NetworkChanged closes a socket-bound ICE attempt exactly once when a newer
// rebind generation arrives.
func (a *Assembly) NetworkChanged(generation uint64) bool {
	if a == nil {
		return false
	}
	a.lifecycleMu.Lock()
	if generation <= a.replacementGeneration {
		a.lifecycleMu.Unlock()
		return false
	}
	a.replacementGeneration = generation
	a.lifecycleMu.Unlock()
	a.signalReplacement(ErrNetworkChanged)
	_ = a.Close()
	return true
}

func (a *Assembly) watchMapping(invalidated <-chan struct{}) {
	defer a.mappingWatch.Done()
	select {
	case <-a.done:
		return
	case <-invalidated:
	}
	a.lifecycleMu.Lock()
	gathered := a.gatherStarted && !a.mappingInvalidatedBeforeGather
	a.lifecycleMu.Unlock()
	if gathered {
		a.signalReplacement(ErrMappingInvalidated)
		go a.Close()
	}
}

func (a *Assembly) signalReplacement(reason error) {
	select {
	case a.replacement <- reason:
	default:
	}
}

// Connect nominates one ICE path and atomically binds PMTU exchanges to that
// selected peer before returning the connection.
func (a *Assembly) Connect(ctx context.Context, role iceagent.Role, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	if a == nil || a.agent == nil {
		return nil, ErrInvalid
	}
	a.connectMu.Lock()
	if a.connectStarted {
		a.connectMu.Unlock()
		return nil, errors.New("direct path ICE connect already started")
	}
	a.connectStarted = true
	a.connectMu.Unlock()
	connection, err := a.agent.Connect(ctx, role, remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}
	localType, remoteType, typeErr := a.agent.SelectedCandidateTypes()
	if typeErr == nil {
		diagnosticlog.TryInfo("peer direct selected candidate pair", "local_type", localType, "remote_type", remoteType, "attempt_generation", a.attempt, "network_generation", a.network)
	}
	var selected *networkadaptation.SharedPacketConn
	var selectedPMTU networkadaptation.PMTUDatagramExchanger
	if a.lease != nil {
		address := connection.RemoteAddr()
		udp, ok := address.(*net.UDPAddr)
		if !ok || udp == nil {
			_ = connection.Close()
			return nil, errors.New("nominated ICE peer is not UDP")
		}
		if udp.IP.To4() != nil {
			selectedPMTU = a.lease.RegistrationFor("udp4")
		} else {
			selectedPMTU = a.lease.RegistrationFor("udp6")
		}
		if selectedPMTU == nil {
			_ = connection.Close()
			return nil, errors.New("nominated ICE peer has no PMTU registration")
		}
	} else {
		selected, err = a.packetForRemote(connection.RemoteAddr())
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	binding := networkadaptation.PMTURemoteBinding{
		Address: connection.RemoteAddr(), AttemptGeneration: a.attempt, NetworkGeneration: a.network,
	}
	var bindErr error
	if a.lease != nil {
		if registration, ok := selectedPMTU.(*networkadaptation.PMTURegistration); ok {
			bindErr = registration.BindPMTURemote(binding)
		}
	} else {
		bindErr = selected.BindPMTURemote(binding)
	}
	if bindErr != nil {
		_ = connection.Close()
		return nil, bindErr
	}
	a.selectedMu.Lock()
	if a.closed {
		a.selectedMu.Unlock()
		_ = connection.Close()
		return nil, net.ErrClosed
	}
	a.selected = selected
	a.selectedPMTU = selectedPMTU
	a.nominated = connection
	a.selectedMu.Unlock()
	return connection, nil
}

type PMTUConfig struct {
	Policy   networkadaptation.PMTUPolicy
	Cache    *networkadaptation.PMTUCache
	Key      networkadaptation.PMTUKey
	Lifetime *LifetimeConfig
}

type LifetimeConfig struct {
	Cache       *networkadaptation.LifetimeCache
	Fingerprint networkadaptation.Fingerprint
	Now         func() time.Time
}

func (a *Assembly) DialQUIC(ctx context.Context, tlsConfig *tls.Config, base peerquic.SessionConfig, adaptation PMTUConfig) (*peerquic.Session, error) {
	if err := a.beginSession(); err != nil {
		return nil, err
	}
	connection, err := a.nominatedConnection()
	if err != nil {
		return nil, err
	}
	configured, err := a.prepareSession(ctx, base, adaptation)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	session, err := peerquic.DialConfigured(ctx, connection, tlsConfig, configured)
	if err != nil {
		_ = connection.Close()
	}
	return session, err
}

func (a *Assembly) ListenQUIC(ctx context.Context, tlsConfig *tls.Config, base peerquic.SessionConfig, adaptation PMTUConfig) (*peerquic.Listener, error) {
	if err := a.beginSession(); err != nil {
		return nil, err
	}
	connection, err := a.nominatedConnection()
	if err != nil {
		return nil, err
	}
	configured, err := a.prepareSession(ctx, base, adaptation)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	listener, err := peerquic.ListenConfigured(connection, tlsConfig, configured)
	if err != nil {
		_ = connection.Close()
	}
	return listener, err
}

// DialProbeQUIC creates an endpoint-authenticated probe-only QUIC session on
// the nominated ICE path with automatic QUIC keepalives disabled.
func (a *Assembly) DialProbeQUIC(ctx context.Context, tlsConfig *tls.Config, maximumIdle time.Duration) (*peerquic.Session, error) {
	if err := a.beginSession(); err != nil {
		return nil, err
	}
	connection, err := a.nominatedConnection()
	if err != nil {
		return nil, err
	}
	session, err := peerquic.DialProbe(ctx, connection, tlsConfig, maximumIdle)
	if err != nil {
		_ = connection.Close()
	}
	return session, err
}

// ListenProbeQUIC accepts an endpoint-authenticated probe-only QUIC session
// on the nominated ICE path with automatic QUIC keepalives disabled.
func (a *Assembly) ListenProbeQUIC(ctx context.Context, tlsConfig *tls.Config, maximumIdle time.Duration) (*peerquic.Listener, error) {
	if err := a.beginSession(); err != nil {
		return nil, err
	}
	connection, err := a.nominatedConnection()
	if err != nil {
		return nil, err
	}
	listener, err := peerquic.ListenProbe(connection, tlsConfig, maximumIdle)
	if err != nil {
		_ = connection.Close()
	}
	return listener, err
}

func (a *Assembly) beginSession() error {
	if a == nil {
		return ErrInvalid
	}
	a.connectMu.Lock()
	defer a.connectMu.Unlock()
	if a.sessionStarted {
		return ErrSessionStarted
	}
	a.sessionStarted = true
	return nil
}

func (a *Assembly) nominatedConnection() (*ice.Conn, error) {
	a.selectedMu.Lock()
	defer a.selectedMu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	if a.nominated == nil {
		return nil, errors.New("direct path has no nominated ICE connection")
	}
	return a.nominated, nil
}

func (a *Assembly) prepareSession(ctx context.Context, base peerquic.SessionConfig, adaptation PMTUConfig) (peerquic.SessionConfig, error) {
	if ctx == nil || adaptation.Cache == nil || !adaptation.Key.Valid() || adaptation.Key.NetworkGeneration != a.network || adaptation.Policy.MaximumPayload > a.maximumPMTU {
		return peerquic.SessionConfig{}, ErrInvalid
	}
	if observation, ok := adaptation.Cache.Lookup(adaptation.Key, time.Now().UTC()); ok {
		if !observation.Eligible {
			return peerquic.SessionConfig{}, ErrPMTUIneligible
		}
		if observation.PacketSize > adaptation.Policy.MaximumPayload || observation.PacketSize > a.maximumPMTU {
			return peerquic.SessionConfig{}, ErrInvalid
		}
		configured, err := networkadaptation.ApplyPMTU(base, observation, time.Now().UTC())
		if err != nil {
			return peerquic.SessionConfig{}, err
		}
		return applyLifetimeConfig(configured, adaptation.Lifetime)
	}
	// A cache miss must not delay connection establishment. QUIC starts at its
	// required 1200-byte floor and discovers a larger path MTU in-band.
	return applyLifetimeConfig(base, adaptation.Lifetime)
}

func applyLifetimeConfig(config peerquic.SessionConfig, lifetime *LifetimeConfig) (peerquic.SessionConfig, error) {
	if lifetime == nil {
		return config, nil
	}
	if lifetime.Cache == nil || !lifetime.Fingerprint.Valid() {
		return peerquic.SessionConfig{}, ErrInvalid
	}
	now := lifetime.Now
	if now == nil {
		now = time.Now
	}
	decision, err := lifetime.Cache.Keepalive(lifetime.Fingerprint, now().UTC())
	if err != nil {
		return peerquic.SessionConfig{}, err
	}
	return networkadaptation.ApplyLifetimeDecision(config, decision)
}

func (a *Assembly) SelectedPMTUExchanger() (networkadaptation.PMTUDatagramExchanger, error) {
	if a == nil {
		return nil, ErrInvalid
	}
	a.selectedMu.Lock()
	defer a.selectedMu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	if a.selected == nil {
		if a.selectedPMTU == nil {
			return nil, errors.New("direct path has no nominated PMTU peer")
		}
		return a.selectedPMTU, nil
	}
	if a.selected == nil {
		return nil, errors.New("direct path has no nominated PMTU peer")
	}
	return a.selected, nil
}

func (a *Assembly) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		close(a.done)
		a.lifecycleMu.Lock()
		a.closing = true
		a.lifecycleMu.Unlock()
		a.mappingWatch.Wait()
		a.selectedMu.Lock()
		a.closed = true
		zeroBytes(a.pmtuKey)
		a.pmtuKey = nil
		a.selectedMu.Unlock()
		if a.agent != nil {
			if a.lease != nil {
				a.closeErr = errors.Join(a.closeErr, a.lease.Close())
			} else {
				a.closeErr = errors.Join(a.closeErr, a.agent.Close())
			}
		} else {
			a.closeErr = errors.Join(a.closeErr, closeShared(a.ipv4), closeShared(a.ipv6))
		}
		if a.sockets != nil {
			a.closeErr = errors.Join(a.closeErr, a.sockets.Close())
		}
	})
	return a.closeErr
}

func (a *Assembly) packetForRemote(address net.Addr) (*networkadaptation.SharedPacketConn, error) {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp == nil || udp.IP == nil {
		return nil, errors.New("nominated ICE peer is not UDP")
	}
	if udp.IP.To4() != nil && a.ipv4 != nil {
		return a.ipv4, nil
	}
	if udp.IP.To4() == nil && a.ipv6 != nil {
		return a.ipv6, nil
	}
	return nil, errors.New("nominated ICE peer has no owned socket family")
}

func closeShared(connection *networkadaptation.SharedPacketConn) error {
	if connection == nil {
		return nil
	}
	return connection.Close()
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
