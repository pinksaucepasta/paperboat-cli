// Package networkmonitor owns Paperboat's typed network-change boundary.
package networkmonitor

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	//paperboat:allow-source-policy tailscale-import owner=peer-networking reason=selected-network-monitor
	"tailscale.com/net/netmon"
	//paperboat:allow-source-policy tailscale-import owner=peer-networking reason=selected-portmapper-client
	"tailscale.com/net/portmapper"
	//paperboat:allow-source-policy tailscale-import owner=peer-networking reason=selected-netmon-event-bus
	"tailscale.com/util/eventbus"
)

var ErrInvalid = errors.New("invalid network monitor configuration")
var ErrDNSUnavailable = errors.New("system DNS fingerprint unavailable")
var interestingInterfaceOnce sync.Once

type Reason uint16

const (
	ReasonDefaultRoute Reason = 1 << iota
	ReasonInterfaceAddress
	ReasonAddressFamily
	ReasonProxy
	ReasonNetworkCost
	ReasonViability
	ReasonWake
	ReasonDNS
)

type Event struct {
	Generation       uint64
	Reasons          Reason
	Rebind           bool
	IPv4             bool
	IPv6             bool
	Viable           bool
	Fingerprint      networkadaptation.Fingerprint
	FingerprintValid bool
}

// DNSFingerprintSource returns an opaque, installation-local DNS
// configuration fingerprint. It must never return resolver addresses or raw
// configuration. The monitor stores only the digest and emits ReasonDNS when
// the digest changes.
type DNSFingerprintSource func(context.Context) ([32]byte, error)

func validateDNSContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

type netMonitor interface {
	RegisterChangeCallback(netmon.ChangeFunc) func()
	InterfaceState() *netmon.State
	Start()
	Close() error
}

type Monitor struct {
	backend                      netMonitor
	native                       *netmon.Monitor
	eventBus                     *eventbus.Bus
	handle                       func(Event)
	generation                   atomic.Uint64
	mu                           sync.Mutex
	callbacks                    sync.WaitGroup
	unregister                   func()
	started                      bool
	closed                       bool
	portMappers                  map[*portMapper]struct{}
	mappingManager               *portmapping.Manager
	mappingUnavailableGeneration uint64
	mappingCreating              bool
	mappingCreateDone            chan struct{}
	newMappingManager            func(portmapping.Config, portmapping.BackendFactory) (*portmapping.Manager, error)
	fingerprintSecret            []byte
	networkIdentity              func() string
	dnsSource                    DNSFingerprintSource
	dnsFingerprint               [32]byte
	dnsFingerprintSet            bool
	dnsCancel                    context.CancelFunc
	dnsDone                      chan struct{}
	dnsPollInterval              time.Duration
}

func New(handle func(Event)) (*Monitor, error) {
	return newNativeMonitor(nil, nil, handle)
}

// NewFingerprinting derives installation-scoped opaque fingerprints while the
// raw netmon state is still inside this package.
func NewFingerprinting(secret []byte, networkIdentity func() string, handle func(Event)) (*Monitor, error) {
	if len(secret) < 32 {
		return nil, ErrInvalid
	}
	return newNativeMonitor(secret, networkIdentity, handle)
}

func newNativeMonitor(secret []byte, networkIdentity func() string, handle func(Event)) (*Monitor, error) {
	if handle == nil {
		return nil, ErrInvalid
	}
	// Paperboat-owned virtual interfaces must not recursively invalidate the
	// physical network generation they are built on.
	interestingInterfaceOnce.Do(func() {
		netmon.IsInterestingInterface = func(item netmon.Interface, _ []netip.Prefix) bool {
			return item.Interface == nil || !paperboatInterface(item.Name)
		}
	})
	bus := eventbus.New()
	backend, err := netmon.New(bus, func(string, ...any) {})
	if err != nil {
		return nil, err
	}
	monitor := newMonitor(backend, handle)
	monitor.fingerprintSecret = append([]byte(nil), secret...)
	monitor.networkIdentity = networkIdentity
	monitor.native, monitor.eventBus = backend, bus
	return monitor, nil
}

func newMonitor(backend netMonitor, handle func(Event)) *Monitor {
	return &Monitor{backend: backend, handle: handle, portMappers: make(map[*portMapper]struct{}), dnsPollInterval: 15 * time.Second}
}

// ConfigureDNS installs the optional privacy-safe DNS observer. It must be
// called before Start; a source error leaves the prior fingerprint intact and
// does not fabricate a network generation.
func (m *Monitor) ConfigureDNS(source DNSFingerprintSource, interval time.Duration) error {
	if m == nil || source == nil || interval <= 0 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closed {
		return ErrInvalid
	}
	m.dnsSource = source
	m.dnsPollInterval = interval
	return nil
}

type PortMapper interface {
	SetLocalPort(uint16)
	Probe(context.Context) error
	Mapping() (netip.AddrPort, bool)
	Protocol() string
	NetworkDown()
	Close() error
}

type portMapper struct {
	client    *portmapper.Client
	owner     *Monitor
	renewal   *leaseRenewal
	closeOnce sync.Once
	closeErr  error
}

func (p *portMapper) SetLocalPort(port uint16) { p.client.SetLocalPort(port) }
func (p *portMapper) Probe(ctx context.Context) error {
	_, err := p.client.Probe(ctx)
	return err
}
func (p *portMapper) Mapping() (netip.AddrPort, bool) {
	return p.client.GetCachedMappingOrStartCreatingOne()
}
func (p *portMapper) Protocol() string { return p.renewal.Protocol() }
func (p *portMapper) NetworkDown()     { p.client.NoteNetworkDown() }
func (p *portMapper) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.renewal.Close()
		p.closeErr = p.client.Close()
		if p.owner != nil {
			p.owner.mu.Lock()
			delete(p.owner.portMappers, p)
			p.owner.mu.Unlock()
		}
	})
	return p.closeErr
}

func (m *Monitor) newPortMapper(enableUPnP bool, onChange func()) (PortMapper, error) {
	if m == nil || m.native == nil || m.eventBus == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrInvalid
	}
	client := portmapper.NewClient(portmapper.Config{
		EventBus: m.eventBus,
		NetMon:   m.native,
		OnChange: onChange,
		DebugKnobs: &portmapper.DebugKnobs{
			DisableUPnPFunc: func() bool { return !enableUPnP },
		},
	})
	mapper := &portMapper{client: client, owner: m}
	mapper.renewal = newLeaseRenewal(m.eventBus, func() bool {
		_, ok := mapper.Mapping()
		return ok
	})
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = mapper.Close()
		return nil, ErrInvalid
	}
	m.portMappers[mapper] = struct{}{}
	m.mu.Unlock()
	return mapper, nil
}

type PortMappingConfig struct {
	Verifier       portmapping.Verifier
	SocketVerifier portmapping.SocketVerifier
	ProbeTimeout   time.Duration
	CreateTimeout  time.Duration
	EnableUPnP     bool
	OnState        func(portmapping.State)
}

// NewPortMappingManager constructs the runtime's sole mapping owner from this
// monitor's shared netmon/event-bus instance and private trust classifier.
func (m *Monitor) NewPortMappingManager(config PortMappingConfig) (*portmapping.Manager, error) {
	if m == nil || m.native == nil || m.eventBus == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	if m.closed || m.mappingManager != nil || m.mappingCreating {
		m.mu.Unlock()
		return nil, ErrInvalid
	}
	m.mappingCreating = true
	creationDone := make(chan struct{})
	m.mappingCreateDone = creationDone
	newManager := m.newMappingManager
	m.mu.Unlock()
	if newManager == nil {
		newManager = portmapping.NewManaged
	}

	manager, err := newManager(portmapping.Config{
		Verifier: config.Verifier, SocketVerifier: config.SocketVerifier, Trust: m.PortMappingTrust,
		ProbeTimeout: config.ProbeTimeout, CreateTimeout: config.CreateTimeout, OnState: config.OnState,
	}, func(onChange func()) (portmapping.Backend, error) {
		return m.newPortMapper(config.EnableUPnP, onChange)
	})
	if err != nil {
		m.mu.Lock()
		m.finishMappingCreationLocked(creationDone)
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Lock()
	if m.closed || m.mappingManager != nil {
		m.mu.Unlock()
		_ = manager.Close()
		m.mu.Lock()
		m.finishMappingCreationLocked(creationDone)
		m.mu.Unlock()
		return nil, ErrInvalid
	}
	m.mappingManager = manager
	m.finishMappingCreationLocked(creationDone)
	m.mu.Unlock()
	return manager, nil
}

// AcquireSocketMapping verifies the mapping from the exact socket that will be
// handed to ICE. It is the production path; AcquireMapping remains for legacy
// callers and deterministic tests.
func (m *Monitor) AcquireSocketMapping(ctx context.Context, generation uint64, localPort uint16, connection net.PacketConn, stunURLs []string) (portmapping.VerifiedMapping, netip.Addr, error) {
	if m == nil || ctx == nil || generation == 0 || localPort == 0 || connection == nil || len(stunURLs) == 0 {
		return portmapping.VerifiedMapping{}, netip.Addr{}, ErrInvalid
	}
	m.mu.Lock()
	if m.mappingUnavailableGeneration == generation {
		m.mu.Unlock()
		return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrUnavailable
	}
	manager := m.mappingManager
	m.mu.Unlock()
	if manager == nil {
		return portmapping.VerifiedMapping{}, netip.Addr{}, ErrInvalid
	}
	if _, err := manager.AcquireSocket(ctx, generation, localPort, connection, stunURLs); err != nil {
		if errors.Is(err, portmapping.ErrUnavailable) || errors.Is(err, portmapping.ErrUnreachable) {
			m.mu.Lock()
			m.mappingUnavailableGeneration = generation
			m.mu.Unlock()
		}
		return portmapping.VerifiedMapping{}, netip.Addr{}, err
	}
	trust, related := classifyPortMapping(m.backend.InterfaceState())
	if trust != portmapping.TrustPrivateLAN || !related.IsValid() {
		manager.NetworkChanged(generation)
		return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrUntrusted
	}
	verified, ok := manager.Verified(generation)
	if !ok || !verified.Valid() {
		return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrStale
	}
	return verified, related, nil
}

// WarmSocketMapping performs the optional router-mapping capability probe on
// daemon startup. A negative result is cached for this network generation so
// every application attempt does not pay the probe timeout.
func (m *Monitor) WarmSocketMapping(ctx context.Context, generation uint64, stunURL string) error {
	if m == nil || ctx == nil || generation == 0 || stunURL == "" {
		return ErrInvalid
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, _, err = m.AcquireSocketMapping(ctx, generation, uint16(connection.LocalAddr().(*net.UDPAddr).Port), connection, []string{stunURL})
	return err
}

func (m *Monitor) finishMappingCreationLocked(done chan struct{}) {
	if m.mappingCreateDone != done {
		return
	}
	m.mappingCreating = false
	m.mappingCreateDone = nil
	close(done)
}

// PortMappingTrust classifies the current default route without exposing raw
// interface names or addresses outside the network-monitor boundary.
func (m *Monitor) PortMappingTrust() portmapping.InterfaceTrust {
	if m == nil || m.backend == nil {
		return portmapping.TrustUntrusted
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return portmapping.TrustUntrusted
	}
	trust, _ := classifyPortMapping(m.backend.InterfaceState())
	return trust
}

func classifyPortMappingTrust(state *netmon.State) portmapping.InterfaceTrust {
	trust, _ := classifyPortMapping(state)
	return trust
}

func classifyPortMapping(state *netmon.State) (portmapping.InterfaceTrust, netip.Addr) {
	if state == nil || state.DefaultRouteInterface == "" {
		return portmapping.TrustUntrusted, netip.Addr{}
	}
	if state.IsExpensive {
		return portmapping.TrustCellular, netip.Addr{}
	}
	name := state.DefaultRouteInterface
	if interfaceKind(name, false) == networkadaptation.InterfaceVPN {
		return portmapping.TrustVPN, netip.Addr{}
	}
	item, ok := state.Interface[name]
	if !ok || item.Interface == nil || !item.IsUp() || item.IsLoopback() || paperboatInterface(name) {
		return portmapping.TrustUntrusted, netip.Addr{}
	}
	var privateIPv4 netip.Addr
	var publicIPv4 bool
	for _, prefix := range state.InterfaceIPs[name] {
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			continue
		}
		if address.IsPrivate() {
			if !privateIPv4.IsValid() || address.Less(privateIPv4) {
				privateIPv4 = address
			}
		} else {
			publicIPv4 = true
		}
	}
	if publicIPv4 {
		return portmapping.TrustPublic, netip.Addr{}
	}
	if privateIPv4.IsValid() {
		return portmapping.TrustPrivateLAN, privateIPv4
	}
	return portmapping.TrustUntrusted, netip.Addr{}
}

// AcquireMapping binds the shared mapper to one assembly socket generation and
// returns only a still-current verified capability and its private-LAN related address.
func (m *Monitor) AcquireMapping(ctx context.Context, generation uint64, localPort uint16) (portmapping.VerifiedMapping, netip.Addr, error) {
	if m == nil || ctx == nil || generation == 0 || localPort == 0 {
		return portmapping.VerifiedMapping{}, netip.Addr{}, ErrInvalid
	}
	m.mu.Lock()
	manager := m.mappingManager
	m.mu.Unlock()
	if manager == nil {
		return portmapping.VerifiedMapping{}, netip.Addr{}, ErrInvalid
	}
	if _, err := manager.Acquire(ctx, generation, localPort); err != nil {
		return portmapping.VerifiedMapping{}, netip.Addr{}, err
	}
	trust, related := classifyPortMapping(m.backend.InterfaceState())
	if trust != portmapping.TrustPrivateLAN || !related.IsValid() {
		manager.NetworkChanged(generation)
		return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrUntrusted
	}
	verified, ok := manager.Verified(generation)
	if !ok || !verified.Valid() {
		return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrStale
	}
	return verified, related, nil
}

func (m *Monitor) Start() error {
	if m == nil || m.backend == nil || m.handle == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closed {
		return ErrInvalid
	}
	m.unregister = m.backend.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return
		}
		m.callbacks.Add(1)
		m.mu.Unlock()
		defer m.callbacks.Done()
		event, ok := m.translate(delta)
		if ok {
			m.dispatch(event)
		}
	})
	m.started = true
	m.backend.Start()
	if m.dnsSource != nil {
		dnsCtx, cancel := context.WithCancel(context.Background())
		m.dnsCancel = cancel
		m.dnsDone = make(chan struct{})
		done := m.dnsDone
		interval := m.dnsPollInterval
		go m.runDNS(dnsCtx, interval, done)
	}
	return nil
}

func (m *Monitor) runDNS(ctx context.Context, interval time.Duration, done chan struct{}) {
	defer close(done)
	// Establish a baseline without publishing a synthetic network change.
	_, _ = m.CheckDNS(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = m.CheckDNS(ctx)
		}
	}
}

// CheckDNS performs one deterministic DNS fingerprint sample. It is exported
// for platform adapters and tests that already own their polling/debounce
// loop. A changed fingerprint consumes one monotonic network generation and
// emits exactly one DNS-only event.
func (m *Monitor) CheckDNS(ctx context.Context) (bool, error) {
	if m == nil || ctx == nil {
		return false, ErrInvalid
	}
	m.mu.Lock()
	if m.closed || m.dnsSource == nil {
		m.mu.Unlock()
		return false, ErrInvalid
	}
	source := m.dnsSource
	m.mu.Unlock()
	fingerprint, err := source(ctx)
	if err != nil {
		return false, err
	}
	if fingerprint == [32]byte{} {
		return false, ErrInvalid
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, ErrInvalid
	}
	if !m.dnsFingerprintSet {
		m.dnsFingerprint = fingerprint
		m.dnsFingerprintSet = true
		m.mu.Unlock()
		return false, nil
	}
	if m.dnsFingerprint == fingerprint {
		m.mu.Unlock()
		return false, nil
	}
	m.dnsFingerprint = fingerprint
	m.mu.Unlock()
	generation, ok := m.nextGeneration()
	if !ok {
		return false, ErrInvalid
	}
	m.dispatch(Event{Generation: generation, Reasons: ReasonDNS, Rebind: true, Viable: true})
	return true, nil
}

func (m *Monitor) dispatch(event Event) {
	if m == nil {
		return
	}
	if event.Rebind {
		m.mu.Lock()
		m.mappingUnavailableGeneration = 0
		manager := m.mappingManager
		m.mu.Unlock()
		if manager != nil {
			manager.NetworkChanged(event.Generation)
		}
	}
	if m.handle != nil {
		m.handle(event)
	}
}

func (m *Monitor) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	unregister := m.unregister
	m.unregister = nil
	mappingManager := m.mappingManager
	m.mappingManager = nil
	mappingCreateDone := m.mappingCreateDone
	dnsCancel, dnsDone := m.dnsCancel, m.dnsDone
	m.dnsCancel, m.dnsDone = nil, nil
	mappers := make([]*portMapper, 0, len(m.portMappers))
	for mapper := range m.portMappers {
		mappers = append(mappers, mapper)
	}
	m.mu.Unlock()
	if dnsCancel != nil {
		dnsCancel()
	}
	if dnsDone != nil {
		<-dnsDone
	}
	if mappingCreateDone != nil {
		<-mappingCreateDone
	}
	if mappingManager != nil {
		_ = mappingManager.Close()
	}
	for _, mapper := range mappers {
		_ = mapper.Close()
	}
	if unregister != nil {
		unregister()
	}
	if m.backend == nil {
		m.callbacks.Wait()
		m.clearFingerprintSecret()
		return nil
	}
	err := m.backend.Close()
	m.callbacks.Wait()
	m.clearFingerprintSecret()
	return err
}

func (m *Monitor) translate(delta *netmon.ChangeDelta) (Event, bool) {
	if delta == nil || delta.CurrentState() == nil || delta.IsInitialState {
		return Event{}, false
	}
	state := delta.CurrentState()
	event := Event{
		Rebind: delta.RebindLikelyRequired,
		IPv4:   state.HaveV4,
		IPv6:   state.HaveV6,
		Viable: delta.DefaultInterfaceMaybeViable,
	}
	if delta.DefaultInterfaceChanged {
		event.Reasons |= ReasonDefaultRoute
	}
	if delta.InterfaceIPsChanged {
		event.Reasons |= ReasonInterfaceAddress
	}
	if delta.AvailableProtocolsChanged {
		event.Reasons |= ReasonAddressFamily
	}
	if delta.HasPACOrProxyConfigChanged {
		event.Reasons |= ReasonProxy
	}
	if delta.IsLessExpensive {
		event.Reasons |= ReasonNetworkCost
	}
	if !delta.DefaultInterfaceMaybeViable {
		event.Reasons |= ReasonViability
	}
	if delta.TimeJumped() {
		event.Reasons |= ReasonWake
	}
	if event.Reasons == 0 {
		return Event{}, false
	}
	generation, ok := m.nextGeneration()
	if !ok {
		return Event{}, false
	}
	event.Generation = generation
	if fingerprint, err := m.fingerprint(state); err == nil {
		event.Fingerprint = fingerprint
		event.FingerprintValid = true
	}
	return event, true
}

func (m *Monitor) nextGeneration() (uint64, bool) {
	if m == nil {
		return 0, false
	}
	for {
		current := m.generation.Load()
		if current == math.MaxUint64 {
			return 0, false
		}
		if m.generation.CompareAndSwap(current, current+1) {
			return current + 1, true
		}
	}
}

// Generation returns the current network generation used to fence socket and
// mapping capabilities.
func (m *Monitor) Generation() uint64 {
	if m == nil {
		return 0
	}
	return m.generation.Load()
}

// CurrentFingerprint derives the current opaque network key without exposing
// the underlying interface snapshot.
func (m *Monitor) CurrentFingerprint() (networkadaptation.Fingerprint, error) {
	if m == nil || m.backend == nil {
		return networkadaptation.Fingerprint{}, ErrInvalid
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return networkadaptation.Fingerprint{}, ErrInvalid
	}
	return m.fingerprint(m.backend.InterfaceState())
}

func (m *Monitor) fingerprint(state *netmon.State) (networkadaptation.Fingerprint, error) {
	if m == nil {
		return networkadaptation.Fingerprint{}, ErrInvalid
	}
	m.mu.Lock()
	secret := append([]byte(nil), m.fingerprintSecret...)
	identitySource := m.networkIdentity
	m.mu.Unlock()
	defer clear(secret)
	if len(secret) < 32 {
		return networkadaptation.Fingerprint{}, ErrInvalid
	}
	identity := ""
	if identitySource != nil {
		identity = identitySource()
	}
	observation, err := fingerprintObservation(state, identity)
	if err != nil {
		return networkadaptation.Fingerprint{}, err
	}
	return networkadaptation.DeriveFingerprint(secret, observation)
}

func fingerprintObservation(state *netmon.State, identity string) (networkadaptation.NetworkObservation, error) {
	if state == nil || state.DefaultRouteInterface == "" {
		return networkadaptation.NetworkObservation{}, ErrInvalid
	}
	observation := networkadaptation.NetworkObservation{
		DefaultInterface: state.DefaultRouteInterface, NetworkIdentity: identity,
		IPv4: state.HaveV4, IPv6: state.HaveV6,
	}
	for name, item := range state.Interface {
		if item.Interface == nil || !item.IsUp() || item.IsLoopback() || paperboatInterface(name) {
			continue
		}
		kind := interfaceKind(name, state.IsExpensive && name == state.DefaultRouteInterface)
		prefixes := make([]netip.Prefix, 0, len(state.InterfaceIPs[name]))
		for _, prefix := range state.InterfaceIPs[name] {
			if !prefix.IsValid() || !prefix.Addr().IsValid() || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			prefixes = append(prefixes, prefix.Masked())
		}
		observation.Interfaces = append(observation.Interfaces, networkadaptation.Interface{Name: name, Kind: kind, Prefixes: prefixes})
		observation.VPN = observation.VPN || kind == networkadaptation.InterfaceVPN
	}
	if _, err := networkadaptation.DeriveFingerprint(make([]byte, 32), observation); err != nil {
		return networkadaptation.NetworkObservation{}, err
	}
	return observation, nil
}

func interfaceKind(name string, expensive bool) networkadaptation.InterfaceKind {
	if expensive {
		return networkadaptation.InterfaceCellular
	}
	lower := strings.ToLower(name)
	for _, prefix := range []string{"utun", "tun", "tap", "wg", "wireguard", "tailscale", "ppp", "ipsec"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"-") || strings.HasPrefix(lower, prefix) {
			return networkadaptation.InterfaceVPN
		}
	}
	return networkadaptation.InterfacePhysical
}

func (m *Monitor) clearFingerprintSecret() {
	m.mu.Lock()
	clear(m.fingerprintSecret)
	m.fingerprintSecret = nil
	m.networkIdentity = nil
	m.mu.Unlock()
}

func paperboatInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "paperboat" || name == "pprbt" || strings.HasPrefix(name, "paperboat-") || strings.HasPrefix(name, "pprbt-") || strings.HasPrefix(name, "pb-")
}
