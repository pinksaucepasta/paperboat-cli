package networkmonitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"tailscale.com/net/netmon"
)

func testDNSFingerprint(value string) [32]byte { return sha256.Sum256([]byte(value)) }

type fakeNetMonitor struct {
	mu       sync.Mutex
	change   netmon.ChangeFunc
	starts   int
	closes   int
	closeErr error
	state    *netmon.State
}

type acceptingMappingVerifier struct{}

func (acceptingMappingVerifier) VerifyMapping(context.Context, netip.AddrPort, uint16) error {
	return nil
}

type monitorMappingBackend struct {
	mu          sync.Mutex
	mapping     netip.AddrPort
	localPort   uint16
	networkDown int
	probes      int
}

func (b *monitorMappingBackend) Protocol() string { return "pcp" }

func (b *monitorMappingBackend) SetLocalPort(port uint16) {
	b.mu.Lock()
	b.localPort = port
	b.mu.Unlock()
}
func (b *monitorMappingBackend) Probe(context.Context) error {
	b.mu.Lock()
	b.probes++
	b.mu.Unlock()
	return nil
}
func (b *monitorMappingBackend) Mapping() (netip.AddrPort, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mapping, b.mapping.IsValid()
}
func (b *monitorMappingBackend) NetworkDown() {
	b.mu.Lock()
	b.networkDown++
	b.mapping = netip.AddrPort{}
	b.mu.Unlock()
}
func (*monitorMappingBackend) Close() error { return nil }

type rejectingSocketVerifier struct{}

func (rejectingSocketVerifier) VerifySocketMapping(context.Context, netip.AddrPort, uint16, net.PacketConn, []string) error {
	return errors.New("not externally reachable")
}

func (m *fakeNetMonitor) RegisterChangeCallback(change netmon.ChangeFunc) func() {
	m.mu.Lock()
	m.change = change
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		m.change = nil
		m.mu.Unlock()
	}
}
func (m *fakeNetMonitor) InterfaceState() *netmon.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}
func (m *fakeNetMonitor) Start() { m.mu.Lock(); m.starts++; m.mu.Unlock() }
func (m *fakeNetMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closes++
	return m.closeErr
}
func (m *fakeNetMonitor) emit(delta *netmon.ChangeDelta) {
	m.mu.Lock()
	change := m.change
	m.mu.Unlock()
	if change != nil {
		change(delta)
	}
}

func TestMonitorTranslatesBoundedRebindState(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 1)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	old := testState(false, true, "old0")
	current := testState(true, false, "new0")
	delta, err := netmon.NewChangeDelta(old, current, 11*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	delta.HasPACOrProxyConfigChanged = true
	delta.InterfaceIPsChanged = true
	delta.IsLessExpensive = true
	delta.RebindLikelyRequired = true
	backend.emit(delta)
	event := <-events
	want := ReasonDefaultRoute | ReasonInterfaceAddress | ReasonAddressFamily | ReasonProxy | ReasonNetworkCost | ReasonWake
	if event.Generation != 1 || event.Reasons&want != want || !event.Rebind || !event.IPv4 || event.IPv6 || !event.Viable {
		t.Fatalf("event=%+v want reasons=%b", event, want)
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	backend.emit(delta)
	select {
	case event := <-events:
		t.Fatalf("event after close: %+v", event)
	default:
	}
}

func TestMonitorSuppressesInitialAndEmptyDeltas(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 1)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	initial, _ := netmon.NewChangeDelta(nil, testState(true, true, "en0"), 0, true)
	backend.emit(initial)
	unchanged, _ := netmon.NewChangeDelta(testState(true, true, "en0"), testState(true, true, "en0"), 0, true)
	backend.emit(unchanged)
	if monitor.generation.Load() != 0 {
		t.Fatalf("suppressed deltas consumed generation %d", monitor.generation.Load())
	}
	select {
	case event := <-events:
		t.Fatalf("unexpected event: %+v", event)
	default:
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorGenerationExhaustionNeverPublishesZeroOrReuses(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 2)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	monitor.generation.Store(math.MaxUint64 - 1)
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	delta, _ := netmon.NewChangeDelta(testState(true, false, "old0"), testState(false, true, "new0"), 0, true)
	delta.InterfaceIPsChanged = true
	backend.emit(delta)
	if event := <-events; event.Generation != math.MaxUint64 {
		t.Fatalf("last generation=%d", event.Generation)
	}
	for range 2 {
		backend.emit(delta)
	}
	select {
	case event := <-events:
		t.Fatalf("event after generation exhaustion: %+v", event)
	default:
	}
	if monitor.generation.Load() != math.MaxUint64 {
		t.Fatalf("generation wrapped to %d", monitor.generation.Load())
	}
	_ = monitor.Close()
}

func TestMonitorReportsLossOfViabilityWithoutRequestingRebind(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 1)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	_ = monitor.Start()
	delta, _ := netmon.NewChangeDelta(testState(true, false, "en0"), testState(true, false, "en0"), 0, false)
	delta.DefaultInterfaceMaybeViable = false
	delta.RebindLikelyRequired = false
	backend.emit(delta)
	event := <-events
	if event.Reasons != ReasonViability || event.Rebind || event.Viable {
		t.Fatalf("event=%+v", event)
	}
	_ = monitor.Close()
}

func TestMonitorPublishesDNSOnlyFingerprintChanges(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 2)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	var mu sync.Mutex
	current := testDNSFingerprint("resolver-a")
	if err := monitor.ConfigureDNS(func(context.Context) ([32]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return current, nil
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if changed, err := monitor.CheckDNS(context.Background()); err != nil || changed {
		t.Fatalf("initial DNS sample changed=%t err=%v", changed, err)
	}
	if changed, err := monitor.CheckDNS(context.Background()); err != nil || changed {
		t.Fatalf("unchanged DNS sample changed=%t err=%v", changed, err)
	}
	mu.Lock()
	current = testDNSFingerprint("resolver-b")
	mu.Unlock()
	changed, err := monitor.CheckDNS(context.Background())
	if err != nil || !changed {
		t.Fatalf("changed DNS sample changed=%t err=%v", changed, err)
	}
	event := <-events
	if event.Generation != 1 || event.Reasons != ReasonDNS || !event.Rebind || !event.Viable {
		t.Fatalf("DNS event=%+v", event)
	}
	if changed, err := monitor.CheckDNS(context.Background()); err != nil || changed {
		t.Fatalf("repeated DNS sample changed=%t err=%v", changed, err)
	}
	select {
	case event := <-events:
		t.Fatalf("duplicate DNS event=%+v", event)
	default:
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorDNSFingerprintErrorsFailClosed(t *testing.T) {
	backend := &fakeNetMonitor{}
	events := make(chan Event, 1)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	wantErr := errors.New("resolver unavailable")
	if err := monitor.ConfigureDNS(func(context.Context) ([32]byte, error) {
		return [32]byte{}, wantErr
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	changed, err := monitor.CheckDNS(context.Background())
	if changed || !errors.Is(err, wantErr) {
		t.Fatalf("error sample changed=%t err=%v", changed, err)
	}
	if monitor.generation.Load() != 0 {
		t.Fatalf("DNS source error consumed generation=%d", monitor.generation.Load())
	}
	select {
	case event := <-events:
		t.Fatalf("source error emitted event=%+v", event)
	default:
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorDNSFingerprintShutdownCancelsSource(t *testing.T) {
	backend := &fakeNetMonitor{}
	started := make(chan struct{})
	monitor := newMonitor(backend, func(Event) {})
	if err := monitor.ConfigureDNS(func(ctx context.Context) ([32]byte, error) {
		close(started)
		<-ctx.Done()
		return [32]byte{}, ctx.Err()
	}, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS source was not started")
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorPublishesOpaqueStableFingerprintAndErasesSecret(t *testing.T) {
	state := testState(true, true, "en0")
	state.InterfaceIPs["en0"] = []netip.Prefix{netip.MustParsePrefix("192.0.2.44/24"), netip.MustParsePrefix("2001:db8::44/64")}
	backend := &fakeNetMonitor{state: state}
	events := make(chan Event, 1)
	monitor := newMonitor(backend, func(event Event) { events <- event })
	monitor.fingerprintSecret = bytes.Repeat([]byte{9}, 32)
	monitor.networkIdentity = func() string { return "wifi-network-identity" }
	first, err := monitor.CurrentFingerprint()
	if err != nil || first == [32]byte{} {
		t.Fatalf("fingerprint=%x error=%v", first, err)
	}
	second, err := monitor.CurrentFingerprint()
	if err != nil || second != first {
		t.Fatalf("second=%x first=%x error=%v", second, first, err)
	}
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	previous := testState(true, false, "old0")
	delta, _ := netmon.NewChangeDelta(previous, state, 0, true)
	delta.InterfaceIPsChanged = true
	delta.RebindLikelyRequired = true
	backend.emit(delta)
	event := <-events
	if !event.FingerprintValid || event.Fingerprint != first {
		t.Fatalf("event=%+v fingerprint=%x", event, first)
	}
	monitor.networkIdentity = func() string { return "another-network" }
	changed, err := monitor.CurrentFingerprint()
	if err != nil || changed == first {
		t.Fatalf("changed=%x first=%x error=%v", changed, first, err)
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if len(monitor.fingerprintSecret) != 0 || monitor.networkIdentity != nil {
		t.Fatal("fingerprint secret or identity source survived close")
	}
	if _, err := monitor.CurrentFingerprint(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("closed fingerprint error=%v", err)
	}
}

func TestFingerprintObservationClassifiesVPNAndCellularWithoutRawPublication(t *testing.T) {
	state := &netmon.State{
		Interface: map[string]netmon.Interface{
			"wwan0": {Interface: &net.Interface{Name: "wwan0", Flags: net.FlagUp}},
			"utun4": {Interface: &net.Interface{Name: "utun4", Flags: net.FlagUp}},
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"wwan0": {netip.MustParsePrefix("198.51.100.7/24")},
			"utun4": {netip.MustParsePrefix("10.0.0.8/24")},
		},
		HaveV4: true, DefaultRouteInterface: "wwan0", IsExpensive: true,
	}
	observation, err := fingerprintObservation(state, "carrier-network")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]networkadaptation.InterfaceKind{}
	for _, item := range observation.Interfaces {
		kinds[item.Name] = item.Kind
	}
	if kinds["wwan0"] != networkadaptation.InterfaceCellular || kinds["utun4"] != networkadaptation.InterfaceVPN || !observation.VPN {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestPaperboatInterfacePolicy(t *testing.T) {
	for _, name := range []string{"paperboat", "paperboat-ice0", "pprbt-0", "pb-peer0"} {
		if !paperboatInterface(name) {
			t.Fatalf("owned interface accepted: %q", name)
		}
	}
	for _, name := range []string{"en0", "eth0", "wlan0", "utun4", "tailscale0"} {
		if paperboatInterface(name) {
			t.Fatalf("external interface rejected: %q", name)
		}
	}
}

func TestMonitorOwnsPortMapperLifecycle(t *testing.T) {
	monitor, err := New(func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := monitor.newPortMapper(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	mapper.SetLocalPort(4242)
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mapper.Close(); err != nil {
		t.Fatalf("idempotent mapper close: %v", err)
	}
	monitor.mu.Lock()
	remaining := len(monitor.portMappers)
	monitor.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining mappers=%d", remaining)
	}
	if _, err := monitor.newPortMapper(false, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mapper after close err=%v", err)
	}
}

func TestMonitorOwnsSinglePortMappingManagerLifecycle(t *testing.T) {
	monitor, err := New(func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	config := PortMappingConfig{
		Verifier:     acceptingMappingVerifier{},
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	}
	manager, err := monitor.NewPortMappingManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := monitor.NewPortMappingManager(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second manager error=%v", err)
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Acquire(context.Background(), 1, 4242); !errors.Is(err, portmapping.ErrClosed) {
		t.Fatalf("closed manager error=%v", err)
	}
	monitor.mu.Lock()
	remaining := len(monitor.portMappers)
	monitor.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining mappers=%d", remaining)
	}
}

func TestMonitorCloseWaitsForConcurrentMappingManagerConstruction(t *testing.T) {
	monitor, err := New(func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	monitor.newMappingManager = func(config portmapping.Config, factory portmapping.BackendFactory) (*portmapping.Manager, error) {
		close(started)
		<-release
		return portmapping.NewManaged(config, factory)
	}
	created := make(chan error, 1)
	go func() {
		_, createErr := monitor.NewPortMappingManager(PortMappingConfig{
			Verifier: acceptingMappingVerifier{}, ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
		})
		created <- createErr
	}()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- monitor.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("close returned during construction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-created; !errors.Is(err, ErrInvalid) {
		t.Fatalf("construction error=%v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	monitor.mu.Lock()
	manager, creating, remaining := monitor.mappingManager, monitor.mappingCreating, len(monitor.portMappers)
	monitor.mu.Unlock()
	if manager != nil || creating || remaining != 0 {
		t.Fatalf("manager=%v creating=%v remaining=%d", manager, creating, remaining)
	}
}

func TestMonitorRebindInvalidatesMappingBeforeRuntimeHandler(t *testing.T) {
	backend := &monitorMappingBackend{mapping: netip.MustParseAddrPort("198.51.100.5:5443")}
	manager, err := portmapping.New(portmapping.Config{
		Backend: backend, Verifier: acceptingMappingVerifier{},
		Trust:        func() portmapping.InterfaceTrust { return portmapping.TrustPrivateLAN },
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Acquire(context.Background(), 1, 4242); err != nil {
		t.Fatal(err)
	}
	verified, ok := manager.Verified(1)
	if !ok {
		t.Fatal("verified mapping not issued")
	}
	var observed []bool
	monitor := newMonitor(&fakeNetMonitor{}, func(Event) { observed = append(observed, verified.Valid()) })
	monitor.mappingManager = manager
	monitor.dispatch(Event{Generation: 2})
	monitor.dispatch(Event{Generation: 3, Rebind: true})
	if len(observed) != 2 || !observed[0] || observed[1] {
		t.Fatalf("handler observations=%v", observed)
	}
	backend.mu.Lock()
	networkDown, localPort := backend.networkDown, backend.localPort
	backend.mu.Unlock()
	if networkDown != 1 || localPort != 4242 {
		t.Fatalf("network down=%d local port=%d", networkDown, localPort)
	}
	if state := manager.State(); state.Generation != 3 || state.Result != portmapping.ResultInvalidated {
		t.Fatalf("state=%+v", state)
	}
}

func TestMonitorAcquireMappingReturnsCurrentCapabilityAndRelatedPrivateAddress(t *testing.T) {
	state := &netmon.State{
		Interface: map[string]netmon.Interface{"en0": {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}}},
		InterfaceIPs: map[string][]netip.Prefix{"en0": {
			netip.MustParsePrefix("192.168.1.20/24"), netip.MustParsePrefix("10.0.0.9/24"),
		}},
		DefaultRouteInterface: "en0",
	}
	backend := &monitorMappingBackend{mapping: netip.MustParseAddrPort("198.51.100.5:5443")}
	monitor := newMonitor(&fakeNetMonitor{state: state}, func(Event) {})
	manager, err := portmapping.New(portmapping.Config{
		Backend: backend, Verifier: acceptingMappingVerifier{}, Trust: monitor.PortMappingTrust,
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	monitor.mappingManager = manager
	verified, related, err := monitor.AcquireMapping(context.Background(), 4, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || verified.Generation() != 4 || verified.LocalPort() != 4242 || related != netip.MustParseAddr("10.0.0.9") {
		t.Fatalf("verified=%+v related=%v", verified, related)
	}
}

func TestMonitorCachesNegativeSocketMappingForNetworkGeneration(t *testing.T) {
	state := &netmon.State{Interface: map[string]netmon.Interface{"en0": {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}}}, InterfaceIPs: map[string][]netip.Prefix{"en0": {netip.MustParsePrefix("192.168.1.20/24")}}, DefaultRouteInterface: "en0"}
	backend := &monitorMappingBackend{mapping: netip.MustParseAddrPort("198.51.100.5:5443")}
	monitor := newMonitor(&fakeNetMonitor{state: state}, func(Event) {})
	manager, err := portmapping.New(portmapping.Config{Backend: backend, SocketVerifier: rejectingSocketVerifier{}, Trust: monitor.PortMappingTrust, ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	monitor.mappingManager = manager
	for attempt := 0; attempt < 2; attempt++ {
		_, _, err = monitor.AcquireSocketMapping(context.Background(), 1, uint16(4242+attempt), &net.UDPConn{}, []string{"stun:example.test:3478"})
		if !errors.Is(err, portmapping.ErrUnreachable) && !errors.Is(err, portmapping.ErrUnavailable) {
			t.Fatalf("attempt=%d error=%v", attempt, err)
		}
	}
	backend.mu.Lock()
	probes := backend.probes
	backend.mu.Unlock()
	if probes != 1 {
		t.Fatalf("backend probes=%d", probes)
	}
	monitor.mu.Lock()
	if monitor.mappingUnavailableGeneration != 1 {
		t.Fatalf("unavailable generation=%d", monitor.mappingUnavailableGeneration)
	}
	monitor.mu.Unlock()
}

func TestPortMappingTrustFailsClosedOutsidePrivatePhysicalLAN(t *testing.T) {
	physical := func(name string, addresses ...string) *netmon.State {
		prefixes := make([]netip.Prefix, 0, len(addresses))
		for _, address := range addresses {
			prefixes = append(prefixes, netip.MustParsePrefix(address))
		}
		return &netmon.State{
			Interface:    map[string]netmon.Interface{name: {Interface: &net.Interface{Name: name, Flags: net.FlagUp}}},
			InterfaceIPs: map[string][]netip.Prefix{name: prefixes}, DefaultRouteInterface: name,
		}
	}
	tests := []struct {
		name  string
		state *netmon.State
		want  portmapping.InterfaceTrust
	}{
		{name: "private IPv4", state: physical("en0", "192.168.1.9/24"), want: portmapping.TrustPrivateLAN},
		{name: "public IPv4", state: physical("eth0", "203.0.113.9/24"), want: portmapping.TrustPublic},
		{name: "mixed addressing", state: physical("eth0", "10.0.0.9/24", "203.0.113.9/24"), want: portmapping.TrustPublic},
		{name: "VPN", state: physical("utun4", "10.0.0.9/24"), want: portmapping.TrustVPN},
		{name: "cellular", state: func() *netmon.State {
			state := physical("wwan0", "10.0.0.9/24")
			state.IsExpensive = true
			return state
		}(), want: portmapping.TrustCellular},
		{name: "IPv6 only", state: physical("en0", "fd00::9/64"), want: portmapping.TrustUntrusted},
		{name: "link local only", state: physical("en0", "169.254.1.9/16"), want: portmapping.TrustUntrusted},
		{name: "missing default route", state: &netmon.State{}, want: portmapping.TrustUntrusted},
		{name: "unknown default interface", state: &netmon.State{DefaultRouteInterface: "en0"}, want: portmapping.TrustUntrusted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyPortMappingTrust(test.state); got != test.want {
				t.Fatalf("trust=%d want=%d", got, test.want)
			}
		})
	}
}

func TestMonitorPortMappingTrustUsesCurrentStateAndRejectsClosedMonitor(t *testing.T) {
	backend := &fakeNetMonitor{state: &netmon.State{
		Interface:    map[string]netmon.Interface{"en0": {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}}},
		InterfaceIPs: map[string][]netip.Prefix{"en0": {netip.MustParsePrefix("10.0.0.4/24")}}, DefaultRouteInterface: "en0",
	}}
	monitor := newMonitor(backend, func(Event) {})
	if got := monitor.PortMappingTrust(); got != portmapping.TrustPrivateLAN {
		t.Fatalf("trust=%d", got)
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if got := monitor.PortMappingTrust(); got != portmapping.TrustUntrusted {
		t.Fatalf("closed trust=%d", got)
	}
}

func testState(v4, v6 bool, defaultInterface string) *netmon.State {
	item := netmon.Interface{Interface: &net.Interface{Name: defaultInterface, Flags: net.FlagUp}}
	return &netmon.State{
		Interface:             map[string]netmon.Interface{defaultInterface: item},
		InterfaceIPs:          map[string][]netip.Prefix{},
		HaveV4:                v4,
		HaveV6:                v6,
		DefaultRouteInterface: defaultInterface,
	}
}
