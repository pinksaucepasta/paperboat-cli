//go:build darwin || linux || windows

package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
)

type networkObserver interface {
	Start() error
	Close() error
}

func (s *networkChangeService) ConfigurePortMapping(verifier portmapping.SocketVerifier) error {
	monitor, ok := s.observer.(*networkmonitor.Monitor)
	if !ok || verifier == nil {
		return ErrProductionInvalid
	}
	_, err := monitor.NewPortMappingManager(networkmonitor.PortMappingConfig{SocketVerifier: verifier, ProbeTimeout: 500 * time.Millisecond, CreateTimeout: 3 * time.Second, EnableUPnP: true})
	return err
}

func (s *networkChangeService) AcquireSocketMapping(ctx context.Context, generation uint64, localPort uint16, connection net.PacketConn, stunURLs []string) (portmapping.VerifiedMapping, netip.Addr, error) {
	monitor, ok := s.observer.(*networkmonitor.Monitor)
	if !ok {
		return portmapping.VerifiedMapping{}, netip.Addr{}, ErrProductionInvalid
	}
	return monitor.AcquireSocketMapping(ctx, generation, localPort, connection, stunURLs)
}

func (s *networkChangeService) WarmSocketMapping(ctx context.Context, generation uint64, stunURL string) error {
	monitor, ok := s.observer.(*networkmonitor.Monitor)
	if !ok {
		return ErrProductionInvalid
	}
	return monitor.WarmSocketMapping(ctx, generation, stunURL)
}

func (s *networkChangeService) Generation() uint64 {
	monitor, ok := s.observer.(*networkmonitor.Monitor)
	if !ok {
		return 0
	}
	return monitor.Generation()
}

type networkChangeService struct {
	observer networkObserver
	mu       sync.Mutex
	started  bool
	closed   bool
}

type connectorNetworkRecovery interface{ NetworkChanged() }
type directNetworkRecovery interface{ NetworkChanged(uint64) bool }

type directNetworkProxy struct {
	mu     sync.RWMutex
	target directNetworkRecovery
}

func (p *directNetworkProxy) Set(target directNetworkRecovery) {
	p.mu.Lock()
	p.target = target
	p.mu.Unlock()
}

func (p *directNetworkProxy) NetworkChanged(generation uint64) bool {
	p.mu.RLock()
	target := p.target
	p.mu.RUnlock()
	return target != nil && target.NetworkChanged(generation)
}

type networkMetricRecorder interface {
	Record(string, float64, map[string]string) error
}

type networkChangeHandler struct {
	connector connectorNetworkRecovery
	direct    directNetworkRecovery
	metrics   networkMetricRecorder
	changed   func()
}

func (h *networkChangeHandler) SetObserver(observer func()) { h.changed = observer }

func newNetworkChangeHandler(connector connectorNetworkRecovery, direct directNetworkRecovery, metrics networkMetricRecorder) (*networkChangeHandler, error) {
	if connector == nil || metrics == nil {
		return nil, ErrProductionInvalid
	}
	return &networkChangeHandler{connector: connector, direct: direct, metrics: metrics}, nil
}

func (h *networkChangeHandler) Handle(event networkmonitor.Event) {
	if h == nil || h.connector == nil || h.metrics == nil || event.Generation == 0 {
		return
	}
	h.record(event)
	if h.changed != nil {
		h.changed()
	}
	if !event.Rebind {
		return
	}
	// Fence and retire the socket-bound direct attempt before requesting a
	// replacement connector admission for the new network.
	if h.direct != nil {
		h.direct.NetworkChanged(event.Generation)
	}
	h.connector.NetworkChanged()
}

func (h *networkChangeHandler) record(event networkmonitor.Event) {
	_ = h.metrics.Record("paperboat_runtime_network_generation", float64(event.Generation), nil)
	action := "observe"
	if event.Rebind {
		action = "rebind"
	}
	for _, item := range [...]struct {
		reason networkmonitor.Reason
		label  string
	}{
		{networkmonitor.ReasonDefaultRoute, "default_route"},
		{networkmonitor.ReasonInterfaceAddress, "interface_address"},
		{networkmonitor.ReasonAddressFamily, "address_family"},
		{networkmonitor.ReasonProxy, "proxy"},
		{networkmonitor.ReasonNetworkCost, "network_cost"},
		{networkmonitor.ReasonViability, "viability"},
		{networkmonitor.ReasonWake, "wake"},
	} {
		if event.Reasons&item.reason != 0 {
			_ = h.metrics.Record("paperboat_runtime_network_changes_total", 1, map[string]string{"reason": item.label, "action": action})
		}
	}
}

func newNetworkChangeService(changed func(networkmonitor.Event)) (*networkChangeService, error) {
	if changed == nil {
		return nil, ErrProductionInvalid
	}
	observer, err := networkmonitor.New(changed)
	if err != nil {
		return nil, err
	}
	return &networkChangeService{observer: observer}, nil
}

func newFingerprintingNetworkChangeService(secret []byte, changed func(networkmonitor.Event)) (*networkChangeService, error) {
	if changed == nil || len(secret) < 32 {
		return nil, ErrProductionInvalid
	}
	observer, err := networkmonitor.NewFingerprinting(secret, nil, changed)
	if err != nil {
		return nil, err
	}
	return &networkChangeService{observer: observer}, nil
}

func (s *networkChangeService) CurrentFingerprint() (networkadaptation.Fingerprint, error) {
	if s == nil || s.observer == nil {
		return networkadaptation.Fingerprint{}, ErrProductionInvalid
	}
	source, ok := s.observer.(interface {
		CurrentFingerprint() (networkadaptation.Fingerprint, error)
	})
	if !ok {
		return networkadaptation.Fingerprint{}, ErrProductionInvalid
	}
	return source.CurrentFingerprint()
}

func (s *networkChangeService) Start(context.Context) error {
	if s == nil || s.observer == nil {
		return ErrProductionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return ErrProductionInvalid
	}
	if err := s.observer.Start(); err != nil {
		return err
	}
	s.started = true
	return nil
}

func (s *networkChangeService) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	observer := s.observer
	s.mu.Unlock()
	if observer == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- observer.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
