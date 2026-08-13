package portmapping

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
)

var (
	ErrInvalid     = errors.New("invalid port mapping configuration")
	ErrUntrusted   = errors.New("port mapping forbidden on untrusted interface")
	ErrUnavailable = errors.New("port mapping unavailable")
	ErrUnreachable = errors.New("port mapping externally unreachable")
	ErrStale       = errors.New("stale port mapping generation")
	ErrClosed      = errors.New("port mapping manager closed")
	ErrExhausted   = errors.New("port mapping attempt generation exhausted")
)

type InterfaceTrust uint8

const (
	TrustPrivateLAN InterfaceTrust = iota + 1
	TrustPublic
	TrustVPN
	TrustCellular
	TrustUntrusted
)

type Backend interface {
	SetLocalPort(uint16)
	Probe(context.Context) error
	Mapping() (netip.AddrPort, bool)
	Protocol() string
	NetworkDown()
	Close() error
}

type Verifier interface {
	VerifyMapping(context.Context, netip.AddrPort, uint16) error
}

type SocketVerifier interface {
	VerifySocketMapping(context.Context, netip.AddrPort, uint16, net.PacketConn, []string) error
}

type Result uint8

const (
	ResultUnavailable Result = iota + 1
	ResultProbing
	ResultVerifying
	ResultVerified
	ResultInvalidated
)

type State struct {
	Generation uint64
	Result     Result
	Retryable  bool
}

// VerifiedMapping is issued only after the backend result passes the external
// reachability verifier and the attempt remains current.
type VerifiedMapping struct {
	external   netip.AddrPort
	localPort  uint16
	generation uint64
	protocol   string
	manager    *Manager
	done       <-chan struct{}
}

func (m VerifiedMapping) Valid() bool {
	_, _, _, ok := m.Snapshot()
	return ok
}

func (m VerifiedMapping) External() netip.AddrPort { return m.external }
func (m VerifiedMapping) LocalPort() uint16        { return m.localPort }
func (m VerifiedMapping) Generation() uint64       { return m.generation }
func (m VerifiedMapping) Protocol() string         { return m.protocol }

func (m VerifiedMapping) Snapshot() (netip.AddrPort, uint16, uint64, bool) {
	if m.manager == nil || !validExternal(m.external) || m.localPort == 0 || m.generation == 0 {
		return netip.AddrPort{}, 0, 0, false
	}
	m.manager.mu.Lock()
	defer m.manager.mu.Unlock()
	current := !m.manager.closed && m.manager.generation == m.generation && m.manager.state.Result == ResultVerified && m.manager.mapping == m.external && m.manager.protocol == m.protocol && m.manager.localPort == m.localPort && m.done != nil && m.done == m.manager.verifiedDone
	return m.external, m.localPort, m.generation, current
}

func (m VerifiedMapping) Invalidated() <-chan struct{} { return m.done }

type Config struct {
	Backend        Backend
	Verifier       Verifier
	SocketVerifier SocketVerifier
	Trust          func() InterfaceTrust
	ProbeTimeout   time.Duration
	CreateTimeout  time.Duration
	OnState        func(State)
}

type BackendFactory func(onChange func()) (Backend, error)

type Manager struct {
	config  Config
	changes chan struct{}

	backendMu    sync.Mutex
	mu           sync.Mutex
	generation   uint64
	nextAttempt  uint64
	attempt      uint64
	mapping      netip.AddrPort
	protocol     string
	localPort    uint16
	verifiedDone chan struct{}
	backendState chan struct{}
	state        State
	cancel       context.CancelFunc
	closed       bool
	exhausted    bool
}

func New(config Config) (*Manager, error) {
	if nilInterface(config.Backend) || nilInterface(config.Verifier) == nilInterface(config.SocketVerifier) || config.Trust == nil || config.ProbeTimeout <= 0 || config.CreateTimeout <= 0 || config.ProbeTimeout >= config.CreateTimeout {
		return nil, ErrInvalid
	}
	return &Manager{config: config, changes: make(chan struct{}, 1), backendState: make(chan struct{}), state: State{Result: ResultUnavailable}}, nil
}

// NewManaged constructs a backend whose asynchronous changes wake the manager.
// Config.Backend must be nil because the returned manager owns the created backend.
func NewManaged(config Config, factory BackendFactory) (*Manager, error) {
	if config.Backend != nil || factory == nil {
		return nil, ErrInvalid
	}
	var manager atomic.Pointer[Manager]
	backend, err := factory(func() {
		if current := manager.Load(); current != nil {
			current.Changed()
		}
	})
	if err != nil {
		return nil, err
	}
	config.Backend = backend
	created, err := New(config)
	if err != nil {
		if !nilInterface(backend) {
			_ = backend.Close()
		}
		return nil, err
	}
	manager.Store(created)
	return created, nil
}

// Changed wakes an acquisition waiting for an asynchronous backend mapping update.
func (m *Manager) Changed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if m.state.Result == ResultVerified {
		attempt, generation, external := m.attempt, m.generation, m.mapping
		m.mu.Unlock()
		m.backendMu.Lock()
		current, ok := m.config.Backend.Mapping()
		m.backendMu.Unlock()
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return
		}
		if m.state.Result == ResultVerified && m.attempt == attempt && m.generation == generation && m.mapping == external && ok && current == external {
			m.mu.Unlock()
			return
		}
	}
	var state State
	var callback func(State)
	m.backendState = make(chan struct{})
	if m.state.Result == ResultVerifying || m.state.Result == ResultVerified {
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.invalidateVerifiedLocked()
		m.attempt = 0
		state, callback = m.updateStateLocked(State{Generation: m.generation, Result: ResultInvalidated, Retryable: true})
	}
	m.mu.Unlock()
	notify(callback, state)
	select {
	case m.changes <- struct{}{}:
	default:
	}
}

func (m *Manager) Acquire(ctx context.Context, generation uint64, localPort uint16) (netip.AddrPort, error) {
	return m.acquire(ctx, generation, localPort, nil, nil)
}

func (m *Manager) AcquireSocket(ctx context.Context, generation uint64, localPort uint16, connection net.PacketConn, stunURLs []string) (netip.AddrPort, error) {
	if m == nil || nilInterface(m.config.SocketVerifier) || connection == nil || len(stunURLs) == 0 {
		return netip.AddrPort{}, ErrInvalid
	}
	return m.acquire(ctx, generation, localPort, connection, append([]string(nil), stunURLs...))
}

func (m *Manager) acquire(ctx context.Context, generation uint64, localPort uint16, connection net.PacketConn, stunURLs []string) (netip.AddrPort, error) {
	if m == nil || ctx == nil || generation == 0 || localPort == 0 {
		return netip.AddrPort{}, ErrInvalid
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return netip.AddrPort{}, ErrClosed
	}
	trust := m.config.Trust()
	if trust != TrustPrivateLAN {
		m.networkChanged(generation, trust)
		return netip.AddrPort{}, ErrUntrusted
	}

	attemptCtx, cancel := context.WithTimeout(ctx, m.config.CreateTimeout)
	started := time.Now()
	timing := map[string]int64{}
	mark := func(name string) { timing[name] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer port mapping timing", "network_generation", generation, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		return netip.AddrPort{}, ErrClosed
	}
	if generation < m.generation {
		m.mu.Unlock()
		cancel()
		return netip.AddrPort{}, ErrStale
	}
	if m.exhausted || m.nextAttempt == math.MaxUint64 {
		m.exhausted = true
		m.mu.Unlock()
		cancel()
		return netip.AddrPort{}, ErrExhausted
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.nextAttempt++
	attempt := m.nextAttempt
	m.attempt = attempt
	m.cancel = cancel
	m.generation = generation
	m.localPort = localPort
	m.invalidateVerifiedLocked()
	state, callback := m.updateStateLocked(State{Generation: generation, Result: ResultProbing, Retryable: true})
	m.mu.Unlock()
	notify(callback, state)
	defer m.finishAttempt(attempt, cancel)

	m.backendMu.Lock()
	defer m.backendMu.Unlock()
	if !m.current(attempt, generation) {
		return netip.AddrPort{}, m.inactiveError(attempt, generation)
	}

	m.config.Backend.SetLocalPort(localPort)
	probeCtx, probeCancel := context.WithTimeout(attemptCtx, m.config.ProbeTimeout)
	err := m.config.Backend.Probe(probeCtx)
	probeCancel()
	mark("backend_probe_ready")
	if err != nil {
		if !m.current(attempt, generation) {
			m.config.Backend.NetworkDown()
			return netip.AddrPort{}, m.inactiveError(attempt, generation)
		}
		m.fail(attempt, generation, true)
		m.config.Backend.NetworkDown()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return netip.AddrPort{}, ctxErr
		}
		return netip.AddrPort{}, errors.Join(ErrUnavailable, err)
	}

	for {
		if !m.current(attempt, generation) {
			m.config.Backend.NetworkDown()
			return netip.AddrPort{}, m.inactiveError(attempt, generation)
		}
		backendState := m.currentBackendState()
		external, ok := m.config.Backend.Mapping()
		if ok {
			mark("backend_mapping_ready")
			if !validExternal(external) {
				m.fail(attempt, generation, false)
				m.config.Backend.NetworkDown()
				return netip.AddrPort{}, ErrInvalid
			}
			if !m.setStateForBackend(attempt, generation, backendState, ResultVerifying, true) {
				m.config.Backend.NetworkDown()
				return netip.AddrPort{}, ErrStale
			}
			var verifyErr error
			if !nilInterface(m.config.SocketVerifier) {
				verifyErr = m.config.SocketVerifier.VerifySocketMapping(attemptCtx, external, localPort, connection, stunURLs)
			} else {
				verifyErr = m.config.Verifier.VerifyMapping(attemptCtx, external, localPort)
			}
			mark("mapping_verification_ready")
			if verifyErr != nil {
				if !m.current(attempt, generation) {
					m.config.Backend.NetworkDown()
					return netip.AddrPort{}, m.inactiveError(attempt, generation)
				}
				m.fail(attempt, generation, true)
				m.config.Backend.NetworkDown()
				if ctxErr := ctx.Err(); ctxErr != nil {
					return netip.AddrPort{}, ctxErr
				}
				return netip.AddrPort{}, errors.Join(ErrUnreachable, verifyErr)
			}
			if !m.publish(attempt, generation, backendState, external) {
				m.config.Backend.NetworkDown()
				return netip.AddrPort{}, m.inactiveError(attempt, generation)
			}
			mark("mapping_published")
			return external, nil
		}
		select {
		case <-attemptCtx.Done():
			if !m.current(attempt, generation) {
				m.config.Backend.NetworkDown()
				return netip.AddrPort{}, m.inactiveError(attempt, generation)
			}
			m.fail(attempt, generation, true)
			m.config.Backend.NetworkDown()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return netip.AddrPort{}, ctxErr
			}
			return netip.AddrPort{}, errors.Join(ErrUnavailable, attemptCtx.Err())
		case <-m.changes:
		}
	}
}

func (m *Manager) NetworkChanged(generation uint64) {
	if m == nil {
		return
	}
	m.networkChanged(generation, m.config.Trust())
}

func (m *Manager) networkChanged(generation uint64, trust InterfaceTrust) {
	if m == nil || generation == 0 {
		return
	}
	m.mu.Lock()
	if generation < m.generation || m.closed {
		m.mu.Unlock()
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel = nil
	m.attempt = 0
	m.generation = generation
	m.invalidateVerifiedLocked()
	state, callback := m.updateStateLocked(State{Generation: generation, Result: ResultInvalidated, Retryable: trust == TrustPrivateLAN})
	m.mu.Unlock()
	notify(callback, state)

	m.backendMu.Lock()
	m.mu.Lock()
	stillInvalidated := !m.closed && m.generation == generation && m.attempt == 0
	m.mu.Unlock()
	if stillInvalidated {
		m.config.Backend.NetworkDown()
	}
	m.backendMu.Unlock()
}

func (m *Manager) Mapping(generation uint64) (netip.AddrPort, bool) {
	if m == nil {
		return netip.AddrPort{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mapping, !m.closed && generation == m.generation && m.state.Result == ResultVerified && m.mapping.IsValid()
}

func (m *Manager) Verified(generation uint64) (VerifiedMapping, bool) {
	if m == nil {
		return VerifiedMapping{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || generation != m.generation || m.state.Result != ResultVerified || !m.mapping.IsValid() {
		return VerifiedMapping{}, false
	}
	verified := VerifiedMapping{external: m.mapping, localPort: m.localPort, generation: generation, protocol: m.protocol, manager: m, done: m.verifiedDone}
	return verified, true
}

func (m *Manager) State() State {
	if m == nil {
		return State{Result: ResultUnavailable}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.invalidateVerifiedLocked()
	m.attempt = 0
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel = nil
	state, callback := m.updateStateLocked(State{Generation: m.generation, Result: ResultInvalidated})
	m.mu.Unlock()
	notify(callback, state)

	m.backendMu.Lock()
	defer m.backendMu.Unlock()
	return m.config.Backend.Close()
}

func (m *Manager) current(attempt, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.attempt == attempt && m.generation == generation
}

func (m *Manager) inactiveError(attempt, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if m.attempt != attempt || m.generation != generation {
		return ErrStale
	}
	return ErrInvalid
}

func (m *Manager) finishAttempt(attempt uint64, cancel context.CancelFunc) {
	cancel()
	m.mu.Lock()
	if m.attempt == attempt {
		m.cancel = nil
	}
	m.mu.Unlock()
}

func (m *Manager) fail(attempt, generation uint64, retryable bool) {
	m.setState(attempt, generation, ResultUnavailable, retryable)
}

func (m *Manager) setState(attempt, generation uint64, result Result, retryable bool) bool {
	m.mu.Lock()
	if m.closed || m.attempt != attempt || m.generation != generation {
		m.mu.Unlock()
		return false
	}
	state, callback := m.updateStateLocked(State{Generation: generation, Result: result, Retryable: retryable})
	m.mu.Unlock()
	notify(callback, state)
	return true
}

func (m *Manager) setStateForBackend(attempt, generation uint64, backendState <-chan struct{}, result Result, retryable bool) bool {
	m.mu.Lock()
	if m.closed || m.attempt != attempt || m.generation != generation || backendState == nil {
		m.mu.Unlock()
		return false
	}
	if backendState != m.backendState {
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.attempt = 0
		m.invalidateVerifiedLocked()
		state, callback := m.updateStateLocked(State{Generation: generation, Result: ResultInvalidated, Retryable: true})
		m.mu.Unlock()
		notify(callback, state)
		return false
	}
	state, callback := m.updateStateLocked(State{Generation: generation, Result: result, Retryable: retryable})
	m.mu.Unlock()
	notify(callback, state)
	return true
}

func (m *Manager) currentBackendState() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backendState
}

func (m *Manager) publish(attempt, generation uint64, backendState <-chan struct{}, mapping netip.AddrPort) bool {
	protocol := m.config.Backend.Protocol()
	if !validProtocol(protocol) {
		return false
	}
	m.mu.Lock()
	if m.closed || m.attempt != attempt || m.generation != generation || backendState == nil || backendState != m.backendState {
		m.mu.Unlock()
		return false
	}
	m.invalidateVerifiedLocked()
	m.mapping = mapping
	m.protocol = protocol
	m.verifiedDone = make(chan struct{})
	state, callback := m.updateStateLocked(State{Generation: generation, Result: ResultVerified})
	m.mu.Unlock()
	notify(callback, state)
	return true
}

func (m *Manager) invalidateVerifiedLocked() {
	m.mapping = netip.AddrPort{}
	m.protocol = ""
	if m.verifiedDone != nil {
		close(m.verifiedDone)
		m.verifiedDone = nil
	}
}

func validProtocol(value string) bool {
	return value == "pcp" || value == "nat_pmp" || value == "upnp"
}

func (m *Manager) updateStateLocked(state State) (State, func(State)) {
	m.state = state
	return state, m.config.OnState
}

func notify(callback func(State), state State) {
	if callback != nil {
		callback(state)
	}
}

func validExternal(value netip.AddrPort) bool {
	return value.IsValid() && value.Port() != 0 && value.Addr().Is4() && !value.Addr().IsUnspecified() && !value.Addr().IsLoopback() && !value.Addr().IsMulticast()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
