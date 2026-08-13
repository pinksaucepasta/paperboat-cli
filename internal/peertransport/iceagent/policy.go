// Package iceagent owns Paperboat's narrow Pion ICE boundary.
//
// Pion supports TURN, TCP, and mDNS for general WebRTC deployments. Paperboat
// deliberately does not expose those modes: direct transport is authenticated
// UDP ICE followed by native Paperboat QUIC.
package iceagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
)

var (
	ErrInvalidSTUNURL          = errors.New("invalid STUN URL")
	ErrTURNNotAllowed          = errors.New("TURN is not allowed")
	ErrTCPNotAllowed           = errors.New("TCP ICE is not allowed")
	ErrMDNSNotAllowed          = errors.New("mDNS ICE candidates are not allowed")
	ErrCandidateTypeNotAllowed = errors.New("ICE candidate type is not allowed")
	ErrCandidateLimit          = errors.New("ICE candidate limit exceeded")
	ErrConnectionFailed        = errors.New("ICE connectivity checks failed")
	ErrConnectionClosed        = errors.New("ICE agent closed before connection")
)

const (
	MaximumCandidates     = 64
	MaximumCandidateBytes = 2048
)

type Role uint8

const (
	RoleControlling Role = iota + 1
	RoleControlled
)

// Config is the complete Paperboat-owned ICE policy. Credentials and STUN URLs
// are short-lived values supplied by the authenticated signaling exchange.
type Config struct {
	STUNURLs   []string
	LocalUfrag string
	LocalPwd   string
	ProbeOnly  bool
}

// OwnedMuxConfig transfers ownership of the supplied wildcard UDP sockets to
// the returned Agent. Both sockets, when supplied, must use the same port.
// The sockets are normally networkadaptation.SharedPacketConn values so ICE
// and authenticated PMTU probing share one reader and descriptor.
type OwnedMuxConfig struct {
	IPv4 net.PacketConn
	IPv6 net.PacketConn
}

// Agent owns one Pion agent. Gathering is single-use, matching one signaling
// attempt generation; an ICE restart creates a replacement Agent.
type Agent struct {
	inner        *ice.Agent
	mux          *ownedUniversalUDPMux
	sharedMux    *SharedUDPMux
	ownedSockets OwnedMuxConfig
	ownedPort    uint16
	mapped       *MappedCandidate

	gatherMu sync.Mutex
	gathered bool
	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

// SharedUDPMux is a daemon-owned Pion mux. Individual ICE agents borrow it and
// remove only their ufrag on close; the substrate owner closes the physical
// sockets on network replacement or daemon shutdown.
type SharedUDPMux struct {
	mux       *ownedUniversalUDPMux
	port      uint16
	closeOnce sync.Once
	closeErr  error
}

func NewSharedUDPMux(ipv4, ipv6 net.PacketConn) (*SharedUDPMux, error) {
	sockets := OwnedMuxConfig{IPv4: ipv4, IPv6: ipv6}
	if err := validateOwnedSockets(sockets); err != nil {
		return nil, err
	}
	stdNetwork, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("create ICE network: %w", err)
	}
	muxes := make([]ice.UniversalUDPMux, 0, 2)
	for _, socket := range []net.PacketConn{ipv4, ipv6} {
		if nilPacketConn(socket) {
			continue
		}
		muxes = append(muxes, ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: socket, Net: stdNetwork}))
	}
	port := uint16(0)
	if !nilPacketConn(ipv4) {
		port = uint16(ipv4.LocalAddr().(*net.UDPAddr).Port)
	} else {
		port = uint16(ipv6.LocalAddr().(*net.UDPAddr).Port)
	}
	return &SharedUDPMux{mux: newOwnedUniversalUDPMux(muxes), port: port}, nil
}

func (m *SharedUDPMux) Port() uint16 {
	if m == nil {
		return 0
	}
	return m.port
}

func (m *SharedUDPMux) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() { m.closeErr = m.mux.Close() })
	return m.closeErr
}

// MappedCandidate can only be constructed from a current externally verified
// router mapping. Pion's existing mux receives checks for this signaled
// address; no rewrite socket or second checklist is created.
type MappedCandidate struct {
	candidate  ice.Candidate
	localPort  uint16
	generation uint64
	mapping    portmapping.VerifiedMapping
}

func NewMappedCandidate(mapping portmapping.VerifiedMapping, related netip.Addr) (MappedCandidate, error) {
	external, localPort, generation, verified := mapping.Snapshot()
	if !verified || !related.IsValid() || !related.Is4() || related.IsUnspecified() || related.IsMulticast() {
		return MappedCandidate{}, errors.New("invalid verified mapped ICE candidate")
	}
	candidate, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network: "udp4", Address: external.Addr().String(), Port: int(external.Port()), Component: ice.ComponentRTP,
		RelAddr: related.String(), RelPort: int(localPort),
	})
	if err != nil {
		return MappedCandidate{}, fmt.Errorf("create verified mapped ICE candidate: %w", err)
	}
	if err := ValidateCandidate(candidate); err != nil {
		return MappedCandidate{}, err
	}
	return MappedCandidate{candidate: candidate, localPort: localPort, generation: generation, mapping: mapping}, nil
}

// ValidateSTUNURLs accepts only UDP stun: endpoints. TURN, STUNS, credentials,
// and explicit TCP transports are rejected before Pion sees them.
func ValidateSTUNURLs(raw []string) ([]*stun.URI, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	urls := make([]*stun.URI, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if strings.Contains(strings.ToLower(value), "transport=tcp") || strings.HasPrefix(strings.ToLower(value), "stuns:") {
			return nil, fmt.Errorf("%w: %s", ErrTCPNotAllowed, value)
		}
		u, err := stun.ParseURI(value)
		if err != nil || u.Host == "" || u.Scheme != stun.SchemeTypeSTUN {
			if u != nil && (u.Scheme == stun.SchemeTypeTURN || u.Scheme == stun.SchemeTypeTURNS) {
				return nil, fmt.Errorf("%w: %s", ErrTURNNotAllowed, value)
			}
			return nil, fmt.Errorf("%w: %s", ErrInvalidSTUNURL, value)
		}
		if u.Proto != stun.ProtoTypeUnknown && u.Proto != stun.ProtoTypeUDP {
			return nil, fmt.Errorf("%w: %s", ErrTCPNotAllowed, value)
		}
		if u.Username != "" || u.Password != "" {
			return nil, fmt.Errorf("%w: STUN credentials are not accepted in signaling URLs", ErrInvalidSTUNURL)
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// New creates a Pion agent with the exact candidate policy required by
// Paperboat. The returned agent still owns its UDP sockets and lifecycle.
func New(config Config) (*Agent, error) {
	return newAgent(config, nil)
}

// NewWithUDPMux creates an agent using already-owned UDP sockets. The agent
// closes the supplied sockets when it is closed, including on construction
// failure. This is the only production constructor that permits external
// socket ownership; deterministic vnet tests continue to use New/newAgent.
func NewWithUDPMux(config Config, sockets OwnedMuxConfig) (*Agent, error) {
	if err := validateOwnedSockets(sockets); err != nil {
		return nil, errors.Join(err, closeOwnedSockets(sockets))
	}
	stdNetwork, err := stdnet.NewNet()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create ICE network: %w", err), closeOwnedSockets(sockets))
	}
	muxes := make([]ice.UniversalUDPMux, 0, 2)
	for _, socket := range []net.PacketConn{sockets.IPv4, sockets.IPv6} {
		if nilPacketConn(socket) {
			continue
		}
		ready := make(chan struct{})
		mux := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: &constructorGatedPacketConn{PacketConn: socket, ready: ready}, Net: stdNetwork})
		close(ready)
		muxes = append(muxes, mux)
	}
	multi := newOwnedUniversalUDPMux(muxes)
	agent, err := newAgentWithOptions(config, []ice.AgentOption{ice.WithNet(stdNetwork), ice.WithUDPMux(multi), ice.WithUDPMuxSrflx(multi)})
	if err != nil {
		return nil, errors.Join(err, multi.Close(), closeOwnedSockets(sockets))
	}
	agent.mux = multi
	agent.ownedSockets = sockets
	if !nilPacketConn(sockets.IPv4) {
		agent.ownedPort = uint16(sockets.IPv4.LocalAddr().(*net.UDPAddr).Port)
	} else {
		agent.ownedPort = uint16(sockets.IPv6.LocalAddr().(*net.UDPAddr).Port)
	}
	return agent, nil
}

// NewWithSharedUDPMux creates an attempt-scoped ICE agent borrowing the
// daemon's mux. The caller must keep the mux alive until the agent is closed.
func NewWithSharedUDPMux(config Config, shared *SharedUDPMux) (*Agent, error) {
	if shared == nil || shared.mux == nil || shared.port == 0 {
		return nil, errors.New("shared UDP mux is required")
	}
	stdNetwork, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("create ICE network: %w", err)
	}
	agent, err := newAgentWithOptions(config, []ice.AgentOption{ice.WithNet(stdNetwork), ice.WithUDPMux(shared.mux), ice.WithUDPMuxSrflx(shared.mux)})
	if err != nil {
		return nil, err
	}
	agent.sharedMux = shared
	agent.ownedPort = shared.port
	return agent, nil
}

func (a *Agent) ConfigureMappedCandidate(candidate MappedCandidate) error {
	if a == nil || candidate.candidate == nil || candidate.localPort == 0 || candidate.generation == 0 {
		return errors.New("invalid verified mapped ICE candidate")
	}
	a.gatherMu.Lock()
	defer a.gatherMu.Unlock()
	if a.gathered {
		return errors.New("verified mapped ICE candidate configured after gathering started")
	}
	if a.ownedPort == 0 || candidate.localPort != a.ownedPort {
		return errors.New("verified mapping does not belong to the owned ICE socket")
	}
	if a.mapped != nil {
		if a.mapped.generation == candidate.generation && a.mapped.candidate.Marshal() == candidate.candidate.Marshal() {
			return nil
		}
		return errors.New("verified mapped ICE candidate already configured")
	}
	a.mapped = &candidate
	return nil
}

func newAgent(config Config, network transport.Net) (*Agent, error) {
	var options []ice.AgentOption
	if network != nil {
		options = append(options, ice.WithNet(network))
	}
	return newAgentWithOptions(config, options)
}

func newAgentWithOptions(config Config, extra []ice.AgentOption) (*Agent, error) {
	urls, err := ValidateSTUNURLs(config.STUNURLs)
	if err != nil {
		return nil, err
	}
	if config.LocalUfrag == "" || config.LocalPwd == "" {
		return nil, errors.New("ICE local credentials are required")
	}
	options := []ice.AgentOption{
		ice.WithUrls(urls),
		ice.WithLocalCredentials(config.LocalUfrag, config.LocalPwd),
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive}),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
		ice.WithDisableActiveTCP(),
		// Paperboat races direct against relay on a one-second budget. A valid
		// authenticated srflx or prflx pair must not wait for a host pair that
		// may be unroutable across NAT boundaries.
		ice.WithSrflxAcceptanceMinWait(0),
		ice.WithPrflxAcceptanceMinWait(0),
	}
	if config.ProbeOnly {
		// A mapping-lifetime probe must leave the nominated socket completely
		// idle. Normal sessions retain Pion's consent/keepalive behavior.
		options = append(options,
			ice.WithKeepaliveInterval(0),
			ice.WithDisconnectedTimeout(0),
			ice.WithFailedTimeout(0),
			ice.WithCheckInterval(200*time.Millisecond),
		)
	}
	options = append(options, extra...)
	inner, err := ice.NewAgentWithOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("create ICE agent: %w", err)
	}
	return &Agent{inner: inner}, nil
}

// ValidateCandidate enforces the same policy on candidates received from the
// authenticated peer. It is intentionally independent of Pion's parser so a
// future signaling implementation cannot accidentally widen the boundary.
func ValidateCandidate(candidate ice.Candidate) error {
	if candidate == nil {
		return errors.New("nil ICE candidate")
	}
	if candidate.NetworkType() != ice.NetworkTypeUDP4 && candidate.NetworkType() != ice.NetworkTypeUDP6 {
		return fmt.Errorf("%w: %s", ErrTCPNotAllowed, candidate.NetworkType())
	}
	switch candidate.Type() {
	case ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive:
	default:
		return fmt.Errorf("%w: %s", ErrCandidateTypeNotAllowed, candidate.Type())
	}
	if net.ParseIP(candidate.Address()) == nil {
		if strings.HasSuffix(strings.ToLower(candidate.Address()), ".local") {
			return fmt.Errorf("%w: %s", ErrMDNSNotAllowed, candidate.Address())
		}
		return errors.New("ICE candidate address is not an IP")
	}
	return nil
}

// ValidateCandidateString parses and validates one candidate without mutating
// an agent. Signaling uses this before admitting a message into its sequence.
func ValidateCandidateString(raw string) error {
	if len(raw) == 0 || len(raw) > MaximumCandidateBytes {
		return errors.New("invalid ICE candidate length")
	}
	candidate, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		return fmt.Errorf("parse ICE candidate: %w", err)
	}
	return ValidateCandidate(candidate)
}

// Gather emits the complete bounded local candidate set. The nil Pion
// callback terminates gathering; context cancellation closes the attempt.
func (a *Agent) Gather(ctx context.Context, emit func(string) error) error {
	if emit == nil {
		return errors.New("ICE candidate emitter is required")
	}
	a.gatherMu.Lock()
	if a.gathered {
		a.gatherMu.Unlock()
		return errors.New("ICE candidates already gathered")
	}
	a.gathered = true
	var mapped string
	if a.mapped != nil && a.mapped.mapping.Valid() {
		mapped = a.mapped.candidate.Marshal()
	}
	a.gatherMu.Unlock()

	candidates := make(chan ice.Candidate, MaximumCandidates+1)
	overflow := make(chan struct{}, 1)
	if err := a.inner.OnCandidate(func(candidate ice.Candidate) {
		select {
		case candidates <- candidate:
		default:
			select {
			case overflow <- struct{}{}:
			default:
			}
		}
	}); err != nil {
		return fmt.Errorf("register ICE candidate callback: %w", err)
	}
	if err := a.inner.GatherCandidates(); err != nil {
		return fmt.Errorf("gather ICE candidates: %w", err)
	}
	for count := 0; ; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-overflow:
			return ErrCandidateLimit
		case candidate := <-candidates:
			if candidate == nil {
				if mapped != "" {
					count++
					if count > MaximumCandidates {
						return ErrCandidateLimit
					}
					if err := emit(mapped); err != nil {
						return fmt.Errorf("emit verified mapped ICE candidate: %w", err)
					}
				}
				return nil
			}
			count++
			if count > MaximumCandidates {
				return ErrCandidateLimit
			}
			if err := ValidateCandidate(candidate); err != nil {
				return fmt.Errorf("gathered forbidden ICE candidate: %w", err)
			}
			if err := emit(candidate.Marshal()); err != nil {
				return fmt.Errorf("emit ICE candidate: %w", err)
			}
		}
	}
}

// AddRemoteCandidate is the only remote-candidate admission path.
func (a *Agent) AddRemoteCandidate(raw string) error {
	if err := ValidateCandidateString(raw); err != nil {
		return err
	}
	candidate, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		return fmt.Errorf("parse ICE candidate: %w", err)
	}
	if err := ValidateCandidate(candidate); err != nil {
		return err
	}
	if err := a.inner.AddRemoteCandidate(candidate); err != nil {
		return fmt.Errorf("add ICE candidate: %w", err)
	}
	return nil
}

// Connect runs the role-specific ICE checklist and returns the nominated UDP
// packet connection used by native Paperboat QUIC.
func (a *Agent) Connect(ctx context.Context, role Role, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	if ctx == nil || a == nil || a.inner == nil {
		return nil, errors.New("ICE agent is unavailable")
	}
	if remoteUfrag == "" || remotePwd == "" {
		return nil, errors.New("remote ICE credentials are required")
	}
	states := make(chan ice.ConnectionState, 1)
	if err := a.inner.OnConnectionStateChange(func(state ice.ConnectionState) {
		switch state {
		case ice.ConnectionStateFailed, ice.ConnectionStateClosed:
			select {
			case states <- state:
			default:
			}
		}
	}); err != nil {
		return nil, fmt.Errorf("observe ICE connection state: %w", err)
	}
	var conn *ice.Conn
	var err error
	switch role {
	case RoleControlling:
		conn, err = a.inner.StartDial(remoteUfrag, remotePwd)
	case RoleControlled:
		conn, err = a.inner.StartAccept(remoteUfrag, remotePwd)
	default:
		return nil, errors.New("invalid ICE role")
	}
	if err != nil {
		return nil, fmt.Errorf("start ICE connectivity checks: %w", err)
	}
	connected := make(chan error, 1)
	go func() { connected <- a.inner.AwaitConnect(ctx) }()
	select {
	case err = <-connected:
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("establish ICE connection: %w", err)
		}
		return conn, nil
	case state := <-states:
		// Pion's AwaitConnect does not return when its checklist transitions to
		// Failed. Stop the inner attempt loop here; the assembly owner performs
		// the wrapper's serialized mux/socket cleanup on the normal error path.
		closeErr := a.inner.Close()
		<-connected
		if state == ice.ConnectionStateFailed {
			return nil, errors.Join(ErrConnectionFailed, closeErr)
		}
		return nil, errors.Join(ErrConnectionClosed, closeErr)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SelectedCandidateTypes returns the nominated pair's bounded candidate types.
func (a *Agent) SelectedCandidateTypes() (string, string, error) {
	if a == nil || a.inner == nil {
		return "", "", errors.New("ICE agent is unavailable")
	}
	pair, err := a.inner.GetSelectedCandidatePair()
	if err != nil {
		return "", "", err
	}
	if pair == nil || pair.Local == nil || pair.Remote == nil {
		return "", "", errors.New("ICE candidate pair is not selected")
	}
	return pair.Local.Type().String(), pair.Remote.Type().String(), nil
}

func (a *Agent) Close() error {
	if a == nil {
		return nil
	}
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return a.closeErr
	}
	a.closed = true
	a.closeErr = a.inner.Close()
	if a.mux != nil {
		a.closeErr = errors.Join(a.closeErr, a.mux.Close())
	}
	a.closeErr = errors.Join(a.closeErr, closeOwnedSockets(a.ownedSockets))
	return a.closeErr
}

func validateOwnedSockets(sockets OwnedMuxConfig) error {
	if nilPacketConn(sockets.IPv4) && nilPacketConn(sockets.IPv6) {
		return errors.New("at least one owned UDP socket is required")
	}
	var port int
	for _, owned := range []struct {
		family string
		socket net.PacketConn
	}{{"IPv4", sockets.IPv4}, {"IPv6", sockets.IPv6}} {
		family, socket := owned.family, owned.socket
		if nilPacketConn(socket) {
			continue
		}
		address, ok := socket.LocalAddr().(*net.UDPAddr)
		if !ok || address == nil || address.Port < 1 || address.IP == nil || !address.IP.IsUnspecified() {
			return fmt.Errorf("%s owned socket must be a wildcard UDP socket", family)
		}
		is4 := address.IP.To4() != nil
		if (family == "IPv4" && !is4) || (family == "IPv6" && is4) {
			return fmt.Errorf("%s owned socket has the wrong address family", family)
		}
		if port == 0 {
			port = address.Port
		} else if port != address.Port {
			return errors.New("owned IPv4 and IPv6 sockets must share a port")
		}
	}
	return nil
}

func closeOwnedSockets(sockets OwnedMuxConfig) error {
	return errors.Join(closePacketConn(sockets.IPv4), closePacketConn(sockets.IPv6))
}

func closePacketConn(socket net.PacketConn) error {
	if nilPacketConn(socket) {
		return nil
	}
	err := socket.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func nilPacketConn(socket net.PacketConn) bool {
	if socket == nil {
		return true
	}
	value := reflect.ValueOf(socket)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
