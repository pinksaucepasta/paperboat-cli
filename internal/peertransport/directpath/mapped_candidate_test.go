package directpath

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pion/ice/v4"
)

type mappedBackend struct {
	external netip.AddrPort
	port     uint16
}

func (b *mappedBackend) SetLocalPort(port uint16)        { b.port = port }
func (b *mappedBackend) Probe(context.Context) error     { return nil }
func (b *mappedBackend) Mapping() (netip.AddrPort, bool) { return b.external, true }
func (b *mappedBackend) Protocol() string                { return "pcp" }
func (b *mappedBackend) NetworkDown()                    {}
func (b *mappedBackend) Close() error                    { return nil }

type reachableMapping struct{}

func (reachableMapping) VerifyMapping(context.Context, netip.AddrPort, uint16) error { return nil }
func privateLANTrust() portmapping.InterfaceTrust                                    { return portmapping.TrustPrivateLAN }

func TestVerifiedMappedCandidateCarriesICEChecksInBothRoles(t *testing.T) {
	address, ok := privateTestIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 address available")
	}
	for _, changedPort := range []bool{false, true} {
		for _, mappedRole := range []iceagent.Role{iceagent.RoleControlling, iceagent.RoleControlled} {
			name := "same-port/" + roleName(mappedRole)
			if changedPort {
				name = "changed-port/" + roleName(mappedRole)
			}
			t.Run(name, func(t *testing.T) {
				testMappedCandidateRole(t, address, mappedRole, changedPort)
			})
		}
	}
}

func TestInvalidatedMappingIsNotSignaled(t *testing.T) {
	address, ok := privateTestIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 address available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assembly, err := Open(ctx, assemblyConfig("stale-mapping", "stale-password-123456789012345678901", make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Close()
	backend := &mappedBackend{external: netip.AddrPortFrom(address, assembly.Port())}
	manager, err := portmapping.New(portmapping.Config{
		Backend: backend, Verifier: reachableMapping{}, Trust: privateLANTrust,
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Acquire(ctx, 1, assembly.Port()); err != nil {
		t.Fatal(err)
	}
	verified, ok := manager.Verified(1)
	if !ok {
		t.Fatal("verified mapping not issued")
	}
	if err := assembly.ConfigureVerifiedMapping(verified, address); err != nil {
		t.Fatal(err)
	}
	manager.NetworkChanged(2)
	for _, raw := range gather(t, ctx, assembly) {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Type() == ice.CandidateTypeServerReflexive && candidate.Address() == address.String() {
			t.Fatalf("invalidated mapping signaled: %s", raw)
		}
	}
}

func TestMappingInvalidationAfterGatherRequiresReplacement(t *testing.T) {
	address, ok := privateTestIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 address available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assembly, err := Open(ctx, assemblyConfig("replace-mapping", "replace-password-1234567890123456789", make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Close()
	manager := mappedManager(t, assembly.Port(), netip.AddrPortFrom(address, assembly.Port()))
	defer manager.Close()
	if _, err := manager.Acquire(ctx, 1, assembly.Port()); err != nil {
		t.Fatal(err)
	}
	verified, _ := manager.Verified(1)
	if err := assembly.ConfigureVerifiedMapping(verified, address); err != nil {
		t.Fatal(err)
	}
	_ = gather(t, ctx, assembly)
	manager.NetworkChanged(2)
	select {
	case reason := <-assembly.ReplacementRequired():
		if !errors.Is(reason, ErrMappingInvalidated) {
			t.Fatalf("replacement reason=%v", reason)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitAssemblyClosed(t, assembly)
}

func TestNetworkChangeClosesSocketGenerationExactlyOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assembly, err := Open(ctx, assemblyConfig("network-change", "network-password-1234567890123456789", make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Close()
	if assembly.NetworkChanged(1) {
		t.Fatal("current generation replaced")
	}
	if !assembly.NetworkChanged(2) || assembly.NetworkChanged(2) {
		t.Fatal("network generation was not fenced exactly once")
	}
	select {
	case reason := <-assembly.ReplacementRequired():
		if !errors.Is(reason, ErrNetworkChanged) {
			t.Fatalf("replacement reason=%v", reason)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitAssemblyClosed(t, assembly)
}

func mappedManager(t *testing.T, localPort uint16, external netip.AddrPort) *portmapping.Manager {
	t.Helper()
	manager, err := portmapping.New(portmapping.Config{
		Backend: &mappedBackend{external: external}, Verifier: reachableMapping{}, Trust: privateLANTrust,
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func waitAssemblyClosed(t *testing.T, assembly *Assembly) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for assembly.Port() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if assembly.Port() != 0 {
		t.Fatal("replaced assembly retained its UDP socket")
	}
}

func testMappedCandidateRole(t *testing.T, address netip.Addr, mappedRole iceagent.Role, changedPort bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := make([]byte, 32)
	mappedConfig := assemblyConfig("mapped-side", "mapped-password-123456789012345678901", key)
	peerConfig := assemblyConfig("peer-side", "peer-password-12345678901234567890123", key)
	mapped, err := Open(ctx, mappedConfig)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Open(ctx, peerConfig)
	if err != nil {
		_ = mapped.Close()
		t.Fatal(err)
	}
	defer peer.Close()
	defer mapped.Close()
	external := netip.AddrPortFrom(address, mapped.Port())
	var forwarder *mappingForwarder
	if changedPort {
		forwarder = newMappingForwarder(t, address, external)
		defer forwarder.Close()
		external = forwarder.External()
		if external.Port() == mapped.Port() {
			t.Fatal("mapping fixture did not change the external port")
		}
	}
	backend := &mappedBackend{external: external}
	manager, err := portmapping.New(portmapping.Config{
		Backend: backend, Verifier: reachableMapping{}, Trust: privateLANTrust,
		ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Acquire(ctx, 1, mapped.Port()); err != nil {
		t.Fatal(err)
	}
	verified, ok := manager.Verified(1)
	if !ok {
		t.Fatal("verified mapping not issued")
	}
	if err := mapped.ConfigureVerifiedMapping(verified, address); err != nil {
		t.Fatal(err)
	}
	mappedCandidates := gather(t, ctx, mapped)
	peerCandidates := gather(t, ctx, peer)
	var signaledMapped []string
	for _, raw := range mappedCandidates {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Type() == ice.CandidateTypeServerReflexive {
			signaledMapped = append(signaledMapped, raw)
			if candidate.Address() != address.String() || candidate.Port() != int(external.Port()) || candidate.RelatedAddress() == nil || candidate.RelatedAddress().Port != int(mapped.Port()) {
				t.Fatalf("mapped candidate=%s", raw)
			}
		}
	}
	if len(signaledMapped) != 1 {
		t.Fatalf("mapped candidates=%v", signaledMapped)
	}
	for _, raw := range signaledMapped {
		if err := peer.AddRemoteCandidate(raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range peerCandidates {
		if err := mapped.AddRemoteCandidate(raw); err != nil {
			t.Fatal(err)
		}
	}

	type outcome struct {
		connection net.Conn
		err        error
	}
	mappedResult := make(chan outcome, 1)
	peerResult := make(chan outcome, 1)
	go func() {
		connection, err := mapped.Connect(ctx, mappedRole, peerConfig.ICE.LocalUfrag, peerConfig.ICE.LocalPwd)
		mappedResult <- outcome{connection, err}
	}()
	peerRole := iceagent.RoleControlled
	if mappedRole == iceagent.RoleControlled {
		peerRole = iceagent.RoleControlling
	}
	go func() {
		connection, err := peer.Connect(ctx, peerRole, mappedConfig.ICE.LocalUfrag, mappedConfig.ICE.LocalPwd)
		peerResult <- outcome{connection, err}
	}()
	mappedOutcome, peerOutcome := <-mappedResult, <-peerResult
	if mappedOutcome.err != nil || peerOutcome.err != nil {
		t.Fatalf("mapped error=%v peer error=%v", mappedOutcome.err, peerOutcome.err)
	}
	defer mappedOutcome.connection.Close()
	defer peerOutcome.connection.Close()
	payload := []byte("verified-mapped-candidate")
	if _, err := peerOutcome.connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := mappedOutcome.connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := mappedOutcome.connection.Read(received); err != nil {
		t.Fatal(err)
	}
}

type mappingForwarder struct {
	connection *net.UDPConn
	target     netip.AddrPort
	done       chan struct{}
}

func newMappingForwarder(t *testing.T, address netip.Addr, target netip.AddrPort) *mappingForwarder {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatal(err)
	}
	forwarder := &mappingForwarder{connection: connection, target: target, done: make(chan struct{})}
	go forwarder.run()
	return forwarder
}

func (f *mappingForwarder) External() netip.AddrPort {
	return f.connection.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *mappingForwarder) Close() {
	_ = f.connection.Close()
	<-f.done
}

func (f *mappingForwarder) run() {
	defer close(f.done)
	buffer := make([]byte, 65535)
	var peer netip.AddrPort
	for {
		count, source, err := f.connection.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		sourcePort := source.AddrPort()
		destination := f.target
		if sourcePort == f.target {
			if !peer.IsValid() {
				continue
			}
			destination = peer
		} else {
			peer = sourcePort
		}
		if _, err := f.connection.WriteToUDPAddrPort(buffer[:count], destination); err != nil && !errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

func privateTestIPv4() (netip.Addr, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := item.Addrs()
		if err != nil {
			continue
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
				return prefix.Addr(), true
			}
		}
	}
	return netip.Addr{}, false
}

func roleName(role iceagent.Role) string {
	if role == iceagent.RoleControlling {
		return "mapped-controlling"
	}
	return "mapped-controlled"
}
