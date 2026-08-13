package iceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4/vnet"
)

func TestVNetEndpointIndependentNATsNominatePaperboatUDP(t *testing.T) {
	leftNet, rightNet, closeTopology := newNATVNet(t,
		&vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent},
		&vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent},
	)
	defer closeTopology()
	leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-nat-ufrag", LocalPwd: "left-nat-password-1234567890123456789"}
	rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-nat-ufrag", LocalPwd: "right-nat-password-123456789012345678"}
	left, right := connectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, 5*time.Second)
	defer left.Close()
	defer right.Close()

	request := []byte("paperboat-nat-left-to-right")
	response := []byte("paperboat-nat-right-to-left")
	writeErrors := make(chan error, 1)
	go func() {
		_, err := left.Write(request)
		writeErrors <- err
	}()
	buffer := make([]byte, len(request))
	if _, err := io.ReadFull(right, buffer); err != nil || !bytes.Equal(buffer, request) {
		t.Fatalf("NAT request=%q error=%v", buffer, err)
	}
	if err := <-writeErrors; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := right.Write(response)
		writeErrors <- err
	}()
	buffer = make([]byte, len(response))
	if _, err := io.ReadFull(left, buffer); err != nil || !bytes.Equal(buffer, response) {
		t.Fatalf("NAT response=%q error=%v", buffer, err)
	}
	if err := <-writeErrors; err != nil {
		t.Fatal(err)
	}
	assertVNetNativeQUIC(t, left, right, []byte("paperboat-nat-native-quic"))
}

func TestVNetNATBehaviorMatrix(t *testing.T) {
	tests := []struct {
		name   string
		nat    vnet.NATType
		direct bool
	}{
		{"address-restricted-cone", vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointAddrDependent}, true},
		{"port-restricted-cone", vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointAddrPortDependent}, true},
		{"address-dependent-mapping", vnet.NATType{MappingBehavior: vnet.EndpointAddrDependent, FilteringBehavior: vnet.EndpointAddrDependent}, false},
		{"symmetric", vnet.NATType{MappingBehavior: vnet.EndpointAddrPortDependent, FilteringBehavior: vnet.EndpointAddrPortDependent}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leftNet, rightNet, closeTopology := newNATVNet(t, &test.nat, &test.nat)
			defer closeTopology()
			leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-" + test.name, LocalPwd: "left-password-123456789012345678901234"}
			rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-" + test.name, LocalPwd: "right-password-12345678901234567890123"}
			left, right, err := tryConnectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, 3*time.Second)
			if !test.direct {
				if err == nil {
					_ = left.Close()
					_ = right.Close()
					t.Fatal("destination-dependent NAT unexpectedly produced a direct path")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer left.Close()
			defer right.Close()
			assertVNetNativeQUIC(t, left, right, []byte("paperboat-"+test.name+"-quic"))
		})
	}
}

func TestVNetExpiredMappingsCannotProduceDirectSuccess(t *testing.T) {
	nat := &vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent, MappingLifeTime: 3 * time.Second}
	leftNet, rightNet, closeTopology := newNATVNet(t, nat, nat)
	defer closeTopology()
	leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-expired-mapping", LocalPwd: "left-expired-password-1234567890123456"}
	rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-expired-mapping", LocalPwd: "right-expired-password-123456789012345"}
	left, right, err := tryConnectVNetAgentsAfter(t, leftNet, rightNet, leftConfig, rightConfig, 7*time.Second, 3500*time.Millisecond)
	if !nilNetConn(left) {
		_ = left.Close()
	}
	if !nilNetConn(right) {
		_ = right.Close()
	}
	if err == nil {
		t.Fatal("expired server-reflexive mappings unexpectedly produced a direct path")
	}
}

func TestVNetDoubleNATNominationCarriesNativeQUIC(t *testing.T) {
	leftNet, rightNet, closeTopology := newDoubleNATVNet(t)
	defer closeTopology()
	leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-double-nat", LocalPwd: "left-double-nat-password-123456789012"}
	rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-double-nat", LocalPwd: "right-double-nat-password-12345678901"}
	left, right := connectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, 7*time.Second)
	defer left.Close()
	defer right.Close()
	assertVNetNativeQUIC(t, left, right, []byte("paperboat-double-nat-native-quic"))
}

func TestVNetDeterministicPacketLossCarriesNativeQUIC(t *testing.T) {
	var packets, dropped atomic.Uint64
	filter := func(vnet.Chunk) bool {
		sequence := packets.Add(1)
		if sequence%10 == 0 {
			dropped.Add(1)
			return false
		}
		return true
	}
	nat := &vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent}
	leftNet, rightNet, closeTopology := newNATVNetWithWANFilter(t, nat, nat, filter)
	defer closeTopology()
	leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-packet-loss", LocalPwd: "left-packet-loss-password-123456789012"}
	rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-packet-loss", LocalPwd: "right-packet-loss-password-12345678901"}
	left, right := connectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, 10*time.Second)
	defer left.Close()
	defer right.Close()
	assertVNetNativeQUIC(t, left, right, bytes.Repeat([]byte("paperboat-loss-"), 4096))
	if dropped.Load() == 0 || packets.Load() < 10 {
		t.Fatalf("impairment not exercised: packets=%d dropped=%d", packets.Load(), dropped.Load())
	}
}

func TestVNetDeterministicLatencyCarriesNativeQUIC(t *testing.T) {
	nat := &vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent}
	leftNet, rightNet, closeTopology := newNATVNetWithWANConfig(t, nat, nat, 20*time.Millisecond, 0, nil)
	defer closeTopology()
	leftConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "left-latency", LocalPwd: "left-latency-password-1234567890123456"}
	rightConfig := Config{STUNURLs: []string{"stun:1.2.3.4:3478"}, LocalUfrag: "right-latency", LocalPwd: "right-latency-password-123456789012345"}
	started := time.Now()
	left, right := connectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, 10*time.Second)
	defer left.Close()
	defer right.Close()
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("configured WAN latency was not exercised: elapsed=%s", elapsed)
	}
	assertVNetNativeQUIC(t, left, right, bytes.Repeat([]byte("paperboat-latency-"), 1024))
}

func assertVNetNativeQUIC(t *testing.T, left, right net.Conn, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientTLS, serverTLS := peerTLSConfigs(t)
	listener, err := peerquic.Listen(right, serverTLS, peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *peerquic.Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- session
	}()
	client, err := peerquic.Dial(ctx, left, clientTLS, peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	bindingContext := peercontext.Context{AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 1, AuthorizationGeneration: 1, IntentID: "intent_nat", OperationID: "operation_nat", Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 1}
	copy(bindingContext.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(bindingContext.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	clientBinding, err := peerquic.ExporterBinding(client.Connection.ConnectionState().TLS, bindingContext)
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := peerquic.ExporterBinding(server.Connection.ConnectionState().TLS, bindingContext)
	if err != nil || clientBinding != serverBinding {
		t.Fatalf("NAT QUIC exporter binding mismatch: %v", err)
	}
	stream, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := peerquic.SealFirstRecord(clientBinding, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(sealed); err != nil {
		t.Fatal(err)
	}
	remote, err := server.Connection.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(sealed))
	if _, err := io.ReadFull(remote, received); err != nil {
		t.Fatal(err)
	}
	opened, err := peerquic.OpenFirstRecord(serverBinding, received)
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("NAT QUIC payload=%q error=%v", opened, err)
	}
}

func connectVNetAgents(t *testing.T, leftNet, rightNet *vnet.Net, leftConfig, rightConfig Config, timeout time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	leftConn, rightConn, err := tryConnectVNetAgents(t, leftNet, rightNet, leftConfig, rightConfig, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return leftConn, rightConn
}

func tryConnectVNetAgents(t *testing.T, leftNet, rightNet *vnet.Net, leftConfig, rightConfig Config, timeout time.Duration) (net.Conn, net.Conn, error) {
	return tryConnectVNetAgentsAfter(t, leftNet, rightNet, leftConfig, rightConfig, timeout, 0)
}

func tryConnectVNetAgentsAfter(t *testing.T, leftNet, rightNet *vnet.Net, leftConfig, rightConfig Config, timeout, connectDelay time.Duration) (net.Conn, net.Conn, error) {
	t.Helper()
	left, err := newAgent(leftConfig, leftNet)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { _ = left.Close() })
	right, err := newAgent(rightConfig, rightNet)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { _ = right.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	var leftCandidates, rightCandidates []string
	if err := left.Gather(ctx, func(candidate string) error {
		leftCandidates = append(leftCandidates, candidate)
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if err := right.Gather(ctx, func(candidate string) error {
		rightCandidates = append(rightCandidates, candidate)
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if len(leftCandidates) == 0 || len(rightCandidates) == 0 {
		return nil, nil, fmt.Errorf("candidates left=%d right=%d", len(leftCandidates), len(rightCandidates))
	}
	for _, candidate := range leftCandidates {
		if err := right.AddRemoteCandidate(candidate); err != nil {
			return nil, nil, err
		}
	}
	for _, candidate := range rightCandidates {
		if err := left.AddRemoteCandidate(candidate); err != nil {
			return nil, nil, err
		}
	}
	if connectDelay > 0 {
		timer := time.NewTimer(connectDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, nil, ctx.Err()
		}
	}
	var wait sync.WaitGroup
	wait.Add(1)
	var rightConn net.Conn
	var rightErr error
	go func() {
		defer wait.Done()
		rightConn, rightErr = right.Connect(ctx, RoleControlled, leftConfig.LocalUfrag, leftConfig.LocalPwd)
	}()
	leftConn, leftErr := left.Connect(ctx, RoleControlling, rightConfig.LocalUfrag, rightConfig.LocalPwd)
	wait.Wait()
	if leftErr != nil || rightErr != nil {
		if !nilNetConn(leftConn) {
			_ = leftConn.Close()
		}
		if !nilNetConn(rightConn) {
			_ = rightConn.Close()
		}
		return nil, nil, errors.Join(leftErr, rightErr)
	}
	if nilNetConn(rightConn) {
		_ = leftConn.Close()
		return nil, nil, errors.New("controlled ICE endpoint returned no connection")
	}
	return leftConn, rightConn, nil
}

func nilNetConn(connection net.Conn) bool {
	if connection == nil {
		return true
	}
	value := reflect.ValueOf(connection)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func newNATVNet(t *testing.T, leftNAT, rightNAT *vnet.NATType) (*vnet.Net, *vnet.Net, func()) {
	return newNATVNetWithWANFilter(t, leftNAT, rightNAT, nil)
}

func newNATVNetWithWANFilter(t *testing.T, leftNAT, rightNAT *vnet.NATType, filter vnet.ChunkFilter) (*vnet.Net, *vnet.Net, func()) {
	return newNATVNetWithWANConfig(t, leftNAT, rightNAT, 0, 0, filter)
}

func newNATVNetWithWANConfig(t *testing.T, leftNAT, rightNAT *vnet.NATType, minDelay, maxJitter time.Duration, filter vnet.ChunkFilter) (*vnet.Net, *vnet.Net, func()) {
	t.Helper()
	logger := logging.NewDefaultLoggerFactory()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", MinDelay: minDelay, MaxJitter: maxJitter, LoggerFactory: logger})
	if err != nil {
		t.Fatal(err)
	}
	stunNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wan.AddNet(stunNet); err != nil {
		t.Fatal(err)
	}
	if filter != nil {
		wan.AddChunkFilter(filter)
	}
	addEndpoint := func(name, cidr, privateIP, publicIP string, nat *vnet.NATType) *vnet.Net {
		router, err := vnet.NewRouter(&vnet.RouterConfig{Name: name, CIDR: cidr, StaticIPs: []string{publicIP}, NATType: nat, LoggerFactory: logger})
		if err != nil {
			t.Fatal(err)
		}
		network, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{privateIP}})
		if err != nil {
			t.Fatal(err)
		}
		if err := router.AddNet(network); err != nil {
			t.Fatal(err)
		}
		if err := wan.AddRouter(router); err != nil {
			t.Fatal(err)
		}
		return network
	}
	left := addEndpoint("left-nat", "192.168.10.0/24", "192.168.10.10", "27.1.1.1", leftNAT)
	right := addEndpoint("right-nat", "192.168.20.0/24", "192.168.20.20", "28.1.1.1", rightNAT)
	if err := wan.Start(); err != nil {
		t.Fatal(err)
	}
	stunConn, err := stunNet.ListenPacket("udp", "1.2.3.4:3478")
	if err != nil {
		_ = wan.Stop()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveVNetSTUN(stunConn) }()
	return left, right, func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("vnet STUN server exited before shutdown: %v", err)
			}
			if err := wan.Stop(); err != nil {
				t.Errorf("stop vnet: %v", err)
			}
			return
		default:
		}
		_ = stunConn.Close()
		<-done
		if err := wan.Stop(); err != nil {
			t.Errorf("stop vnet: %v", err)
		}
	}
}

func newDoubleNATVNet(t *testing.T) (*vnet.Net, *vnet.Net, func()) {
	t.Helper()
	logger := logging.NewDefaultLoggerFactory()
	nat := &vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent}
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: logger})
	if err != nil {
		t.Fatal(err)
	}
	stunNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wan.AddNet(stunNet); err != nil {
		t.Fatal(err)
	}
	addEndpoint := func(name, outerCIDR, outerPublic, innerCIDR, innerPublic, endpointIP string) *vnet.Net {
		outer, err := vnet.NewRouter(&vnet.RouterConfig{Name: name + "-outer", CIDR: outerCIDR, StaticIPs: []string{outerPublic}, NATType: nat, LoggerFactory: logger})
		if err != nil {
			t.Fatal(err)
		}
		inner, err := vnet.NewRouter(&vnet.RouterConfig{Name: name + "-inner", CIDR: innerCIDR, StaticIPs: []string{innerPublic}, NATType: nat, LoggerFactory: logger})
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{endpointIP}})
		if err != nil {
			t.Fatal(err)
		}
		if err := inner.AddNet(endpoint); err != nil {
			t.Fatal(err)
		}
		if err := outer.AddRouter(inner); err != nil {
			t.Fatal(err)
		}
		if err := wan.AddRouter(outer); err != nil {
			t.Fatal(err)
		}
		return endpoint
	}
	left := addEndpoint("left", "27.1.1.0/24", "27.1.1.1", "192.168.10.0/24", "27.1.1.10", "192.168.10.10")
	right := addEndpoint("right", "28.1.1.0/24", "28.1.1.1", "192.168.20.0/24", "28.1.1.20", "192.168.20.20")
	if err := wan.Start(); err != nil {
		t.Fatal(err)
	}
	stunConn, err := stunNet.ListenPacket("udp", "1.2.3.4:3478")
	if err != nil {
		_ = wan.Stop()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveVNetSTUN(stunConn) }()
	return left, right, func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("vnet STUN server exited before shutdown: %v", err)
			}
			if err := wan.Stop(); err != nil {
				t.Errorf("stop vnet: %v", err)
			}
			return
		default:
		}
		_ = stunConn.Close()
		<-done
		if err := wan.Stop(); err != nil {
			t.Errorf("stop vnet: %v", err)
		}
	}
}

func serveVNetSTUN(conn net.PacketConn) error {
	buffer := make([]byte, 2048)
	for {
		count, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:count]...)}
		if err := request.Decode(); err != nil || request.Type != stun.BindingRequest {
			continue
		}
		udp, ok := remote.(*net.UDPAddr)
		if !ok {
			continue
		}
		response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
		if err != nil {
			return fmt.Errorf("build vnet STUN response: %w", err)
		}
		if _, err := conn.WriteTo(response.Raw, remote); err != nil {
			return err
		}
	}
}

func TestVNetAgentsNominateUDPAndCarryNativeQUIC(t *testing.T) {
	router, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "10.0.0.0/24", LoggerFactory: logging.NewDefaultLoggerFactory()})
	if err != nil {
		t.Fatal(err)
	}
	leftNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"10.0.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	rightNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"10.0.0.20"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := router.AddNet(leftNet); err != nil {
		t.Fatal(err)
	}
	if err := router.AddNet(rightNet); err != nil {
		t.Fatal(err)
	}
	if err := router.Start(); err != nil {
		t.Fatal(err)
	}
	defer router.Stop()

	leftConfig := Config{LocalUfrag: "left-ufrag", LocalPwd: "left-password-123456789012345678901234"}
	rightConfig := Config{LocalUfrag: "right-ufrag", LocalPwd: "right-password-12345678901234567890123"}
	left, err := newAgent(leftConfig, leftNet)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := newAgent(rightConfig, rightNet)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var leftCandidates, rightCandidates []string
	if err := left.Gather(ctx, func(candidate string) error {
		leftCandidates = append(leftCandidates, candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := right.Gather(ctx, func(candidate string) error {
		rightCandidates = append(rightCandidates, candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(leftCandidates) == 0 || len(rightCandidates) == 0 {
		t.Fatalf("candidates left=%d right=%d", len(leftCandidates), len(rightCandidates))
	}
	for _, candidate := range leftCandidates {
		if err := right.AddRemoteCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range rightCandidates {
		if err := left.AddRemoteCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}

	var wait sync.WaitGroup
	wait.Add(1)
	var rightConn net.Conn
	var rightErr error
	go func() {
		defer wait.Done()
		rightConn, rightErr = right.Connect(ctx, RoleControlled, leftConfig.LocalUfrag, leftConfig.LocalPwd)
	}()
	leftConn, err := left.Connect(ctx, RoleControlling, rightConfig.LocalUfrag, rightConfig.LocalPwd)
	if err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if rightErr != nil {
		t.Fatal(rightErr)
	}
	clientTLS, serverTLS := peerTLSConfigs(t)
	listener, err := peerquic.Listen(rightConn, serverTLS, peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *peerquic.Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- session
	}()
	client, err := peerquic.Dial(ctx, leftConn, clientTLS, peerquic.ClassInteractive)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	exporterContext := peercontext.Context{AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 1, AuthorizationGeneration: 1, IntentID: "intent_01", OperationID: "operation_01", Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 1}
	copy(exporterContext.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(exporterContext.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	clientBinding, err := peerquic.ExporterBinding(client.Connection.ConnectionState().TLS, exporterContext)
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := peerquic.ExporterBinding(server.Connection.ConnectionState().TLS, exporterContext)
	if err != nil {
		t.Fatal(err)
	}
	if clientBinding != serverBinding {
		t.Fatal("peer QUIC TLS exporter binding mismatch")
	}

	clientStream, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("paperboat-direct-quic")
	firstRecord, err := peerquic.SealFirstRecord(clientBinding, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientStream.Write(firstRecord); err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.Connection.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(firstRecord))
	if _, err := io.ReadFull(serverStream, received); err != nil {
		t.Fatal(err)
	}
	opened, err := peerquic.OpenFirstRecord(serverBinding, received)
	if err != nil || string(opened) != string(payload) {
		t.Fatalf("payload=%q err=%v", opened, err)
	}
}

func peerTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	issue := func(serial uint64, role endpointidentity.Role, endpointID string) (endpointidentity.Certificate, tls.Certificate) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var noise [32]byte
		if _, err := rand.Read(noise[:]); err != nil {
			t.Fatal(err)
		}
		certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: role, EndpointID: endpointID, NoisePublicKey: noise, QUICPublicKey: public, Generation: 1, Serial: serial, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := endpointidentity.NewTLSCertificate(certificate, rootPublic, private, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, leaf
	}
	clientCertificate, clientLeaf := issue(2, endpointidentity.RoleCLI, "cli_01")
	serverCertificate, serverLeaf := issue(3, endpointidentity.RoleMachine, "machine_01")
	clientRaw, _ := clientCertificate.MarshalBinary()
	serverRaw, _ := serverCertificate.MarshalBinary()
	clock := func() time.Time { return now }
	client, err := endpointidentity.ClientTLS(clientLeaf, endpointidentity.PeerExpectation{RootPublic: rootPublic, Certificate: serverRaw, Expected: endpointidentity.Expected{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", Generation: 1}}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	server, err := endpointidentity.ServerTLS(serverLeaf, endpointidentity.PeerExpectation{RootPublic: rootPublic, Certificate: clientRaw, Expected: endpointidentity.Expected{AccountID: "account_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01", Generation: 1}}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}
