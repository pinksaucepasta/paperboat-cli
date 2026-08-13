package iceagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	pionice "github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

func TestOwnedUDPMuxServerReflexiveCandidateUsesOwnedPort(t *testing.T) {
	server := listenWildcardUDP4(t)
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		count, remote, err := server.ReadFrom(buffer)
		if err != nil {
			serverDone <- err
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:count]...)}
		if err := request.Decode(); err != nil {
			serverDone <- err
			return
		}
		udp := remote.(*net.UDPAddr)
		response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
		if err == nil {
			_, err = server.WriteTo(response.Raw, remote)
		}
		serverDone <- err
	}()

	owned := listenWildcardUDP4(t)
	ownedPort := owned.LocalAddr().(*net.UDPAddr).Port
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	agent, err := NewWithUDPMux(Config{
		LocalUfrag: "owned-srflx-port", LocalPwd: "owned-password-1234567890123456789012",
		STUNURLs: []string{"stun:127.0.0.1:" + fmt.Sprint(serverPort)},
	}, OwnedMuxConfig{IPv4: owned})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	candidates := gatherCandidates(t, ctx, agent)
	found := false
	for _, raw := range candidates {
		candidate, err := pionice.UnmarshalCandidate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Type() == pionice.CandidateTypeServerReflexive {
			found = true
			if candidate.Port() != ownedPort {
				t.Fatalf("server-reflexive port=%d owned port=%d", candidate.Port(), ownedPort)
			}
		}
	}
	if !found {
		t.Fatal("no server-reflexive candidate gathered")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestOwnedUDPMuxAgentsNominateAndExchange(t *testing.T) {
	leftSocket := listenWildcardUDP4(t)
	rightSocket := listenWildcardUDP4(t)
	leftConfig := Config{LocalUfrag: "left-owned-mux", LocalPwd: "left-password-123456789012345678901234"}
	rightConfig := Config{LocalUfrag: "right-owned-mux", LocalPwd: "right-password-12345678901234567890123"}
	left, err := NewWithUDPMux(leftConfig, OwnedMuxConfig{IPv4: leftSocket})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewWithUDPMux(rightConfig, OwnedMuxConfig{IPv4: rightSocket})
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	defer right.Close()
	defer left.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leftCandidates := gatherCandidates(t, ctx, left)
	rightCandidates := gatherCandidates(t, ctx, right)
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
	defer rightConn.Close()
	defer leftConn.Close()

	payload := []byte("owned-pion-udp-mux")
	if _, err := leftConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := rightConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := rightConn.Read(received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("payload=%q", received)
	}

	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := leftSocket.WriteTo([]byte("closed"), rightSocket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("owned socket remained open: %v", err)
	}
}

func TestNewWithUDPMuxRejectsMismatchedPortsAndClosesSockets(t *testing.T) {
	ipv4 := listenWildcardUDP4(t)
	ipv6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		_ = ipv4.Close()
		t.Skipf("IPv6 unavailable: %v", err)
	}
	if ipv4.LocalAddr().(*net.UDPAddr).Port == ipv6.LocalAddr().(*net.UDPAddr).Port {
		_ = ipv4.Close()
		_ = ipv6.Close()
		t.Skip("kernel selected the same random port")
	}
	_, err = NewWithUDPMux(Config{LocalUfrag: "invalid", LocalPwd: "invalid-password-123456789012345678901"}, OwnedMuxConfig{IPv4: ipv4, IPv6: ipv6})
	if err == nil {
		t.Fatal("mismatched ports accepted")
	}
	if _, writeErr := ipv4.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(writeErr, net.ErrClosed) {
		t.Fatalf("IPv4 socket remained open: %v", writeErr)
	}
	if _, writeErr := ipv6.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv6loopback, Port: 9}); !errors.Is(writeErr, net.ErrClosed) {
		t.Fatalf("IPv6 socket remained open: %v", writeErr)
	}
}

func gatherCandidates(t *testing.T, ctx context.Context, agent *Agent) []string {
	t.Helper()
	var candidates []string
	if err := agent.Gather(ctx, func(candidate string) error {
		candidates = append(candidates, candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 {
		t.Fatal("no ICE candidates gathered from owned UDP mux")
	}
	return candidates
}

func listenWildcardUDP4(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}
