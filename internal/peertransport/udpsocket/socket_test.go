package udpsocket

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestOpenOwnsIPv4SocketAndCarriesDatagrams(t *testing.T) {
	set, err := Open(context.Background(), DevelopmentConfig(true, false))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if set.Port() == 0 || set.IPv4() == nil || set.IPv6() != nil {
		t.Fatalf("port=%d ipv4=%v ipv6=%v", set.Port(), set.IPv4(), set.IPv6())
	}
	verifySocketControls(t, set.IPv4(), false)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	payload := []byte("owned-udp4")
	if _, err := sender.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(set.Port())}); err != nil {
		t.Fatal(err)
	}
	_ = set.IPv4().SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	count, _, err := set.IPv4().ReadFromUDP(buffer)
	if err != nil || string(buffer[:count]) != string(payload) {
		t.Fatalf("payload=%q error=%v", buffer[:count], err)
	}
}

func TestOpenBindsAvailableFamiliesToSamePort(t *testing.T) {
	config := DevelopmentConfig(true, true)
	config.IPv6Viable = func(context.Context) bool { return true }
	set, err := Open(context.Background(), config)
	if err != nil {
		t.Skipf("dual-stack loopback unavailable: %v", err)
	}
	defer set.Close()
	v4Port := set.IPv4().LocalAddr().(*net.UDPAddr).Port
	v6Port := set.IPv6().LocalAddr().(*net.UDPAddr).Port
	if v4Port != v6Port || v4Port != int(set.Port()) {
		t.Fatalf("ports v4=%d v6=%d set=%d", v4Port, v6Port, set.Port())
	}
	verifySocketControls(t, set.IPv4(), false)
	verifySocketControls(t, set.IPv6(), true)
}

func TestOpenKeepsIPv4WhenIPv6RouteIsUnavailable(t *testing.T) {
	config := DevelopmentConfig(true, true)
	config.IPv6Viable = func(context.Context) bool { return false }
	set, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if set.IPv4() == nil || set.IPv6() != nil {
		t.Fatalf("ipv4=%v ipv6=%v", set.IPv4(), set.IPv6())
	}
}

func TestSocketSetCloseIsConcurrentAndIdempotent(t *testing.T) {
	set, err := Open(context.Background(), DevelopmentConfig(true, false))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = set.Port()
			_ = set.IPv4()
			_ = set.Close()
		}()
	}
	wait.Wait()
	if err := set.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if set.Port() != 0 || set.IPv4() == nil {
		t.Fatalf("closed set port=%d socket=%v", set.Port(), set.IPv4())
	}
}

func TestOpenRejectsInvalidConfigurationAndCancellation(t *testing.T) {
	for _, config := range []Config{
		{},
		{IPv4: true},
		{IPv4: true, BindAttempts: 65},
	} {
		if _, err := Open(context.Background(), config); !errors.Is(err, ErrInvalid) {
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, DevelopmentConfig(true, false)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}
