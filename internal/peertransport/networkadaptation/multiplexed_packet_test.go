package networkadaptation

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMultiplexedPacketConnConcurrentRegistrationsAndCleanup(t *testing.T) {
	left, right := udpPair(t)
	defer right.Close()
	mux, err := NewMultiplexedPacketConn(MultiplexedPacketConfig{Connection: left, MaximumPMTU: 1452, ApplicationQueue: 8, ResponseTimeout: 100 * time.Millisecond, MaximumChannels: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	first, err := mux.RegisterPMTU(bytesOf(1), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mux.RegisterPMTU(bytesOf(2), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if mux.LocalAddr().String() != left.LocalAddr().String() {
		t.Fatalf("mux changed physical address: %s != %s", mux.LocalAddr(), left.LocalAddr())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.BindPMTURemote(PMTURemoteBinding{Address: right.LocalAddr(), AttemptGeneration: 2, NetworkGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ExchangePMTU(context.Background(), make([]byte, 1200)); err == nil {
		t.Fatal("closed registration accepted PMTU exchange")
	}
}

func TestMultiplexedPacketConnForwardsApplicationBytes(t *testing.T) {
	left, right := udpPair(t)
	defer right.Close()
	mux, err := NewMultiplexedPacketConn(MultiplexedPacketConfig{Connection: left, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: 100 * time.Millisecond, MaximumChannels: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	want := []byte{0, 1, 2, 3, 0xff}
	if _, err := right.WriteTo(want, left.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := mux.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, address, err := mux.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if address == nil || n != len(want) || string(got) != string(want) {
		t.Fatalf("got %d bytes from %v: %v", n, address, got[:n])
	}
}

func TestMultiplexedPacketConnSurvivesTransientReachabilityError(t *testing.T) {
	connection := &transientReadPacketConn{closed: make(chan struct{})}
	mux, err := NewMultiplexedPacketConn(MultiplexedPacketConfig{Connection: connection, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: 100 * time.Millisecond, MaximumChannels: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	buffer := make([]byte, 8)
	if err := mux.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count, _, err := mux.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:count]); got != "healthy" {
		t.Fatalf("packet after transient error = %q", got)
	}
}

type transientReadPacketConn struct {
	mu     sync.Mutex
	reads  int
	closed chan struct{}
	once   sync.Once
}

func (c *transientReadPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.mu.Lock()
	c.reads++
	read := c.reads
	c.mu.Unlock()
	if read == 1 {
		return 0, nil, syscall.ENETUNREACH
	}
	if read == 2 {
		return copy(buffer, "healthy"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil
	}
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (*transientReadPacketConn) WriteTo(value []byte, _ net.Addr) (int, error) {
	return len(value), nil
}
func (*transientReadPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *transientReadPacketConn) Close() error                   { c.once.Do(func() { close(c.closed) }); return nil }
func (*transientReadPacketConn) SetDeadline(time.Time) error      { return nil }
func (*transientReadPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*transientReadPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*transientReadPacketConn)(nil)

func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	left, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	right, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		left.Close()
		t.Fatal(err)
	}
	return left, right
}

func bytesOf(seed byte) []byte {
	value := make([]byte, sha256Size)
	for index := range value {
		value[index] = seed
	}
	return value
}
