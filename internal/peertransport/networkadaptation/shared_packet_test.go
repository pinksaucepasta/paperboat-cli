package networkadaptation

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

func TestSharedPacketConnCarriesApplicationAndAuthenticatedPMTU(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{21}, 32)
	left, err := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 16, ResponseTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewSharedPacketConn(SharedPacketConfig{Connection: rightUDP, Remote: testPMTURemote(leftUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 16, ResponseTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()

	application := []byte("pion-stun-packet")
	if count, err := right.WriteTo(application, left.LocalAddr()); err != nil || count != len(application) {
		t.Fatalf("application write count=%d error=%v", count, err)
	}
	buffer := make([]byte, 64)
	_ = left.SetReadDeadline(time.Now().Add(time.Second))
	count, source, err := left.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != string(application) || !sameAddress(source, right.LocalAddr()) {
		t.Fatalf("application payload=%q source=%v error=%v", buffer[:count], source, err)
	}
	_ = left.SetReadDeadline(time.Time{})

	prober, err := NewAuthenticatedPMTUProber(key, 1452, left)
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := prober.ProbePayload(ctx, 1380)
	if err != nil || !result.Supported {
		t.Fatalf("PMTU result=%+v error=%v", result, err)
	}
	_ = left.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := left.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("PMTU frame leaked to application: %v", err)
	}
}

func TestSharedPacketConnSurvivesRefusedICECandidate(t *testing.T) {
	if !udpsocket.SupportsPathErrors() {
		t.Skip("platform does not expose UDP path errors")
	}
	sockets, err := udpsocket.Open(context.Background(), udpsocket.DevelopmentConfig(true, false))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := NewSharedPacketConn(SharedPacketConfig{Connection: sockets.IPv4(), PMTUKey: bytes.Repeat([]byte{31}, 32), MaximumPMTU: 1452, ApplicationQueue: 8, ResponseTimeout: 100 * time.Millisecond})
	if err != nil {
		sockets.Close()
		t.Fatal(err)
	}
	defer shared.Close()
	refused, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	refusedAddress := refused.LocalAddr()
	if err := refused.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := shared.WriteTo([]byte("failed-candidate"), refusedAddress); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for shared.candidateRefusals.Load() == 0 {
		select {
		case <-deadline.C:
			t.Fatal("refused candidate was not classified")
		case <-ticker.C:
		}
	}
	peer := listenLoopbackUDP(t)
	defer peer.Close()
	if _, err := peer.WriteTo([]byte("valid-candidate"), shared.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if err := shared.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count, _, err := shared.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != "valid-candidate" {
		t.Fatalf("count=%d payload=%q error=%v", count, buffer[:count], err)
	}
}

func TestSharedPacketConnSerializesConcurrentPMTUExchanges(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{22}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 16, ResponseTimeout: 100 * time.Millisecond})
	right, _ := NewSharedPacketConn(SharedPacketConfig{Connection: rightUDP, Remote: testPMTURemote(leftUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 16, ResponseTimeout: 100 * time.Millisecond})
	defer left.Close()
	defer right.Close()
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, left)
	defer prober.Close()
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 8)
	for index := range 8 {
		wait.Add(1)
		go func(size uint16) {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := prober.ProbePayload(ctx, size)
			if err != nil || !result.Supported {
				errorsChannel <- errors.Join(err, errors.New("unsupported concurrent PMTU result"))
			}
		}(1200 + uint16(index))
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
}

func TestSharedPacketConnUsesInternalResponseTimeoutAsNegativeEvidence(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t) // Keep the destination bound without serving PMTU.
	defer rightUDP.Close()
	key := bytes.Repeat([]byte{27}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{
		Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key,
		MaximumPMTU: 1452, ApplicationQueue: 2, ResponseTimeout: 20 * time.Millisecond,
	})
	defer left.Close()
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, left)
	defer prober.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := prober.ProbePayload(ctx, 1200)
	if err != nil || result.Supported || result.At.IsZero() || ctx.Err() != nil {
		t.Fatalf("result=%+v error=%v context=%v", result, err, ctx.Err())
	}
}

func TestSharedPacketConnPassesUnauthenticatedMagicToApplication(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{23}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 2, ResponseTimeout: 100 * time.Millisecond})
	defer left.Close()
	value := make([]byte, 1200)
	copy(value, pmtuFrameMagic[:])
	if _, err := rightUDP.WriteTo(value, leftUDP.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1452)
	_ = left.SetReadDeadline(time.Now().Add(time.Second))
	count, _, err := left.ReadFrom(buffer)
	if err != nil || count != len(value) || !bytes.Equal(buffer[:count], value) {
		t.Fatalf("count=%d error=%v", count, err)
	}
}

func TestSharedPacketConnAppliesApplicationBackpressureWithoutClosing(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{24}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: 100 * time.Millisecond})
	defer left.Close()
	for _, value := range [][]byte{{1}, {2}, {3}} {
		if _, err := rightUDP.WriteTo(value, leftUDP.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-left.done:
		t.Fatal("transient application backpressure closed packet owner")
	case <-time.After(20 * time.Millisecond):
	}
	buffer := make([]byte, 8)
	for want := byte(1); want <= 3; want++ {
		_ = left.SetReadDeadline(time.Now().Add(time.Second))
		count, _, err := left.ReadFrom(buffer)
		if err != nil || count != 1 || buffer[0] != want {
			t.Fatalf("packet=%d count=%d error=%v want=%d", buffer[0], count, err, want)
		}
	}
}

func TestSharedPacketConnCloseInterruptsApplicationBackpressure(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{29}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: 100 * time.Millisecond})
	for _, value := range [][]byte{{1}, {2}, {3}} {
		if _, err := rightUDP.WriteTo(value, leftUDP.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- left.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt application backpressure")
	}
}

func TestSharedPacketConnReadDeadlineCanBeMovedAndCleared(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	key := bytes.Repeat([]byte{25}, 32)
	left, _ := NewSharedPacketConn(SharedPacketConfig{Connection: leftUDP, PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: 100 * time.Millisecond})
	defer left.Close()
	buffer := make([]byte, 8)
	_ = left.SetReadDeadline(time.Now().Add(time.Hour))
	_ = left.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err := left.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}
	_ = left.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := left.ReadFrom(buffer)
		done <- err
	}()
	<-ctx.Done()
	_ = left.Close()
	if err := <-done; err == nil {
		t.Fatal("close did not interrupt cleared-deadline read")
	}
}

func TestSharedPacketConnFencesRemoteBindingAcrossActiveExchange(t *testing.T) {
	leftUDP := listenLoopbackUDP(t)
	rightUDP := listenLoopbackUDP(t)
	replacementUDP := listenLoopbackUDP(t)
	defer rightUDP.Close()
	defer replacementUDP.Close()
	key := bytes.Repeat([]byte{27}, 32)
	left, err := NewSharedPacketConn(SharedPacketConfig{
		Connection: leftUDP, Remote: testPMTURemote(rightUDP.LocalAddr()), PMTUKey: key,
		MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	nonce := [16]byte{1, 2, 3}
	request, err := buildPMTUFrame(key, pmtuFrameRequest, 1200, nonce)
	if err != nil {
		t.Fatal(err)
	}
	exchangeDone := make(chan error, 1)
	go func() {
		_, exchangeErr := left.ExchangePMTU(context.Background(), request)
		exchangeDone <- exchangeErr
	}()
	received := make([]byte, 1200)
	if err := rightUDP.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count, sender, err := rightUDP.ReadFrom(received)
	if err != nil || count != len(received) {
		t.Fatalf("read request count=%d err=%v", count, err)
	}
	replacement := PMTURemoteBinding{Address: replacementUDP.LocalAddr(), AttemptGeneration: 2, NetworkGeneration: 1}
	bindDone := make(chan error, 1)
	go func() { bindDone <- left.BindPMTURemote(replacement) }()
	select {
	case err := <-bindDone:
		t.Fatalf("remote changed during active exchange: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	response, err := buildPMTUFrame(key, pmtuFrameResponse, 1200, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rightUDP.WriteTo(response, sender); err != nil {
		t.Fatal(err)
	}
	if err := <-exchangeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-bindDone; err != nil {
		t.Fatal(err)
	}
	if err := left.BindPMTURemote(replacement); err != nil {
		t.Fatalf("idempotent binding failed: %v", err)
	}
	if err := left.BindPMTURemote(testPMTURemote(rightUDP.LocalAddr())); !errors.Is(err, ErrStalePMTURemote) {
		t.Fatalf("stale attempt error=%v", err)
	}
	conflict := replacement
	conflict.Address = rightUDP.LocalAddr()
	if err := left.BindPMTURemote(conflict); !errors.Is(err, ErrStalePMTURemote) {
		t.Fatalf("same-generation conflict error=%v", err)
	}
	nextNetwork := replacement
	nextNetwork.NetworkGeneration++
	if err := left.BindPMTURemote(nextNetwork); !errors.Is(err, ErrSocketGeneration) {
		t.Fatalf("new network generation error=%v", err)
	}
}

type blockingWritePacketConn struct {
	deadlines chan time.Time
	started   chan time.Time
	closed    chan struct{}
	closeOnce sync.Once
}

func newBlockingWritePacketConn() *blockingWritePacketConn {
	return &blockingWritePacketConn{deadlines: make(chan time.Time, 8), started: make(chan time.Time, 1), closed: make(chan struct{})}
}

func (c *blockingWritePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *blockingWritePacketConn) WriteTo(value []byte, _ net.Addr) (int, error) {
	initial := <-c.deadlines
	c.started <- initial
	for {
		select {
		case deadline := <-c.deadlines:
			if !deadline.IsZero() && !deadline.After(time.Now()) {
				return 0, os.ErrDeadlineExceeded
			}
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
}

func (c *blockingWritePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingWritePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 1234}
}
func (c *blockingWritePacketConn) SetDeadline(time.Time) error     { return nil }
func (c *blockingWritePacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *blockingWritePacketConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines <- deadline
	return nil
}

func TestSharedPacketConnInternalWriteUsesCallerDeadlineAndCancellation(t *testing.T) {
	connection := newBlockingWritePacketConn()
	key := bytes.Repeat([]byte{28}, 32)
	shared, err := NewSharedPacketConn(SharedPacketConfig{
		Connection: connection, Remote: testPMTURemote(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321}), PMTUKey: key,
		MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	request, err := buildPMTUFrame(key, pmtuFrameRequest, 1200, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	done := make(chan error, 1)
	go func() {
		_, exchangeErr := shared.ExchangePMTU(ctx, request)
		done <- exchangeErr
	}()
	initial := <-connection.started
	callerDeadline, _ := ctx.Deadline()
	if initial.After(callerDeadline) || initial.Before(callerDeadline.Add(-10*time.Millisecond)) {
		t.Fatalf("internal deadline=%v caller=%v", initial, callerDeadline)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt internal write")
	}
}

func TestSharedPacketConnRejectsInvalidAndTypedNilConfiguration(t *testing.T) {
	key := bytes.Repeat([]byte{26}, 32)
	var typedNil *net.UDPConn
	owned := listenLoopbackUDP(t)
	defer owned.Close()
	for _, config := range []SharedPacketConfig{
		{},
		{Connection: typedNil, PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: time.Second},
		{Connection: owned, PMTUKey: key[:31], MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: time.Second},
		{Connection: owned, Remote: PMTURemoteBinding{Address: owned.LocalAddr()}, PMTUKey: key, MaximumPMTU: 1452, ApplicationQueue: 1, ResponseTimeout: time.Second},
	} {
		if connection, err := NewSharedPacketConn(config); !errors.Is(err, ErrInvalid) {
			if connection != nil {
				_ = connection.Close()
			}
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func testPMTURemote(address net.Addr) PMTURemoteBinding {
	return PMTURemoteBinding{Address: address, AttemptGeneration: 1, NetworkGeneration: 1}
}
