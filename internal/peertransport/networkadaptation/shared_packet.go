package networkadaptation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

var (
	ErrStalePMTURemote  = errors.New("stale selected PMTU remote")
	ErrSocketGeneration = errors.New("selected PMTU remote requires a new socket generation")
)

type PMTURemoteBinding struct {
	Address           net.Addr
	AttemptGeneration uint64
	NetworkGeneration uint64
}

func (b PMTURemoteBinding) valid() bool {
	return b.Address != nil && b.AttemptGeneration > 0 && b.NetworkGeneration > 0
}

type SharedPacketConfig struct {
	Connection       net.PacketConn
	Remote           PMTURemoteBinding
	PMTUKey          []byte
	MaximumPMTU      uint16
	ApplicationQueue int
	ResponseTimeout  time.Duration
}

type sharedPacket struct {
	value   []byte
	address net.Addr
}

type pendingPMTU struct {
	nonce    [16]byte
	size     uint16
	remote   net.Addr
	response chan []byte
}

// SharedPacketConn is the sole reader for one owned UDP socket. Authenticated
// PMTU control frames are intercepted; every other datagram is exposed through
// net.PacketConn for Pion's UDP mux.
type SharedPacketConn struct {
	connection      net.PacketConn
	maximum         uint16
	responseTimeout time.Duration
	key             []byte
	application     chan sharedPacket

	writeMu        sync.Mutex
	deadlineMu     sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	deadlineChange chan struct{}

	exchangeMu sync.Mutex
	remoteMu   sync.Mutex
	remote     PMTURemoteBinding
	pendingMu  sync.Mutex
	pending    *pendingPMTU

	closeOnce         sync.Once
	doneOnce          sync.Once
	closing           chan struct{}
	done              chan struct{}
	mu                sync.Mutex
	readErr           error
	closeErr          error
	candidateRefusals atomic.Uint64
	datagramsReceived atomic.Uint64
	applicationFrames atomic.Uint64
	pmtuWrites        atomic.Uint64
	pmtuRequests      atomic.Uint64
	pmtuResponses     atomic.Uint64
	pmtuInvalid       atomic.Uint64
}

func NewSharedPacketConn(config SharedPacketConfig) (*SharedPacketConn, error) {
	if nilPacketConn(config.Connection) || len(config.PMTUKey) < sha256Size || config.MaximumPMTU < 1200 || config.ApplicationQueue < 1 || config.ApplicationQueue > 4096 || config.ResponseTimeout <= 0 || config.Remote.Address != nil && !config.Remote.valid() {
		return nil, ErrInvalid
	}
	connection := &SharedPacketConn{
		connection: config.Connection, remote: config.Remote, maximum: config.MaximumPMTU, responseTimeout: config.ResponseTimeout,
		key: append([]byte(nil), config.PMTUKey...), application: make(chan sharedPacket, config.ApplicationQueue),
		deadlineChange: make(chan struct{}), closing: make(chan struct{}), done: make(chan struct{}),
	}
	go connection.readLoop()
	return connection, nil
}

const sha256Size = 32

func (c *SharedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if c == nil || len(buffer) == 0 {
		return 0, nil, ErrInvalid
	}
	for {
		deadline, changed := c.readDeadlineSnapshot()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			duration := time.Until(deadline)
			if duration <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(duration)
			timeout = timer.C
		}
		select {
		case packet := <-c.application:
			if timer != nil {
				timer.Stop()
			}
			count := copy(buffer, packet.value)
			return count, packet.address, nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, c.terminalError()
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *SharedPacketConn) WriteTo(value []byte, address net.Addr) (int, error) {
	if c == nil || len(value) == 0 || address == nil {
		return 0, ErrInvalid
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, c.terminalError()
	default:
	}
	deadline := c.writeDeadlineSnapshot()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := c.connection.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	count, err := c.connection.WriteTo(value, address)
	return count, errors.Join(err, c.connection.SetWriteDeadline(time.Time{}))
}

func (c *SharedPacketConn) ExchangePMTU(ctx context.Context, request []byte) ([]byte, error) {
	if c == nil || ctx == nil || len(request) < 1200 || len(request) > int(c.maximum) {
		return nil, ErrInvalid
	}
	key := c.keyCopy()
	if len(key) == 0 {
		return nil, net.ErrClosed
	}
	nonce, err := parsePMTUFrame(key, request, pmtuFrameRequest, uint16(len(request)))
	zeroBytes(key)
	if err != nil {
		return nil, err
	}
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	remote := c.remoteSnapshot()
	if !remote.valid() {
		return nil, ErrInvalid
	}
	pending := &pendingPMTU{nonce: nonce, size: uint16(len(request)), remote: remote.Address, response: make(chan []byte, 1)}
	c.pendingMu.Lock()
	c.pending = pending
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		if c.pending == pending {
			c.pending = nil
		}
		c.pendingMu.Unlock()
	}()
	if err := c.writeInternal(ctx, request, remote.Address); err != nil {
		if classified := c.classifyPathError(); classified != nil {
			return nil, classified
		}
		return nil, err
	}
	timer := time.NewTimer(c.responseTimeout)
	defer timer.Stop()
	select {
	case response := <-pending.response:
		return response, nil
	case <-timer.C:
		if classified := c.classifyPathError(); classified != nil {
			return nil, classified
		}
		return nil, ErrPMTUProbeUnreachable
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.terminalError()
	}
}

// BindPMTURemote binds probes to the peer nominated by one ICE attempt. A
// newer attempt may replace the peer on the same network generation. Network
// generation changes require a newly bound socket and SharedPacketConn.
func (c *SharedPacketConn) BindPMTURemote(binding PMTURemoteBinding) error {
	if c == nil || !binding.valid() {
		return ErrInvalid
	}
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	select {
	case <-c.done:
		return c.terminalError()
	default:
	}
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	current := c.remote
	if !current.valid() {
		c.remote = binding
		return nil
	}
	if binding.NetworkGeneration < current.NetworkGeneration || binding.NetworkGeneration == current.NetworkGeneration && binding.AttemptGeneration < current.AttemptGeneration {
		return ErrStalePMTURemote
	}
	if binding.NetworkGeneration != current.NetworkGeneration {
		return ErrSocketGeneration
	}
	if binding.AttemptGeneration == current.AttemptGeneration {
		if sameAddress(binding.Address, current.Address) {
			return nil
		}
		return ErrStalePMTURemote
	}
	c.remote = binding
	return nil
}

func (c *SharedPacketConn) classifyPathError() error {
	connection, ok := c.connection.(*net.UDPConn)
	if !ok || !udpsocket.SupportsPathErrors() {
		return nil
	}
	pathError, found, err := udpsocket.ReadPathError(connection)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if pathError.Kind == udpsocket.PathErrorPacketTooBig {
		return ErrPMTUProbeUnreachable
	}
	return fmt.Errorf("UDP path error origin=%d type=%d code=%d: %w", pathError.Origin, pathError.Type, pathError.Code, pathError.Errno)
}

func (c *SharedPacketConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.closing)
		c.mu.Lock()
		zeroBytes(c.key)
		c.key = nil
		c.mu.Unlock()
		c.closeErr = c.connection.Close()
		if errors.Is(c.closeErr, net.ErrClosed) {
			c.closeErr = nil
		}
		<-c.done
	})
	return c.closeErr
}

func (c *SharedPacketConn) LocalAddr() net.Addr {
	if c == nil || c.connection == nil {
		return nil
	}
	return c.connection.LocalAddr()
}

func (c *SharedPacketConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func (c *SharedPacketConn) SetReadDeadline(deadline time.Time) error {
	if c == nil {
		return ErrInvalid
	}
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	close(c.deadlineChange)
	c.deadlineChange = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *SharedPacketConn) SetWriteDeadline(deadline time.Time) error {
	if c == nil {
		return ErrInvalid
	}
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *SharedPacketConn) readLoop() {
	buffer := make([]byte, 65535)
	for {
		count, address, err := c.connection.ReadFrom(buffer)
		if err != nil {
			if c.recoverCandidateReadError(err) {
				continue
			}
			c.finish(err)
			return
		}
		value := append([]byte(nil), buffer[:count]...)
		c.datagramsReceived.Add(1)
		handled, err := c.handlePMTU(value, address)
		if err != nil {
			zeroBytes(value)
			c.finish(err)
			_ = c.connection.Close()
			return
		}
		if handled {
			zeroBytes(value)
			continue
		}
		c.applicationFrames.Add(1)
		select {
		case c.application <- sharedPacket{value: value, address: address}:
		case <-c.closing:
			zeroBytes(value)
			c.finish(net.ErrClosed)
			return
		}
	}
}

func (c *SharedPacketConn) recoverCandidateReadError(err error) bool {
	connection, ok := c.connection.(*net.UDPConn)
	if !ok || !errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	if !udpsocket.SupportsPathErrors() {
		return true
	}
	pathError, found, queueErr := udpsocket.ReadPathError(connection)
	recoverable := queueErr == nil && (!found || pathError.Errno == syscall.ECONNREFUSED)
	if recoverable {
		c.candidateRefusals.Add(1)
	}
	return recoverable
}

func (c *SharedPacketConn) handlePMTU(value []byte, address net.Addr) (bool, error) {
	if len(value) < 1200 || len(value) > int(c.maximum) || len(value) < 4 || string(value[:4]) != string(pmtuFrameMagic[:]) {
		return false, nil
	}
	key := c.keyCopy()
	if len(key) == 0 {
		return false, net.ErrClosed
	}
	defer zeroBytes(key)
	size := uint16(len(value))
	if nonce, err := parsePMTUFrame(key, value, pmtuFrameRequest, size); err == nil {
		c.pmtuRequests.Add(1)
		response, err := buildPMTUFrame(key, pmtuFrameResponse, size, nonce)
		if err != nil {
			return true, err
		}
		defer zeroBytes(response)
		return true, c.writeInternal(context.Background(), response, address)
	}
	nonce, err := parsePMTUFrame(key, value, pmtuFrameResponse, size)
	if err != nil {
		c.pmtuInvalid.Add(1)
		return false, nil
	}
	c.pmtuResponses.Add(1)
	c.pendingMu.Lock()
	pending := c.pending
	if pending != nil && pending.size == size && pending.nonce == nonce && sameAddress(pending.remote, address) {
		select {
		case pending.response <- append([]byte(nil), value...):
		default:
		}
	}
	c.pendingMu.Unlock()
	return true, nil
}

// PMTUFrameCounts returns aggregate control-frame diagnostics without exposing
// peer addresses, credentials, or packet contents.
func (c *SharedPacketConn) PMTUFrameCounts() (writes, datagrams, application, requests, responses, invalid uint64) {
	if c == nil {
		return 0, 0, 0, 0, 0, 0
	}
	return c.pmtuWrites.Load(), c.datagramsReceived.Load(), c.applicationFrames.Load(), c.pmtuRequests.Load(), c.pmtuResponses.Load(), c.pmtuInvalid.Load()
}

func (c *SharedPacketConn) writeInternal(ctx context.Context, value []byte, address net.Addr) error {
	if ctx == nil {
		return ErrInvalid
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(c.responseTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := c.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = c.connection.SetWriteDeadline(time.Now())
		close(canceled)
	})
	count, err := c.connection.WriteTo(value, address)
	if !stopCancellation() {
		<-canceled
	}
	clearErr := c.connection.SetWriteDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err, clearErr)
	}
	if err == nil && count != len(value) {
		err = errors.New("short shared UDP datagram write")
	}
	if err == nil {
		c.pmtuWrites.Add(1)
	}
	return errors.Join(err, clearErr)
}

func (c *SharedPacketConn) finish(err error) {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.mu.Unlock()
	c.doneOnce.Do(func() { close(c.done) })
}

func (c *SharedPacketConn) terminalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	return net.ErrClosed
}

func (c *SharedPacketConn) keyCopy() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.key...)
}

func (c *SharedPacketConn) remoteSnapshot() PMTURemoteBinding {
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	return c.remote
}

func (c *SharedPacketConn) readDeadlineSnapshot() (time.Time, <-chan struct{}) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline, c.deadlineChange
}

func (c *SharedPacketConn) writeDeadlineSnapshot() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func sameAddress(a, b net.Addr) bool {
	return a != nil && b != nil && a.Network() == b.Network() && a.String() == b.String()
}

func nilPacketConn(connection net.PacketConn) bool {
	if connection == nil {
		return true
	}
	value := reflect.ValueOf(connection)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
