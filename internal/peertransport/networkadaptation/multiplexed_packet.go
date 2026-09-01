package networkadaptation

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrPMTURegistrationLimit = errors.New("PMTU registration limit reached")

// MultiplexedPacketConn is the daemon-owned reader for one UDP socket. It
// forwards ordinary datagrams to Pion and dispatches authenticated PMTU frames
// to bounded attempt-scoped registrations.
type MultiplexedPacketConn struct {
	connection      net.PacketConn
	maximum         uint16
	responseTimeout time.Duration
	application     chan sharedPacket
	maximumChannels int

	writeMu        sync.Mutex
	deadlineMu     sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	deadlineChange chan struct{}

	registrationsMu sync.RWMutex
	registrations   map[*PMTURegistration]struct{}

	closeOnce sync.Once
	doneOnce  sync.Once
	closing   chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	readErr   error
	closeErr  error

	datagramsReceived atomic.Uint64
	applicationFrames atomic.Uint64
	pmtuWrites        atomic.Uint64
	pmtuRequests      atomic.Uint64
	pmtuResponses     atomic.Uint64
	pmtuInvalid       atomic.Uint64
}

type MultiplexedPacketConfig struct {
	Connection       net.PacketConn
	MaximumPMTU      uint16
	ApplicationQueue int
	ResponseTimeout  time.Duration
	MaximumChannels  int
}

// PMTURegistration owns one attempt's PMTU authority without owning the
// daemon-wide socket.
type PMTURegistration struct {
	owner   *MultiplexedPacketConn
	keyMu   sync.Mutex
	key     []byte
	attempt uint64
	network uint64

	exchangeMu sync.Mutex
	remoteMu   sync.Mutex
	remote     PMTURemoteBinding
	pendingMu  sync.Mutex
	pending    *pendingPMTU
	closeOnce  sync.Once
	done       chan struct{}
}

func NewMultiplexedPacketConn(config MultiplexedPacketConfig) (*MultiplexedPacketConn, error) {
	if nilPacketConn(config.Connection) || config.MaximumPMTU < 1200 || config.ApplicationQueue < 1 || config.ApplicationQueue > 4096 || config.ResponseTimeout <= 0 || config.MaximumChannels < 1 || config.MaximumChannels > 4096 {
		return nil, ErrInvalid
	}
	connection := &MultiplexedPacketConn{
		connection: config.Connection, maximum: config.MaximumPMTU, responseTimeout: config.ResponseTimeout,
		application: make(chan sharedPacket, config.ApplicationQueue), maximumChannels: config.MaximumChannels,
		deadlineChange: make(chan struct{}), registrations: make(map[*PMTURegistration]struct{}),
		closing: make(chan struct{}), done: make(chan struct{}),
	}
	go connection.readLoop()
	return connection, nil
}

func (c *MultiplexedPacketConn) RegisterPMTU(key []byte, attempt, network uint64) (*PMTURegistration, error) {
	if c == nil || len(key) < sha256Size || attempt == 0 || network == 0 {
		return nil, ErrInvalid
	}
	registration := &PMTURegistration{owner: c, key: append([]byte(nil), key...), attempt: attempt, network: network, done: make(chan struct{})}
	c.registrationsMu.Lock()
	defer c.registrationsMu.Unlock()
	select {
	case <-c.done:
		zeroBytes(registration.key)
		return nil, c.terminalError()
	default:
	}
	if len(c.registrations) >= c.maximumChannels {
		zeroBytes(registration.key)
		return nil, ErrPMTURegistrationLimit
	}
	c.registrations[registration] = struct{}{}
	return registration, nil
}

func (r *PMTURegistration) BindPMTURemote(binding PMTURemoteBinding) error {
	if r == nil || r.owner == nil || !binding.valid() || binding.AttemptGeneration != r.attempt || binding.NetworkGeneration != r.network {
		return ErrInvalid
	}
	r.exchangeMu.Lock()
	defer r.exchangeMu.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	r.remoteMu.Lock()
	defer r.remoteMu.Unlock()
	if r.remote.valid() && !sameAddress(r.remote.Address, binding.Address) {
		return ErrStalePMTURemote
	}
	r.remote = binding
	return nil
}

func (r *PMTURegistration) ExchangePMTU(ctx context.Context, request []byte) ([]byte, error) {
	if r == nil || r.owner == nil || ctx == nil || len(request) < 1200 || len(request) > int(r.owner.maximum) {
		return nil, ErrInvalid
	}
	r.exchangeMu.Lock()
	defer r.exchangeMu.Unlock()
	select {
	case <-r.done:
		return nil, net.ErrClosed
	default:
	}
	key := r.keyCopy()
	nonce, err := parsePMTUFrame(key, request, pmtuFrameRequest, uint16(len(request)))
	zeroBytes(key)
	if err != nil {
		return nil, err
	}
	remote := r.remoteSnapshot()
	if !remote.valid() {
		return nil, ErrInvalid
	}
	pending := &pendingPMTU{nonce: nonce, size: uint16(len(request)), remote: remote.Address, response: make(chan []byte, 1)}
	r.pendingMu.Lock()
	r.pending = pending
	r.pendingMu.Unlock()
	defer func() {
		r.pendingMu.Lock()
		if r.pending == pending {
			r.pending = nil
		}
		r.pendingMu.Unlock()
	}()
	if err := r.owner.writeInternal(ctx, request, remote.Address); err != nil {
		return nil, err
	}
	timer := time.NewTimer(r.owner.responseTimeout)
	defer timer.Stop()
	select {
	case response := <-pending.response:
		return response, nil
	case <-timer.C:
		return nil, ErrPMTUProbeUnreachable
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return nil, net.ErrClosed
	case <-r.owner.done:
		return nil, r.owner.terminalError()
	}
}

func (r *PMTURegistration) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		close(r.done)
		if r.owner != nil {
			r.owner.registrationsMu.Lock()
			delete(r.owner.registrations, r)
			r.owner.registrationsMu.Unlock()
		}
		r.pendingMu.Lock()
		r.pending = nil
		r.pendingMu.Unlock()
		r.keyMu.Lock()
		zeroBytes(r.key)
		r.key = nil
		r.keyMu.Unlock()
	})
	return nil
}

func (c *MultiplexedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
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
			return copy(buffer, packet.value), packet.address, nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, c.terminalError()
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *MultiplexedPacketConn) WriteTo(value []byte, address net.Addr) (int, error) {
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

func (c *MultiplexedPacketConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.closing)
		c.registrationsMu.RLock()
		registrations := make([]*PMTURegistration, 0, len(c.registrations))
		for registration := range c.registrations {
			registrations = append(registrations, registration)
		}
		c.registrationsMu.RUnlock()
		for _, registration := range registrations {
			_ = registration.Close()
		}
		c.closeErr = c.connection.Close()
		if errors.Is(c.closeErr, net.ErrClosed) {
			c.closeErr = nil
		}
		<-c.done
	})
	return c.closeErr
}

func (c *MultiplexedPacketConn) LocalAddr() net.Addr { return c.connection.LocalAddr() }

func (c *MultiplexedPacketConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func (c *MultiplexedPacketConn) SetReadDeadline(deadline time.Time) error {
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

func (c *MultiplexedPacketConn) SetWriteDeadline(deadline time.Time) error {
	if c == nil {
		return ErrInvalid
	}
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *MultiplexedPacketConn) readLoop() {
	buffer := make([]byte, 65535)
	for {
		count, address, err := c.connection.ReadFrom(buffer)
		if err != nil {
			if transientPacketReadError(err) {
				continue
			}
			c.finish(err)
			return
		}
		value := append([]byte(nil), buffer[:count]...)
		c.datagramsReceived.Add(1)
		handled, handleErr := c.handlePMTU(value, address)
		if handleErr != nil {
			zeroBytes(value)
			c.finish(handleErr)
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

func transientPacketReadError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}

func (c *MultiplexedPacketConn) handlePMTU(value []byte, address net.Addr) (bool, error) {
	if len(value) < 1200 || len(value) > int(c.maximum) || string(value[:4]) != string(pmtuFrameMagic[:]) {
		return false, nil
	}
	c.registrationsMu.RLock()
	registrations := make([]*PMTURegistration, 0, len(c.registrations))
	for registration := range c.registrations {
		registrations = append(registrations, registration)
	}
	c.registrationsMu.RUnlock()
	size := uint16(len(value))
	for _, registration := range registrations {
		key := registration.keyCopy()
		if len(key) == 0 {
			continue
		}
		nonce, requestErr := parsePMTUFrame(key, value, pmtuFrameRequest, size)
		if requestErr == nil {
			c.pmtuRequests.Add(1)
			response, err := buildPMTUFrame(key, pmtuFrameResponse, size, nonce)
			zeroBytes(key)
			if err != nil {
				return true, err
			}
			defer zeroBytes(response)
			return true, c.writeInternal(context.Background(), response, address)
		}
		nonce, responseErr := parsePMTUFrame(key, value, pmtuFrameResponse, size)
		zeroBytes(key)
		if responseErr != nil {
			continue
		}
		c.pmtuResponses.Add(1)
		registration.pendingMu.Lock()
		pending := registration.pending
		if pending != nil && pending.size == size && pending.nonce == nonce && sameAddress(pending.remote, address) {
			select {
			case pending.response <- append([]byte(nil), value...):
			default:
			}
		}
		registration.pendingMu.Unlock()
		return true, nil
	}
	c.pmtuInvalid.Add(1)
	return false, nil
}

func (c *MultiplexedPacketConn) writeInternal(ctx context.Context, value []byte, address net.Addr) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(c.responseTimeout)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	if err := c.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	count, err := c.connection.WriteTo(value, address)
	clearErr := c.connection.SetWriteDeadline(time.Time{})
	if err == nil && count != len(value) {
		err = errors.New("short shared UDP datagram write")
	}
	if err == nil {
		c.pmtuWrites.Add(1)
	}
	return errors.Join(err, clearErr)
}

func (c *MultiplexedPacketConn) finish(err error) {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.mu.Unlock()
	c.doneOnce.Do(func() { close(c.done) })
}

func (c *MultiplexedPacketConn) terminalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	return net.ErrClosed
}

func (c *MultiplexedPacketConn) readDeadlineSnapshot() (time.Time, <-chan struct{}) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline, c.deadlineChange
}

func (c *MultiplexedPacketConn) writeDeadlineSnapshot() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func (r *PMTURegistration) keyCopy() []byte {
	if r == nil {
		return nil
	}
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	return append([]byte(nil), r.key...)
}

func (r *PMTURegistration) remoteSnapshot() PMTURemoteBinding {
	r.remoteMu.Lock()
	defer r.remoteMu.Unlock()
	return r.remote
}
