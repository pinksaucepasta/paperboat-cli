// Package resumablestream provides an ordered, acknowledged byte stream that
// can replace its encrypted carrier without exposing framing to applications.
package resumablestream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	frameData byte = iota + 1
	frameAck
	frameFIN
	frameReset
	frameFINAck
	frameCommit
	frameCommitAck
	frameConfirm
	frameDiscard
	frameDiscardAck
	maximumFrame = 32 << 10
	headerSize   = 13
)

var (
	ErrInvalid  = errors.New("invalid resumable stream")
	ErrProtocol = errors.New("resumable stream protocol violation")
)

type Config struct {
	WindowBytes     int
	Role            Role
	Identity        StreamIdentity
	DetachedTimeout time.Duration
}

type carrierState uint8

type applicationDisposition uint8

const (
	carrierProvisional carrierState = iota + 1
	carrierPrepared
	carrierCommitting
	carrierActive
	carrierRetained
	carrierSuperseded
	carrierFailed
)

const (
	applicationReject applicationDisposition = iota
	applicationAccept
	applicationIgnoreLate
)

type physicalCarrier struct {
	id      CarrierID
	epoch   uint64
	conn    net.Conn
	state   carrierState
	finSent bool
	writeMu sync.Mutex
}

type Conn struct {
	id       uint64
	ctx      context.Context
	cancel   context.CancelFunc
	window   int
	role     Role
	identity [32]byte

	transitionMu    sync.Mutex
	mu              sync.Mutex
	notify          chan struct{}
	active          *physicalCarrier
	prepared        *physicalCarrier
	retained        *physicalCarrier
	nextEpoch       uint64
	committedEpoch  uint64
	commitWait      map[CarrierID]chan error
	discardWait     map[CarrierID]chan error
	events          chan Event
	detached        bool
	detachedSeq     uint64
	detachedTimeout time.Duration

	sendBase uint64
	sendNext uint64
	send     []byte
	localFIN bool
	finSent  CarrierID
	finAcked bool

	recvNext    uint64
	recvBase    uint64
	recv        []byte
	ackCarrier  CarrierID
	ackOffset   uint64
	remoteFIN   bool
	remoteFINAt uint64

	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	terminalErr   error
	firstSendSeen bool
	firstRecvSeen bool
}

var nextDiagnosticID atomic.Uint64

func New(parent context.Context, config Config) (*Conn, error) {
	digest, identityErr := config.Identity.digest()
	if parent == nil || config.WindowBytes < maximumFrame || config.WindowBytes > 64<<20 || identityErr != nil ||
		config.Role != RoleInitiator && config.Role != RoleResponder {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(parent)
	detachedTimeout := config.DetachedTimeout
	if detachedTimeout <= 0 {
		detachedTimeout = 30 * time.Second
	}
	connection := &Conn{id: nextDiagnosticID.Add(1), ctx: ctx, cancel: cancel, window: config.WindowBytes, role: config.Role, identity: digest, notify: make(chan struct{}), events: make(chan Event, 16), commitWait: make(map[CarrierID]chan error), discardWait: make(map[CarrierID]chan error), detachedTimeout: detachedTimeout}
	go connection.watchContext()
	go connection.writeAcknowledgements()
	return connection, nil
}

func (c *Conn) AttachInitial(ctx context.Context, link net.Conn) error {
	handle, err := c.PrepareCarrier(ctx, link)
	if err != nil {
		return err
	}
	return c.PromoteCarrier(ctx, handle)
}

func (c *Conn) Recover(ctx context.Context, link net.Conn) error {
	handle, err := c.PrepareCarrier(ctx, link)
	if err != nil {
		return err
	}
	return c.PromoteCarrier(ctx, handle)
}

func (c *Conn) PrepareCarrier(ctx context.Context, link net.Conn) (CarrierHandle, error) {
	if c == nil || ctx == nil || link == nil || c.role != RoleInitiator {
		return CarrierHandle{}, ErrInvalid
	}
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()
	c.mu.Lock()
	if c.closed || c.terminalErr != nil || c.prepared != nil || c.nextEpoch == ^uint64(0) {
		c.mu.Unlock()
		_ = link.Close()
		return CarrierHandle{}, ErrProtocol
	}
	epoch := c.nextEpoch + 1
	id, err := randomCarrierID()
	if err != nil {
		c.mu.Unlock()
		_ = link.Close()
		return CarrierHandle{}, err
	}
	request := helloV2{kind: helloPrepare, digest: c.identity, carrier: id, epoch: epoch, committedEpoch: c.committedEpoch, ack: c.recvBase, fin: c.remoteFIN, finOffset: c.remoteFINAt}
	c.mu.Unlock()
	if err = writeHello(link, request); err == nil {
		var ready helloV2
		ready, err = readHello(link)
		if err == nil && (ready.kind != helloReady || ready.digest != c.identity || ready.carrier != id || ready.epoch != epoch) {
			err = ErrProtocol
		}
		if err == nil {
			c.mu.Lock()
			if ready.ack > c.sendNext || c.closed || c.terminalErr != nil || c.prepared != nil {
				err = ErrProtocol
			} else {
				c.discardAckedLocked(ready.ack)
				c.nextEpoch = epoch
				c.prepared = &physicalCarrier{id: id, epoch: epoch, conn: link, state: carrierPrepared}
				c.detached = c.active == nil
				c.signalLocked()
			}
			c.mu.Unlock()
		}
	}
	if err != nil {
		_ = link.Close()
		return CarrierHandle{}, err
	}
	go c.readCarrier(c.prepared)
	c.emit(Event{Type: EventPrepared, PreparedCarrier: id, CommittedEpoch: c.committedEpoch})
	return CarrierHandle{ID: id, Epoch: epoch}, nil
}

func (c *Conn) AcceptCarrier(ctx context.Context, link net.Conn) error {
	if c == nil || ctx == nil || link == nil || c.role != RoleResponder {
		return ErrInvalid
	}
	c.transitionMu.Lock()
	request, err := readHello(link)
	if err != nil || request.kind != helloPrepare || request.digest != c.identity {
		c.transitionMu.Unlock()
		_ = link.Close()
		if err != nil {
			return err
		}
		return ErrProtocol
	}
	c.mu.Lock()
	if c.closed || c.terminalErr != nil || request.committedEpoch != c.committedEpoch || request.epoch <= c.committedEpoch || request.epoch <= c.nextEpoch || request.ack > c.sendNext {
		c.mu.Unlock()
		c.transitionMu.Unlock()
		_ = link.Close()
		return ErrProtocol
	}
	old := c.prepared
	if old != nil {
		if old.state == carrierCommitting || old.epoch >= request.epoch {
			c.mu.Unlock()
			c.transitionMu.Unlock()
			_ = link.Close()
			return ErrProtocol
		}
		if old.state != carrierPrepared && old.state != carrierProvisional {
			c.mu.Unlock()
			c.transitionMu.Unlock()
			_ = link.Close()
			return ErrProtocol
		}
		old.state = carrierSuperseded
		c.prepared = nil
	}
	c.discardAckedLocked(request.ack)
	carrier := &physicalCarrier{id: request.carrier, epoch: request.epoch, conn: link, state: carrierProvisional}
	c.nextEpoch = request.epoch
	c.prepared = carrier
	ready := helloV2{kind: helloReady, digest: c.identity, carrier: request.carrier, epoch: request.epoch, committedEpoch: c.committedEpoch, ack: c.recvBase, fin: c.remoteFIN, finOffset: c.remoteFINAt}
	c.signalLocked()
	c.mu.Unlock()
	if err := writeHello(link, ready); err != nil {
		c.mu.Lock()
		if c.prepared == carrier && carrier.state == carrierProvisional {
			c.prepared = nil
			carrier.state = carrierFailed
			c.signalLocked()
		}
		c.mu.Unlock()
		c.transitionMu.Unlock()
		if old != nil {
			_ = old.conn.Close()
		}
		_ = link.Close()
		return err
	}
	c.mu.Lock()
	if c.prepared != carrier || carrier.state != carrierProvisional {
		c.mu.Unlock()
		c.transitionMu.Unlock()
		if old != nil {
			_ = old.conn.Close()
		}
		_ = link.Close()
		return ErrProtocol
	}
	carrier.state = carrierPrepared
	committedEpoch := c.committedEpoch
	c.mu.Unlock()
	c.transitionMu.Unlock()
	if old != nil {
		_ = old.conn.Close()
	}
	go c.readCarrier(carrier)
	c.emit(Event{Type: EventPrepared, PreparedCarrier: carrier.id, CommittedEpoch: committedEpoch})
	return nil
}

func (c *Conn) PromoteCarrier(ctx context.Context, handle CarrierHandle) error {
	if c == nil || ctx == nil || c.role != RoleInitiator || handle.ID == (CarrierID{}) || handle.Epoch == 0 {
		return ErrInvalid
	}
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()
	c.mu.Lock()
	carrier := c.prepared
	if carrier == nil || carrier.id != handle.ID || carrier.epoch != handle.Epoch || carrier.state != carrierPrepared && carrier.state != carrierCommitting {
		c.mu.Unlock()
		return ErrProtocol
	}
	carrier.state = carrierCommitting
	waitCommit := c.commitWait[carrier.id]
	if waitCommit == nil {
		waitCommit = make(chan error, 1)
		c.commitWait[carrier.id] = waitCommit
	}
	c.mu.Unlock()
	if err := c.writeControl(carrier, frameCommit); err != nil {
		c.failCarrier(carrier, err)
		return err
	}
	select {
	case err := <-waitCommit:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
	c.mu.Lock()
	delete(c.commitWait, carrier.id)
	if c.active != carrier || carrier.state != carrierActive || c.committedEpoch != carrier.epoch {
		c.mu.Unlock()
		return ErrProtocol
	}
	c.mu.Unlock()
	// COMMIT_ACK is the authoritative promotion boundary. CONFIRM only lets the
	// peer retire the previous carrier, so a failed path must not block the
	// coordinator from promoting the next prepared carrier.
	go c.confirmCarrier(carrier)
	c.emit(Event{Type: EventActive, ActiveCarrier: carrier.id, CommittedEpoch: carrier.epoch})
	return nil
}

func (c *Conn) confirmCarrier(carrier *physicalCarrier) {
	if c.writeControl(carrier, frameConfirm) == nil {
		c.mu.Lock()
		var old *physicalCarrier
		if c.active == carrier {
			old = c.retained
			c.retained = nil
		}
		c.mu.Unlock()
		if old != nil {
			_ = old.conn.Close()
		}
	}
	c.writeActive(carrier, 0)
}

func (c *Conn) Events() <-chan Event {
	if c == nil {
		return nil
	}
	return c.events
}

func (c *Conn) DropPrepared(ctx context.Context, handle CarrierHandle) error {
	if c == nil || handle.ID == (CarrierID{}) {
		return ErrInvalid
	}
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()
	c.mu.Lock()
	if c.prepared == nil || c.prepared.id != handle.ID || c.prepared.state == carrierCommitting {
		c.mu.Unlock()
		return ErrProtocol
	}
	carrier := c.prepared
	waitDiscard := make(chan error, 1)
	c.discardWait[carrier.id] = waitDiscard
	c.mu.Unlock()
	if err := c.writeControl(carrier, frameDiscard); err != nil {
		c.failCarrier(carrier, err)
		return err
	}
	select {
	case err := <-waitDiscard:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
	_ = carrier.conn.Close()
	return nil
}

func (c *Conn) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.ctx.Done()
}

// Abort terminates the logical stream itself. Carrier failures must use
// failLink instead so an authenticated standby can preserve the application.
func (c *Conn) Abort(reason error) {
	if c == nil {
		return
	}
	if reason == nil {
		reason = net.ErrClosed
	}
	c.failTerminal(reason)
}

func (c *Conn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.recv) > 0 {
			n := copy(buffer, c.recv)
			c.recv = c.recv[n:]
			c.recvBase += uint64(n)
			c.signalLocked()
			c.mu.Unlock()
			return n, nil
		}
		if c.remoteFIN && c.recvNext >= c.remoteFINAt {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.terminalErr != nil || c.closed {
			err := c.terminalErr
			if err == nil {
				err = net.ErrClosed
			}
			c.mu.Unlock()
			return 0, err
		}
		notify, deadline := c.notify, c.readDeadline
		c.mu.Unlock()
		if err := wait(c.ctx, notify, deadline); err != nil {
			return 0, err
		}
	}
}

func (c *Conn) writeAcknowledgements() {
	for {
		c.mu.Lock()
		carrier, offset := c.active, c.recvBase
		if carrier == nil || c.ackCarrier == carrier.id && c.ackOffset >= offset {
			notify := c.notify
			c.mu.Unlock()
			if err := wait(c.ctx, notify, time.Time{}); err != nil {
				return
			}
			continue
		}
		c.mu.Unlock()
		if err := c.writeFrame(carrier, frameAck, offset, nil); err != nil {
			c.failCarrier(carrier, err)
			continue
		}
		c.mu.Lock()
		if c.active == carrier {
			c.ackCarrier = carrier.id
			if offset > c.ackOffset {
				c.ackOffset = offset
			}
		}
		c.mu.Unlock()
	}
}

func (c *Conn) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(data) {
		c.mu.Lock()
		if c.localFIN || c.closed || c.terminalErr != nil {
			err := c.terminalErr
			if err == nil {
				err = net.ErrClosed
			}
			c.mu.Unlock()
			return written, err
		}
		available := c.window - len(c.send)
		if available > 0 {
			n := min(available, len(data)-written)
			c.send = append(c.send, data[written:written+n]...)
			c.sendNext += uint64(n)
			written += n
			c.signalLocked()
			c.mu.Unlock()
			continue
		}
		notify, deadline := c.notify, c.writeDeadline
		c.mu.Unlock()
		if err := wait(c.ctx, notify, deadline); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *Conn) CloseWrite() error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.terminalErr != nil {
		return net.ErrClosed
	}
	c.localFIN = true
	slog.Info("resumable local FIN requested", "stream_instance", c.id, "send_base", c.sendBase, "send_next", c.sendNext, "pending_bytes", len(c.send), "epoch", c.committedEpoch)
	c.signalLocked()
	return nil
}

// WaitAcknowledged waits until the peer has consumed every byte accepted by
// Write. It is the graceful application-close boundary used before Close.
func (c *Conn) WaitAcknowledged(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalid
	}
	for {
		c.mu.Lock()
		if len(c.send) == 0 {
			c.mu.Unlock()
			return nil
		}
		if c.closed || c.terminalErr != nil {
			err := c.terminalErr
			if err == nil {
				err = net.ErrClosed
			}
			c.mu.Unlock()
			return err
		}
		notify := c.notify
		c.mu.Unlock()
		select {
		case <-notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// WaitWriteClosed waits until all accepted bytes are acknowledged and the FIN
// has been written on the current carrier. Callers may then close the carrier
// without racing a graceful half-close into a reset at the peer.
func (c *Conn) WaitWriteClosed(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrInvalid
	}
	for {
		c.mu.Lock()
		if c.localFIN && len(c.send) == 0 && c.finAcked {
			c.mu.Unlock()
			return nil
		}
		if c.closed || c.terminalErr != nil {
			err := c.terminalErr
			if err == nil {
				err = net.ErrClosed
			}
			c.mu.Unlock()
			return err
		}
		notify := c.notify
		c.mu.Unlock()
		select {
		case <-notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	carriers := c.detachAllLocked()
	graceful := c.localFIN && len(c.send) == 0 && c.finAcked || c.remoteFIN && c.recvNext >= c.remoteFINAt
	c.signalLocked()
	c.mu.Unlock()
	// Wake carrier workers before waiting for their Close methods. During a
	// path transition a carrier may be blocked on this logical stream's
	// context; waiting to cancel until after Close would retain the owner
	// lease indefinitely.
	c.cancel()
	for _, carrier := range carriers {
		if carrier == nil {
			continue
		}
		if !graceful {
			_ = carrier.conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = c.writeFrame(carrier, frameReset, 0, nil)
		}
		_ = carrier.conn.Close()
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return streamAddr("local") }
func (c *Conn) RemoteAddr() net.Addr { return streamAddr("peer") }
func (c *Conn) SetDeadline(value time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = value, value
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *Conn) SetReadDeadline(value time.Time) error {
	c.mu.Lock()
	c.readDeadline = value
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *Conn) SetWriteDeadline(value time.Time) error {
	c.mu.Lock()
	c.writeDeadline = value
	c.signalLocked()
	c.mu.Unlock()
	return nil
}

func (c *Conn) readCarrier(carrier *physicalCarrier) {
	for {
		kind, sequence, payload, err := readFrame(carrier.conn)
		if err != nil {
			c.failCarrier(carrier, err)
			return
		}
		c.mu.Lock()
		superseded := carrier.state == carrierSuperseded || carrier.state == carrierFailed
		c.mu.Unlock()
		if superseded {
			_ = carrier.conn.Close()
			return
		}
		switch kind {
		case frameData:
			if disposition := c.applicationDisposition(carrier); disposition != applicationAccept {
				if disposition == applicationIgnoreLate {
					continue
				}
				c.failFrameProtocol(carrier, kind, sequence, "data_carrier_not_application")
				return
			}
			c.mu.Lock()
			if !c.firstRecvSeen {
				c.firstRecvSeen = true
				slog.Info("resumable first data received", "stream_instance", c.id, "epoch", carrier.epoch, "sequence", sequence, "bytes", len(payload))
			}
			if sequence > c.recvNext {
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "data_sequence_gap")
				return
			}
			if end := sequence + uint64(len(payload)); end > c.recvNext {
				start := c.recvNext - sequence
				if len(c.recv)+len(payload)-int(start) > c.window {
					c.mu.Unlock()
					c.failFrameProtocol(carrier, kind, sequence, "data_window_exceeded")
					return
				}
				c.recv = append(c.recv, payload[int(start):]...)
				c.recvNext = end
				c.signalLocked()
			}
			c.mu.Unlock()
		case frameAck:
			if disposition := c.applicationDisposition(carrier); disposition != applicationAccept {
				if disposition == applicationIgnoreLate {
					continue
				}
				c.failFrameProtocol(carrier, kind, sequence, "ack_carrier_not_application")
				return
			}
			c.mu.Lock()
			if sequence > c.sendNext {
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "ack_beyond_send_next")
				return
			}
			c.discardAckedLocked(sequence)
			c.signalLocked()
			c.mu.Unlock()
		case frameFIN:
			if disposition := c.applicationDisposition(carrier); disposition != applicationAccept {
				if disposition == applicationIgnoreLate {
					continue
				}
				c.failFrameProtocol(carrier, kind, sequence, "fin_carrier_not_application")
				return
			}
			c.mu.Lock()
			if sequence < c.recvNext || c.remoteFIN && sequence == c.remoteFINAt {
				c.mu.Unlock()
				continue
			}
			if sequence > c.recvNext || c.remoteFIN {
				slog.Warn("resumable remote FIN sequence mismatch", "stream_instance", c.id, "epoch", carrier.epoch, "sequence", sequence, "recv_next", c.recvNext, "recv_base", c.recvBase, "buffered_bytes", len(c.recv))
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "fin_sequence_mismatch")
				return
			}
			c.remoteFIN, c.remoteFINAt = true, sequence
			slog.Info("resumable remote FIN received", "stream_instance", c.id, "epoch", carrier.epoch, "sequence", sequence, "recv_base", c.recvBase, "buffered_bytes", len(c.recv))
			c.signalLocked()
			c.mu.Unlock()
			// Keep receiving while the final acknowledgement is serialized. If
			// both peers finish together, synchronously writing FINAck here can
			// deadlock both receive loops behind application ACK writes on a
			// backpressured full-duplex carrier.
			go func() {
				if err := c.writeFrame(carrier, frameFINAck, sequence, nil); err != nil {
					c.failCarrier(carrier, err)
				}
			}()
		case frameFINAck:
			if disposition := c.applicationDisposition(carrier); disposition != applicationAccept {
				if disposition == applicationIgnoreLate {
					continue
				}
				c.failFrameProtocol(carrier, kind, sequence, "fin_ack_carrier_not_application")
				return
			}
			c.mu.Lock()
			if !c.localFIN || sequence != c.sendNext {
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "fin_ack_state_mismatch")
				return
			}
			c.finAcked = true
			c.signalLocked()
			c.mu.Unlock()
		case frameReset:
			c.mu.Lock()
			finished := c.remoteFIN && c.recvNext >= c.remoteFINAt
			c.mu.Unlock()
			if finished {
				return
			}
			c.failTerminal(net.ErrClosed)
			return
		case frameCommit:
			if c.role != RoleResponder || sequence != carrier.epoch || len(payload) != 0 {
				c.failFrameProtocol(carrier, kind, sequence, "commit_shape_or_role")
				return
			}
			c.transitionMu.Lock()
			c.mu.Lock()
			if carrier.state == carrierSuperseded || carrier.state == carrierFailed {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				_ = carrier.conn.Close()
				return
			}
			if c.active == carrier && c.committedEpoch == carrier.epoch {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				if err := c.writeControl(carrier, frameCommitAck); err != nil {
					c.failCarrier(carrier, err)
					return
				}
				continue
			}
			if c.prepared != carrier || carrier.state != carrierPrepared && carrier.state != carrierCommitting {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "commit_carrier_not_prepared")
				return
			}
			old := c.active
			if old != nil {
				old.state = carrierRetained
			}
			c.retained, c.active, c.prepared = old, carrier, nil
			carrier.state = carrierActive
			c.committedEpoch = carrier.epoch
			c.detached = false
			c.signalLocked()
			c.mu.Unlock()
			c.transitionMu.Unlock()
			if err := c.writeControl(carrier, frameCommitAck); err != nil {
				c.failCarrier(carrier, err)
				return
			}
			go c.writeActive(carrier, 0)
			c.emit(Event{Type: EventActive, ActiveCarrier: carrier.id, CommittedEpoch: carrier.epoch})
		case frameCommitAck:
			if c.role != RoleInitiator || sequence != carrier.epoch || len(payload) != 0 {
				c.failFrameProtocol(carrier, kind, sequence, "commit_ack_shape_or_role")
				return
			}
			c.mu.Lock()
			if c.prepared != carrier || carrier.state != carrierCommitting {
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "commit_ack_carrier_not_committing")
				return
			}
			old := c.active
			if old != nil {
				old.state = carrierRetained
			}
			c.retained, c.active, c.prepared = old, carrier, nil
			carrier.state = carrierActive
			c.committedEpoch = carrier.epoch
			c.detached = false
			c.signalLocked()
			commit := c.commitWait[carrier.id]
			c.mu.Unlock()
			if commit != nil {
				select {
				case commit <- nil:
				default:
				}
			}
		case frameConfirm:
			if c.role != RoleResponder || sequence != carrier.epoch || len(payload) != 0 {
				c.failFrameProtocol(carrier, kind, sequence, "confirm_shape_or_role")
				return
			}
			c.transitionMu.Lock()
			c.mu.Lock()
			if carrier.state == carrierSuperseded || carrier.state == carrierFailed {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				_ = carrier.conn.Close()
				return
			}
			if c.retained != nil {
				old := c.retained
				c.retained = nil
				c.mu.Unlock()
				c.transitionMu.Unlock()
				_ = old.conn.Close()
			} else {
				c.mu.Unlock()
				c.transitionMu.Unlock()
			}
		case frameDiscard:
			if c.role != RoleResponder || sequence != carrier.epoch || len(payload) != 0 {
				c.failFrameProtocol(carrier, kind, sequence, "discard_shape_or_role")
				return
			}
			c.transitionMu.Lock()
			c.mu.Lock()
			if carrier.state == carrierSuperseded || carrier.state == carrierFailed {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				_ = carrier.conn.Close()
				return
			}
			if c.prepared != carrier || carrier.state != carrierPrepared {
				c.mu.Unlock()
				c.transitionMu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "discard_carrier_not_prepared")
				return
			}
			c.prepared = nil
			c.signalLocked()
			c.mu.Unlock()
			c.transitionMu.Unlock()
			if err := c.writeControl(carrier, frameDiscardAck); err != nil {
				_ = carrier.conn.Close()
				return
			}
			_ = carrier.conn.Close()
			return
		case frameDiscardAck:
			if c.role != RoleInitiator || sequence != carrier.epoch || len(payload) != 0 {
				c.failFrameProtocol(carrier, kind, sequence, "discard_ack_shape_or_role")
				return
			}
			c.mu.Lock()
			if c.prepared != carrier || carrier.state != carrierPrepared {
				c.mu.Unlock()
				c.failFrameProtocol(carrier, kind, sequence, "discard_ack_carrier_not_prepared")
				return
			}
			c.prepared = nil
			waiter := c.discardWait[carrier.id]
			delete(c.discardWait, carrier.id)
			c.signalLocked()
			c.mu.Unlock()
			if waiter != nil {
				select {
				case waiter <- nil:
				default:
				}
			}
		default:
			c.failFrameProtocol(carrier, kind, sequence, "unknown_frame")
			return
		}
	}
}

func (c *Conn) failFrameProtocol(carrier *physicalCarrier, kind byte, sequence uint64, stage string) {
	c.mu.Lock()
	state, epoch, committed := carrierFailed, uint64(0), c.committedEpoch
	if carrier != nil {
		state, epoch = carrier.state, carrier.epoch
	}
	c.mu.Unlock()
	c.failTerminal(fmt.Errorf("%w: stage=%s frame=%d sequence=%d carrier_epoch=%d carrier_state=%d committed_epoch=%d", ErrProtocol, stage, kind, sequence, epoch, state, committed))
}

func (c *Conn) applicationDisposition(carrier *physicalCarrier) applicationDisposition {
	c.mu.Lock()
	defer c.mu.Unlock()
	if carrier == nil {
		return applicationReject
	}
	if c.active == carrier && carrier.state == carrierActive || c.retained == carrier && carrier.state == carrierRetained {
		return applicationAccept
	}
	// A COMMIT can retire the old active carrier while its read loop already
	// holds a queued frame. That orphaned carrier is no longer authoritative;
	// discard its late frame just as for an explicitly retained/superseded one.
	if carrier.state == carrierRetained || carrier.state == carrierSuperseded || carrier.state == carrierFailed || carrier.state == carrierActive && c.active != carrier {
		return applicationIgnoreLate
	}
	return applicationReject
}

func (c *Conn) writeActive(carrier *physicalCarrier, offset uint64) {
	for {
		c.mu.Lock()
		if c.active != carrier || c.closed || c.terminalErr != nil {
			c.mu.Unlock()
			return
		}
		if offset < c.sendBase {
			offset = c.sendBase
		}
		if offset < c.sendNext {
			start := offset - c.sendBase
			n := min(maximumFrame, len(c.send)-int(start))
			payload := append([]byte(nil), c.send[int(start):int(start)+n]...)
			sequence := offset
			offset += uint64(n)
			c.mu.Unlock()
			if err := c.writeFrame(carrier, frameData, sequence, payload); err != nil {
				c.failCarrier(carrier, err)
				return
			}
			continue
		}
		if c.localFIN && !c.finAcked && c.finSent != carrier.id {
			sequence := c.sendNext
			c.mu.Unlock()
			if err := c.writeFrame(carrier, frameFIN, sequence, nil); err != nil {
				c.failCarrier(carrier, err)
				return
			}
			slog.Info("resumable active FIN sent", "stream_instance", c.id, "epoch", carrier.epoch, "sequence", sequence)
			c.mu.Lock()
			if c.active == carrier {
				c.finSent = carrier.id
				c.signalLocked()
			}
			c.mu.Unlock()
			continue
		}
		notify := c.notify
		c.mu.Unlock()
		if err := wait(c.ctx, notify, time.Time{}); err != nil {
			return
		}
	}
}

func (c *Conn) writeControl(carrier *physicalCarrier, kind byte) error {
	return c.writeFrame(carrier, kind, carrier.epoch, nil)
}
func (c *Conn) writeFrame(carrier *physicalCarrier, kind byte, sequence uint64, payload []byte) error {
	if carrier == nil || carrier.conn == nil {
		return net.ErrClosed
	}
	carrier.writeMu.Lock()
	defer carrier.writeMu.Unlock()
	var header [headerSize]byte
	header[0] = kind
	binary.BigEndian.PutUint64(header[1:9], sequence)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(payload)))
	if err := writeAll(carrier.conn, header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		return writeAll(carrier.conn, payload)
	}
	return nil
}

func readFrame(link net.Conn) (byte, uint64, []byte, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(link, header[:]); err != nil {
		return 0, 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[9:13])
	if size > maximumFrame || header[0] < frameData || header[0] > frameDiscardAck || header[0] != frameData && size != 0 {
		return 0, 0, nil, ErrProtocol
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(link, payload); err != nil {
		return 0, 0, nil, err
	}
	return header[0], binary.BigEndian.Uint64(header[1:9]), payload, nil
}

func (c *Conn) discardAckedLocked(offset uint64) {
	if offset <= c.sendBase {
		return
	}
	n := offset - c.sendBase
	clear(c.send[:int(n)])
	c.send = c.send[int(n):]
	c.sendBase = offset
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func (c *Conn) failCarrier(carrier *physicalCarrier, err error) {
	if carrier == nil {
		return
	}
	if c.role == RoleResponder {
		c.transitionMu.Lock()
		defer c.transitionMu.Unlock()
	}
	c.mu.Lock()
	active := c.active == carrier
	var detachedSequence uint64
	prepared := c.prepared == carrier
	retained := c.retained == carrier
	if !active && !prepared && !retained {
		c.mu.Unlock()
		return
	}
	if active {
		c.active = nil
		if !c.detached {
			c.detached = true
			c.detachedSeq++
		}
		detachedSequence = c.detachedSeq
	}
	if prepared {
		c.prepared = nil
	}
	if retained {
		c.retained = nil
	}
	carrier.state = carrierFailed
	if waiter := c.commitWait[carrier.id]; waiter != nil {
		delete(c.commitWait, carrier.id)
		select {
		case waiter <- err:
		default:
		}
	}
	if waiter := c.discardWait[carrier.id]; waiter != nil {
		delete(c.discardWait, carrier.id)
		select {
		case waiter <- err:
		default:
		}
	}
	event := Event{Type: EventCarrierFailed, FailedCarrier: carrier.id, CommittedEpoch: c.committedEpoch, Err: err}
	if active {
		event.Type = EventDetached
	}
	if c.active != nil {
		event.ActiveCarrier = c.active.id
	}
	if c.prepared != nil {
		event.PreparedCarrier = c.prepared.id
	}
	c.signalLocked()
	c.mu.Unlock()
	_ = carrier.conn.Close()
	c.emit(event)
	if active {
		go c.expireDetached(detachedSequence)
	}
}

func (c *Conn) expireDetached(sequence uint64) {
	timer := time.NewTimer(c.detachedTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		c.mu.Lock()
		expired := c.detached && c.detachedSeq == sequence && c.active == nil && c.terminalErr == nil && !c.closed
		c.mu.Unlock()
		if expired {
			c.failTerminal(errors.New("resumable stream detached recovery expired"))
		}
	case <-c.ctx.Done():
	}
}

func (c *Conn) watchContext() {
	<-c.ctx.Done()
	c.mu.Lock()
	if !c.closed && c.terminalErr == nil {
		c.terminalErr = context.Cause(c.ctx)
	}
	carriers := c.detachAllLocked()
	c.signalLocked()
	c.mu.Unlock()
	for _, carrier := range carriers {
		if carrier != nil {
			_ = carrier.conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = c.writeFrame(carrier, frameReset, 0, nil)
			_ = carrier.conn.Close()
		}
	}
}

func (c *Conn) failTerminal(err error) {
	c.mu.Lock()
	if c.terminalErr == nil {
		c.terminalErr = err
	}
	carriers := c.detachAllLocked()
	slog.Warn("resumable logical stream failed", "stream_instance", c.id, "committed_epoch", c.committedEpoch, "send_base", c.sendBase, "send_next", c.sendNext, "recv_base", c.recvBase, "recv_next", c.recvNext, "local_fin", c.localFIN, "remote_fin", c.remoteFIN, "error", err)
	c.signalLocked()
	c.mu.Unlock()
	c.cancel()
	for _, carrier := range carriers {
		if carrier != nil {
			_ = carrier.conn.Close()
		}
	}
	c.emit(Event{Type: EventAborted, CommittedEpoch: c.committedEpoch, Err: err})
}

func (c *Conn) detachAllLocked() []*physicalCarrier {
	result := []*physicalCarrier{c.active, c.prepared, c.retained}
	c.active, c.prepared, c.retained = nil, nil, nil
	return result
}

func (c *Conn) emit(event Event) {
	if event.Type == EventDetached {
		select {
		case c.events <- event:
		case <-c.ctx.Done():
		}
		return
	}
	select {
	case c.events <- event:
	default:
	}
}

func (c *Conn) signalLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

func wait(ctx context.Context, notify <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-notify:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-notify:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

type streamAddr string

func (streamAddr) Network() string  { return "paperboat-resumable" }
func (a streamAddr) String() string { return string(a) }

var _ net.Conn = (*Conn)(nil)
