package peerquic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	lifetimeProbeVersion  = 1
	lifetimeProbeRequest  = 1
	lifetimeProbeResponse = 2
	lifetimeProbeAck      = 3
	lifetimeProbeComplete = 4
	lifetimeProbeSize     = 30
	lifetimeProbeCancel   = quic.StreamErrorCode(0x5042)
)

var lifetimeProbeMagic = [4]byte{'P', 'B', 'L', 'P'}
var ErrLifetimeProbeUnreachable = errors.New("QUIC lifetime probe unreachable after idle")

type probeStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

// ProbeAfterIdle leaves the authenticated probe-only QUIC connection silent,
// then performs one nonce-bound exchange. The peer must call ServeLifetimeProbe.
func (s *Session) ProbeAfterIdle(ctx context.Context, idle time.Duration) (time.Time, error) {
	if s == nil || s.Connection == nil || ctx == nil || idle <= 0 {
		return time.Time{}, errors.New("invalid QUIC lifetime probe")
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	}
	stream, err := s.Connection.OpenStreamSync(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("open lifetime probe stream: %w", err)
	}
	defer stream.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return time.Time{}, fmt.Errorf("generate lifetime probe nonce: %w", err)
	}
	if err := exchangeLifetimeProbeIdle(ctx, stream, nonce, idle); err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC(), nil
}

// ServeLifetimeProbe accepts and authenticates exactly one probe-control
// exchange on an endpoint-authenticated probe-only connection.
func (s *Session) ServeLifetimeProbe(ctx context.Context) error {
	if s == nil || s.Connection == nil || ctx == nil {
		return errors.New("invalid QUIC lifetime probe server")
	}
	stream, err := s.Connection.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept lifetime probe stream: %w", err)
	}
	defer stream.Close()
	return serveLifetimeProbe(ctx, stream)
}

// HealthExchange performs one authenticated nonce-bound control exchange and
// reports PTO expirations observed locally during it.
func (s *Session) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	if s == nil || s.Connection == nil || s.pto == nil || ctx == nil {
		return 0, errors.New("invalid QUIC health exchange")
	}
	before := s.pto.total.Load()
	stream, err := s.Connection.OpenStreamSync(ctx)
	if err != nil {
		return 0, fmt.Errorf("open health exchange stream: %w", err)
	}
	if err := exchangeLifetimeProbe(ctx, stream, nonce); err != nil {
		stream.CancelRead(lifetimeProbeCancel)
		stream.CancelWrite(lifetimeProbeCancel)
		_ = stream.Close()
		return 0, err
	}
	stream.CancelRead(0)
	// The responder may close the probe-only connection immediately after its
	// authenticated completion frame. Cleanup after that proof must not turn a
	// successful exchange into a reachability failure.
	_ = stream.Close()
	return s.pto.total.Load() - before, nil
}

func (s *Session) ServeHealthExchanges(ctx context.Context, count int) error {
	if s == nil || s.Connection == nil || ctx == nil || count < 1 || count > 64 {
		return errors.New("invalid QUIC health exchange server")
	}
	for range count {
		if err := s.ServeLifetimeProbe(ctx); err != nil {
			return err
		}
	}
	return nil
}

func exchangeLifetimeProbe(ctx context.Context, stream probeStream, nonce [16]byte) error {
	return exchangeLifetimeProbeIdle(ctx, stream, nonce, 0)
}

func exchangeLifetimeProbeIdle(ctx context.Context, stream probeStream, nonce [16]byte, idle time.Duration) error {
	if idle < 0 || idle > 5*time.Minute || idle%time.Millisecond != 0 {
		return errors.New("invalid lifetime probe idle duration")
	}
	stop, err := bindProbeContext(ctx, stream)
	if err != nil {
		return err
	}
	defer stop()
	request := lifetimeFrameWithIdle(lifetimeProbeRequest, nonce, idle)
	if err := writeFull(stream, request[:]); err != nil {
		return fmt.Errorf("write lifetime probe request: %w", err)
	}
	var response [lifetimeProbeSize]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil {
		if lifetimeResponseDeadlineExceeded(ctx, err) {
			return errors.Join(ErrLifetimeProbeUnreachable, fmt.Errorf("read lifetime probe response: %w", err))
		}
		return fmt.Errorf("read lifetime probe response: %w", err)
	}
	responseNonce, responseIdle, err := parseLifetimeFrameWithIdle(response, lifetimeProbeResponse)
	if err != nil {
		return err
	}
	if responseNonce != nonce {
		return errors.New("lifetime probe nonce mismatch")
	}
	if responseIdle != idle {
		return errors.New("lifetime probe idle duration mismatch")
	}
	// An idle=0 exchange is admission health on an already mutually
	// authenticated QUIC session. The nonce-bound response proves both
	// directions; acknowledgment/completion is reserved for idle-lifetime
	// measurement where the responder must prove it observed the post-idle ack.
	if idle == 0 {
		return nil
	}
	ack := lifetimeFrameWithIdle(lifetimeProbeAck, nonce, idle)
	if err := writeFull(stream, ack[:]); err != nil {
		return fmt.Errorf("write lifetime probe acknowledgment: %w", err)
	}
	var complete [lifetimeProbeSize]byte
	if _, err := io.ReadFull(stream, complete[:]); err != nil {
		return fmt.Errorf("read lifetime probe completion: %w", err)
	}
	completeNonce, completeIdle, err := parseLifetimeFrameWithIdle(complete, lifetimeProbeComplete)
	if err != nil || completeNonce != nonce || completeIdle != idle {
		return errors.Join(errors.New("invalid lifetime probe completion"), err)
	}
	return nil
}

func lifetimeResponseDeadlineExceeded(ctx context.Context, err error) bool {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	deadline, ok := ctx.Deadline()
	var timeout net.Error
	return ok && !time.Now().Before(deadline) && errors.As(err, &timeout) && timeout.Timeout()
}

func serveLifetimeProbe(ctx context.Context, stream probeStream) error {
	stop, err := bindProbeContext(ctx, stream)
	if err != nil {
		return err
	}
	defer stop()
	var request [lifetimeProbeSize]byte
	if _, err := io.ReadFull(stream, request[:]); err != nil {
		return fmt.Errorf("read lifetime probe request: %w", err)
	}
	nonce, idle, err := parseLifetimeFrameWithIdle(request, lifetimeProbeRequest)
	if err != nil {
		return err
	}
	response := lifetimeFrameWithIdle(lifetimeProbeResponse, nonce, idle)
	if err := writeFull(stream, response[:]); err != nil {
		return fmt.Errorf("write lifetime probe response: %w", err)
	}
	if idle == 0 {
		return nil
	}
	var ack [lifetimeProbeSize]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		return fmt.Errorf("read lifetime probe acknowledgment: %w", err)
	}
	ackNonce, ackIdle, err := parseLifetimeFrameWithIdle(ack, lifetimeProbeAck)
	if err != nil || ackNonce != nonce || ackIdle != idle {
		return errors.Join(errors.New("invalid lifetime probe acknowledgment"), err)
	}
	complete := lifetimeFrameWithIdle(lifetimeProbeComplete, nonce, idle)
	if err := writeFull(stream, complete[:]); err != nil {
		return fmt.Errorf("write lifetime probe completion: %w", err)
	}
	return nil
}

func lifetimeFrame(kind byte, nonce [16]byte) [lifetimeProbeSize]byte {
	return lifetimeFrameWithIdle(kind, nonce, 0)
}

func lifetimeFrameWithIdle(kind byte, nonce [16]byte, idle time.Duration) [lifetimeProbeSize]byte {
	var frame [lifetimeProbeSize]byte
	copy(frame[:4], lifetimeProbeMagic[:])
	frame[4], frame[5] = lifetimeProbeVersion, kind
	copy(frame[6:], nonce[:])
	binary.BigEndian.PutUint64(frame[22:], uint64(idle/time.Millisecond))
	return frame
}

func parseLifetimeFrameWithIdle(frame [lifetimeProbeSize]byte, kind byte) ([16]byte, time.Duration, error) {
	if string(frame[:4]) != string(lifetimeProbeMagic[:]) || frame[4] != lifetimeProbeVersion || frame[5] != kind {
		return [16]byte{}, 0, errors.New("invalid lifetime probe frame")
	}
	var nonce [16]byte
	copy(nonce[:], frame[6:22])
	milliseconds := binary.BigEndian.Uint64(frame[22:])
	if milliseconds > uint64((5*time.Minute)/time.Millisecond) {
		return [16]byte{}, 0, errors.New("invalid lifetime probe frame")
	}
	return nonce, time.Duration(milliseconds) * time.Millisecond, nil
}

func bindProbeContext(ctx context.Context, stream probeStream) (func(), error) {
	if ctx == nil || stream == nil {
		return nil, errors.New("invalid lifetime probe stream")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(lifetimeProbeCancel)
		stream.CancelWrite(lifetimeProbeCancel)
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}, nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		value = value[written:]
	}
	return nil
}
