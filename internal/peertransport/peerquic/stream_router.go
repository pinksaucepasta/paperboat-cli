package peerquic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

var ErrStreamRouterProtocol = errors.New("peer QUIC stream router protocol failure")
var ErrStreamRouterLimit = errors.New("peer QUIC stream router limit reached")

type StreamRouterConfig struct {
	PendingConsumers    int
	MaximumClassifiers  int
	ClassificationLimit time.Duration
}

func DevelopmentStreamRouterConfig() StreamRouterConfig {
	return StreamRouterConfig{PendingConsumers: 32, MaximumClassifiers: 16, ClassificationLimit: 5 * time.Second}
}

func (c StreamRouterConfig) valid() bool {
	return c.PendingConsumers > 0 && c.PendingConsumers <= 256 && c.MaximumClassifiers > 0 && c.MaximumClassifiers <= 256 && c.ClassificationLimit > 0 && c.ClassificationLimit <= 30*time.Second
}

// RoutedStream restores bytes consumed while distinguishing an application
// stream from the reserved health-control frame.
type RoutedStream struct {
	*quic.Stream
	prefix []byte
}

func (s *RoutedStream) Read(target []byte) (int, error) {
	if len(s.prefix) > 0 && len(target) > 0 {
		count := copy(target, s.prefix)
		s.prefix = s.prefix[count:]
		return count, nil
	}
	return s.Stream.Read(target)
}

// StreamRouter is the single owner of native QUIC stream acceptance. It serves
// reserved health frames and publishes only non-health streams to consumers.
type StreamRouter struct {
	session       *Session
	config        StreamRouterConfig
	ctx           context.Context
	cancel        context.CancelFunc
	consumers     chan *RoutedStream
	classifiers   chan struct{}
	done          chan struct{}
	healthReady   chan struct{}
	healthChanged chan struct{}
	lifetime      chan time.Duration

	mu              sync.Mutex
	err             error
	closeOnce       sync.Once
	healthOnce      sync.Once
	healthCompleted atomic.Uint64
	workers         sync.WaitGroup
}

// Handoff stops stream acceptance without closing the QUIC session. It is used
// after authenticated health admission when a protocol such as HTTP/3 becomes
// the sole owner of the connection's bidirectional and unidirectional streams.
func (r *StreamRouter) Handoff() error {
	if r == nil {
		return errors.New("invalid peer QUIC stream router")
	}
	r.closeOnce.Do(r.cancel)
	<-r.done
	for stream := range r.consumers {
		_ = stream.Close()
	}
	err := r.result()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func NewStreamRouter(session *Session, config StreamRouterConfig) (*StreamRouter, error) {
	if session == nil || session.Connection == nil || !config.valid() {
		return nil, errors.New("invalid peer QUIC stream router")
	}
	ctx, cancel := context.WithCancel(context.Background())
	router := &StreamRouter{
		session: session, config: config, ctx: ctx, cancel: cancel,
		consumers:   make(chan *RoutedStream, config.PendingConsumers),
		classifiers: make(chan struct{}, config.MaximumClassifiers), done: make(chan struct{}), healthReady: make(chan struct{}), healthChanged: make(chan struct{}, 1),
		lifetime: make(chan time.Duration, 1),
	}
	go router.run()
	return router, nil
}

func (r *StreamRouter) run() {
	defer func() {
		r.workers.Wait()
		close(r.consumers)
		close(r.done)
	}()
	for {
		stream, err := r.session.Connection.AcceptStream(r.ctx)
		if err != nil {
			if r.ctx.Err() == nil {
				r.fail(err, false)
			}
			return
		}
		select {
		case r.classifiers <- struct{}{}:
			r.workers.Add(1)
			go r.classify(stream)
		default:
			stream.CancelRead(lifetimeProbeCancel)
			stream.CancelWrite(lifetimeProbeCancel)
			_ = stream.Close()
			r.fail(ErrStreamRouterLimit, true)
			return
		}
	}
}

func (r *StreamRouter) classify(stream *quic.Stream) {
	defer r.workers.Done()
	defer func() { <-r.classifiers }()
	ctx, cancel := context.WithTimeout(r.ctx, r.config.ClassificationLimit)
	defer cancel()
	stop, err := bindProbeContext(ctx, stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	var prefix [len(lifetimeProbeMagic)]byte
	_, err = io.ReadFull(stream, prefix[:])
	stop()
	clearErr := stream.SetDeadline(time.Time{})
	if err != nil {
		stream.CancelRead(lifetimeProbeCancel)
		stream.CancelWrite(lifetimeProbeCancel)
		_ = stream.Close()
		return
	}
	if clearErr != nil {
		stream.CancelRead(lifetimeProbeCancel)
		stream.CancelWrite(lifetimeProbeCancel)
		_ = stream.Close()
		r.fail(errors.Join(ErrStreamRouterProtocol, clearErr), true)
		return
	}
	if bytes.Equal(prefix[:], lifetimeProbeMagic[:]) {
		r.serveHealth(stream, prefix)
		return
	}
	routed := &RoutedStream{Stream: stream, prefix: append([]byte(nil), prefix[:]...)}
	select {
	case r.consumers <- routed:
	case <-r.ctx.Done():
		_ = routed.Close()
	}
}

func (r *StreamRouter) serveHealth(stream *quic.Stream, prefix [len(lifetimeProbeMagic)]byte) {
	ctx, cancel := context.WithTimeout(r.ctx, r.config.ClassificationLimit)
	defer cancel()
	stop, err := bindProbeContext(ctx, stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	var request [lifetimeProbeSize]byte
	copy(request[:len(prefix)], prefix[:])
	if _, err := io.ReadFull(stream, request[len(prefix):]); err != nil {
		if canceledHealthStream(err) {
			_ = stream.Close()
			return
		}
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	nonce, idle, err := parseLifetimeFrameWithIdle(request, lifetimeProbeRequest)
	if err != nil {
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	response := lifetimeFrameWithIdle(lifetimeProbeResponse, nonce, idle)
	if err := writeFull(stream, response[:]); err != nil {
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	if idle == 0 {
		stop()
		stopped = true
		if err := stream.SetDeadline(time.Time{}); err != nil {
			r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
			_ = stream.Close()
			return
		}
		// The request is an exact fixed-size frame, so no more peer bytes belong
		// to this control exchange. Close the receive half explicitly; Close only
		// closes QUIC's send half and otherwise leaks one incoming-stream credit
		// per active-health exchange.
		stream.CancelRead(0)
		_ = stream.Close()
		r.healthOnce.Do(func() { close(r.healthReady) })
		r.healthCompleted.Add(1)
		select {
		case r.healthChanged <- struct{}{}:
		default:
		}
		return
	}
	var ack [lifetimeProbeSize]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		if canceledHealthStream(err) {
			_ = stream.Close()
			return
		}
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	ackNonce, ackIdle, err := parseLifetimeFrameWithIdle(ack, lifetimeProbeAck)
	if err != nil || ackNonce != nonce || ackIdle != idle {
		r.fail(errors.Join(ErrStreamRouterProtocol, errors.New("invalid health acknowledgment"), err), true)
		_ = stream.Close()
		return
	}
	complete := lifetimeFrameWithIdle(lifetimeProbeComplete, nonce, idle)
	if err := writeFull(stream, complete[:]); err != nil {
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	// Finish ownership of the control stream before publishing completion. A
	// waiter may immediately close the router; leaving the cancellation hook
	// armed until after publication would reset an already successful stream.
	stop()
	stopped = true
	if err := stream.SetDeadline(time.Time{}); err != nil {
		r.fail(errors.Join(ErrStreamRouterProtocol, err), true)
		_ = stream.Close()
		return
	}
	stream.CancelRead(0)
	// The initiator stops reading after sending the acknowledgment, so quic-go
	// may report its receive-side cancellation from Close. The authenticated
	// acknowledgment above is the completion boundary; this close only releases
	// the responder's send half.
	_ = stream.Close()
	r.healthOnce.Do(func() { close(r.healthReady) })
	r.healthCompleted.Add(1)
	select {
	case r.healthChanged <- struct{}{}:
	default:
	}
	if idle > 0 {
		select {
		case r.lifetime <- idle:
		default:
		}
	}
}

func canceledHealthStream(err error) bool {
	var streamErr *quic.StreamError
	return errors.As(err, &streamErr) && streamErr.ErrorCode == lifetimeProbeCancel
}

// WaitInitialHealth waits for the first valid health request answered by this
// router. It is the responder-side trust admission boundary.
func (r *StreamRouter) WaitInitialHealth(ctx context.Context) error {
	return r.WaitHealthExchanges(ctx, 1)
}

// WaitHealthExchanges waits until the router has answered the requested number
// of authenticated health-control exchanges on this exact QUIC session.
func (r *StreamRouter) WaitHealthExchanges(ctx context.Context, minimum uint64) error {
	if r == nil || ctx == nil || minimum == 0 || minimum > 64 {
		return errors.New("invalid peer QUIC health readiness wait")
	}
	for {
		if r.healthCompleted.Load() >= minimum {
			return nil
		}
		select {
		case <-r.healthChanged:
		case <-r.done:
			if r.healthCompleted.Load() >= minimum {
				return nil
			}
			return r.result()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// WaitLifetimeProbe returns one authenticated, successfully answered idle
// observation from the reserved health-control stream.
func (r *StreamRouter) WaitLifetimeProbe(ctx context.Context) (time.Duration, error) {
	if r == nil || ctx == nil {
		return 0, errors.New("invalid peer QUIC lifetime wait")
	}
	select {
	case idle := <-r.lifetime:
		return idle, nil
	case <-r.done:
		return 0, r.result()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (r *StreamRouter) Owns(session *Session) bool {
	return r != nil && session != nil && r.session == session
}

func (r *StreamRouter) Accept(ctx context.Context) (*RoutedStream, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("invalid peer QUIC consumer accept")
	}
	select {
	case stream, ok := <-r.consumers:
		if !ok {
			return nil, r.result()
		}
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *StreamRouter) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(r.cancel)
	<-r.done
	for stream := range r.consumers {
		_ = stream.Close()
	}
	err := r.result()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (r *StreamRouter) fail(err error, closeSession bool) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	if closeSession {
		_ = r.session.Close()
	}
	r.cancel()
}

func (r *StreamRouter) result() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	return context.Canceled
}
