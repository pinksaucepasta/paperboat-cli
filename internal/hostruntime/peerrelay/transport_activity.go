package peerrelay

import (
	"context"
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
)

// transportActivity accounts stream use across one reusable peer-transport
// attempt. Candidate lifetime belongs to the physical attempt: an idle
// authenticated fallback remains valid until its connection closes, authority
// is revoked, or the host shuts down.
type transportActivity struct {
	mu              sync.Mutex
	ready           bool
	used            bool
	active          int
	closed          bool
	cancelTransport func()
	observe         func(string)
	owner           *candidateOwner
}

// candidateOwner owns exactly one authenticated physical candidate. Its
// parent is descriptor authority, never a sibling candidate or setup deadline.
type candidateOwner struct {
	ctx         context.Context
	cancel      context.CancelFunc
	activity    *transportActivity
	once        sync.Once
	lease       *candidatelease.Lease
	retained    chan struct{}
	released    chan struct{}
	retainOnce  sync.Once
	releaseOnce sync.Once
}

func newCandidateOwner(parent context.Context, observe func(string)) *candidateOwner {
	ctx, cancel := context.WithCancel(parent)
	owner := &candidateOwner{ctx: ctx, cancel: cancel, retained: make(chan struct{}), released: make(chan struct{})}
	owner.activity = newTransportActivity(cancel, observe)
	owner.activity.owner = owner
	return owner
}

func (o *candidateOwner) Stop() {
	if o == nil {
		return
	}
	o.once.Do(func() { o.activity.Stop() })
}

func (o *candidateOwner) Configure(id candidatelease.ID, generation uint64) error {
	if o == nil || o.lease != nil {
		return candidatelease.ErrInvalid
	}
	lease, err := candidatelease.New(id, generation)
	if err != nil {
		return err
	}
	o.lease = lease
	return nil
}

func (o *candidateOwner) Handle(message candidatelease.Message) (candidatelease.Message, error) {
	if o == nil || o.lease == nil || message.Candidate != o.lease.ID() {
		return candidatelease.Message{}, candidatelease.ErrFenced
	}
	ack := candidatelease.Message{Version: 1, Candidate: message.Candidate, LeaseGeneration: message.LeaseGeneration}
	switch message.Type {
	case candidatelease.Adopt:
		if err := o.lease.Adopt(message.LeaseGeneration); err != nil {
			return candidatelease.Message{}, err
		}
		ack.Type = candidatelease.AdoptAck
		o.retainOnce.Do(func() { close(o.retained) })
	case candidatelease.Release:
		if err := o.lease.Release(message.LeaseGeneration); err != nil {
			return candidatelease.Message{}, err
		}
		ack.Type = candidatelease.ReleaseAck
		o.releaseOnce.Do(func() { close(o.released) })
	default:
		return candidatelease.Message{}, candidatelease.ErrProtocol
	}
	return ack, nil
}

func (o *candidateOwner) WaitRetained(ctx context.Context) error {
	if o == nil || ctx == nil {
		return candidatelease.ErrInvalid
	}
	select {
	case <-o.retained:
		return o.Retained()
	case <-o.released:
		return candidatelease.ErrFenced
	case <-o.ctx.Done():
		return o.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *candidateOwner) Released() <-chan struct{} {
	if o == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return o.released
}

func (o *candidateOwner) Retained() error {
	if o == nil || o.lease == nil || o.lease.State() != candidatelease.Retained {
		return errors.Join(candidatelease.ErrFenced, context.Canceled)
	}
	return nil
}

func newTransportActivity(cancelTransport func(), observers ...func(string)) *transportActivity {
	if cancelTransport == nil {
		cancelTransport = func() {}
	}
	var observe func(string)
	if len(observers) > 0 {
		observe = observers[0]
	}
	return &transportActivity{cancelTransport: cancelTransport, observe: observe}
}

func (a *transportActivity) Ready() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if !a.closed {
		a.ready = true
	}
	a.mu.Unlock()
}

func (a *transportActivity) Open() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if !a.closed {
		a.ready = true
		a.used = true
		a.active++
	}
	a.mu.Unlock()
}

func (a *transportActivity) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	becameIdle := false
	if !a.closed && a.active > 0 {
		a.active--
		becameIdle = a.active == 0
	}
	observe := a.observe
	a.mu.Unlock()
	if becameIdle && observe != nil {
		observe("stream_activity_zero")
		observe("carrier_retained_idle")
	}
}

func (a *transportActivity) Stop() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	cancel := a.cancelTransport
	observe := a.observe
	a.mu.Unlock()
	if observe != nil {
		observe("carrier_closed")
	}
	cancel()
}
