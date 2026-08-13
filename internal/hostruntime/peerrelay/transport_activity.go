package peerrelay

import (
	"context"
	"sync"
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
}

// candidateOwner owns exactly one authenticated physical candidate. Its
// parent is descriptor authority, never a sibling candidate or setup deadline.
type candidateOwner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	activity *transportActivity
	once     sync.Once
}

func newCandidateOwner(parent context.Context, observe func(string)) *candidateOwner {
	ctx, cancel := context.WithCancel(parent)
	owner := &candidateOwner{ctx: ctx, cancel: cancel}
	owner.activity = newTransportActivity(cancel, observe)
	return owner
}

func (o *candidateOwner) Stop() {
	if o == nil {
		return
	}
	o.once.Do(func() { o.activity.Stop() })
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
