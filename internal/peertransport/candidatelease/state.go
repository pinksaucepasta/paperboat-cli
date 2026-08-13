package candidatelease

import (
	"errors"
	"sync"
)

var (
	ErrFenced = errors.New("candidate lease fenced")
)

type State uint8

const (
	Provisional State = iota
	Retained
	Closed
)

type Lease struct {
	mu         sync.Mutex
	id         ID
	generation uint64
	state      State
}

func New(id ID, generation uint64) (*Lease, error) {
	if id == "" || generation == 0 {
		return nil, ErrInvalid
	}
	return &Lease{id: id, generation: generation}, nil
}

func (l *Lease) State() State {
	if l == nil {
		return Closed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}
func (l *Lease) ID() ID {
	if l == nil {
		return ""
	}
	return l.id
}
func (l *Lease) Adopt(generation uint64) error {
	if l == nil || generation == 0 {
		return ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if generation != l.generation || l.state == Closed {
		return ErrFenced
	}
	if l.state == Retained {
		return nil
	}
	l.state = Retained
	return nil
}
func (l *Lease) Release(generation uint64) error {
	if l == nil || generation == 0 {
		return ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if generation != l.generation {
		return ErrFenced
	}
	if l.state == Closed {
		return nil
	}
	l.state = Closed
	return nil
}
func (l *Lease) AttachAllowed(generation uint64) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return generation == l.generation && l.state == Retained
}
