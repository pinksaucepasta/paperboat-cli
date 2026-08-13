package relaynoise

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/flynn/noise"
)

type InitiatorRekeySupervisorConfig struct {
	Session              *Session
	Carrier              RekeyCarrier
	LocalStatic          noise.DHKey
	ResponderPublic      [32]byte
	Prologue             Prologue
	FirstRekeyGeneration uint64
}

type InitiatorRekeySupervisor struct {
	session         *Session
	carrier         RekeyCarrier
	local           noise.DHKey
	responderPublic [32]byte
	prologue        Prologue
	firstGeneration uint64

	mu      sync.Mutex
	running bool
}

func NewInitiatorRekeySupervisor(config InitiatorRekeySupervisorConfig) (*InitiatorRekeySupervisor, error) {
	if config.Session == nil || !config.Session.initiator || config.Carrier == nil || validateKeypair(config.LocalStatic) != nil || allZero(config.ResponderPublic[:]) || config.FirstRekeyGeneration == 0 {
		return nil, errors.New("invalid relay E2EE rekey supervisor")
	}
	if _, err := config.Prologue.MarshalBinary(); err != nil {
		return nil, err
	}
	return &InitiatorRekeySupervisor{session: config.Session, carrier: config.Carrier, local: cloneKey(config.LocalStatic), responderPublic: config.ResponderPublic, prologue: config.Prologue, firstGeneration: config.FirstRekeyGeneration}, nil
}

func (s *InitiatorRekeySupervisor) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("invalid relay E2EE rekey supervisor")
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("relay E2EE rekey supervisor already running")
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	generation := s.firstGeneration
	for {
		delay := s.session.NextRekeyDelay()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-s.session.RekeyEvents():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
		if !s.session.RekeyNeeded() {
			continue
		}
		if err := RunInitiatorRekey(ctx, s.session, s.carrier, s.local, s.responderPublic, s.prologue, generation); err != nil {
			return err
		}
		if generation == ^uint64(0) {
			s.session.poison()
			return ErrRekeyMarker
		}
		generation++
	}
}
