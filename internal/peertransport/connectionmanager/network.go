package connectionmanager

import (
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

type qualityInvalidator interface{ Invalidate() int }
type generationQualityInvalidator interface{ InvalidateNetwork(uint64) int }
type eventQualityInvalidator interface {
	ApplyNetworkEvent(networkmonitor.Event) int
}
type poolNetworkInvalidator interface{ NetworkChanged() }
type probeNetworkInvalidator interface{ NetworkChanged() }

// NetworkCoordinator applies one ordered network-generation transition across
// connection selection state. Duplicate and rollback events are ignored.
type NetworkCoordinator struct {
	observations []qualityInvalidator
	pool         poolNetworkInvalidator
	probes       probeNetworkInvalidator

	mu         sync.Mutex
	generation uint64
}

func NewNetworkCoordinator(quality qualityInvalidator, pool poolNetworkInvalidator, probes probeNetworkInvalidator, additionalObservations ...qualityInvalidator) (*NetworkCoordinator, error) {
	if quality == nil || pool == nil || probes == nil {
		return nil, errors.New("invalid network recovery coordinator")
	}
	observations := make([]qualityInvalidator, 1, 1+len(additionalObservations))
	observations[0] = quality
	for _, invalidator := range additionalObservations {
		if invalidator == nil {
			return nil, errors.New("invalid network recovery coordinator")
		}
		observations = append(observations, invalidator)
	}
	return &NetworkCoordinator{observations: observations, pool: pool, probes: probes}, nil
}

func (c *NetworkCoordinator) Handle(event networkmonitor.Event) bool {
	if c == nil || event.Generation == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if event.Generation <= c.generation {
		return false
	}
	c.generation = event.Generation
	if !event.Rebind {
		return false
	}
	// Fence promotion first. A promotion already holding the scheduler lock
	// completes before pool invalidation; every later result observes the new
	// network generation and is closed as stale.
	c.probes.NetworkChanged()
	for _, observations := range c.observations {
		if eventOwner, ok := observations.(eventQualityInvalidator); ok {
			eventOwner.ApplyNetworkEvent(event)
		} else if generationOwner, ok := observations.(generationQualityInvalidator); ok {
			generationOwner.InvalidateNetwork(event.Generation)
		} else {
			observations.Invalidate()
		}
	}
	c.pool.NetworkChanged()
	return true
}

func (c *NetworkCoordinator) Generation() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}
