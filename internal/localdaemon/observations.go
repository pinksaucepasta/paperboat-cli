package localdaemon

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

const maxObservationSources = 128

type ObservationConfig struct {
	Store    *localapi.SnapshotStore
	OwnerUID int
	Clock    func() time.Time
	Interval time.Duration
}

type ObservationStore struct {
	store    *localapi.SnapshotStore
	ownerUID int
	clock    func() time.Time
	interval time.Duration

	mu      sync.Mutex
	sources map[string]localapi.TransportObservation
}

func NewObservationStore(config ObservationConfig) (*ObservationStore, error) {
	if config.Store == nil || config.OwnerUID < 0 || config.Interval < 0 {
		return nil, ErrInvalidInventoryConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Interval == 0 {
		config.Interval = time.Second
	}
	if config.Interval < 10*time.Millisecond || config.Interval > 10*time.Second {
		return nil, ErrInvalidInventoryConfig
	}
	return &ObservationStore{store: config.Store, ownerUID: config.OwnerUID, clock: config.Clock, interval: config.Interval, sources: make(map[string]localapi.TransportObservation)}, nil
}

func (s *ObservationStore) PublishObservation(ctx context.Context, peer localapi.Peer, observation localapi.TransportObservation) error {
	if ctx == nil || peer.UID != s.ownerUID || peer.PID <= 0 {
		return localapi.ErrPermission
	}
	if observation.Validate() != nil {
		return localapi.ErrInvalidResponse
	}
	now := s.clock().UTC()
	if observation.ObservedAt.Before(now.Add(-30*time.Second)) || observation.ObservedAt.After(now.Add(5*time.Second)) || !observation.ExpiresAt.After(now) || observation.ExpiresAt.After(now.Add(30*time.Second)) {
		return localapi.ErrStaleObservation
	}
	key := observationKey(peer, observation.SourceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.sources[key]
	if exists {
		if observation.Sequence < previous.Sequence || observation.Sequence == previous.Sequence && !reflect.DeepEqual(observation, previous) {
			return localapi.ErrStaleObservation
		}
		if reflect.DeepEqual(observation, previous) {
			return nil
		}
	} else if len(s.sources) >= maxObservationSources {
		return localapi.ErrObservationLimit
	}
	s.sources[key] = observation
	if err := s.applyLocked(now); err != nil {
		if exists {
			s.sources[key] = previous
		} else {
			delete(s.sources, key)
		}
		return err
	}
	return nil
}

func (s *ObservationStore) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.Expire(); err != nil {
				return err
			}
		}
	}
}

func (s *ObservationStore) Expire() error {
	now := s.clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for key, observation := range s.sources {
		if !observation.ExpiresAt.After(now) {
			delete(s.sources, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.applyLocked(now)
}

func (s *ObservationStore) applyLocked(now time.Time) error {
	active := make([]localapi.TransportObservation, 0, len(s.sources))
	for _, observation := range s.sources {
		if observation.SelectedPath != "none" && observation.ExpiresAt.After(now) {
			active = append(active, observation)
		}
	}
	sort.Slice(active, func(left, right int) bool {
		if active[left].ObservedAt.Equal(active[right].ObservedAt) {
			if active[left].MachineID == active[right].MachineID {
				return active[left].SourceID < active[right].SourceID
			}
			return active[left].MachineID < active[right].MachineID
		}
		return active[left].ObservedAt.Before(active[right].ObservedAt)
	})
	_, err := s.store.Update(now, func(current *localapi.Snapshot) (localapi.Snapshot, error) {
		if current == nil {
			return localapi.Snapshot{}, localapi.ErrSnapshotUnavailable
		}
		desired := *current
		indices := make(map[string]int, len(desired.Machines))
		for index := range desired.Machines {
			indices[desired.Machines[index].ID] = index
			desired.Machines[index].ActiveConsumers = 0
			desired.Machines[index].SelectedPath = "none"
			desired.Machines[index].TransportConsumers = nil
			desired.Machines[index].StandbyPath = "none"
			desired.Machines[index].RelayRegion = ""
			desired.Machines[index].NATMappingIPv4 = "unknown"
			desired.Machines[index].NATMappingIPv6 = "unknown"
			desired.Machines[index].CaptivePortal = "unknown"
			desired.Machines[index].PMTU = "unknown"
			desired.Machines[index].RouterMapping = "unknown"
			desired.Machines[index].RouterProtocol = "unknown"
			desired.Machines[index].MappingLifetime = "unknown"
		}
		type aggregate struct {
			consumers uint64
			region    string
		}
		paths := make(map[string]map[string]aggregate, len(desired.Machines))
		latest := make(map[string]localapi.TransportObservation, len(desired.Machines))
		for _, observation := range active {
			index, ok := indices[observation.MachineID]
			if !ok {
				continue
			}
			desired.Machines[index].ActiveConsumers += observation.ActiveConsumers
			latest[observation.MachineID] = observation
			for _, consumer := range observationConsumers(observation) {
				byPath := paths[observation.MachineID]
				if byPath == nil {
					byPath = make(map[string]aggregate, 3)
					paths[observation.MachineID] = byPath
				}
				value := byPath[consumer.Path]
				value.consumers += consumer.ActiveConsumers
				if consumer.RelayRegion != "" {
					value.region = consumer.RelayRegion
				}
				byPath[consumer.Path] = value
			}
		}
		for machineID, index := range indices {
			machine := &desired.Machines[index]
			if observation, ok := latest[machineID]; ok {
				machine.StandbyPath = observation.StandbyPath
				if machine.StandbyPath == "" {
					machine.StandbyPath = "none"
				}
				machine.RelayRegion = observation.RelayRegion
				machine.NATMappingIPv4 = observation.NATMappingIPv4
				machine.NATMappingIPv6 = observation.NATMappingIPv6
				machine.CaptivePortal = observation.CaptivePortal
				machine.PMTU = observation.PMTU
				machine.RouterMapping = observation.RouterMapping
				machine.RouterProtocol = observation.RouterProtocol
				machine.MappingLifetime = observation.MappingLifetime
				// A legacy warm observation has no active consumers but still
				// describes a ready path. Keep its scalar projection.
				if machine.ActiveConsumers == 0 {
					machine.SelectedPath = observation.SelectedPath
				}
			}
			for path, value := range paths[machineID] {
				machine.TransportConsumers = append(machine.TransportConsumers, localapi.TransportConsumer{Path: path, ActiveConsumers: value.consumers, RelayRegion: value.region})
			}
			sort.Slice(machine.TransportConsumers, func(left, right int) bool {
				return machine.TransportConsumers[left].Path < machine.TransportConsumers[right].Path
			})
			switch len(machine.TransportConsumers) {
			case 0:
			case 1:
				machine.SelectedPath = machine.TransportConsumers[0].Path
				machine.RelayRegion = machine.TransportConsumers[0].RelayRegion
			case 2, 3:
				machine.SelectedPath = "mixed"
				machine.StandbyPath = "none"
				machine.RelayRegion = ""
			}
		}
		return desired, nil
	})
	return err
}

func observationConsumers(observation localapi.TransportObservation) []localapi.TransportConsumer {
	if len(observation.TransportConsumers) > 0 {
		return observation.TransportConsumers
	}
	if observation.ActiveConsumers == 0 || observation.SelectedPath == "none" || observation.SelectedPath == "mixed" {
		return nil
	}
	return []localapi.TransportConsumer{{Path: observation.SelectedPath, ActiveConsumers: observation.ActiveConsumers, RelayRegion: observation.RelayRegion}}
}

func observationKey(peer localapi.Peer, sourceID string) string {
	return fmt.Sprintf("%d:%d:%s", peer.UID, peer.PID, sourceID)
}

var _ localapi.ObservationSink = (*ObservationStore)(nil)
