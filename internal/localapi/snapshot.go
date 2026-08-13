package localapi

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"
)

var (
	ErrSnapshotUnavailable = errors.New("local snapshot is unavailable")
	ErrStaleGeneration     = errors.New("local snapshot generation is stale")
	ErrWatcherLimit        = errors.New("local snapshot watcher limit reached")
	ErrGenerationExhausted = errors.New("local snapshot generation exhausted")
)

const maxSnapshotWatchers = 128

type SnapshotStore struct {
	mu       sync.Mutex
	current  *Snapshot
	watchers map[uint64]chan Snapshot
	nextID   uint64
}

func NewSnapshotStore(initial *Snapshot) (*SnapshotStore, error) {
	store := &SnapshotStore{watchers: make(map[uint64]chan Snapshot)}
	if initial != nil {
		if err := initial.Validate(); err != nil {
			return nil, err
		}
		copy := cloneSnapshot(*initial)
		store.current = &copy
	}
	return store, nil
}

func (s *SnapshotStore) Snapshot(context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return Snapshot{}, ErrSnapshotUnavailable
	}
	return cloneSnapshot(*s.current), nil
}

func (s *SnapshotStore) Publish(snapshot Snapshot) (bool, error) {
	if err := snapshot.Validate(); err != nil {
		return false, err
	}
	s.mu.Lock()
	if s.current != nil {
		if snapshot.Generation < s.current.Generation {
			s.mu.Unlock()
			return false, ErrStaleGeneration
		}
		if snapshot.Generation == s.current.Generation {
			unchanged := reflect.DeepEqual(snapshot, *s.current)
			s.mu.Unlock()
			if unchanged {
				return false, nil
			}
			return false, ErrStaleGeneration
		}
	}
	copy := cloneSnapshot(snapshot)
	s.current = &copy
	watchers := make([]chan Snapshot, 0, len(s.watchers))
	for _, watcher := range s.watchers {
		watchers = append(watchers, watcher)
	}
	s.mu.Unlock()
	for _, watcher := range watchers {
		select {
		case watcher <- cloneSnapshot(snapshot):
		default:
			select {
			case <-watcher:
			default:
			}
			select {
			case watcher <- cloneSnapshot(snapshot):
			default:
			}
		}
	}
	return true, nil
}

// Update applies one semantic state mutation and owns generation assignment.
// The callback runs under the store lock and must not call back into the store.
func (s *SnapshotStore) Update(observedAt time.Time, update func(*Snapshot) (Snapshot, error)) (bool, error) {
	if observedAt.IsZero() || update == nil {
		return false, ErrInvalidConfig
	}
	s.mu.Lock()
	var current *Snapshot
	if s.current != nil {
		copy := cloneSnapshot(*s.current)
		current = &copy
	}
	desired, err := update(current)
	if err != nil {
		s.mu.Unlock()
		return false, err
	}
	desired.Schema = SnapshotSchemaV1
	desired.ObservedAt = observedAt.UTC()
	desired.Generation = 1
	if s.current != nil {
		if semanticSnapshotEqual(*s.current, desired) {
			s.mu.Unlock()
			return false, nil
		}
		if s.current.Generation == ^uint64(0) {
			s.mu.Unlock()
			return false, ErrGenerationExhausted
		}
		desired.Generation = s.current.Generation + 1
	}
	if err := desired.Validate(); err != nil {
		s.mu.Unlock()
		return false, err
	}
	copy := cloneSnapshot(desired)
	s.current = &copy
	watchers := make([]chan Snapshot, 0, len(s.watchers))
	for _, watcher := range s.watchers {
		watchers = append(watchers, watcher)
	}
	s.mu.Unlock()
	notifyWatchers(watchers, desired)
	return true, nil
}

func (s *SnapshotStore) Watch(ctx context.Context, after uint64) (Snapshot, error) {
	s.mu.Lock()
	if s.current != nil && s.current.Generation > after {
		current := cloneSnapshot(*s.current)
		s.mu.Unlock()
		return current, nil
	}
	if len(s.watchers) >= maxSnapshotWatchers {
		s.mu.Unlock()
		return Snapshot{}, ErrWatcherLimit
	}
	s.nextID++
	id := s.nextID
	updates := make(chan Snapshot, 1)
	s.watchers[id] = updates
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.watchers, id)
		s.mu.Unlock()
	}()
	for {
		select {
		case snapshot := <-updates:
			if snapshot.Generation > after {
				return snapshot, nil
			}
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copy := snapshot
	copy.Health = append([]HealthItem(nil), snapshot.Health...)
	copy.Machines = append([]MachineStatus(nil), snapshot.Machines...)
	for index := range copy.Machines {
		copy.Machines[index].Health = append([]HealthItem(nil), snapshot.Machines[index].Health...)
	}
	return copy
}

func semanticSnapshotEqual(left, right Snapshot) bool {
	left.Generation, right.Generation = 0, 0
	left.ObservedAt, right.ObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

func notifyWatchers(watchers []chan Snapshot, snapshot Snapshot) {
	for _, watcher := range watchers {
		select {
		case watcher <- cloneSnapshot(snapshot):
		default:
			select {
			case <-watcher:
			default:
			}
			select {
			case watcher <- cloneSnapshot(snapshot):
			default:
			}
		}
	}
}
