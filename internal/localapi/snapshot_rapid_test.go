//go:build darwin || linux

package localapi

import (
	"context"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestSnapshotStoreRapidGenerationModel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(rapid.Uint8(), 1, 256).Draw(t, "operations")
		store, err := NewSnapshotStore(nil)
		if err != nil {
			t.Fatal(err)
		}
		var generation uint64
		for index, operation := range operations {
			var before *Snapshot
			if generation > 0 {
				value, snapshotErr := store.Snapshot(context.Background())
				if snapshotErr != nil {
					t.Fatal(snapshotErr)
				}
				before = &value
			}
			wantChanged := before == nil
			observedAt := time.Date(2026, 8, 7, 0, 0, index+1, 0, time.UTC)
			changed, updateErr := store.Update(observedAt, func(current *Snapshot) (Snapshot, error) {
				var desired Snapshot
				if current == nil {
					desired = validSnapshot()
				} else {
					desired = *current
				}
				switch operation % 3 {
				case 1:
					state := "ready"
					if operation&4 != 0 {
						state = "degraded"
					}
					if desired.DaemonState != state {
						wantChanged = true
					}
					desired.DaemonState = state
				case 2:
					alias := "studio"
					if operation&4 != 0 {
						alias = "office"
					}
					if desired.Machines[0].Alias != alias {
						wantChanged = true
					}
					desired.Machines[0].Alias = alias
				}
				return desired, nil
			})
			if updateErr != nil || changed != wantChanged {
				t.Fatalf("operation=%d changed=%v want=%v err=%v", operation, changed, wantChanged, updateErr)
			}
			if wantChanged {
				generation++
			}
			current, snapshotErr := store.Snapshot(context.Background())
			if snapshotErr != nil || current.Generation != generation {
				t.Fatalf("generation=%d want=%d err=%v", current.Generation, generation, snapshotErr)
			}
			storedAlias := current.Machines[0].Alias
			current.Machines[0].Alias = "mutated"
			again, snapshotErr := store.Snapshot(context.Background())
			if snapshotErr != nil || again.Machines[0].Alias != storedAlias {
				t.Fatalf("snapshot mutation escaped: alias=%q want=%q err=%v", again.Machines[0].Alias, storedAlias, snapshotErr)
			}
		}
	})
}
