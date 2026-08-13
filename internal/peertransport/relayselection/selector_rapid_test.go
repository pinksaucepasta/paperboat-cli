package relayselection

import (
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestSelectorRapidElectionStateMachine(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(rapid.Uint8(), 1, 192).Draw(t, "operations")
		selector, err := New(DevelopmentConfig())
		if err != nil {
			t.Fatal(err)
		}
		base := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
		previous := ""
		for index, operation := range operations {
			generation := uint64(index + 1)
			observedAt := base.Add(time.Duration(index) * 4 * time.Second)
			bom := time.Duration(20+operation%100) * time.Millisecond
			fra := time.Duration(20+(operation*7)%100) * time.Millisecond
			states := map[string]RegionState{
				"bom": {Healthy: operation&1 == 0, Capacity: operation&2 == 0},
				"fra": {Healthy: operation&4 == 0, Capacity: operation&8 == 0},
			}
			if !eligible(states["bom"]) && !eligible(states["fra"]) {
				states["bom"] = RegionState{Healthy: true, Capacity: true}
			}
			set := VectorSet{
				Generation: generation, ObservedAt: observedAt,
				Client: Vector{Samples: []RegionSample{{Region: "bom", RTT: bom / 2}, {Region: "fra", RTT: fra / 2}}},
				Host:   Vector{Samples: []RegionSample{{Region: "bom", RTT: bom - bom/2}, {Region: "fra", RTT: fra - fra/2}}},
			}
			decision, selectErr := selector.Select(observedAt.Add(time.Second), set, states)
			if selectErr != nil {
				t.Fatalf("generation=%d: %v", generation, selectErr)
			}
			if !eligible(states[decision.Region]) {
				t.Fatalf("selected ineligible region %q with states=%+v", decision.Region, states)
			}
			wantCombined := bom
			if decision.Region == "fra" {
				wantCombined = fra
			} else if decision.Region != "bom" {
				t.Fatalf("selected unknown region %q", decision.Region)
			}
			if decision.Combined != wantCombined {
				t.Fatalf("region=%q combined=%s want=%s", decision.Region, decision.Combined, wantCombined)
			}
			if decision.Switched != (previous != "" && previous != decision.Region) {
				t.Fatalf("previous=%q decision=%+v", previous, decision)
			}
			previous = decision.Region
			if _, replayErr := selector.Select(observedAt.Add(2*time.Second), set, states); !errors.Is(replayErr, ErrInvalid) {
				t.Fatalf("generation replay accepted: %v", replayErr)
			}
		}
	})
}

func eligible(state RegionState) bool { return state.Healthy && state.Capacity }
