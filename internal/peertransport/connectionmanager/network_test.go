package connectionmanager

import (
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

type recoveryRecorder struct {
	mu      sync.Mutex
	actions []string
}

type recordingQuality struct{ recorder *recoveryRecorder }
type recordingLifetime struct{ recorder *recoveryRecorder }
type recordingPool struct{ recorder *recoveryRecorder }
type recordingProbes struct{ recorder *recoveryRecorder }

func (r *recoveryRecorder) add(value string) {
	r.mu.Lock()
	r.actions = append(r.actions, value)
	r.mu.Unlock()
}
func (r *recordingQuality) Invalidate() int  { r.recorder.add("quality"); return 1 }
func (r *recordingLifetime) Invalidate() int { r.recorder.add("lifetime"); return 1 }
func (r *recordingPool) NetworkChanged()     { r.recorder.add("pool") }
func (r *recordingProbes) NetworkChanged()   { r.recorder.add("probes") }

func TestNetworkCoordinatorAppliesRebindExactlyOnceInOrder(t *testing.T) {
	recorder := &recoveryRecorder{}
	coordinator, err := NewNetworkCoordinator(&recordingQuality{recorder}, &recordingPool{recorder}, &recordingProbes{recorder}, &recordingLifetime{recorder})
	if err != nil {
		t.Fatal(err)
	}
	event := networkmonitor.Event{Generation: 2, Rebind: true, Reasons: networkmonitor.ReasonDefaultRoute}
	if !coordinator.Handle(event) || coordinator.Handle(event) || coordinator.Handle(networkmonitor.Event{Generation: 1, Rebind: true}) {
		t.Fatal("rebind application or replay fencing mismatch")
	}
	recorder.mu.Lock()
	actions := append([]string(nil), recorder.actions...)
	recorder.mu.Unlock()
	if len(actions) != 4 || actions[0] != "probes" || actions[1] != "quality" || actions[2] != "lifetime" || actions[3] != "pool" || coordinator.Generation() != 2 {
		t.Fatalf("actions=%v generation=%d", actions, coordinator.Generation())
	}
}

func TestNetworkCoordinatorAdvancesNonRebindGenerationWithoutInvalidation(t *testing.T) {
	recorder := &recoveryRecorder{}
	coordinator, _ := NewNetworkCoordinator(&recordingQuality{recorder}, &recordingPool{recorder}, &recordingProbes{recorder})
	if coordinator.Handle(networkmonitor.Event{Generation: 3, Rebind: false, Reasons: networkmonitor.ReasonViability}) || coordinator.Generation() != 3 {
		t.Fatalf("generation=%d", coordinator.Generation())
	}
	if coordinator.Handle(networkmonitor.Event{Generation: 3, Rebind: true}) {
		t.Fatal("same-generation event bypassed replay fence")
	}
	if len(recorder.actions) != 0 {
		t.Fatalf("actions=%v", recorder.actions)
	}
}

func TestNetworkCoordinatorRequiresAllOwners(t *testing.T) {
	if _, err := NewNetworkCoordinator(nil, nil, nil); err == nil {
		t.Fatal("nil recovery owners accepted")
	}
	if _, err := NewNetworkCoordinator(&recordingQuality{}, &recordingPool{}, &recordingProbes{}, nil); err == nil {
		t.Fatal("nil observation owner accepted")
	}
}
