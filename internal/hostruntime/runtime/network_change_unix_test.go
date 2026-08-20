//go:build darwin || linux || windows

package runtime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

type fakeNetworkObserver struct {
	starts atomic.Int32
	closes atomic.Int32
	err    error
}

type recordedNetworkMetric struct {
	name   string
	value  float64
	labels map[string]string
}

type recordingNetworkMetrics struct {
	mu      sync.Mutex
	records []recordedNetworkMetric
	err     error
}

func (m *recordingNetworkMetrics) Record(name string, value float64, labels map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make(map[string]string, len(labels))
	for key, label := range labels {
		copied[key] = label
	}
	m.records = append(m.records, recordedNetworkMetric{name: name, value: value, labels: copied})
	return m.err
}

func (o *fakeNetworkObserver) Start() error { o.starts.Add(1); return o.err }
func (o *fakeNetworkObserver) Close() error { o.closes.Add(1); return o.err }

func TestNetworkChangeServiceOwnsObserverLifecycle(t *testing.T) {
	observer := &fakeNetworkObserver{}
	service := &networkChangeService{observer: observer}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("second start err=%v", err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observer.starts.Load() != 1 || observer.closes.Load() != 1 {
		t.Fatalf("starts=%d closes=%d", observer.starts.Load(), observer.closes.Load())
	}
}

func TestNetworkChangeServicePropagatesObserverFailure(t *testing.T) {
	want := errors.New("monitor unavailable")
	service := &networkChangeService{observer: &fakeNetworkObserver{err: want}}
	if err := service.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("start err=%v", err)
	}
}

type recordingConnectorRecovery struct {
	mu      *sync.Mutex
	actions *[]string
}

func (r recordingConnectorRecovery) NetworkChanged() {
	r.mu.Lock()
	*r.actions = append(*r.actions, "connector")
	r.mu.Unlock()
}

type recordingDirectRecovery struct {
	mu          *sync.Mutex
	actions     *[]string
	generations []uint64
}

type atomicDirectRecovery struct {
	calls      atomic.Uint64
	generation atomic.Uint64
	result     bool
}

func (r *atomicDirectRecovery) NetworkChanged(generation uint64) bool {
	r.generation.Store(generation)
	r.calls.Add(1)
	return r.result
}

func TestDirectNetworkProxyForwardsExactGenerationToCurrentOwner(t *testing.T) {
	proxy := &directNetworkProxy{}
	if proxy.NetworkChanged(1) {
		t.Fatal("proxy without an owner reported a handled generation")
	}
	first := &atomicDirectRecovery{result: true}
	proxy.Set(first)
	if !proxy.NetworkChanged(7) || first.calls.Load() != 1 || first.generation.Load() != 7 {
		t.Fatalf("first calls=%d generation=%d", first.calls.Load(), first.generation.Load())
	}
	second := &atomicDirectRecovery{}
	proxy.Set(second)
	if proxy.NetworkChanged(9) || second.calls.Load() != 1 || second.generation.Load() != 9 {
		t.Fatalf("second calls=%d generation=%d", second.calls.Load(), second.generation.Load())
	}
	if first.calls.Load() != 1 {
		t.Fatalf("replaced owner received another event: %d", first.calls.Load())
	}
	proxy.Set(nil)
	if proxy.NetworkChanged(11) || second.calls.Load() != 1 {
		t.Fatal("cleared proxy retained its previous owner")
	}
}

func TestDirectNetworkProxySetAndDispatchAreRaceSafe(t *testing.T) {
	proxy := &directNetworkProxy{}
	owners := []*atomicDirectRecovery{{result: true}, {result: true}}
	var wait sync.WaitGroup
	for index := range 100 {
		wait.Add(2)
		go func(index int) {
			defer wait.Done()
			proxy.Set(owners[index%len(owners)])
		}(index)
		go func(generation uint64) {
			defer wait.Done()
			proxy.NetworkChanged(generation)
		}(uint64(index + 1))
	}
	wait.Wait()
	if owners[0].calls.Load()+owners[1].calls.Load() == 0 {
		t.Fatal("concurrent dispatch never reached an installed owner")
	}
}

func (r *recordingDirectRecovery) NetworkChanged(generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generations = append(r.generations, generation)
	*r.actions = append(*r.actions, "direct")
	return true
}

func TestNetworkChangeHandlerFencesDirectBeforeConnectorWake(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	direct := &recordingDirectRecovery{mu: &mu, actions: &actions}
	metrics := &recordingNetworkMetrics{}
	handler, err := newNetworkChangeHandler(recordingConnectorRecovery{mu: &mu, actions: &actions}, direct, metrics)
	if err != nil {
		t.Fatal(err)
	}
	handler.Handle(networkmonitor.Event{Generation: 7, Rebind: true, Reasons: networkmonitor.ReasonDefaultRoute})
	mu.Lock()
	defer mu.Unlock()
	if len(actions) != 2 || actions[0] != "direct" || actions[1] != "connector" {
		t.Fatalf("actions=%v", actions)
	}
	if len(direct.generations) != 1 || direct.generations[0] != 7 {
		t.Fatalf("generations=%v", direct.generations)
	}
	if len(metrics.records) != 2 || metrics.records[0].name != "paperboat_runtime_network_generation" || metrics.records[0].value != 7 || metrics.records[1].labels["reason"] != "default_route" || metrics.records[1].labels["action"] != "rebind" {
		t.Fatalf("metrics=%+v", metrics.records)
	}
}

func TestNetworkChangeHandlerSuppressesNonRebindAndInvalidGeneration(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	direct := &recordingDirectRecovery{mu: &mu, actions: &actions}
	metrics := &recordingNetworkMetrics{}
	handler, err := newNetworkChangeHandler(recordingConnectorRecovery{mu: &mu, actions: &actions}, direct, metrics)
	if err != nil {
		t.Fatal(err)
	}
	handler.Handle(networkmonitor.Event{Generation: 3, Reasons: networkmonitor.ReasonViability})
	handler.Handle(networkmonitor.Event{Rebind: true, Reasons: networkmonitor.ReasonDefaultRoute})
	if len(actions) != 0 || len(direct.generations) != 0 || len(metrics.records) != 2 {
		t.Fatalf("actions=%v generations=%v", actions, direct.generations)
	}
	if metrics.records[0].value != 3 || metrics.records[1].labels["reason"] != "viability" || metrics.records[1].labels["action"] != "observe" {
		t.Fatalf("metrics=%+v", metrics.records)
	}
	if _, err := newNetworkChangeHandler(nil, direct, metrics); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("nil connector error=%v", err)
	}
	if _, err := newNetworkChangeHandler(recordingConnectorRecovery{mu: &mu, actions: &actions}, direct, nil); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("nil metrics error=%v", err)
	}
}

func TestNetworkChangeHandlerRecordsBoundedReasonsAndIgnoresMetricFailure(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	metrics := &recordingNetworkMetrics{err: errors.New("metrics unavailable")}
	handler, err := newNetworkChangeHandler(recordingConnectorRecovery{mu: &mu, actions: &actions}, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	handler.Handle(networkmonitor.Event{Generation: 9, Rebind: true, Reasons: networkmonitor.ReasonInterfaceAddress | networkmonitor.ReasonAddressFamily | networkmonitor.ReasonProxy | networkmonitor.ReasonNetworkCost | networkmonitor.ReasonWake})
	if len(actions) != 1 || actions[0] != "connector" {
		t.Fatalf("actions=%v", actions)
	}
	if len(metrics.records) != 6 {
		t.Fatalf("metrics=%+v", metrics.records)
	}
	for _, metric := range metrics.records[1:] {
		if metric.labels["action"] != "rebind" {
			t.Fatalf("metric=%+v", metric)
		}
	}
}
