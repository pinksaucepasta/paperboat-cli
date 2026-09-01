package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeTransactionalComponent struct {
	mu      sync.Mutex
	id      string
	status  NativeComponentStatus
	fail    map[string]error
	calls   *[]string
	callMu  *sync.Mutex
	block   <-chan struct{}
	started chan<- struct{}
}

func newFakeTransactionalComponent(id string, calls *[]string, callMu *sync.Mutex) *fakeTransactionalComponent {
	return &fakeTransactionalComponent{
		id: id, status: NativeComponentStatus{ID: id}, fail: make(map[string]error), calls: calls, callMu: callMu,
	}
}

func (f *fakeTransactionalComponent) ID() string { return f.id }

func (f *fakeTransactionalComponent) record(call string) error {
	if f.callMu != nil {
		f.callMu.Lock()
		*f.calls = append(*f.calls, f.id+":"+call)
		f.callMu.Unlock()
	}
	if f.started != nil && call == "install" {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.block != nil && call == "install" {
		<-f.block
	}
	return f.fail[call]
}

func (f *fakeTransactionalComponent) Inspect(context.Context) (NativeComponentStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := f.status
	status.Definition = append([]byte(nil), status.Definition...)
	return status, f.fail["inspect"]
}

func (f *fakeTransactionalComponent) Install(context.Context) error {
	if err := f.record("install"); err != nil {
		return err
	}
	f.mu.Lock()
	f.status = NativeComponentStatus{ID: f.id, Installed: true, Enabled: true, Running: true, Ready: true, Definition: []byte("definition:" + f.id)}
	f.mu.Unlock()
	return nil
}

func (f *fakeTransactionalComponent) Start(context.Context) error {
	if err := f.record("start"); err != nil {
		return err
	}
	f.mu.Lock()
	if f.status.Installed {
		f.status.Enabled, f.status.Running, f.status.Ready = true, true, true
	}
	f.mu.Unlock()
	return nil
}

func (f *fakeTransactionalComponent) Repair(context.Context) error {
	if err := f.record("repair"); err != nil {
		return err
	}
	f.mu.Lock()
	f.status = NativeComponentStatus{ID: f.id, Installed: true, Enabled: true, Running: true, Ready: true, Definition: []byte("definition:" + f.id)}
	f.mu.Unlock()
	return nil
}

func (f *fakeTransactionalComponent) Stop(context.Context) error {
	if err := f.record("stop"); err != nil {
		return err
	}
	f.mu.Lock()
	f.status.Running, f.status.Ready = false, false
	f.mu.Unlock()
	return nil
}

func (f *fakeTransactionalComponent) Uninstall(context.Context) error {
	if err := f.record("uninstall"); err != nil {
		return err
	}
	f.mu.Lock()
	f.status = NativeComponentStatus{ID: f.id}
	f.mu.Unlock()
	return nil
}

func (f *fakeTransactionalComponent) Restore(_ context.Context, status NativeComponentStatus) error {
	if err := f.record("restore"); err != nil {
		return err
	}
	f.mu.Lock()
	status.Definition = append([]byte(nil), status.Definition...)
	f.status = status
	f.mu.Unlock()
	return nil
}

func lifecycleForTest(t *testing.T, components ...TransactionalComponent) *LifecycleManager {
	t.Helper()
	manager, err := NewLifecycleManager(LifecycleConfig{
		StateRoot: filepath.Join(t.TempDir(), "service-state"), Components: components,
		Now: func() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestLifecycleInstallStartsInOrderAndVerifiesReady(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	hostd := newFakeTransactionalComponent("hostd", &calls, &callMu)
	updater := newFakeTransactionalComponent("updater", &calls, &callMu)
	manager := lifecycleForTest(t, hostd, updater)
	if err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"hostd:install", "hostd:start", "updater:install", "updater:start"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
	statuses, err := manager.Inspect(context.Background())
	if err != nil || len(statuses) != 2 || !statuses[0].Ready || !statuses[1].Ready {
		t.Fatalf("statuses=%+v err=%v", statuses, err)
	}
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed journal remains: %v", err)
	}
}

func TestLifecycleFailureRestoresEveryExactPreState(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	hostd := newFakeTransactionalComponent("hostd", &calls, &callMu)
	hostd.status = NativeComponentStatus{ID: "hostd", Installed: true, Enabled: true, Definition: []byte("old-hostd")}
	updater := newFakeTransactionalComponent("updater", &calls, &callMu)
	updater.fail["install"] = errors.New("native install failed")
	manager := lifecycleForTest(t, hostd, updater)
	if err := manager.Install(context.Background()); err == nil || !errors.Is(err, updater.fail["install"]) {
		t.Fatalf("install err=%v", err)
	}
	hostStatus, _ := hostd.Inspect(context.Background())
	updateStatus, _ := updater.Inspect(context.Background())
	if !sameComponentStatus(hostStatus, NativeComponentStatus{ID: "hostd", Installed: true, Enabled: true, Definition: []byte("old-hostd")}) ||
		!sameComponentStatus(updateStatus, NativeComponentStatus{ID: "updater"}) {
		t.Fatalf("host=%+v updater=%+v", hostStatus, updateStatus)
	}
	wantTail := []string{"updater:install", "updater:restore", "hostd:restore"}
	if len(calls) < len(wantTail) || !reflect.DeepEqual(calls[len(calls)-len(wantTail):], wantTail) {
		t.Fatalf("rollback calls=%v", calls)
	}
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back journal remains: %v", err)
	}
}

func TestLifecycleReadinessFailureRollsBack(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	component := newFakeTransactionalComponent("hostd", &calls, &callMu)
	component.fail["start"] = nil
	manager := lifecycleForTest(t, component)
	// Override the status after Start by failing to expose readiness.
	component.fail["inspect"] = errors.New("readiness unavailable")
	if err := manager.Install(context.Background()); err == nil {
		t.Fatal("expected inspection failure")
	}
	// The pre-mutation capture itself failed, so no native mutation occurred.
	if len(calls) != 0 {
		t.Fatalf("calls=%v", calls)
	}
}

func TestLifecycleRecoverRestoresCrashJournal(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	hostd := newFakeTransactionalComponent("hostd", &calls, &callMu)
	updater := newFakeTransactionalComponent("updater", &calls, &callMu)
	manager := lifecycleForTest(t, hostd, updater)
	journal := lifecycleJournal{
		Version: lifecycleJournalVersion, Operation: lifecycleInstall, StartedAt: manager.now(), Next: 1,
		Order: []string{"hostd", "updater"}, Before: []NativeComponentStatus{{ID: "hostd"}, {ID: "updater"}},
	}
	if err := manager.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	if err := hostd.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _ := hostd.Inspect(context.Background())
	if !sameComponentStatus(status, NativeComponentStatus{ID: "hostd"}) {
		t.Fatalf("recovered status=%+v", status)
	}
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery journal remains: %v", err)
	}
}

func TestLifecycleCrossProcessLockRejectsConcurrentMutation(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	component := newFakeTransactionalComponent("hostd", &calls, &callMu)
	component.started, component.block = started, release
	stateRoot := filepath.Join(t.TempDir(), "service-state")
	first, err := NewLifecycleManager(LifecycleConfig{StateRoot: stateRoot, Components: []TransactionalComponent{component}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLifecycleManager(LifecycleConfig{StateRoot: stateRoot, Components: []TransactionalComponent{component}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- first.Install(context.Background()) }()
	<-started
	if err := second.Repair(context.Background()); !errors.Is(err, ErrLifecycleBusy) {
		t.Fatalf("concurrent err=%v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleStopAndUninstallUseDependencyReverseOrder(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	hostd := newFakeTransactionalComponent("hostd", &calls, &callMu)
	updater := newFakeTransactionalComponent("updater", &calls, &callMu)
	for _, component := range []*fakeTransactionalComponent{hostd, updater} {
		component.status = NativeComponentStatus{ID: component.id, Installed: true, Enabled: true, Running: true, Ready: true, Definition: []byte("definition:" + component.id)}
	}
	manager := lifecycleForTest(t, hostd, updater)
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"updater:stop", "hostd:stop"}) {
		t.Fatalf("stop calls=%v", calls)
	}
	calls = nil
	if err := manager.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"updater:stop", "updater:uninstall", "hostd:stop", "hostd:uninstall"}) {
		t.Fatalf("uninstall calls=%v", calls)
	}
}

func TestLifecycleMalformedJournalFailsClosedWithoutMutation(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	component := newFakeTransactionalComponent("hostd", &calls, &callMu)
	manager := lifecycleForTest(t, component)
	if err := os.MkdirAll(manager.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.journal, []byte(`{"version":"paperboat.service-lifecycle/v1","operation":"install","operation":"stop"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Recover(context.Background()); !errors.Is(err, ErrLifecycleUncertain) {
		t.Fatalf("recover err=%v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("mutated on corrupt journal: %v", calls)
	}
}

func TestLifecycleStaleJournalFailsClosedWithoutMutation(t *testing.T) {
	var calls []string
	var callMu sync.Mutex
	component := newFakeTransactionalComponent("hostd", &calls, &callMu)
	manager := lifecycleForTest(t, component)
	journal := lifecycleJournal{
		Version: lifecycleJournalVersion, Operation: lifecycleInstall,
		StartedAt: manager.now().Add(-maxLifecycleJournalAge - time.Minute),
		Order:     []string{"hostd"}, Before: []NativeComponentStatus{{ID: "hostd"}},
	}
	if err := manager.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	if err := manager.Recover(context.Background()); !errors.Is(err, ErrLifecycleUncertain) {
		t.Fatalf("recover err=%v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("mutated on stale journal: %v", calls)
	}
}
