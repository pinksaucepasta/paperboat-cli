package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type localDaemonSnapshotClientFunc func(context.Context) (localapi.Snapshot, error)

func (f localDaemonSnapshotClientFunc) Snapshot(ctx context.Context) (localapi.Snapshot, error) {
	return f(ctx)
}

type concurrentLocalDaemonReadinessState struct {
	ready        atomic.Bool
	initialCalls atomic.Int32
	launchCalls  atomic.Int32
	bothInitial  chan struct{}
	closeInitial sync.Once
	snapshot     localapi.Snapshot
}

type concurrentLocalDaemonReadinessClient struct {
	state *concurrentLocalDaemonReadinessState
	first sync.Once
}

func (c *concurrentLocalDaemonReadinessClient) Snapshot(ctx context.Context) (localapi.Snapshot, error) {
	select {
	case <-ctx.Done():
		return localapi.Snapshot{}, ctx.Err()
	default:
	}
	if c.state.ready.Load() {
		return c.state.snapshot, nil
	}
	c.first.Do(func() {
		if c.state.initialCalls.Add(1) == 2 {
			c.state.closeInitial.Do(func() { close(c.state.bothInitial) })
		}
	})
	return localapi.Snapshot{}, os.ErrNotExist
}

func localDaemonReadinessServer(t *testing.T) (*localapi.Server, localapi.Snapshot) {
	t.Helper()
	paths, err := currentLocalDaemonPaths()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := localapi.Snapshot{
		Schema:      localapi.SnapshotSchemaV1,
		Generation:  1,
		ObservedAt:  time.Date(2026, 8, 24, 7, 35, 0, 0, time.UTC),
		DaemonState: "ready",
	}
	store, err := localapi.NewSnapshotStore(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	return server, snapshot
}

func stopLocalDaemonReadinessServer(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("local daemon test server exit=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("local daemon test server did not stop")
	}
}

func TestStartLocalDaemonAndWaitUsesReadyDaemonWithoutInstaller(t *testing.T) {
	cfg, _ := localDaemonReadinessTestConfig(t, true)
	server, want := localDaemonReadinessServer(t)
	serverCtx, cancelServer := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(serverCtx) }()
	paths, err := currentLocalDaemonPaths()
	if err != nil {
		t.Fatal(err)
	}
	waitForCommandSocket(t, paths.SocketPath)
	defer stopLocalDaemonReadinessServer(t, cancelServer, done)

	installCalls := 0
	client, got, err := startLocalDaemonAndWait(context.Background(), cfg, func(context.Context, string, string, string) error {
		installCalls++
		return errors.New("ready daemon must not be reinstalled")
	})
	if err != nil || client == nil || got.Generation != want.Generation {
		t.Fatalf("client=%v snapshot=%#v install_calls=%d err=%v", client != nil, got, installCalls, err)
	}
	if installCalls != 0 {
		t.Fatalf("ready daemon installer calls=%d, want 0", installCalls)
	}
}

func TestStartLocalDaemonAndWaitAllowsColdReadinessBeyondLegacyFiveSeconds(t *testing.T) {
	const legacyTimeout = 5 * time.Second
	if localDaemonReadyTimeout <= legacyTimeout {
		t.Fatalf("local daemon readiness timeout=%s must cover cold startup beyond %s", localDaemonReadyTimeout, legacyTimeout)
	}
	cfg, configPath := localDaemonReadinessTestConfig(t, true)
	server, want := localDaemonReadinessServer(t)
	serverCtx, cancelServer := context.WithCancel(context.Background())
	done := make(chan error, 1)
	installCalls := 0
	installer := func(_ context.Context, _ string, gotConfigPath, serverURL string) error {
		installCalls++
		if gotConfigPath != configPath || serverURL != "https://api.paperboat.test" {
			t.Fatalf("config=%q server=%q", gotConfigPath, serverURL)
		}
		go func() {
			timer := time.NewTimer(legacyTimeout + 250*time.Millisecond)
			defer timer.Stop()
			select {
			case <-serverCtx.Done():
				done <- serverCtx.Err()
			case <-timer.C:
				done <- server.Run(serverCtx)
			}
		}()
		return nil
	}
	defer stopLocalDaemonReadinessServer(t, cancelServer, done)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	started := time.Now()
	client, got, err := startLocalDaemonAndWait(ctx, cfg, installer)
	elapsed := time.Since(started)
	if err != nil || client == nil || got.Generation != want.Generation {
		t.Fatalf("client=%v snapshot=%#v install_calls=%d elapsed=%s err=%v", client != nil, got, installCalls, elapsed, err)
	}
	if installCalls != 1 {
		t.Fatalf("installer calls=%d, want 1", installCalls)
	}
	if elapsed <= legacyTimeout {
		t.Fatalf("readiness returned in %s before delayed daemon passed legacy boundary %s", elapsed, legacyTimeout)
	}
}

func TestStartLocalDaemonAndWaitBoundsBlockedInstallerAcrossWholeOperation(t *testing.T) {
	if localDaemonReadyTimeout != 30*time.Second {
		t.Fatalf("default local daemon operation timeout=%s, want 30s", localDaemonReadyTimeout)
	}
	cfg, _ := localDaemonReadinessTestConfig(t, true)
	installCalls := 0
	started := time.Now()
	_, _, err := startLocalDaemonAndWaitWithin(context.Background(), cfg, func(ctx context.Context, _, _, _ string) error {
		installCalls++
		<-ctx.Done()
		return ctx.Err()
	}, 150*time.Millisecond)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "connect local daemon") {
		t.Fatalf("blocked installer error=%v", err)
	}
	if installCalls != 1 {
		t.Fatalf("installer calls=%d, want 1", installCalls)
	}
	if elapsed < 100*time.Millisecond || elapsed > time.Second {
		t.Fatalf("blocked installer elapsed=%s, want bounded near 150ms", elapsed)
	}
}

func TestStartLocalDaemonAndWaitCallerCancellationWins(t *testing.T) {
	cfg, _ := localDaemonReadinessTestConfig(t, true)
	parent, cancel := context.WithCancel(context.Background())
	installCalls := 0
	started := time.Now()
	_, _, err := startLocalDaemonAndWaitWithin(parent, cfg, func(ctx context.Context, _, _, _ string) error {
		installCalls++
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}, 5*time.Second)
	if !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller cancellation error=%v", err)
	}
	if installCalls != 1 {
		t.Fatalf("installer calls=%d, want 1", installCalls)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("caller cancellation took %s", elapsed)
	}
}

func TestRecoverLocalDaemonSnapshotReturnsSemanticFailureWithoutLaunchOrRetry(t *testing.T) {
	sentinel := errors.New("semantic snapshot failure")
	snapshotCalls := 0
	launchCalls := 0
	client := localDaemonSnapshotClientFunc(func(context.Context) (localapi.Snapshot, error) {
		snapshotCalls++
		return localapi.Snapshot{}, sentinel
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := recoverLocalDaemonSnapshot(ctx, client, "semantic-test-socket", func(context.Context) error {
		launchCalls++
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("semantic snapshot error=%v", err)
	}
	if snapshotCalls != 1 || launchCalls != 0 {
		t.Fatalf("snapshot calls=%d launch calls=%d, want 1/0", snapshotCalls, launchCalls)
	}
}

func TestRecoverLocalDaemonSnapshotJoinsLastSocketAndContextFailure(t *testing.T) {
	snapshotCalls := 0
	client := localDaemonSnapshotClientFunc(func(ctx context.Context) (localapi.Snapshot, error) {
		snapshotCalls++
		if snapshotCalls <= 2 {
			return localapi.Snapshot{}, os.ErrNotExist
		}
		<-ctx.Done()
		return localapi.Snapshot{}, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := recoverLocalDaemonSnapshot(ctx, client, "joined-error-test-socket", func(context.Context) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "connect local daemon at joined-error-test-socket") {
		t.Fatalf("joined readiness error=%v", err)
	}
	if snapshotCalls != 3 {
		t.Fatalf("snapshot calls=%d, want 3", snapshotCalls)
	}
}

func TestRecoverLocalDaemonSnapshotConcurrentCallersConvergeOnOneLaunch(t *testing.T) {
	state := &concurrentLocalDaemonReadinessState{
		bothInitial: make(chan struct{}),
		snapshot: localapi.Snapshot{
			Schema: localapi.SnapshotSchemaV1, Generation: 1,
			ObservedAt: time.Date(2026, 8, 24, 7, 35, 0, 0, time.UTC), DaemonState: "ready",
		},
	}
	clients := []*concurrentLocalDaemonReadinessClient{{state: state}, {state: state}}
	launch := func(ctx context.Context) error {
		state.launchCalls.Add(1)
		select {
		case <-state.bothInitial:
			state.ready.Store(true)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	type result struct {
		snapshot localapi.Snapshot
		err      error
	}
	results := make(chan result, len(clients))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, client := range clients {
		client := client
		go func() {
			snapshot, err := recoverLocalDaemonSnapshot(ctx, client, "concurrent-test-socket", launch)
			results <- result{snapshot: snapshot, err: err}
		}()
	}
	for range clients {
		got := <-results
		if got.err != nil || got.snapshot.Generation != 1 {
			t.Fatalf("concurrent recovery snapshot=%#v err=%v", got.snapshot, got.err)
		}
	}
	if state.initialCalls.Load() != 2 || state.launchCalls.Load() != 1 {
		t.Fatalf("initial calls=%d launch calls=%d, want 2/1", state.initialCalls.Load(), state.launchCalls.Load())
	}
}
