//go:build darwin || linux

package runtime

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configapply"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

// TestRuntimeObservationRemainsStableAcrossWorkerReplacement protects the
// hostd ownership boundary. A worker update must stop only the replaceable
// coordination runtime; the observation loop is the hostd-owned machine
// presence signal and must continue until the whole host shuts down.
func TestRuntimeObservationRemainsStableAcrossWorkerReplacement(t *testing.T) {
	transport := &livenessObservationTransport{notify: make(chan struct{}, 32)}
	sender := &runtimeObservationSender{
		endpoint:         "https://observations.invalid/v1/runtime-observations",
		tokens:           livenessObservationTokenSource{},
		proofs:           livenessObservationProofSource{},
		operationID:      func() (string, error) { return "op_runtime_observation_hostd_0001", nil },
		environmentID:    "env_runtime_observation_hostd",
		machineID:        "machine_runtime_observation_hostd",
		reporterVersion:  "test",
		client:           &http.Client{Transport: transport},
		workerGeneration: 1,
		osBootID:         "boot-runtime-observation-hostd",
	}
	observation := &runtimeObservationService{sender: sender, interval: 15 * time.Millisecond, timeout: 250 * time.Millisecond}
	listener := &hostListener{closed: make(chan struct{})}
	root := t.TempDir()
	runtimeConfig := runtimeconfig.Config{
		Profile:   runtimeconfig.BYOD,
		StateRoot: root,
		Version:   "test",
		Limits:    runtimeconfig.DefaultLimits,
		Resources: runtimeconfig.DefaultResources,
	}
	host, err := NewHost(context.Background(), HostConfig{
		Runtime:       runtimeConfig,
		ListenAddress: "127.0.0.1:0",
		WorkspaceRoot: root,
		EnvironmentID: "env_runtime_observation_hostd",
		MachineID:     "machine_runtime_observation_hostd",
	}, HostDependencies{
		Authorizer:                func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Listener:                  func() (net.Listener, error) { return listener, nil },
		ConfigApply:               configapply.ConformanceHandler{},
		SessionLauncherFactory:    testSessionLauncherFactory("/bin/sh", []string{"-l"}, []string{"PATH=/usr/bin:/bin"}),
		RuntimeObservationService: serviceGroup{runtimeObservationGroupMember{}, observation},
	})
	if err != nil {
		t.Fatal(err)
	}

	startupCtx, cancelStartup := context.WithCancel(context.Background())
	if err := host.Start(startupCtx); err != nil {
		cancelStartup()
		t.Fatal(err)
	}
	// The startup context is not the ownership context. Hostd must retain the
	// observation loop after supervisors cancel the worker-start request.
	cancelStartup()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = host.Shutdown(shutdownCtx)
	})

	waitForRuntimeObservationCalls(t, transport, 2)
	beforeReplacement := transport.calls.Load()
	candidate, err := NewRuntime(Config{
		Version:         "replacement",
		ShutdownTimeout: time.Second,
		Components:      []Component{{Capability: "worker_lifecycle", Required: true, Service: workerLifecycleService{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.ReplaceWorker(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	// A broken composition puts observation in the worker. Replacement would
	// then emit one final observation and stop; requiring two subsequent ticks
	// distinguishes stable ownership from that false-positive final send.
	waitForRuntimeObservationCalls(t, transport, beforeReplacement+2)

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	if err := host.Shutdown(shutdownCtx); err != nil {
		cancelShutdown()
		t.Fatal(err)
	}
	cancelShutdown()
	stoppedAt := transport.calls.Load()
	time.Sleep(4 * observation.interval)
	if got := transport.calls.Load(); got != stoppedAt {
		t.Fatalf("observation loop continued after host shutdown: calls=%d want=%d", got, stoppedAt)
	}
}

// TestStartHostdKeepsProductionObservationGroupAlive verifies the lifecycle
// used by hostruntimecmd: hostd starts the production observation group, then
// the separately fenced worker is activated. The worker Runtime must remain
// New in this process; otherwise its shutdown can take the machine heartbeat
// down with it.
func TestStartHostdKeepsProductionObservationGroupAlive(t *testing.T) {
	transport := &livenessObservationTransport{notify: make(chan struct{}, 32)}
	sender := &runtimeObservationSender{
		endpoint:         "https://observations.invalid/v1/runtime-observations",
		tokens:           livenessObservationTokenSource{},
		proofs:           livenessObservationProofSource{},
		operationID:      func() (string, error) { return "op_runtime_observation_hostd_only_0001", nil },
		environmentID:    "env_runtime_observation_hostd_only",
		machineID:        "machine_runtime_observation_hostd_only",
		reporterVersion:  "test",
		client:           &http.Client{Transport: transport},
		workerGeneration: 1,
		osBootID:         "boot-runtime-observation-hostd-only",
	}
	observation := &runtimeObservationService{sender: sender, interval: 15 * time.Millisecond, timeout: 250 * time.Millisecond}
	root := t.TempDir()
	host, err := NewHost(context.Background(), HostConfig{
		Runtime: runtimeconfig.Config{
			Profile:   runtimeconfig.BYOD,
			StateRoot: root,
			Version:   "test",
			Limits:    runtimeconfig.DefaultLimits,
			Resources: runtimeconfig.DefaultResources,
		},
		ListenAddress: "127.0.0.1:0",
		WorkspaceRoot: root,
		EnvironmentID: "env_runtime_observation_hostd_only",
		MachineID:     "machine_runtime_observation_hostd_only",
	}, HostDependencies{
		Authorizer:                func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Listener:                  func() (net.Listener, error) { return &hostListener{closed: make(chan struct{})}, nil },
		ConfigApply:               configapply.ConformanceHandler{},
		SessionLauncherFactory:    testSessionLauncherFactory("/bin/sh", []string{"-l"}, []string{"PATH=/usr/bin:/bin"}),
		RuntimeObservationService: serviceGroup{runtimeObservationGroupMember{}, observation},
	})
	if err != nil {
		t.Fatal(err)
	}
	startupCtx, cancelStartup := context.WithCancel(context.Background())
	if err := host.StartHostd(startupCtx); err != nil {
		cancelStartup()
		t.Fatal(err)
	}
	cancelStartup()
	if state := host.State(); state != New {
		t.Fatalf("replaceable runtime state = %q, want %q", state, New)
	}
	waitForRuntimeObservationCalls(t, transport, 2)
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := host.ShutdownHostd(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	stoppedAt := transport.calls.Load()
	time.Sleep(4 * observation.interval)
	if got := transport.calls.Load(); got != stoppedAt {
		t.Fatalf("observation loop continued after hostd shutdown: calls=%d want=%d", got, stoppedAt)
	}
}

func waitForRuntimeObservationCalls(t *testing.T, transport *livenessObservationTransport, want int64) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for transport.calls.Load() < want {
		select {
		case <-transport.notify:
		case <-deadline.C:
			t.Fatalf("observation calls=%d, want at least %d", transport.calls.Load(), want)
		}
	}
}
