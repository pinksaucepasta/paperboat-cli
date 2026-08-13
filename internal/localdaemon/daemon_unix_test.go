//go:build darwin || linux

package localdaemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

func daemonTestPaths(t *testing.T) localapi.Paths {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "pb-ld-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return localapi.Paths{StateRoot: root, RuntimeRoot: root, SocketPath: filepath.Join(root, "api.sock"), LockPath: filepath.Join(root, "daemon.lock")}
}

func TestProcessLockIsExclusiveAndRejectsUnsafePath(t *testing.T) {
	paths := daemonTestPaths(t)
	first, err := acquireProcessLock(paths.LockPath, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireProcessLock(paths.LockPath, os.Geteuid()); !errors.Is(err, localapi.ErrAlreadyRunning) {
		t.Fatalf("second lock err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireProcessLock(paths.LockPath, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	unsafeTarget := filepath.Join(paths.StateRoot, "target")
	if err := os.WriteFile(unsafeTarget, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(paths.StateRoot, "symlink.lock")
	if err := os.Symlink(unsafeTarget, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireProcessLock(symlink, os.Geteuid()); !errors.Is(err, localapi.ErrUnsafeSocket) {
		t.Fatalf("symlink lock err=%v", err)
	}
}

func TestDaemonPublishesSnapshotServesAPIAndStopsCleanly(t *testing.T) {
	paths := daemonTestPaths(t)
	source := &scriptedMachineSource{results: []machineResult{{machines: []api.UserMachine{{ID: "machine_1", DisplayName: "Studio Mac", Online: true, InstallationGeneration: 4}}}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, DaemonConfig{Paths: paths, Source: source, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), RefreshInterval: time.Second, RequestTimeout: time.Second})
	}()
	waitForDaemonSocket(t, paths.SocketPath)
	client, err := localapi.NewClient(paths.SocketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Snapshot(context.Background())
	if err != nil || snapshot.DaemonState != "ready" || len(snapshot.Machines) != 1 || snapshot.Machines[0].Alias != "Studio Mac" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	now := time.Now().UTC()
	observation := localapi.TransportObservation{Schema: localapi.ObservationSchemaV1, SourceID: "source_canary", Sequence: 1, ObservedAt: now, ExpiresAt: now.Add(15 * time.Second), MachineID: "machine_1", ActiveConsumers: 1, SelectedPath: "relay", RelayRegion: "bom", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if err := client.PublishTransportObservation(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	snapshot, err = client.Snapshot(context.Background())
	if err != nil || snapshot.Generation != 2 || snapshot.Machines[0].ActiveConsumers != 1 || snapshot.Machines[0].SelectedPath != "relay" || snapshot.Machines[0].RelayRegion != "bom" {
		t.Fatalf("observed snapshot=%#v err=%v", snapshot, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if _, err := os.Lstat(paths.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup err=%v", err)
	}
}

func TestDaemonOwnsStaleSocketCleanupAfterLockAcquisition(t *testing.T) {
	paths := daemonTestPaths(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	source := &scriptedMachineSource{results: []machineResult{{err: errors.New("offline")}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, DaemonConfig{Paths: paths, Source: source, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), RefreshInterval: time.Second, RequestTimeout: time.Second})
	}()
	waitForDaemonSocket(t, paths.SocketPath)
	client, _ := localapi.NewClient(paths.SocketPath, time.Second)
	snapshot, err := client.Snapshot(context.Background())
	if err != nil || snapshot.DaemonState != "degraded" || len(snapshot.Health) != 1 || snapshot.Health[0].Code != "control_plane_unavailable" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run err=%v", err)
	}
}

func waitForDaemonSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", path, 20*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("daemon socket %s was not ready", path)
}
