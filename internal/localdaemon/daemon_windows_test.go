//go:build windows

package localdaemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type blockingWindowsMachineSource struct {
	started chan struct{}
}

func (s blockingWindowsMachineSource) ListUserMachines(ctx context.Context) ([]api.UserMachine, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWindowsDaemonServesStartingSnapshotBeforeInitialRefresh(t *testing.T) {
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	paths := localapi.Paths{
		StateRoot:   root,
		RuntimeRoot: root,
		SocketPath:  fmt.Sprintf(`\\.\pipe\paperboat-startup-%d-%d`, os.Getpid(), time.Now().UnixNano()),
		LockPath:    filepath.Join(root, "daemon.lock"),
	}
	started := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWindowsDaemon(ctx, DaemonConfig{
			Paths: paths, Source: blockingWindowsMachineSource{started: started}, OwnerSID: ownerSID,
			RefreshInterval: time.Second, RequestTimeout: 30 * time.Second,
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("initial inventory refresh did not start")
	}
	client, err := localapi.NewClient(paths.SocketPath, 100*time.Millisecond)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var snapshot localapi.Snapshot
	for time.Now().Before(deadline) {
		snapshot, err = client.Snapshot(context.Background())
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || snapshot.DaemonState != "starting" || snapshot.Generation != 1 {
		cancel()
		t.Fatalf("startup snapshot=%+v error=%v", snapshot, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("daemon stop error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
}
